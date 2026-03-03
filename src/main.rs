use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use eframe::egui;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

type LogFn = Arc<dyn Fn(String) + Send + Sync + 'static>;

const TOKEN_FILE: &str = "figma-tokens.json";
const CLIENT_CREDS_FILE: &str = "figma-client-creds.json";
const MCP_URL: &str = "https://mcp.figma.com/mcp";
const TOKEN_ENDPOINT: &str = "https://api.figma.com/v1/oauth/token";
const AUTH_ENDPOINT: &str = "https://www.figma.com/oauth/mcp";
const SCOPE: &str = "mcp:connect";

struct FigmaNode {
    file_key: String,
    node_id: String,
}

fn parse_figma_url(raw: &str) -> Result<FigmaNode> {
    let parsed = Url::parse(raw).context("Invalid URL")?;

    let segments: Vec<&str> = parsed
        .path_segments()
        .ok_or_else(|| anyhow!("URL has no path"))?
        .collect();

    let file_key = segments
        .get(1)
        .ok_or_else(|| anyhow!("Cannot find fileKey in URL path"))?
        .to_string();

    let node_id = parsed
        .query_pairs()
        .find(|(k, _)| k == "node-id")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| anyhow!("URL is missing ?node-id=... query parameter"))?;

    Ok(FigmaNode { file_key, node_id })
}

#[derive(Deserialize)]
struct ClientCreds {
    client_id: String,
    client_secret: String,
}

fn load_client_creds() -> Result<ClientCreds> {
    let raw = fs::read_to_string(CLIENT_CREDS_FILE)
        .with_context(|| format!("Cannot read {CLIENT_CREDS_FILE}"))?;
    let creds: ClientCreds = serde_json::from_str(&raw)
        .with_context(|| format!("Malformed JSON in {CLIENT_CREDS_FILE}"))?;
    Ok(creds)
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct TokenStore {
    access_token: String,
    refresh_token: String,
    expires_at_ms: i64,
}

fn load_tokens() -> TokenStore {
    fs::read_to_string(TOKEN_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_tokens(store: &TokenStore) -> Result<()> {
    fs::write(TOKEN_FILE, serde_json::to_string_pretty(store)?)
        .with_context(|| format!("Failed to write {TOKEN_FILE}"))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn random_b64url(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    b64url(&buf)
}

fn temp_file_path(prefix: &str, ext: &str) -> PathBuf {
    let nonce = rand::thread_rng().next_u64();
    env::temp_dir().join(format!("{prefix}-{}-{nonce:016x}.{ext}", now_ms()))
}

async fn do_browser_auth(
    http: &reqwest::Client,
    creds: &ClientCreds,
    store: &mut TokenStore,
    log: &LogFn,
) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("Failed to bind local redirect listener")?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let code_verifier = random_b64url(32);
    let code_challenge = b64url(&Sha256::digest(code_verifier.as_bytes()));
    let state = random_b64url(16);

    let auth_url = Url::parse_with_params(
        AUTH_ENDPOINT,
        &[
            ("response_type", "code"),
            ("client_id", creds.client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", SCOPE),
            ("state", state.as_str()),
            ("code_challenge", code_challenge.as_str()),
            ("code_challenge_method", "S256"),
        ],
    )
    .context("Failed to build authorization URL")?;

    log(format!("Opening browser for authorization: {auth_url}"));
    if let Err(err) = open::that(auth_url.as_str()) {
        log(format!(
            "Failed to open browser automatically ({err}). Open the URL manually."
        ));
    }

    log(format!(
        "Waiting for OAuth callback on local port {port}..."
    ));
    let (mut socket, _) = listener.accept().await?;
    let mut buf = vec![0u8; 4096];
    let n = socket.read(&mut buf).await?;
    let raw_request = String::from_utf8_lossy(&buf[..n]).to_string();

    let _ = socket
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
            <html><body><h2>Authorization complete.</h2>\
            <p>You can close this tab and return to the app.</p></body></html>",
        )
        .await;
    drop(socket);

    let request_line = raw_request.lines().next().unwrap_or("");
    let path = request_line.split_whitespace().nth(1).unwrap_or("");
    let callback_url =
        Url::parse(&format!("http://localhost{path}")).context("Failed to parse callback URL")?;

    let mut code: Option<String> = None;
    let mut returned_state: Option<String> = None;
    for (k, v) in callback_url.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => returned_state = Some(v.into_owned()),
            "error" => bail!(
                "Figma returned an OAuth error: {v} - {}",
                callback_url
                    .query_pairs()
                    .find(|(k, _)| k == "error_description")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            ),
            _ => {}
        }
    }

    if returned_state.as_deref() != Some(state.as_str()) {
        bail!("OAuth state mismatch; aborting");
    }
    let code = code.ok_or_else(|| anyhow!("No authorization code in callback: {path}"))?;

    log("Exchanging authorization code for tokens...".to_string());
    let resp = http
        .post(TOKEN_ENDPOINT)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", creds.client_id.as_str()),
            ("client_secret", creds.client_secret.as_str()),
            ("code_verifier", code_verifier.as_str()),
        ])
        .send()
        .await
        .context("Token exchange request failed")?;

    apply_token_response(resp, store).await?;
    log(format!("Tokens obtained and saved to {TOKEN_FILE}."));
    Ok(())
}

async fn apply_token_response(resp: reqwest::Response, store: &mut TokenStore) -> Result<()> {
    let body: Value = resp
        .json()
        .await
        .context("Failed to parse token endpoint response")?;

    if let Some(err) = body["error"].as_str() {
        bail!(
            "Token error `{err}`: {}",
            body["error_description"]
                .as_str()
                .unwrap_or("(no description)")
        );
    }

    store.access_token = body["access_token"]
        .as_str()
        .ok_or_else(|| anyhow!("No access_token in response: {body}"))?
        .to_string();

    if let Some(rt) = body["refresh_token"].as_str() {
        store.refresh_token = rt.to_string();
    }

    store.expires_at_ms = now_ms() + body["expires_in"].as_i64().unwrap_or(3600) * 1_000;
    Ok(())
}

async fn ensure_valid_token(
    http: &reqwest::Client,
    creds: &ClientCreds,
    store: &mut TokenStore,
    log: &LogFn,
) -> Result<String> {
    if store.expires_at_ms > now_ms() + 60_000 && !store.access_token.is_empty() {
        log("Using cached access token.".to_string());
        return Ok(store.access_token.clone());
    }

    if !store.refresh_token.is_empty() {
        log("Access token expired; attempting silent refresh...".to_string());
        let resp = http
            .post(TOKEN_ENDPOINT)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", store.refresh_token.as_str()),
                ("client_id", creds.client_id.as_str()),
                ("client_secret", creds.client_secret.as_str()),
            ])
            .send()
            .await
            .context("Token refresh request failed")?;

        match apply_token_response(resp, store).await {
            Ok(()) => {
                log("Token refreshed.".to_string());
                return Ok(store.access_token.clone());
            }
            Err(e) => {
                log(format!(
                    "Silent refresh failed ({e}); falling back to browser auth..."
                ));
                store.refresh_token.clear();
            }
        }
    }

    do_browser_auth(http, creds, store, log).await?;
    Ok(store.access_token.clone())
}

async fn mcp_call(http: &reqwest::Client, token: &str, request: &Value) -> Result<Value> {
    let req_id = request["id"].as_u64().unwrap_or(0);

    let resp = http
        .post(MCP_URL)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(request)
        .send()
        .await
        .context("MCP HTTP request failed")?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp
        .text()
        .await
        .context("Failed to read MCP response body")?;

    if !status.is_success() {
        bail!("MCP server returned HTTP {status}: {body}");
    }

    if content_type.contains("text/event-stream") {
        for line in body.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                if let Ok(v) = serde_json::from_str::<Value>(data) {
                    if v["id"].as_u64() == Some(req_id) {
                        return Ok(v);
                    }
                }
            }
        }
        bail!("No matching JSON-RPC response found in SSE stream:\n{body}");
    } else {
        serde_json::from_str(&body).context("Failed to parse JSON response from MCP server")
    }
}

async fn call_tool(
    http: &reqwest::Client,
    token: &str,
    id: u64,
    tool: &str,
    args: Value,
) -> Result<Value> {
    mcp_call(
        http,
        token,
        &json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "name": tool, "arguments": args },
            "id": id
        }),
    )
    .await
}

fn extract_text(resp: &Value) -> Result<String> {
    let parts: Vec<&str> = resp
        .pointer("/result/content")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("No /result/content array in response:\n{resp}"))?
        .iter()
        .filter(|item| item["type"] == "text")
        .filter_map(|item| item["text"].as_str())
        .collect();

    if parts.is_empty() {
        bail!("No text blocks in MCP response:\n{resp}");
    }
    Ok(parts.join("\n"))
}

fn extract_image(resp: &Value) -> Result<Vec<u8>> {
    let b64 = resp
        .pointer("/result/content")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("No /result/content array in response:\n{resp}"))?
        .iter()
        .find(|item| item["type"] == "image")
        .and_then(|item| item["data"].as_str())
        .ok_or_else(|| anyhow!("No image block in MCP response:\n{resp}"))?;

    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("Failed to base64-decode image data")
}

struct ExportOutput {
    html_path: PathBuf,
    screenshot_path: PathBuf,
    html: String,
    screenshot_png: Vec<u8>,
}

async fn export_from_figma_url(figma_url: String, log: LogFn) -> Result<ExportOutput> {
    let node = parse_figma_url(&figma_url)
        .with_context(|| format!("Could not parse Figma URL: {figma_url}"))?;

    log(format!("File key: {}", node.file_key));
    log(format!("Node ID: {}", node.node_id));

    let creds = load_client_creds()?;
    let id_prefix: String = creds.client_id.chars().take(12).collect();
    log(format!(
        "Client credentials loaded (id prefix: {id_prefix}...)"
    ));

    let http = reqwest::Client::new();
    let mut store = load_tokens();
    let token = ensure_valid_token(&http, &creds, &mut store, &log).await?;
    save_tokens(&store)?;

    log("Calling get_design_context...".to_string());
    let dc = call_tool(
        &http,
        &token,
        1,
        "get_design_context",
        json!({
            "nodeId": node.node_id,
            "fileKey": node.file_key,
            "clientLanguages": "html",
            "clientFrameworks": "tailwind",
            "forceCode": true,
            "excludeScreenshot": true,
        }),
    )
    .await
    .context("get_design_context failed")?;

    let html = extract_text(&dc)?;
    let html_path = temp_file_path("design-ctx", "html");
    fs::write(&html_path, &html)
        .with_context(|| format!("Failed to write {}", html_path.display()))?;
    log(format!(
        "Design context saved: {} ({} bytes)",
        html_path.display(),
        html.len()
    ));

    log("Calling get_screenshot...".to_string());
    let ss = call_tool(
        &http,
        &token,
        2,
        "get_screenshot",
        json!({
            "nodeId": node.node_id,
            "fileKey": node.file_key,
        }),
    )
    .await
    .context("get_screenshot failed")?;

    let png = extract_image(&ss)?;
    let screenshot_path = temp_file_path("design-scr", "png");
    fs::write(&screenshot_path, &png)
        .with_context(|| format!("Failed to write {}", screenshot_path.display()))?;
    log(format!(
        "Screenshot saved: {} ({} bytes)",
        screenshot_path.display(),
        png.len()
    ));

    Ok(ExportOutput {
        html_path,
        screenshot_path,
        html,
        screenshot_png: png,
    })
}

enum WorkerMessage {
    Log(String),
    Finished(Result<ExportOutput, String>),
}

fn start_worker(url: String, tx: Sender<WorkerMessage>) {
    thread::spawn(move || {
        let log_tx = tx.clone();
        let log: LogFn = Arc::new(move |line: String| {
            let _ = log_tx.send(WorkerMessage::Log(line));
        });

        let result = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt
                .block_on(export_from_figma_url(url, log))
                .map_err(|e| format!("{e:#}")),
            Err(err) => Err(format!("Failed to start async runtime: {err}")),
        };

        let _ = tx.send(WorkerMessage::Finished(result));
    });
}

struct FigmaExportApp {
    figma_url: String,
    log_output: String,
    html_output: String,
    html_path: Option<PathBuf>,
    screenshot_png: Vec<u8>,
    screenshot_path: Option<PathBuf>,
    screenshot_texture: Option<egui::TextureHandle>,
    is_running: bool,
    worker_rx: Option<Receiver<WorkerMessage>>,
    texture_nonce: u64,
}

impl Default for FigmaExportApp {
    fn default() -> Self {
        Self {
            figma_url: String::new(),
            log_output: String::new(),
            html_output: String::new(),
            html_path: None,
            screenshot_png: Vec::new(),
            screenshot_path: None,
            screenshot_texture: None,
            is_running: false,
            worker_rx: None,
            texture_nonce: 0,
        }
    }
}

impl FigmaExportApp {
    fn append_log(&mut self, line: impl AsRef<str>) {
        self.log_output.push_str(line.as_ref());
        self.log_output.push('\n');
    }

    fn clear_export_outputs(&mut self) {
        self.html_output.clear();
        self.html_path = None;
        self.screenshot_png.clear();
        self.screenshot_path = None;
        self.screenshot_texture = None;
    }

    fn decode_screenshot_color_image(&self) -> Result<egui::ColorImage> {
        let icon = eframe::icon_data::from_png_bytes(&self.screenshot_png)
            .context("Failed to decode screenshot PNG")?;
        Ok(egui::ColorImage::from_rgba_unmultiplied(
            [icon.width as usize, icon.height as usize],
            &icon.rgba,
        ))
    }

    fn load_screenshot_texture(&mut self, ctx: &egui::Context) -> Result<()> {
        if self.screenshot_png.is_empty() {
            self.screenshot_texture = None;
            return Ok(());
        }

        let image = self
            .decode_screenshot_color_image()
            .context("Failed to decode screenshot PNG for display")?;
        self.texture_nonce = self.texture_nonce.wrapping_add(1);
        self.screenshot_texture = Some(ctx.load_texture(
            format!("screenshot-preview-{}", self.texture_nonce),
            image,
            egui::TextureOptions::LINEAR,
        ));
        Ok(())
    }

    fn start_export(&mut self) {
        if self.is_running {
            return;
        }

        let url = self.figma_url.trim().to_string();
        if url.is_empty() {
            self.append_log("Please enter a Figma URL.");
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.is_running = true;
        self.clear_export_outputs();
        self.append_log(format!("Starting export for URL: {url}"));
        start_worker(url, tx);
    }

    fn poll_worker(&mut self, ctx: &egui::Context) {
        let mut finished: Option<Result<ExportOutput, String>> = None;
        let mut pending_logs: Vec<String> = Vec::new();

        if let Some(rx) = &self.worker_rx {
            loop {
                match rx.try_recv() {
                    Ok(WorkerMessage::Log(line)) => pending_logs.push(line),
                    Ok(WorkerMessage::Finished(result)) => {
                        finished = Some(result);
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        finished = Some(Err("Worker disconnected unexpectedly.".to_string()));
                        break;
                    }
                }
            }
        }

        for line in pending_logs {
            self.append_log(line);
        }

        if let Some(result) = finished {
            self.is_running = false;
            self.worker_rx = None;
            match result {
                Ok(paths) => {
                    self.append_log("Export completed.");
                    self.append_log(format!("HTML file: {}", paths.html_path.display()));
                    self.append_log(format!(
                        "Screenshot file: {}",
                        paths.screenshot_path.display()
                    ));
                    self.html_path = Some(paths.html_path);
                    self.screenshot_path = Some(paths.screenshot_path);
                    self.html_output = paths.html;
                    self.screenshot_png = paths.screenshot_png;
                    if let Err(err) = self.load_screenshot_texture(ctx) {
                        self.append_log(format!("Could not display screenshot: {err:#}"));
                    }
                }
                Err(err) => self.append_log(format!("Export failed:\n{err}")),
            }
        }
    }

    fn copy_html_to_clipboard(&mut self, ctx: &egui::Context) {
        if self.html_output.is_empty() {
            self.append_log("No HTML is available yet.");
            return;
        }

        ctx.copy_text(self.html_output.clone());
        self.append_log(format!(
            "Copied HTML to clipboard ({} bytes).",
            self.html_output.len()
        ));
    }

    fn copy_screenshot_to_clipboard(&mut self, ctx: &egui::Context) {
        if self.screenshot_png.is_empty() {
            self.append_log("No screenshot is available yet.");
            return;
        }

        match self
            .decode_screenshot_color_image()
            .context("Failed to decode screenshot PNG for clipboard copy")
        {
            Ok(image) => {
                ctx.copy_image(image);
                self.append_log("Copied screenshot to clipboard.");
            }
            Err(err) => self.append_log(format!("Could not copy screenshot to clipboard: {err:#}")),
        }
    }
}

impl eframe::App for FigmaExportApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            const PREVIEW_HEIGHT: f32 = 260.0;

            ui.heading("Figma MCP Export");
            ui.label("Enter a Figma URL and export HTML + screenshot to temporary files.");
            ui.add_space(8.0);

            ui.label("Figma URL");
            let mut trigger_export = false;
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                let export_response = ui.add_enabled(!self.is_running, egui::Button::new("Export"));
                if export_response.clicked() {
                    trigger_export = true;
                }

                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.figma_url).desired_width(f32::INFINITY),
                );
                let submitted_with_enter =
                    response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
                if !self.is_running && submitted_with_enter {
                    trigger_export = true;
                }

                if self.is_running {
                    let spinner_size = export_response.rect.height() * 0.55;
                    let spinner_rect = egui::Rect::from_center_size(
                        export_response.rect.center(),
                        egui::vec2(spinner_size, spinner_size),
                    );
                    ui.put(spinner_rect, egui::Spinner::new().size(spinner_size));
                }
            });
            if trigger_export {
                self.start_export();
            }

            ui.add_space(12.0);
            ui.columns(2, |columns| {
                columns[0].horizontal(|ui| {
                    ui.label("Retrieved Screenshot");
                    if ui
                        .add_enabled(
                            !self.screenshot_png.is_empty(),
                            egui::Button::new("Copy Screenshot"),
                        )
                        .clicked()
                    {
                        self.copy_screenshot_to_clipboard(ctx);
                    }
                });
                egui::Frame::group(columns[0].style()).show(&mut columns[0], |ui| {
                    ui.set_height(PREVIEW_HEIGHT);
                    if let Some(texture) = &self.screenshot_texture {
                        egui::ScrollArea::both()
                            .id_salt("screenshot_scroll")
                            .max_height(PREVIEW_HEIGHT)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::Image::from_texture(texture)
                                        .max_width(ui.available_width()),
                                );
                            });
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label("No screenshot loaded yet.");
                        });
                    }
                });

                columns[1].horizontal(|ui| {
                    ui.label("Retrieved HTML");
                    if ui
                        .add_enabled(!self.html_output.is_empty(), egui::Button::new("Copy HTML"))
                        .clicked()
                    {
                        self.copy_html_to_clipboard(ctx);
                    }
                });
                egui::Frame::group(columns[1].style()).show(&mut columns[1], |ui| {
                    ui.set_height(PREVIEW_HEIGHT);
                    egui::ScrollArea::both()
                        .id_salt("html_scroll")
                        .max_height(PREVIEW_HEIGHT)
                        .show(ui, |ui| {
                            let mut visible_html = self.html_output.clone();
                            ui.add(
                                egui::TextEdit::multiline(&mut visible_html)
                                    .desired_rows(1)
                                    .desired_width(f32::INFINITY),
                            );
                        });
                });
            });

            ui.add_space(12.0);
            ui.label("Logs");
            let log_frame = egui::Frame::group(ui.style());
            let log_frame_vertical_margin = log_frame.total_margin().sum().y;
            let remaining_log_height = (ui.available_height() - log_frame_vertical_margin).max(0.0);
            log_frame.show(ui, |ui| {
                ui.set_min_height(remaining_log_height);
                let viewport_height = ui.available_height().max(0.0);
                egui::ScrollArea::both()
                    .id_salt("logs_scroll")
                    .auto_shrink([false, false])
                    .max_height(viewport_height)
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.monospace(&self.log_output);
                    });
            });
        });

        if self.is_running {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Figma MCP Export",
        options,
        Box::new(|_cc| Ok(Box::new(FigmaExportApp::default()))),
    )
}
