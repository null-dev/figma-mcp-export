## VCS Operations
As soon as the user asks you to make a change, you should succintly summarize the change you are about to make. Then, before you start writing the code, you MUST create a new change in `jj` using `jj new -m "<summary of the change>"`.

However, you should inspect the repo state before doing this with `jj status`. If the current change (`@`) is both empty AND has no description, you should create the change on the parent instead (e.g. `jj new -m "..." @-`).

ALWAYS DO THIS, even when the user asks you to tweak/refine a change you just made. This allows easy rollback of design/code tweaks.

## Validation
Always run `cargo fmt` followed by `cargo check` and `cargo build` after making changes to the Rust code.