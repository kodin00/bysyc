# Pure-Rust client on egui — zero web tech

The client must be lightweight (target < 30 MB binary, < 150 MB RAM) with zero web technology. We chose egui/eframe: pure Rust, GPU-rendered, repaints only on interaction (~1–2 ms/frame), with built-in virtualized row support (`ScrollArea::show_rows`) for message lists. Chat UI widgets (message list, text input, inline image rendering via `egui_extras`/image loaders) are hand-assembled from primitives — accepted cost.

## Considered Options

- **iced**: nicer Elm-architecture composition and chat-friendly `anchor_bottom`, but pre-1.0 with API churn between minor versions.
- **Tauri / webview shells**: fastest path to a pretty chat UI, but rely on OS webviews (WebKitGTK pain on Linux), drag web tech into the client, and violate the zero-web constraint.

## Consequences

- Large scroll histories must always be virtualized; unvirtualized message lists will visibly cost CPU in immediate mode.
- Local persistence is SQLite (rusqlite); session token and pickle passphrase live in a 0600 `secrets.json` in the data dir (amended 2026-10-15: previously the OS keychain via the keyring crate — dropped to avoid keychain access prompts; the passphrase still never lives inside the SQLite file it protects).
