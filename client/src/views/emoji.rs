//! Emoji input for the chat composer: a curated in-app picker plus the
//! monochrome emoji font it (and every rendered message) depends on.
//!
//! egui/epaint 0.36 rasterize fonts with skrifa and draw flat-color glyph
//! outlines only — bitmap color-emoji formats (Apple Color Emoji sbix, CBDT,
//! COLR) have no path, so anything outside the registered font set renders
//! as tofu. epaint already registers a 2019-era `NotoEmoji-Regular` as a
//! fallback in both the Proportional and Monospace families, but that copy
//! predates Unicode 11 (even 🙂 is missing). [`install_fonts`] replaces that
//! entry with a current Noto Emoji (variable font, default instance =
//! Regular, Unicode 16 coverage) so the whole app — picker, composer, and
//! incoming messages — renders emoji as theme-tinted monochrome outlines.
//! The font lives in `client/assets/fonts/` under the SIL OFL 1.1
//! (`OFL.txt` beside it) and is embedded via `include_bytes!`.

use eframe::egui;

/// Current Noto Emoji (monochrome outline), embedded at compile time.
/// Variable font; epaint renders the default (Regular) instance.
const NOTO_EMOJI: &[u8] = include_bytes!("../../assets/fonts/NotoEmoji-Regular.ttf");

/// Replace epaint's bundled 2019 `NotoEmoji-Regular` (already a fallback in
/// both default families) with the current one from [`NOTO_EMOJI`]. Called
/// once at app creation; `Context::set_fonts` rebuilds the font atlas, so
/// re-created apps are fine too.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    // Same slot and scale tweak (emoji glyphs run tall) as the builtin, so
    // both the Proportional and Monospace fallback lists pick it up without
    // further edits.
    fonts.font_data.insert(
        "NotoEmoji-Regular".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(NOTO_EMOJI).tweak(
            egui::FontTweak {
                scale: 0.81, // Make smaller — matches the builtin entry
                ..Default::default()
            },
        )),
    );
    ctx.set_fonts(fonts);
}

/// One picker section: a heading followed by its emoji grid.
pub struct Category {
    /// Section label rendered above the grid.
    pub name: &'static str,
    /// Single-codepoint emoji (no variation selectors / ZWJ sequences —
    /// those ligate unreliably through the shaping stack).
    pub emoji: &'static [&'static str],
}

/// Curated common emoji, grouped for the picker. Every entry is covered by
/// [`NOTO_EMOJI`] (verified against its cmap; the unit test guards the
/// file's sfnt magic).
pub const CATEGORIES: &[Category] = &[
    Category {
        name: "Smileys & faces",
        emoji: &[
            "😀", "😄", "😅", "😂", "🤣", "🙂", "😉", "😊", "😇", "🥰", "😍", "😘", "😋", "😛",
            "😜", "🤪", "🤗", "🤭", "🤔", "🤨", "😐", "😶", "😏", "😒", "🙄", "😬", "😌", "😔",
            "😴", "😷", "🤕", "🥵", "🥶", "🤯", "🤠", "🥳", "😎", "🤓", "😕", "😮", "😲", "😳",
            "🥺", "😢", "😭", "😱", "🥱", "😤", "😡", "🤬", "😈", "👿", "💀", "🤡", "👻", "🤖",
            "💩",
        ],
    },
    Category {
        name: "People & gestures",
        emoji: &[
            "👋", "🖐", "✋", "🖖", "👌", "🤌", "🤏", "✌", "🤞", "🤘", "🤙", "👈", "👉", "👆",
            "👇", "👍", "👎", "✊", "👊", "🤛", "🤜", "👏", "🙌", "👐", "🤲", "🤝", "🙏", "✍",
            "💅", "🤳", "💪", "👀", "👁", "👂", "🧠", "👄", "👥", "🫂",
        ],
    },
    Category {
        name: "Hearts",
        emoji: &[
            "❤", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "💔", "💕", "💞", "💓", "💗", "💖",
            "💘", "💌",
        ],
    },
    Category {
        name: "Animals & nature",
        emoji: &[
            "🐶", "🐱", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵",
            "🐔", "🐧", "🐦", "🐤", "🦆", "🦅", "🦉", "🐴", "🦄", "🐝", "🐛", "🦋", "🐞", "🐢",
            "🦖", "🐙", "🐠", "🐟", "🐬", "🐳", "🦈", "🦓", "🐘", "🦒", "🐕", "🐈", "🕊", "🌸",
            "🌳", "🍀", "🌹", "🌻", "🌙", "⭐", "🌈", "☀", "❄", "⚡", "🔥", "🌊",
        ],
    },
    Category {
        name: "Food & drink",
        emoji: &[
            "🍏", "🍎", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🫐", "🍒", "🍑", "🥭", "🍍", "🥝",
            "🍅", "🥑", "🥦", "🌽", "🥕", "🥔", "🥐", "🍞", "🧀", "🍗", "🍔", "🍟", "🍕", "🥪",
            "🌮", "🥗", "🍜", "🍝", "🍣", "🍱", "🍚", "🍛", "🍤", "🍦", "🍰", "🎂", "🍪", "🍫",
            "🍬", "🍭", "🍩", "🍿", "☕", "🍵", "🥤", "🍺", "🍻", "🍷",
        ],
    },
    Category {
        name: "Activities",
        emoji: &[
            "⚽", "🏀", "🏈", "⚾", "🎾", "🏐", "🎱", "🏓", "🏸", "🥊", "🥋", "⛳", "🏹", "🎣",
            "🛹", "⛸", "🎿", "🏂", "🪂", "🏆", "🥇", "🥈", "🥉", "🏅", "🎫", "🎪", "🎭", "🎨",
            "🎬", "🎤", "🎧", "🎹", "🥁", "🎷", "🎸", "🎻", "🎲", "♟", "🎯", "🎳", "🎮", "🧩",
        ],
    },
    Category {
        name: "Objects",
        emoji: &[
            "⌚", "📱", "💻", "⌨", "🖥", "📷", "📸", "📞", "📺", "🎙", "⏰", "📡", "🔋", "🔌",
            "💡", "🔦", "💰", "💳", "💎", "🧰", "🔧", "🔨", "⚙", "🧲", "🔬", "💊", "💉", "🚪",
            "🪑", "🧸", "🖼", "🛍", "🎁", "🎈", "🎀", "🎉", "🎊", "📦", "📊", "📈", "🗓", "📋",
            "📁", "📰", "📚", "📖", "🔖", "🔗", "📎", "📌", "📍", "📝", "✏", "🔍", "🔒", "🔓",
            "🔑", "🔔",
        ],
    },
    Category {
        name: "Symbols",
        emoji: &[
            "✅", "❌", "⭕", "🚫", "⛔", "ℹ", "⚠", "♻", "✨", "🌟", "💫", "💯", "❓", "❗",
            "✔", "✖", "➕", "➖", "🔄", "🎵", "💬", "💭", "💤",
        ],
    },
];

/// Emoji per picker row.
const COLS: usize = 12;
/// Picker popup width: comfortably fits [`COLS`] buttons plus the frame.
const POPUP_WIDTH: f32 = 380.0;
/// Picker scroll height; taller lists scroll instead of growing the popup.
const POPUP_MAX_HEIGHT: f32 = 260.0;

/// The composer's emoji toggle button and, while open, the picker popup
/// anchored above it. `open` is the caller's persisted open state (egui
/// closes the popup on Escape / outside clicks by writing it back). Every
/// selection invokes `on_pick` with the emoji; the popup then stays open —
/// users typically insert several — and the caller returns focus to the
/// composer.
pub fn picker(ui: &mut egui::Ui, open: &mut bool, mut on_pick: impl FnMut(&str)) {
    // 🙂 needs the upgraded fallback font (see [`install_fonts`]); the
    // builtin 2019 copy lacks even this glyph.
    let btn = ui
        .add(egui::Button::new("🙂").small())
        .on_hover_text("Emoji");
    if btn.clicked() {
        *open = !*open;
    }
    // The composer strip sits at the bottom of the window, so the picker
    // opens upward. CloseOnClickOutside keeps it open across inserts.
    let popup = egui::Popup::from_response(&btn)
        .open_bool(open)
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .align(egui::RectAlign::TOP_START)
        .width(POPUP_WIDTH);
    popup.show(|ui| {
        egui::ScrollArea::vertical()
            .id_salt("emoji_picker_scroll")
            .max_height(POPUP_MAX_HEIGHT)
            .show(ui, |ui| {
                for cat in CATEGORIES {
                    ui.weak(cat.name);
                    egui::Grid::new(("emoji_grid", cat.name))
                        .num_columns(COLS)
                        .show(ui, |ui| {
                            for row in cat.emoji.chunks(COLS) {
                                for e in row {
                                    if ui.add(egui::Button::new(*e)).clicked() {
                                        on_pick(e);
                                    }
                                }
                                ui.end_row();
                            }
                        });
                }
            });
    });
}

/// Insert `emoji` into `draft` at `cursor_chars` (a character offset, as
/// reported by the composer's `TextEditOutput::cursor_range` — character,
/// not byte) or at the end when the composer has no cursor. Returns the
/// character index just past the insertion: the composer's new caret, which
/// the caller stores back into the `TextEdit` state so the next insert (and
/// the caret itself) lands after this one.
pub fn insert_at_cursor(draft: &mut String, cursor_chars: Option<usize>, emoji: &str) -> usize {
    let byte_idx = cursor_chars
        .and_then(|chars| draft.char_indices().nth(chars).map(|(b, _)| b))
        .unwrap_or(draft.len());
    draft.insert_str(byte_idx, emoji);
    let chars_before = draft[..byte_idx].chars().count();
    chars_before + emoji.chars().count()
}

/// The embedded font must be a loadable sfnt (TrueType/OTF): a truncated or
/// HTML "download" would otherwise fail only at first emoji render.
#[test]
fn font_blob_is_sfnt() {
    assert!(!NOTO_EMOJI.is_empty());
    let magic: [u8; 4] = NOTO_EMOJI[..4].try_into().unwrap();
    assert!(
        magic == [0x00, 0x01, 0x00, 0x00] || magic == *b"OTTO" || magic == *b"true",
        "unexpected sfnt magic: {magic:?}"
    );
}

/// The replacement must register and parse through the real epaint font
/// pipeline (an unparsable font panics at first use). 🙂 is the picker's
/// toggle glyph and 🥲 is Unicode 13 — the builtin 2019 copy has neither,
/// so this also proves the upgrade actually took.
///
/// `Fonts::has_glyphs` cannot verify this: epaint's replacement sentinel
/// is '◻' (U+25FB), which NotoEmoji itself covers (the builtin copy too),
/// so every glyph the emoji font owns compares equal to the replacement
/// face and reports false — even on stock egui. Instead: shaping 🙂 and 🥲
/// must produce two glyphs with distinct atlas rectangles (tofu would
/// reuse the one replacement rectangle), and the live
/// "NotoEmoji-Regular" must be the shipped variable font (the 2019
/// builtin is static, so it reports no variation axes).
#[test]
fn installed_font_covers_modern_emoji() {
    let ctx = egui::Context::default();
    install_fonts(&ctx);
    // Fonts build lazily at the first pass begin (pixels_per_point is
    // unknown before then); building panics on any unparsable face, so
    // getting past this point proves our blob loaded.
    ctx.begin_pass(egui::RawInput::default());
    let galley = ctx.fonts_mut(|f| {
        f.layout(
            "🙂🥲".to_owned(),
            egui::FontId::proportional(14.0),
            egui::Color32::WHITE,
            100.0,
        )
    });
    // Rasterizing glyphs queues an atlas texture delta; drop it cleanly
    // (dropping it unapplied trips a debug assert in epaint).
    ctx.end_pass().textures_delta.clear();

    let uvs: Vec<_> = galley
        .rows
        .iter()
        .flat_map(|row| row.row.glyphs.iter().map(|g| g.uv_rect))
        .collect();
    assert_eq!(uvs.len(), 2, "expected one glyph per emoji");
    assert_ne!(
        uvs[0], uvs[1],
        "🙂 and 🥲 both resolved to the same (replacement) glyph"
    );

    let axes = ctx.fonts(|f| {
        f.definitions().font_data["NotoEmoji-Regular"].variation_axes()
    });
    assert!(
        !axes.is_empty(),
        "live NotoEmoji-Regular is static — the shipped variable font was not installed"
    );
}

#[test]
fn insert_at_cursor_handles_multibyte() {
    let mut draft = String::from("hällo");
    // Cursor after "hä" = 2 chars in, byte 1+2=3 ("ä" is 2 bytes).
    let caret = insert_at_cursor(&mut draft, Some(2), "🙂");
    assert_eq!(draft, "hä🙂llo");
    assert_eq!(caret, 3); // 2 chars + the 1-char emoji

    // No cursor reported: append at the end, caret past it.
    let caret = insert_at_cursor(&mut draft, None, "😄");
    assert_eq!(draft, "hä🙂llo😄");
    assert_eq!(caret, draft.chars().count());

    // A cursor past the end clamps to it.
    let mut draft = String::from("ab");
    let caret = insert_at_cursor(&mut draft, Some(99), "🔥");
    assert_eq!(draft, "ab🔥");
    assert_eq!(caret, 3);
}
