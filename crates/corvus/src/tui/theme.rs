// theme.rs
//
// The dashboard palette. Blue is the field, pink is what is alive, and orange
// is reserved: it appears only for a warning or an error, so that when it does
// appear it reads instantly. Nothing is fully saturated.

use ratatui::style::{Color, Modifier, Style};

/// Structure: borders, headings, axis labels.
pub const BLUE: Color = Color::Rgb(0x87, 0xD7, 0xFF);
/// Grid lines, axes, inactive chrome.
pub const BLUE_DEEP: Color = Color::Rgb(0x00, 0x87, 0xD7);
/// The faintest structural blue, for rules and separators.
pub const BLUE_DIM: Color = Color::Rgb(0x00, 0x5F, 0x87);

/// The live accent: selection, cursor, the JA4 series.
pub const PINK: Color = Color::Rgb(0xFF, 0x5F, 0xD7);
/// Secondary series, the JA3 line, decaying points.
pub const PINK_DIM: Color = Color::Rgb(0xD7, 0x5F, 0xAF);

/// Body text.
pub const TEXT: Color = Color::Rgb(0xC6, 0xC6, 0xC6);
/// Decay tails, disabled rows, secondary labels.
pub const DIM: Color = Color::Rgb(0x58, 0x58, 0x58);

/// The constellation lattice. Deliberately near the background: it should be
/// felt as structure, not read as data.
pub const GRID: Color = Color::Rgb(0x00, 0x2B, 0x40);

/// Warnings only: a suspicious verdict, a rotation, a mismatch.
pub const WARN: Color = Color::Rgb(0xD7, 0x5F, 0x00);
/// Errors only: a known-bad hit, a malicious verdict.
pub const ALERT: Color = Color::Rgb(0xAF, 0x37, 0x00);

/// Panel borders when the pane does not have focus.
pub fn border() -> Style {
    Style::default().fg(BLUE_DIM)
}

/// Panel borders when the pane has focus.
pub fn border_focus() -> Style {
    Style::default().fg(PINK)
}

/// Panel titles.
pub fn title() -> Style {
    Style::default().fg(BLUE).add_modifier(Modifier::BOLD)
}

/// The row under the cursor. A reversed block reads as a heavy paint smear at
/// this density; a bold row plus a gutter caret is lighter and easier to track.
pub fn selected() -> Style {
    Style::default().fg(PINK).add_modifier(Modifier::BOLD)
}

/// Body text.
pub fn text() -> Style {
    Style::default().fg(TEXT)
}

/// Secondary text.
pub fn dim() -> Style {
    Style::default().fg(DIM)
}

/// In-canvas axis captions.
pub fn axis() -> Style {
    Style::default().fg(BLUE_DEEP)
}
