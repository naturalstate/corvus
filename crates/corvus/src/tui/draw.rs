// draw.rs
//
// Rendering only. Nothing here mutates state or touches the pipeline.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Points};
use ratatui::widgets::{
    Axis, Block, Borders, Cell, Chart, Dataset, GraphType, List, ListItem, Paragraph, Row as TRow,
    Sparkline, Table,
};

use corvus_intel::AlertSeverity;

use super::state::{AppState, Focus, Row, Tone, ciphers_of, extensions_of};
use super::theme;

/// The colour a row, point, or label is painted with.
fn tone_color(tone: Tone) -> Color {
    match tone {
        Tone::Benign => theme::BLUE_DEEP,
        Tone::Unknown => theme::TEXT,
        Tone::Suspicious => theme::WARN,
        Tone::Malicious => theme::ALERT,
    }
}

fn panel(title: &str, focused: bool) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(if focused {
            theme::border_focus()
        } else {
            theme::border()
        })
        .title(Span::styled(format!(" {title} "), theme::title()))
}

pub fn draw(frame: &mut Frame, state: &AppState) {
    let area = frame.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(6),
            Constraint::Length(1),
        ])
        .split(area);

    header(frame, rows[0], state);

    if state.focus == Focus::Inspector {
        inspector(frame, rows[1], state);
    } else {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(rows[1]);
        stream(frame, body[0], state);

        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(45),
                Constraint::Percentage(35),
                Constraint::Percentage(20),
            ])
            .split(body[1]);
        constellation(frame, right[0], state);
        divergence(frame, right[1], state);
        barcode(frame, right[2], state);
    }

    alerts(frame, rows[2], state);
    footer(frame, rows[3], state);
}

fn header(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(theme::border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(34), Constraint::Min(20)])
        .split(inner);

    let secs = state.uptime().as_secs();
    let summary = Paragraph::new(vec![
        Line::from(Span::styled(
            "corvus",
            Style::default()
                .fg(theme::PINK)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(format!("{:>7}", state.total), theme::text()),
            Span::styled(" fingerprints  ", theme::dim()),
            Span::styled(
                format!(
                    "{:02}:{:02}:{:02}",
                    secs / 3600,
                    secs % 3600 / 60,
                    secs % 60
                ),
                Style::default().fg(theme::BLUE),
            ),
        ]),
        Line::from(vec![
            Span::styled("ja3 ", theme::dim()),
            Span::styled(
                format!("{:<5}", state.distinct_ja3()),
                Style::default().fg(theme::PINK_DIM),
            ),
            Span::styled("ja4 ", theme::dim()),
            Span::styled(
                format!("{:<5}", state.distinct_ja4()),
                Style::default().fg(theme::PINK),
            ),
        ]),
    ]);
    frame.render_widget(summary, cols[0]);

    let data: Vec<u64> = state.rate.iter().copied().collect();
    let spark = Sparkline::default()
        .data(&data)
        .style(Style::default().fg(theme::BLUE_DEEP));
    frame.render_widget(spark, cols[1]);
}

fn stream(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = panel("live", state.focus == Focus::Stream);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let height = inner.height as usize;
    let first = state.selected.saturating_sub(height / 2);

    let rows: Vec<TRow> = state
        .rows
        .iter()
        .enumerate()
        .skip(first)
        .take(height)
        .map(|(index, row)| {
            let base = Style::default().fg(tone_color(row.tone));
            let style = if index == state.selected {
                theme::selected()
            } else {
                base
            };
            TRow::new(vec![
                Cell::from(clock(row.ts_nanos)).style(theme::dim()),
                Cell::from(row.kind),
                Cell::from(truncate(&row.fingerprint, 34)),
                Cell::from(truncate(row.sni.as_deref().unwrap_or("-"), 26)),
                Cell::from(label_of(row)),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(13),
            Constraint::Length(34),
            Constraint::Min(14),
            Constraint::Length(18),
        ],
    )
    .header(
        TRow::new(vec!["time", "kind", "fingerprint", "sni", "identity"])
            .style(Style::default().fg(theme::BLUE_DIM)),
    );
    frame.render_widget(table, inner);
}

/// Cipher count against extension count, one point per ClientHello, fading out
/// over a few seconds. Stacks with similar shapes land on top of each other, so
/// a browser population forms a tight cluster and an odd client sits alone.
fn constellation(frame: &mut Frame, area: Rect, state: &AppState) {
    let now = std::time::Instant::now();

    let mut bright: Vec<(f64, f64)> = Vec::new();
    let mut fading: Vec<(f64, f64)> = Vec::new();
    let mut warn: Vec<(f64, f64)> = Vec::new();
    let mut bad: Vec<(f64, f64)> = Vec::new();
    for star in &state.stars {
        let point = (star.ciphers, star.extensions);
        match star.tone {
            Tone::Malicious => bad.push(point),
            Tone::Suspicious => warn.push(point),
            _ if star.intensity(now) > 0.55 => bright.push(point),
            _ => fading.push(point),
        }
    }

    let block = panel("constellation  ciphers × extensions", false);
    let canvas = Canvas::default()
        .block(block)
        .marker(Marker::Braille)
        .x_bounds([0.0, 36.0])
        .y_bounds([0.0, 36.0])
        .paint(move |ctx| {
            ctx.draw(&Points {
                coords: &fading,
                color: theme::DIM,
            });
            ctx.draw(&Points {
                coords: &bright,
                color: theme::PINK,
            });
            ctx.draw(&Points {
                coords: &warn,
                color: theme::WARN,
            });
            ctx.draw(&Points {
                coords: &bad,
                color: theme::ALERT,
            });
        });
    frame.render_widget(canvas, area);
}

/// Distinct JA3 hashes against distinct JA4 hashes over time. With a browser on
/// the wire the JA3 line climbs without bound while JA4 stays flat, which is
/// the entire argument for JA4 drawing itself.
fn divergence(frame: &mut Frame, area: Rect, state: &AppState) {
    #[allow(clippy::cast_precision_loss)]
    let ja3: Vec<(f64, f64)> = state
        .divergence
        .iter()
        .enumerate()
        .map(|(i, (a, _))| (i as f64, *a))
        .collect();
    #[allow(clippy::cast_precision_loss)]
    let ja4: Vec<(f64, f64)> = state
        .divergence
        .iter()
        .enumerate()
        .map(|(i, (_, b))| (i as f64, *b))
        .collect();

    let span = f64::from(u32::try_from(ja3.len().max(2) - 1).unwrap_or(u32::MAX));
    let ceiling = state
        .divergence
        .iter()
        .map(|(a, b)| a.max(*b))
        .fold(1.0_f64, f64::max)
        * 1.15;

    let datasets = vec![
        Dataset::default()
            .name("ja3")
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(theme::PINK_DIM))
            .data(&ja3),
        Dataset::default()
            .name("ja4")
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(theme::BLUE))
            .data(&ja4),
    ];

    let chart = Chart::new(datasets)
        .block(panel("divergence  distinct hashes", false))
        .x_axis(
            Axis::default()
                .style(Style::default().fg(theme::BLUE_DIM))
                .bounds([0.0, span]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(theme::BLUE_DIM))
                .bounds([0.0, ceiling])
                .labels(vec![
                    Span::styled("0", theme::dim()),
                    Span::styled(format!("{ceiling:.0}"), theme::dim()),
                ]),
        );
    frame.render_widget(chart, area);
}

/// The selected client's extension set as a bitmap. Two clients stacked show
/// their difference at a glance; this is the fingerprint made visible.
fn barcode(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = panel("extensions", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(row) = state.current() else {
        return;
    };
    let Some(fields) = row.raw.as_deref() else {
        return;
    };

    let extensions = extensions_of(fields);
    let bars: Vec<Span> = extensions
        .iter()
        .map(|ext| {
            Span::styled(
                "\u{2588}\u{2588} ",
                Style::default().fg(if ext.starts_with("00") {
                    theme::BLUE
                } else {
                    theme::PINK_DIM
                }),
            )
        })
        .collect();

    let text = vec![
        Line::from(bars),
        Line::from(Span::styled(
            format!(
                "{} extensions  {} ciphers",
                extensions.len(),
                ciphers_of(fields).len()
            ),
            theme::dim(),
        )),
    ];
    frame.render_widget(Paragraph::new(text), inner);
}

/// Full-screen decode of the selected fingerprint.
fn inspector(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = panel("inspector", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(row) = state.current() else {
        frame.render_widget(
            Paragraph::new("no fingerprint selected").style(theme::dim()),
            inner,
        );
        return;
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("JA4  ", theme::dim()),
            Span::styled(
                row.fingerprint.clone(),
                Style::default()
                    .fg(theme::PINK)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("JA3  ", theme::dim()),
            Span::styled(
                row.ja3.clone().unwrap_or_else(|| "-".into()),
                Style::default().fg(theme::PINK_DIM),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("{} -> {}", row.src, row.dst), theme::text()),
            Span::styled(format!("   {}", row.kind), theme::dim()),
        ]),
    ];

    if let Some(sni) = &row.sni {
        lines.push(Line::from(vec![
            Span::styled("sni  ", theme::dim()),
            Span::styled(sni.clone(), Style::default().fg(theme::BLUE)),
        ]));
    }
    if let Some(alpn) = &row.alpn {
        lines.push(Line::from(vec![
            Span::styled("alpn ", theme::dim()),
            Span::styled(alpn.clone(), Style::default().fg(theme::BLUE)),
        ]));
    }
    if let Some(ua) = &row.user_agent {
        lines.push(Line::from(vec![
            Span::styled("ua   ", theme::dim()),
            Span::styled(truncate(ua, 90), theme::text()),
        ]));
    }
    if let Some(label) = &row.label {
        lines.push(Line::from(vec![
            Span::styled("intel ", theme::dim()),
            Span::styled(label.clone(), Style::default().fg(tone_color(row.tone))),
            Span::styled(
                if row.fuzzy { "  (fuzzy)" } else { "  (exact)" },
                theme::dim(),
            ),
        ]));
    }

    if let Some(raw) = row.raw.as_deref() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "the field list that was hashed",
            Style::default().fg(theme::BLUE_DIM),
        )));
        lines.push(Line::from(""));

        let ciphers = ciphers_of(raw);
        let extensions = extensions_of(raw);
        lines.push(Line::from(vec![
            Span::styled(format!("ciphers    {:>3}  ", ciphers.len()), theme::dim()),
            Span::styled(ciphers.join(" "), Style::default().fg(theme::PINK)),
        ]));
        lines.push(Line::from(vec![
            Span::styled(
                format!("extensions {:>3}  ", extensions.len()),
                theme::dim(),
            ),
            Span::styled(extensions.join(" "), Style::default().fg(theme::BLUE)),
        ]));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

fn alerts(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = panel("alerts", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if state.alerts.is_empty() {
        frame.render_widget(Paragraph::new("none").style(theme::dim()), inner);
        return;
    }

    let items: Vec<ListItem> = state
        .alerts
        .iter()
        .take(inner.height as usize)
        .map(|alert| {
            let color = match alert.severity {
                AlertSeverity::Critical | AlertSeverity::High => theme::ALERT,
                AlertSeverity::Medium | AlertSeverity::Low => theme::WARN,
                AlertSeverity::Info => theme::BLUE_DEEP,
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<14}", alert.rule.as_str()),
                    Style::default().fg(color),
                ),
                Span::styled(
                    format!("{:<18}", alert.ip.clone().unwrap_or_else(|| "-".into())),
                    theme::dim(),
                ),
                Span::styled(truncate(&alert.title, 80), theme::text()),
            ]))
        })
        .collect();
    frame.render_widget(List::new(items), inner);
}

fn footer(frame: &mut Frame, area: Rect, state: &AppState) {
    let keys = if state.focus == Focus::Inspector {
        "  esc back   q quit"
    } else {
        "  ↑↓ / jk select   enter inspect   space pause   q quit"
    };
    let status = if state.source_done {
        "source finished"
    } else if state.paused {
        "paused"
    } else {
        "running"
    };
    let line = Line::from(vec![
        Span::styled(keys, theme::dim()),
        Span::styled(
            format!("   [{status}]"),
            Style::default().fg(if state.paused {
                theme::WARN
            } else {
                theme::BLUE_DIM
            }),
        ),
    ]);
    frame.render_widget(Paragraph::new(line).alignment(Alignment::Left), area);
}

fn label_of(row: &Row) -> Span<'static> {
    match &row.label {
        Some(label) => Span::styled(
            format!(
                "{}{}",
                if row.fuzzy { "~" } else { "" },
                truncate(label, 17)
            ),
            Style::default().fg(tone_color(row.tone)),
        ),
        None => Span::styled("-", theme::dim()),
    }
}

fn clock(ts_nanos: u64) -> String {
    let secs = ts_nanos / 1_000_000_000;
    let millis = ts_nanos % 1_000_000_000 / 1_000_000;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        secs / 3600 % 24,
        secs % 3600 / 60,
        secs % 60,
        millis
    )
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut out: String = value.chars().take(width.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::draw;
    use crate::tui::state::AppState;

    /// Layout constraints that overflow their area panic at render time, and a
    /// panic inside the alternate screen is the worst failure this can have. So
    /// draw at the sizes most likely to break: empty, tiny, and very wide.
    fn render_at(width: u16, height: u16) {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut state = AppState::new();
        state.tick();
        terminal.draw(|frame| draw(frame, &state)).unwrap();
    }

    #[test]
    fn renders_at_a_normal_size() {
        render_at(140, 44);
    }

    #[test]
    fn renders_in_a_cramped_terminal() {
        render_at(40, 12);
    }

    #[test]
    fn renders_when_absurdly_short() {
        render_at(20, 4);
    }

    #[test]
    fn renders_when_very_wide() {
        render_at(400, 60);
    }
}
