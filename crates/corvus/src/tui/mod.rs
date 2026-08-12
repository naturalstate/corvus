// mod.rs
//
// The full-screen dashboard. Compiled only with the `tui` feature.
//
// The pipeline drives through a blocking callback, so it runs on its own thread
// and hands enriched observations over a channel. The render thread owns the
// terminal, folds whatever has arrived into `AppState`, and draws at a fixed
// rate. Nothing here touches the pipeline or the database directly, which keeps
// the passive engine unaware that a UI exists.

mod draw;
mod state;
mod theme;

use std::io::{Stdout, stdout};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

use corvus_core::{PcapFileSource, Pipeline, PipelineConfig};

use crate::cli::{detect_event, enrich, open_for_run};
use crate::live::{LiveConfig, LiveSource};
use state::{AppState, Focus, Observation};

/// How often the screen is redrawn.
const FRAME: Duration = Duration::from_millis(33);
/// How many observations are folded in per frame, so a fast replay cannot
/// starve rendering.
const DRAIN_PER_FRAME: usize = 512;

/// Where the dashboard's events come from.
pub enum Source {
    /// Replay a capture file, paced so it is watchable.
    Replay {
        path: PathBuf,
        interval: Duration,
        looping: bool,
    },
    /// Capture from an interface in process.
    Live {
        interface: String,
        filter: Option<String>,
    },
}

pub struct TuiConfig {
    pub source: Source,
    pub intel: bool,
    pub detect: bool,
    pub db: Option<PathBuf>,
}

/// Restores the terminal on the way out, including on a panic, so a crash
/// never leaves the user in raw mode with a hidden cursor.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<(Self, Terminal<CrosstermBackend<Stdout>>)> {
        enable_raw_mode().context("entering raw mode")?;
        let mut out = stdout();
        execute!(out, EnterAlternateScreen).context("entering the alternate screen")?;

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let _ = execute!(stdout(), LeaveAlternateScreen);
            previous(info);
        }));

        let mut terminal =
            Terminal::new(CrosstermBackend::new(out)).context("opening the terminal")?;
        // The alternate screen is not guaranteed to arrive blank, and ratatui
        // only repaints cells it believes changed. Without this, whatever was
        // on screen beforehand shows through every cell no widget covers.
        terminal.clear().context("clearing the terminal")?;
        Ok((Self, terminal))
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
    }
}

pub fn run(config: TuiConfig) -> Result<()> {
    let (tx, rx) = flume::bounded::<Observation>(4096);
    let TuiConfig {
        source,
        intel,
        detect,
        db,
    } = config;

    // Fail before taking over the screen, so an error is readable.
    let store = open_for_run(intel, detect, db.as_deref())?;
    if let Source::Replay { path, .. } = &source {
        if !path.exists() {
            anyhow::bail!("replay capture {} does not exist", path.display());
        }
    }

    let producer = thread::Builder::new()
        .name("corvus-tui-source".into())
        .spawn(move || produce(&source, store, intel, detect, &tx))
        .context("spawning the capture thread")?;

    let (_guard, mut terminal) = TerminalGuard::enter()?;
    let mut app = AppState::new();
    let mut last = Instant::now();

    loop {
        if !app.paused {
            for _ in 0..DRAIN_PER_FRAME {
                match rx.try_recv() {
                    Ok(observation) => app.fold(observation),
                    Err(flume::TryRecvError::Empty) => break,
                    Err(flume::TryRecvError::Disconnected) => {
                        app.source_done = true;
                        break;
                    }
                }
            }
        }
        app.tick();

        terminal.draw(|frame| draw::draw(frame, &app))?;

        let budget = FRAME.saturating_sub(last.elapsed());
        if event::poll(budget).context("polling for input")? {
            if let Event::Key(key) = event::read().context("reading input")? {
                if key.kind == KeyEventKind::Press && !handle_key(key.code, &mut app) {
                    break;
                }
            }
        }
        last = Instant::now();
    }

    drop(rx);
    let _ = producer.join();
    Ok(())
}

/// Returns false when the app should exit.
fn handle_key(code: KeyCode, app: &mut AppState) -> bool {
    match code {
        KeyCode::Char('q' | 'Q') => return false,
        KeyCode::Esc => {
            if app.focus == Focus::Inspector {
                app.focus = Focus::Stream;
            } else {
                return false;
            }
        }
        KeyCode::Enter => {
            app.focus = if app.focus == Focus::Inspector {
                Focus::Stream
            } else {
                Focus::Inspector
            };
        }
        KeyCode::Char(' ') => app.paused = !app.paused,
        KeyCode::Down | KeyCode::Char('j') => app.scroll(1),
        KeyCode::Up | KeyCode::Char('k') => app.scroll(-1),
        KeyCode::PageDown => app.scroll(20),
        KeyCode::PageUp => app.scroll(-20),
        KeyCode::Home => app.selected = 0,
        _ => {}
    }
    true
}

/// The producer thread: drive the pipeline, enrich, and hand the result over.
/// Every send failure means the UI has gone, so the thread stops quietly.
fn produce(
    source: &Source,
    mut store: Option<corvus_intel::IntelStore>,
    intel: bool,
    detect: bool,
    tx: &flume::Sender<Observation>,
) {
    match source {
        Source::Replay {
            path,
            interval,
            looping,
        } => loop {
            if !replay_once(path, &mut store, intel, detect, tx, *interval) || !*looping {
                break;
            }
        },
        Source::Live { interface, filter } => {
            let mut config = LiveConfig::default();
            if let Some(filter) = filter {
                config.filter.clone_from(filter);
            }
            match LiveSource::open(interface, &config) {
                Ok(mut live) => {
                    let mut pipeline = Pipeline::new(PipelineConfig::default());
                    let mut alive = true;
                    let _ = pipeline.run(&mut live, |event| {
                        if !alive {
                            return;
                        }
                        alive = emit(tx, &mut store, intel, detect, event);
                    });
                }
                Err(error) => tracing::error!(%error, "live capture failed to start"),
            }
        }
    }
}

/// One pass over a capture file. Returns false if the UI has gone away.
fn replay_once(
    path: &Path,
    store: &mut Option<corvus_intel::IntelStore>,
    intel: bool,
    detect: bool,
    tx: &flume::Sender<Observation>,
    interval: Duration,
) -> bool {
    let Ok(mut source) = PcapFileSource::open(path) else {
        tracing::error!(path = %path.display(), "cannot open capture");
        return false;
    };
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    let mut alive = true;
    let _ = pipeline.run(&mut source, |event| {
        if !alive {
            return;
        }
        alive = emit(tx, store, intel, detect, event);
        if alive && !interval.is_zero() {
            thread::sleep(interval);
        }
    });
    alive
}

/// Enrich one event and send it. Returns false once the receiver is gone.
fn emit(
    tx: &flume::Sender<Observation>,
    store: &mut Option<corvus_intel::IntelStore>,
    intel: bool,
    detect: bool,
    event: corvus_core::FingerprintEvent,
) -> bool {
    let reports = if intel {
        enrich(store.as_ref(), &event)
    } else {
        Vec::new()
    };
    let alerts = detect_event(store.as_mut(), detect, &event);
    tx.send(Observation {
        event,
        reports,
        alerts,
    })
    .is_ok()
}
