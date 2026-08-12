// ©AngelaMos | 2026
// serve.rs

//! The web dashboard and HTTP API.
//!
//! This is the one place in the tool that needs concurrent access to the
//! intelligence store, and the one place the store's deliberate synchrony has
//! to be reconciled with an async runtime. The reconciliation is small on
//! purpose: the store stays a plain blocking handle, and every request that
//! touches it does so inside [`tokio::task::spawn_blocking`], so a slow query
//! parks a blocking thread rather than stalling the reactor. A single
//! `Mutex` serialises access, which is the right shape for a dashboard whose
//! queries are short and whose writers, when present, are one capture loop.
//!
//! The live stream is a `broadcast` channel. Whatever feeds the dashboard, a
//! replayed capture, a live interface, or new alerts tailed from the database,
//! publishes a pre-serialised line onto the channel, and every connected
//! browser's Server-Sent Events response subscribes to it. The stream route is
//! kept off the compression layer on purpose: a compressor buffers to find
//! runs worth packing, and buffering is the one thing a live event stream
//! cannot tolerate.

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::compression::CompressionLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use tlsfp_core::{FingerprintEvent, PcapFileSource, Pipeline, PipelineConfig};
use tlsfp_intel::{Alert, CatalogEntry, FpKind, IntelStore, MatchReport, Rule, Stats};

use crate::live::{LiveConfig, LiveSource, StopHandle};

/// How many serialised live lines the broadcast channel holds before the
/// slowest subscriber starts missing the oldest. A browser that lags past this
/// skips the gap rather than stalling every other client.
const STREAM_BUFFER: usize = 1024;

/// How often the keep-alive comment is sent on an idle stream, below the
/// common sixty second proxy idle timeout so a quiet link stays open.
const KEEPALIVE_SECS: u64 = 15;

/// How often the database tail poller checks for alerts raised by an external
/// sensor writing to the same store.
const TAIL_POLL_MILLIS: u64 = 1000;

/// The largest export or alert page served in one response, a guard against a
/// query string asking the store for everything at once.
const MAX_PAGE: i64 = 100_000;

/// The default alert page when a request does not ask for a size.
const DEFAULT_PAGE: i64 = 200;

/// The largest batch the database tail drains per poll. It carries the last id
/// forward between ticks, so a backlog catches up over several polls rather
/// than blocking one task on a single huge read.
const TAIL_PAGE: i64 = 256;

/// Where the live events shown on the dashboard come from.
pub enum Source {
    /// Nothing in process; the stream tails the database for alerts an external
    /// `tlsfp live --detect` writes to the same store.
    Tail,
    /// Replay a capture file as a synthetic live feed, optionally looping, with
    /// a pause between events so the stream is watchable.
    Replay {
        path: PathBuf,
        looping: bool,
        interval: Duration,
    },
    /// Capture live from an interface in process, detecting and broadcasting as
    /// it goes.
    Live {
        interface: String,
        filter: String,
        promiscuous: bool,
    },
}

/// Everything the server needs to start.
pub struct ServeConfig {
    pub bind: String,
    pub db: PathBuf,
    pub web: PathBuf,
    pub source: Source,
}

/// Shared state every handler reads through. The store is the read side of the
/// database behind a mutex; the sender is the live channel handlers subscribe
/// to.
struct AppState {
    store: Mutex<IntelStore>,
    tx: broadcast::Sender<Arc<str>>,
}

impl AppState {
    /// Locks the store, recovering the guard if a previous handler panicked
    /// while holding it, since a poisoned read connection is still usable.
    fn store(&self) -> MutexGuard<'_, IntelStore> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

type Shared = Arc<AppState>;

/// One message on the live stream: either a freshly fingerprinted flow with its
/// intelligence and any alerts it raised, or a standalone alert the database
/// tail surfaced. Serialised once by the producer and sent as an opaque line,
/// so a thousand subscribers cost one serialisation, not a thousand.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LiveMessage {
    Flow {
        event: FingerprintEvent,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        intel: Vec<MatchReport>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        alerts: Vec<Alert>,
    },
    Alert {
        alert: Alert,
    },
}

/// Runs the dashboard until interrupted. Builds its own runtime so the rest of
/// the program stays a synchronous command line tool, the same split the live
/// capture path uses.
pub fn run(config: ServeConfig) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the async runtime")?;
    runtime.block_on(serve(config))
}

async fn serve(config: ServeConfig) -> Result<()> {
    let store = IntelStore::open(&config.db)
        .with_context(|| format!("opening intelligence database {}", config.db.display()))?;
    if store.latest_alert_id().unwrap_or(0) == 0 {
        tracing::info!(
            "the store holds no alerts yet; run a capture with --detect, or start serve with --replay or --live to populate the stream"
        );
    }

    let (tx, _) = broadcast::channel::<Arc<str>>(STREAM_BUFFER);
    let state: Shared = Arc::new(AppState {
        store: Mutex::new(store),
        tx: tx.clone(),
    });

    let shutdown = Arc::new(AtomicBool::new(false));
    let mut capture = spawn_source(&config, tx, Arc::clone(&shutdown), Arc::clone(&state))?;

    let app = router(&config.web, Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .with_context(|| format!("binding {}", config.bind))?;
    let addr = listener.local_addr().context("reading the bound address")?;
    tracing::info!(%addr, web = %config.web.display(), "dashboard listening on http://{addr}");

    let result = axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving the dashboard");

    shutdown.store(true, Ordering::Relaxed);
    capture.stop();
    result
}

/// Builds the route table. The data API and the static files are compressed;
/// the event stream is merged in afterwards so the compression layer never
/// touches it.
fn router(web: &std::path::Path, state: Shared) -> Router {
    let data_api = Router::new()
        .route("/stats", get(stats))
        .route("/alerts", get(alerts))
        .route("/search", get(search))
        .route("/export", get(export))
        .route("/health", get(health))
        .layer(CompressionLayer::new());

    let stream_api = Router::new().route("/stream", get(stream));

    let api = data_api.merge(stream_api).with_state(state);

    let index = web.join("index.html");
    let static_files = ServeDir::new(web)
        .append_index_html_on_directories(true)
        .fallback(ServeFile::new(index));

    Router::new()
        .nest("/api", api)
        .fallback_service(static_files)
        .layer(TraceLayer::new_for_http())
}

/// A count of alerts attributed to one rule, the shape the distribution chart
/// reads.
#[derive(Serialize)]
struct RuleCount {
    rule: Rule,
    count: i64,
}

/// The summary the dashboard header and distribution chart draw from: what the
/// intelligence store holds, and how the alerts raised so far break down by
/// rule.
#[derive(Serialize)]
struct StatsResponse {
    intel: Stats,
    alerts_by_rule: Vec<RuleCount>,
    alert_total: i64,
}

async fn stats(State(state): State<Shared>) -> Result<Json<StatsResponse>, ApiError> {
    let response = tokio::task::spawn_blocking(move || -> Result<StatsResponse> {
        let store = state.store();
        let intel = store.stats()?;
        let counts = store.alert_counts()?;
        let alert_total = counts.iter().map(|(_, count)| count).sum();
        let alerts_by_rule = counts
            .into_iter()
            .map(|(rule, count)| RuleCount { rule, count })
            .collect();
        Ok(StatsResponse {
            intel,
            alerts_by_rule,
            alert_total,
        })
    })
    .await??;
    Ok(Json(response))
}

#[derive(Deserialize)]
struct AlertsQuery {
    limit: Option<i64>,
}

async fn alerts(
    State(state): State<Shared>,
    Query(query): Query<AlertsQuery>,
) -> Result<Json<Vec<Alert>>, ApiError> {
    let limit = page_size(query.limit);
    let alerts = tokio::task::spawn_blocking(move || state.store().recent_alerts(limit)).await??;
    Ok(Json(alerts))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
    kind: Option<String>,
    limit: Option<i64>,
}

async fn search(
    State(state): State<Shared>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<CatalogEntry>>, ApiError> {
    let kind = match query.kind.as_deref().filter(|token| !token.is_empty()) {
        Some(token) => Some(FpKind::from_token(&token.to_ascii_lowercase()).ok_or_else(|| {
            ApiError::bad_request(format!(
                "unknown fingerprint kind '{token}'; expected ja3, ja3s, ja4, ja4s, ja4h, ja4x, ja4t, or ja4ts"
            ))
        })?),
        None => None,
    };
    let needle = query.q.unwrap_or_default();
    let limit = page_size(query.limit);
    let entries =
        tokio::task::spawn_blocking(move || state.store().search(&needle, kind, limit)).await??;
    Ok(Json(entries))
}

#[derive(Deserialize)]
struct ExportQuery {
    format: Option<String>,
    limit: Option<i64>,
}

async fn export(
    State(state): State<Shared>,
    Query(query): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    let limit = query.limit.unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE);
    let csv = matches!(query.format.as_deref(), Some("csv"));
    let alerts = tokio::task::spawn_blocking(move || state.store().recent_alerts(limit)).await??;

    if csv {
        let body = alerts_to_csv(&alerts)?;
        Ok((
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"tlsfp-alerts.csv\"",
                ),
            ],
            body,
        )
            .into_response())
    } else {
        let body = serde_json::to_vec_pretty(&alerts).context("serialising alerts as JSON")?;
        Ok((
            [
                (header::CONTENT_TYPE, "application/json"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"tlsfp-alerts.json\"",
                ),
            ],
            body,
        )
            .into_response())
    }
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// The Server-Sent Events stream. Subscribes to the broadcast channel and
/// forwards every line as an event, dropping the gap when a lagging client
/// falls behind rather than tearing its connection down.
async fn stream(
    State(state): State<Shared>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.tx.subscribe();
    let events = BroadcastStream::new(receiver).filter_map(|item| match item {
        Ok(line) => Some(Ok(Event::default().data(line.as_ref()))),
        Err(_lagged) => None,
    });
    Sse::new(events).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(KEEPALIVE_SECS))
            .text("keep-alive"),
    )
}

/// Clamps a requested page size into a sane range, defaulting an absent or
/// non-positive request to a readable page.
fn page_size(requested: Option<i64>) -> i64 {
    match requested {
        Some(value) if value > 0 => value.min(MAX_PAGE),
        _ => DEFAULT_PAGE,
    }
}

/// Renders alerts as CSV, quoting through the csv writer so a comma or newline
/// inside a detail string can never break the row structure.
fn alerts_to_csv(alerts: &[Alert]) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record([
        "ts_nanos", "rule", "severity", "ip", "fp_kind", "fp_value", "title", "detail", "score",
    ])?;
    for alert in alerts {
        writer.write_record([
            alert.ts_nanos.to_string(),
            alert.rule.as_str().to_string(),
            alert.severity.as_str().to_string(),
            alert.ip.clone().unwrap_or_default(),
            alert
                .fp_kind
                .map(|kind| kind.as_str().to_string())
                .unwrap_or_default(),
            alert.fp_value.clone().unwrap_or_default(),
            alert.title.clone(),
            alert.detail.clone(),
            alert.score.map(|s| format!("{s:.4}")).unwrap_or_default(),
        ])?;
    }
    writer.into_inner().context("finishing the CSV export")
}

/// A handle to whatever is feeding the live stream, so the server can stop it
/// on shutdown. A replay or tail loop watches the shared flag; a live capture
/// also needs its blocking read woken, which is what the stop handle does.
struct Capture {
    shutdown: Arc<AtomicBool>,
    live_stop: Option<StopHandle>,
    handle: Option<JoinHandle<()>>,
}

impl Capture {
    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(stop) = &self.live_stop {
            stop.stop();
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Starts whatever produces the live stream for this run and returns a handle
/// to stop it. The replay and live producers each own a private write
/// connection to the same database, so detection persists while the API reads
/// through its own connection; SQLite's write-ahead log lets the two coexist.
fn spawn_source(
    config: &ServeConfig,
    tx: broadcast::Sender<Arc<str>>,
    shutdown: Arc<AtomicBool>,
    state: Shared,
) -> Result<Capture> {
    match &config.source {
        Source::Tail => {
            spawn_tail(state, tx, Arc::clone(&shutdown));
            Ok(Capture {
                shutdown,
                live_stop: None,
                handle: None,
            })
        }
        Source::Replay {
            path,
            looping,
            interval,
        } => {
            let path = path.clone();
            let db = config.db.clone();
            let looping = *looping;
            let interval = *interval;
            let stop = Arc::clone(&shutdown);
            let handle = std::thread::Builder::new()
                .name("tlsfp-replay".to_owned())
                .spawn(move || replay_loop(&path, &db, &tx, &stop, looping, interval))
                .context("starting the replay thread")?;
            Ok(Capture {
                shutdown,
                live_stop: None,
                handle: Some(handle),
            })
        }
        Source::Live {
            interface,
            filter,
            promiscuous,
        } => {
            let live_config = LiveConfig {
                filter: filter.clone(),
                promiscuous: *promiscuous,
            };
            let source = LiveSource::open(interface, &live_config)
                .with_context(|| format!("opening live capture on {interface}"))?;
            let live_stop = source.stop_handle();
            let db = config.db.clone();
            let stop = Arc::clone(&shutdown);
            let interface = interface.clone();
            tracing::info!(interface, filter = %live_config.filter, "serving live capture");
            let handle = std::thread::Builder::new()
                .name("tlsfp-live".to_owned())
                .spawn(move || live_loop(source, &db, &tx, &stop))
                .context("starting the live capture thread")?;
            Ok(Capture {
                shutdown,
                live_stop: Some(live_stop),
                handle: Some(handle),
            })
        }
    }
}

/// Replays a capture file as a synthetic live feed, pausing between events so
/// the stream reads at a human pace and looping when asked.
fn replay_loop(
    path: &std::path::Path,
    db: &std::path::Path,
    tx: &broadcast::Sender<Arc<str>>,
    shutdown: &AtomicBool,
    looping: bool,
    interval: Duration,
) {
    let mut store = match IntelStore::open(db) {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "replay: cannot open the intelligence database");
            return;
        }
    };
    tracing::info!(path = %path.display(), looping, "serving replayed capture");
    loop {
        let mut source = match PcapFileSource::open(path) {
            Ok(source) => source,
            Err(error) => {
                tracing::error!(%error, path = %path.display(), "replay: cannot open the capture");
                return;
            }
        };
        let mut pipeline = Pipeline::new(PipelineConfig::default());
        let run = pipeline.run(&mut source, |event| {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            broadcast_flow(&mut store, tx, event);
            if !interval.is_zero() {
                std::thread::sleep(interval);
            }
        });
        if let Err(error) = run {
            tracing::error!(%error, "replay: reading the capture failed");
            return;
        }
        if shutdown.load(Ordering::Relaxed) || !looping {
            return;
        }
    }
}

/// Drives a live capture through the same pipeline the file path uses, on this
/// dedicated thread, detecting and broadcasting until the stop handle wakes the
/// blocking read.
fn live_loop(
    mut source: LiveSource,
    db: &std::path::Path,
    tx: &broadcast::Sender<Arc<str>>,
    shutdown: &AtomicBool,
) {
    let mut store = match IntelStore::open(db) {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "live: cannot open the intelligence database");
            return;
        }
    };
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    let run = pipeline.run(&mut source, |event| {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        broadcast_flow(&mut store, tx, event);
    });
    if let Err(error) = run {
        tracing::warn!(%error, "live capture ended");
    }
}

/// Tails the database for alerts written by an external sensor and broadcasts
/// each new one. Used when nothing is captured in process: a `tlsfp live
/// --detect` writing to the same store shows up on the dashboard without the
/// server holding a capture socket of its own.
fn spawn_tail(state: Shared, tx: broadcast::Sender<Arc<str>>, shutdown: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let start = Arc::clone(&state);
        let mut last_id =
            tokio::task::spawn_blocking(move || start.store().latest_alert_id().unwrap_or(0))
                .await
                .unwrap_or(0);
        let mut ticker = tokio::time::interval(Duration::from_millis(TAIL_POLL_MILLIS));
        loop {
            ticker.tick().await;
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            let reader = Arc::clone(&state);
            let since = last_id;
            let fresh = tokio::task::spawn_blocking(move || {
                reader
                    .store()
                    .alerts_since(since, TAIL_PAGE)
                    .unwrap_or_default()
            })
            .await
            .unwrap_or_default();
            for (id, alert) in fresh {
                last_id = last_id.max(id);
                let message = LiveMessage::Alert { alert };
                if let Ok(line) = serde_json::to_string(&message) {
                    let _ = tx.send(Arc::from(line));
                }
            }
        }
    });
}

/// Enriches one event, runs the detection rules over it, and broadcasts the
/// result as a single line. A serialisation failure is dropped rather than
/// allowed to end the capture, since one bad line is not worth a dark stream.
fn broadcast_flow(
    store: &mut IntelStore,
    tx: &broadcast::Sender<Arc<str>>,
    event: FingerprintEvent,
) {
    let intel = store.match_event(&event).unwrap_or_default();
    let alerts = store.detect(&event).unwrap_or_default();
    let message = LiveMessage::Flow {
        event,
        intel,
        alerts,
    };
    if let Ok(line) = serde_json::to_string(&message) {
        let _ = tx.send(Arc::from(line));
    }
}

/// Resolves when the process is asked to stop, the trigger for axum's graceful
/// shutdown.
async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to listen for ctrl-c; serving until killed");
        std::future::pending::<()>().await;
    }
    tracing::info!("shutting down the dashboard");
}

/// The error type every handler returns. Failures become a 500 with a JSON
/// body; a bad request is the one client-caused case that is reported as a 400.
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(error = %self.message, "request failed");
        }
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl From<tokio::task::JoinError> for ApiError {
    fn from(error: tokio::task::JoinError) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("request task failed: {error}"),
        }
    }
}
