//! Versioned progress/control protocol for streaming downloads.
//!
//! Ported from domsvoboda/nexus-backend
//! crates/xodus-cli/src/commands/streaming_progress.rs, adapted so Highball can
//! consume JSON lines and pause/resume/stop without a terminal. The protocol
//! never emits paths, URLs, credentials or account ids.

use super::ProgressEvent;
use crate::error::CommandError;
use msixvc::streaming::TransferControl;
use std::{
    io::{BufRead, Write},
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};

const MAX_CONTROL_BYTES: usize = 256;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);
const OUTPUT_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const OUTPUT_RETRY_BUDGET: Duration = Duration::from_secs(2);

/// Exit status used when the launcher sends `{"command":"stop"}`.
pub(super) const STOP_EXIT_CODE: i32 = 3;

/// How a failure should be reported to a JSON consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FailureKind {
    Auth,
    Network,
    Other,
    Stopped,
}

impl FailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Network => "network",
            Self::Other => "other",
            Self::Stopped => "stopped",
        }
    }

    /// Fixed, path/URL-free text for launcher-facing error events.
    pub(super) fn message(self) -> &'static str {
        match self {
            Self::Auth => "authentication or licensing failed",
            Self::Network => "a network request failed",
            Self::Other => "streaming failed",
            Self::Stopped => "streaming stopped",
        }
    }
}

#[derive(Debug)]
pub(super) struct StreamingFailure {
    pub(super) kind: FailureKind,
    pub(super) message: String,
}

impl StreamingFailure {
    /// `message` must be a fixed, path/URL-free string. Detailed errors stay on
    /// stderr and are never copied into launcher-facing events.
    pub(super) fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(super) fn network(message: impl Into<String>) -> Self {
        Self::new(FailureKind::Network, message)
    }

    pub(super) fn other(message: impl Into<String>) -> Self {
        Self::new(FailureKind::Other, message)
    }

    pub(super) fn stopped() -> Self {
        Self::new(FailureKind::Stopped, "streaming stopped")
    }

    pub(super) fn from_command(error: CommandError) -> Self {
        let kind = match error {
            CommandError::Auth { .. } => FailureKind::Auth,
            CommandError::Network { .. } => FailureKind::Network,
            CommandError::Other { .. } => FailureKind::Other,
        };
        Self::new(kind, kind.message())
    }
}

pub(super) fn classify_failure(error: &(dyn std::error::Error + 'static)) -> FailureKind {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<CommandError>() {
            return match error {
                CommandError::Auth { .. } => FailureKind::Auth,
                CommandError::Network { .. } => FailureKind::Network,
                CommandError::Other { .. } => FailureKind::Other,
            };
        }
        if error.downcast_ref::<reqwest::Error>().is_some() {
            return FailureKind::Network;
        }
        current = error.source();
    }
    FailureKind::Other
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlCommand {
    Pause,
    Resume,
    Stop,
}

pub(super) fn parse_control(bytes: &[u8]) -> Option<ControlCommand> {
    if bytes.len() > MAX_CONTROL_BYTES {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value.get("schema")? != &serde_json::Value::from(1) {
        return None;
    }
    match value.get("command")?.as_str()? {
        "pause" => Some(ControlCommand::Pause),
        "resume" => Some(ControlCommand::Resume),
        "stop" => Some(ControlCommand::Stop),
        _ => None,
    }
}

/// Atomically transition the control watch channel. `Stop` is terminal: once
/// set, pause/resume/EOF can never overwrite it. Returns true only when the
/// state actually changed. The exit code is stored under the same lock so a
/// woken transfer cannot observe Stop without its code.
pub(super) fn set_control(
    tx: &watch::Sender<TransferControl>,
    next: TransferControl,
    exit: &AtomicI32,
    code: i32,
) -> bool {
    let mut changed = false;
    tx.send_if_modified(|state| {
        if *state == TransferControl::Stop || *state == next {
            return false;
        }
        *state = next;
        if next == TransferControl::Stop {
            exit.store(code, Ordering::SeqCst);
        }
        changed = true;
        true
    });
    changed
}

/// Read control lines from stdin on a plain thread and turn them into a watch
/// value and progress events. Returns the sender used by signal handling too.
pub(super) fn controls(
    enabled: bool,
    events: mpsc::Sender<ProgressEvent>,
    exit: Arc<AtomicI32>,
) -> (
    Option<watch::Sender<TransferControl>>,
    watch::Receiver<TransferControl>,
) {
    let (tx, rx) = watch::channel(TransferControl::Running);
    if !enabled {
        drop(tx);
        return (None, rx);
    }
    let signal_tx = tx.clone();
    // A plain thread avoids Tokio's uncancellable blocking-stdin shutdown.
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        let mut bytes = Vec::new();
        loop {
            bytes.clear();
            // Bound control records; discard overlong lines without parsing.
            let result = std::io::Read::take(
                std::io::Read::by_ref(&mut reader),
                MAX_CONTROL_BYTES as u64 + 1,
            )
            .read_until(b'\n', &mut bytes);
            if !matches!(result, Ok(n) if n > 0) {
                break;
            }
            if bytes.len() > MAX_CONTROL_BYTES {
                if bytes.last() != Some(&b'\n') {
                    reader.skip_until(b'\n').ok();
                }
                continue;
            }
            match parse_control(&bytes) {
                Some(ControlCommand::Pause) => {
                    if set_control(&tx, TransferControl::Paused, &exit, 0)
                        && events
                            .blocking_send(ProgressEvent::Paused { paused: true })
                            .is_err()
                    {
                        return;
                    }
                }
                Some(ControlCommand::Resume) => {
                    if set_control(&tx, TransferControl::Running, &exit, 0)
                        && events
                            .blocking_send(ProgressEvent::Paused { paused: false })
                            .is_err()
                    {
                        return;
                    }
                }
                Some(ControlCommand::Stop) => {
                    set_control(&tx, TransferControl::Stop, &exit, STOP_EXIT_CODE);
                    return;
                }
                None => {}
            }
        }
        // Losing the controller must never leave a live download parked paused.
        // A stop, however, is terminal and is never released by EOF.
        if release_on_eof(&tx, &exit) {
            events
                .blocking_send(ProgressEvent::Paused { paused: false })
                .ok();
        }
    });
    (Some(signal_tx), rx)
}

/// Apply the stdin-EOF guard: a paused transfer becomes runnable again unless
/// a terminal Stop has already won.
pub(super) fn release_on_eof(tx: &watch::Sender<TransferControl>, exit: &AtomicI32) -> bool {
    set_control(tx, TransferControl::Running, exit, 0)
}

#[cfg(unix)]
pub(super) fn install_signal_handlers(
    sender: watch::Sender<TransferControl>,
    exit: Arc<AtomicI32>,
) {
    use tokio::signal::unix::{SignalKind, signal};
    tokio::spawn(async move {
        let Ok(mut interrupt) = signal(SignalKind::interrupt()) else {
            return;
        };
        let Ok(mut terminate) = signal(SignalKind::terminate()) else {
            return;
        };
        let code = tokio::select! {
            _ = interrupt.recv() => 130,
            _ = terminate.recv() => 143,
        };
        // The first stop wins; a later signal never rewrites the exit code.
        set_control(&sender, TransferControl::Stop, &exit, code);
    });
}

#[cfg(not(unix))]
pub(super) fn install_signal_handlers(
    sender: watch::Sender<TransferControl>,
    exit: Arc<AtomicI32>,
) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            set_control(&sender, TransferControl::Stop, &exit, 130);
        }
    });
}

pub(super) struct Throttle {
    last: Instant,
    interval: Duration,
}

impl Throttle {
    pub(super) fn new(interval: Duration) -> Self {
        Self {
            last: Instant::now(),
            interval,
        }
    }

    pub(super) fn ready(&mut self, force: bool) -> bool {
        if force || self.last.elapsed() >= self.interval {
            self.last = Instant::now();
            true
        } else {
            false
        }
    }
}

struct Rate {
    smoothed: f64,
    last_bytes: u64,
    last_emit: Instant,
}

impl Rate {
    fn new(bytes: u64) -> Self {
        Self {
            smoothed: 0.0,
            last_bytes: bytes,
            last_emit: Instant::now(),
        }
    }

    fn reset(&mut self, bytes: u64, now: Instant) {
        self.smoothed = 0.0;
        self.last_bytes = bytes;
        self.last_emit = now;
    }

    fn update(&mut self, bytes: u64, paused: bool, now: Instant) -> u64 {
        let elapsed = now
            .saturating_duration_since(self.last_emit)
            .as_secs_f64()
            .max(0.001);
        if paused {
            self.smoothed = 0.0;
        } else {
            let delta = bytes.saturating_sub(self.last_bytes) as f64;
            let instant = delta / elapsed;
            self.smoothed = if self.smoothed <= f64::EPSILON {
                instant
            } else {
                self.smoothed * 0.7 + instant * 0.3
            };
        }
        self.last_bytes = bytes;
        self.last_emit = now;
        self.smoothed.round() as u64
    }
}

struct State {
    phase: &'static str,
    paused: bool,
    bytes_done: u64,
    bytes_total: u64,
    files_done: u64,
    files_total: u64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            phase: "metadata",
            paused: false,
            bytes_done: 0,
            bytes_total: 0,
            files_done: 0,
            files_total: 0,
        }
    }
}

fn phase_for(name: &str) -> &'static str {
    match name {
        "Licensing" => "licensing",
        "Downloading" => "downloading",
        "Finalizing" => "finalizing",
        _ => "metadata",
    }
}

fn record(state: &State, sequence: u64, event: &str, rate: u64) -> serde_json::Value {
    serde_json::json!({
        "schema": 1,
        "event": event,
        "sequence": sequence,
        "phase": state.phase,
        "paused": state.paused,
        "canPause": state.phase == "downloading",
        "bytesDone": state.bytes_done,
        "bytesTotal": state.bytes_total,
        "filesDone": state.files_done,
        "filesTotal": state.files_total,
        "bytesPerSecond": rate,
    })
}

fn done_record(sequence: u64) -> serde_json::Value {
    serde_json::json!({"schema": 1, "event": "done", "sequence": sequence})
}

fn error_record(sequence: u64, kind: FailureKind, message: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": 1,
        "event": "error",
        "sequence": sequence,
        "kind": kind.as_str(),
        "message": message,
    })
}

fn consumer_gone(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
    )
}

fn retry_write(mut write: impl FnMut() -> std::io::Result<()>) -> bool {
    let mut waited = Duration::ZERO;
    loop {
        match write() {
            Ok(()) => return true,
            Err(err) if consumer_gone(err.kind()) => return false,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if waited >= OUTPUT_RETRY_BUDGET {
                    return false;
                }
                std::thread::sleep(OUTPUT_RETRY_INTERVAL);
                waited += OUTPUT_RETRY_INTERVAL;
            }
            Err(_) => return false,
        }
    }
}

fn emit_line(out: &mut impl Write, value: &serde_json::Value) -> bool {
    let line = format!("{value}\n");
    let mut offset = 0;
    retry_write(|| {
        while offset < line.len() {
            match out.write(&line.as_bytes()[offset..]) {
                Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
                Ok(n) => offset += n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        out.flush()
    })
}

fn emit_stdout(value: &serde_json::Value) -> bool {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    emit_line(&mut out, value)
}

fn output_failed(control: &Option<watch::Sender<TransferControl>>, exit: &AtomicI32) {
    if let Some(sender) = control {
        // A dead consumer is equivalent to a stop: checkpoint and exit 3.
        set_control(sender, TransferControl::Stop, exit, STOP_EXIT_CODE);
    }
}

/// Emit a terminal error without starting the progress reporter. Used for
/// failures that happen before a reader exists (product lookup, source open).
pub(super) fn emit_error(kind: FailureKind, message: &str) {
    emit_stdout(&error_record(0, kind, message));
}

/// Emit a terminal stopped line when a stop happens before the reporter starts.
pub(super) fn emit_stopped() {
    emit_stdout(&record(&State::default(), 0, "stopped", 0));
}

pub(super) async fn report(
    events: mpsc::Receiver<ProgressEvent>,
    control: Option<watch::Sender<TransferControl>>,
    exit: Arc<AtomicI32>,
) {
    report_with(events, control, exit, emit_stdout).await;
}

pub(super) async fn report_with(
    mut events: mpsc::Receiver<ProgressEvent>,
    control: Option<watch::Sender<TransferControl>>,
    exit: Arc<AtomicI32>,
    mut emit: impl FnMut(&serde_json::Value) -> bool,
) {
    let mut state = State::default();
    let mut sequence = 0u64;
    let mut throttle = Throttle::new(PROGRESS_INTERVAL);
    let mut rate = Rate::new(0);
    if !emit(&record(&state, sequence, "progress", 0)) {
        output_failed(&control, &exit);
        return;
    }
    while let Some(event) = events.recv().await {
        let now = Instant::now();
        let mut force = false;
        match event {
            ProgressEvent::Started { .. } | ProgressEvent::Restored { .. } => {}
            ProgressEvent::Advanced { id, delta } => {
                if state.phase == "downloading" && id != usize::MAX {
                    state.bytes_done = state
                        .bytes_done
                        .saturating_add(delta)
                        .min(state.bytes_total);
                }
            }
            ProgressEvent::Finished { .. } => {
                state.files_done = state.files_done.saturating_add(1).min(state.files_total);
            }
            ProgressEvent::UpdateRemaining { .. } => {
                if state.phase != "downloading" {
                    state.phase = "downloading";
                    force = true;
                    rate.reset(state.bytes_done, now);
                }
            }
            ProgressEvent::UpdateStatus { name } => {
                let phase = phase_for(&name);
                if state.phase != phase {
                    state.phase = phase;
                    force = true;
                    rate.reset(state.bytes_done, now);
                }
            }
            ProgressEvent::Planned {
                total,
                saved,
                files,
            } => {
                state.bytes_total = total;
                state.bytes_done = saved.min(total);
                state.files_total = files as u64;
                state.files_done = 0;
                force = true;
                rate.reset(state.bytes_done, now);
            }
            ProgressEvent::Paused { paused } => {
                state.paused = paused;
                throttle.ready(true);
                rate.reset(state.bytes_done, now);
                sequence += 1;
                if !emit(&record(
                    &state,
                    sequence,
                    if paused { "paused" } else { "resumed" },
                    0,
                )) {
                    output_failed(&control, &exit);
                    return;
                }
                continue;
            }
            ProgressEvent::Completed => {
                sequence += 1;
                if !emit(&done_record(sequence)) {
                    output_failed(&control, &exit);
                }
                break;
            }
            ProgressEvent::Failed { kind, message } => {
                sequence += 1;
                if !emit(&error_record(sequence, kind, &message)) {
                    output_failed(&control, &exit);
                }
                break;
            }
            ProgressEvent::Stopped => {
                sequence += 1;
                if !emit(&record(&state, sequence, "stopped", 0)) {
                    output_failed(&control, &exit);
                }
                break;
            }
        }
        if throttle.ready(force) {
            let rate = rate.update(state.bytes_done, state.paused, now);
            sequence += 1;
            if !emit(&record(&state, sequence, "progress", rate)) {
                output_failed(&control, &exit);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_records_carry_schema_and_the_documented_fields() {
        let state = State {
            phase: "downloading",
            paused: false,
            bytes_done: 512,
            bytes_total: 1024,
            files_done: 1,
            files_total: 2,
        };
        let value = record(&state, 7, "progress", 2048);
        assert_eq!(value["schema"], 1);
        assert_eq!(value["event"], "progress");
        assert_eq!(value["sequence"], 7);
        assert_eq!(value["phase"], "downloading");
        assert_eq!(value["bytesDone"], 512);
        assert_eq!(value["bytesTotal"], 1024);
        assert_eq!(value["filesDone"], 1);
        assert_eq!(value["filesTotal"], 2);
        assert_eq!(value["bytesPerSecond"], 2048);
        assert_eq!(value["canPause"], true);
        assert!(value.get("completedBytes").is_none());
        assert!(value.get("totalBytes").is_none());
    }

    #[test]
    fn error_records_are_schema_versioned_and_use_fixed_kind_messages() {
        let value = error_record(3, FailureKind::Network, FailureKind::Network.message());
        let text = value.to_string();
        assert_eq!(value["schema"], 1);
        assert_eq!(value["event"], "error");
        assert_eq!(value["kind"], "network");
        assert!(!text.contains("/tmp"), "{text}");
        assert!(!text.contains("https://"), "{text}");
    }

    #[test]
    fn command_failures_discard_free_text_for_a_fixed_kind_message() {
        let error = CommandError::network_from(
            "could not fetch https://user:pass@host/x?token=abc /tmp/game.msixvc",
            std::io::Error::other("detail"),
        );
        let failure = StreamingFailure::from_command(error);
        assert_eq!(failure.kind, FailureKind::Network);
        assert_eq!(failure.message, FailureKind::Network.message());
        assert!(!failure.message.contains("http"), "{failure:?}");
        assert!(!failure.message.contains("/tmp"), "{failure:?}");
    }

    #[test]
    fn control_parser_accepts_only_versioned_pause_resume_stop() {
        assert_eq!(
            parse_control(br#"{"schema":1,"command":"pause"}"#),
            Some(ControlCommand::Pause)
        );
        assert_eq!(
            parse_control(b"{\"schema\":1,\"command\":\"resume\"}\n"),
            Some(ControlCommand::Resume)
        );
        assert_eq!(
            parse_control(br#"{"schema":1,"command":"stop"}"#),
            Some(ControlCommand::Stop)
        );
        for raw in [
            &br#"{"schema":2,"command":"pause"}"#[..],
            &br#"{"schema":"1","command":"pause"}"#[..],
            &br#"{"schema":1,"command":"rewind"}"#[..],
            &br#"{"schema":1}"#[..],
            &b"not json"[..],
            &b""[..],
            &b"null"[..],
        ] {
            assert_eq!(parse_control(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn overlong_control_lines_are_ignored() {
        let mut raw = br#"{"schema":1,"command":"pause"}"#.to_vec();
        raw.resize(MAX_CONTROL_BYTES + 1, b' ');
        assert_eq!(parse_control(&raw), None);
        assert_eq!(
            parse_control(br#"{"schema":1,"command":"pause"} "#),
            Some(ControlCommand::Pause),
            "a line within the bound is still accepted"
        );
    }

    #[test]
    fn stdin_eof_releases_only_a_paused_transfer() {
        let (tx, rx) = watch::channel(TransferControl::Paused);
        let exit = AtomicI32::new(0);
        assert!(release_on_eof(&tx, &exit));
        assert_eq!(*rx.borrow(), TransferControl::Running);

        let (tx, rx) = watch::channel(TransferControl::Running);
        assert!(!release_on_eof(&tx, &exit));
        assert_eq!(*rx.borrow(), TransferControl::Running);
    }

    #[test]
    fn stop_is_terminal_across_eof_and_late_control_commands() {
        let (tx, rx) = watch::channel(TransferControl::Running);
        let exit = AtomicI32::new(0);
        assert!(set_control(&tx, TransferControl::Paused, &exit, 0));
        assert!(set_control(
            &tx,
            TransferControl::Stop,
            &exit,
            STOP_EXIT_CODE
        ));
        assert_eq!(exit.load(Ordering::SeqCst), STOP_EXIT_CODE);
        assert_eq!(STOP_EXIT_CODE, 3);

        // stdin EOF and late commands must not overwrite a terminal stop.
        assert!(!release_on_eof(&tx, &exit));
        assert!(!set_control(&tx, TransferControl::Paused, &exit, 0));
        assert!(!set_control(&tx, TransferControl::Running, &exit, 0));
        assert!(!set_control(&tx, TransferControl::Stop, &exit, 143));
        assert_eq!(*rx.borrow(), TransferControl::Stop);
        assert_eq!(
            exit.load(Ordering::SeqCst),
            STOP_EXIT_CODE,
            "a later signal must not rewrite the first stop code"
        );
    }

    #[tokio::test]
    async fn a_dead_stdout_stops_the_transfer_with_code_three() {
        let (_tx, rx) = mpsc::channel(4);
        let (control_tx, control_rx) = watch::channel(TransferControl::Running);
        let exit = Arc::new(AtomicI32::new(0));
        report_with(rx, Some(control_tx), exit.clone(), |_| false).await;
        assert_eq!(*control_rx.borrow(), TransferControl::Stop);
        assert_eq!(exit.load(Ordering::SeqCst), STOP_EXIT_CODE);
    }

    #[test]
    fn throttle_allows_forcing_and_rate_limits_regular_updates() {
        let mut throttle = Throttle::new(Duration::from_millis(20));
        assert!(throttle.ready(true), "control/phase changes always emit");
        assert!(!throttle.ready(false), "an immediate update is throttled");
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            throttle.ready(false),
            "the next update after the window emits"
        );
    }

    fn apply(state: &mut State, event: ProgressEvent) {
        match event {
            ProgressEvent::Advanced { id, delta } => {
                if state.phase == "downloading" && id != usize::MAX {
                    state.bytes_done = state
                        .bytes_done
                        .saturating_add(delta)
                        .min(state.bytes_total);
                }
            }
            ProgressEvent::Finished { .. } => {
                state.files_done = state.files_done.saturating_add(1).min(state.files_total);
            }
            _ => {}
        }
    }

    #[test]
    fn state_application_counts_files_and_ignores_metadata_aggregate_events() {
        // The HTTP prefix cache reports metadata reads with id usize::MAX.
        let mut state = State {
            phase: "downloading",
            bytes_total: 100,
            files_total: 2,
            ..Default::default()
        };
        apply(
            &mut state,
            ProgressEvent::Advanced {
                id: usize::MAX,
                delta: 10,
            },
        );
        assert_eq!(state.bytes_done, 0);
        apply(&mut state, ProgressEvent::Advanced { id: 1, delta: 30 });
        apply(&mut state, ProgressEvent::Finished { id: 1 });
        apply(&mut state, ProgressEvent::Finished { id: 1 });
        assert_eq!(state.bytes_done, 30);
        assert_eq!(state.files_done, 2, "files are counted at most once");
    }

    struct FlakyWriter {
        attempts: usize,
        fail_once: bool,
        data: Vec<u8>,
    }

    impl std::io::Write for FlakyWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.attempts += 1;
            if self.fail_once {
                self.fail_once = false;
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct BrokenPipeWriter;

    impl std::io::Write for BrokenPipeWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn would_block_is_retried_and_the_transfer_continues() {
        let (tx, rx) = mpsc::channel(4);
        let (control_tx, control_rx) = watch::channel(TransferControl::Running);
        let exit = Arc::new(AtomicI32::new(0));
        let mut writer = FlakyWriter {
            attempts: 0,
            fail_once: true,
            data: Vec::new(),
        };
        tx.send(ProgressEvent::Completed).await.unwrap();
        drop(tx);
        report_with(rx, Some(control_tx), exit.clone(), |value| {
            emit_line(&mut writer, value)
        })
        .await;

        assert_eq!(*control_rx.borrow(), TransferControl::Running);
        assert_eq!(exit.load(Ordering::SeqCst), 0);
        assert_eq!(writer.attempts, 3, "one retry, then two successful lines");
        let text = String::from_utf8(writer.data).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2, "progress and done, each written once");
        assert!(lines[0].contains("\"event\":\"progress\""));
        assert!(lines[1].contains("\"event\":\"done\""));
    }

    #[tokio::test]
    async fn broken_pipe_stops_the_transfer_with_code_three() {
        let (_tx, rx) = mpsc::channel(4);
        let (control_tx, control_rx) = watch::channel(TransferControl::Running);
        let exit = Arc::new(AtomicI32::new(0));
        let mut writer = BrokenPipeWriter;
        report_with(rx, Some(control_tx), exit.clone(), |value| {
            emit_line(&mut writer, value)
        })
        .await;

        assert_eq!(*control_rx.borrow(), TransferControl::Stop);
        assert_eq!(exit.load(Ordering::SeqCst), STOP_EXIT_CODE);
    }

    #[test]
    fn default_messages_are_fixed_and_path_free() {
        for kind in [FailureKind::Auth, FailureKind::Network, FailureKind::Other] {
            let text = format!("{} {}", kind.as_str(), kind.message());
            assert!(!text.contains('/'), "{text}");
            assert!(!text.contains("://"), "{text}");
        }
    }
}
