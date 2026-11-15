//! Versioned progress/control protocol for streaming downloads.
//!
//! Ported from domsvoboda/nexus-backend
//! crates/xodus-cli/src/commands/streaming_progress.rs, adapted so Highball can
//! consume JSON lines and pause/resume/stop without a terminal. The protocol
//! never emits paths, URLs, credentials or account ids.

use super::ProgressEvent;
use crate::error::CommandError;
use std::{
    io::Write,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);

/// How a failure should be reported to a JSON consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FailureKind {
    Auth,
    Network,
    Other,
}

impl FailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Network => "network",
            Self::Other => "other",
        }
    }
}

#[derive(Debug)]
pub(super) struct StreamingFailure {
    pub(super) kind: FailureKind,
    pub(super) message: String,
}

impl StreamingFailure {
    pub(super) fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: sanitize_message(&message.into()),
        }
    }

    pub(super) fn network(message: impl Into<String>) -> Self {
        Self::new(FailureKind::Network, message)
    }

    pub(super) fn other(message: impl Into<String>) -> Self {
        Self::new(FailureKind::Other, message)
    }

    pub(super) fn from_command(error: CommandError) -> Self {
        let kind = match error {
            CommandError::Auth { .. } => FailureKind::Auth,
            CommandError::Network { .. } => FailureKind::Network,
            CommandError::Other { .. } => FailureKind::Other,
        };
        Self::new(kind, error.to_string())
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
        "Done" => "done",
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
        // Nexus-compatible aliases for consumers written against its protocol.
        "completedBytes": state.bytes_done,
        "totalBytes": state.bytes_total,
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
        "message": sanitize_message(message),
    })
}

fn emit(value: &serde_json::Value) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{value}").ok();
    out.flush().ok();
}

/// Emit a terminal error without starting the progress reporter. Used for
/// failures that happen before a reader exists (product lookup, source open).
pub(super) fn emit_error(kind: FailureKind, message: &str) {
    emit(&error_record(0, kind, message));
}

pub(super) async fn report(mut events: mpsc::Receiver<ProgressEvent>) {
    let mut state = State::default();
    let mut sequence = 0u64;
    let mut throttle = Throttle::new(PROGRESS_INTERVAL);
    let mut rate = Rate::new(0);
    emit(&record(&state, sequence, "progress", 0));
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
            ProgressEvent::Completed => {
                sequence += 1;
                emit(&done_record(sequence));
                break;
            }
            ProgressEvent::Failed { kind, message } => {
                sequence += 1;
                emit(&error_record(sequence, kind, &message));
                break;
            }
        }
        if throttle.ready(force) {
            let rate = rate.update(state.bytes_done, state.paused, now);
            sequence += 1;
            emit(&record(&state, sequence, "progress", rate));
        }
    }
}

/// Remove paths, URLs, and long numeric identifiers from an error message.
///
/// Messages are still useful, but a launcher-facing event must not disclose
/// local paths, CDN URLs, query tokens, or account ids.
pub(super) fn sanitize_message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    let mut boundary = true;
    while let Some(ch) = rest.chars().next() {
        let url = boundary
            && (rest.starts_with("http://")
                || rest.starts_with("https://")
                || rest.starts_with("file://"));
        if url {
            out.push_str("<url>");
            rest = skip_value(rest);
            boundary = false;
            continue;
        }
        if boundary && is_windows_path(rest) {
            out.push_str("<path>");
            rest = skip_value(rest);
            boundary = false;
            continue;
        }
        if boundary && rest.starts_with('/') {
            out.push_str("<path>");
            rest = skip_value(rest);
            boundary = false;
            continue;
        }
        if boundary && starts_long_digits(rest) {
            out.push_str("<id>");
            rest = skip_digits(rest);
            boundary = false;
            continue;
        }
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
        boundary = ch.is_whitespace()
            || matches!(
                ch,
                '(' | '[' | '{' | '"' | '\'' | '`' | '=' | ',' | ';' | ':'
            );
    }
    out
}

fn is_windows_path(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

fn starts_long_digits(rest: &str) -> bool {
    rest.as_bytes()
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count()
        >= 10
}

fn skip_digits(rest: &str) -> &str {
    let len = rest
        .as_bytes()
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    &rest[len..]
}

fn skip_value(rest: &str) -> &str {
    let mut end = 0;
    for (index, ch) in rest.char_indices() {
        if ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
            )
        {
            end = index;
            break;
        }
        end = index + ch.len_utf8();
    }
    &rest[end..]
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
        assert_eq!(value["completedBytes"], 512);
        assert_eq!(value["totalBytes"], 1024);
        assert_eq!(value["canPause"], true);
    }

    #[test]
    fn error_records_are_schema_versioned_and_never_leak_paths_urls_or_ids() {
        let value = error_record(
            3,
            FailureKind::Network,
            "could not open /tmp/highball/game.msixvc from \
             https://user:secret@cdn.example/game?token=abc for account 2533274790395904",
        );
        let text = value.to_string();
        assert_eq!(value["schema"], 1);
        assert_eq!(value["event"], "error");
        assert_eq!(value["kind"], "network");
        assert!(!text.contains("/tmp/highball"), "{text}");
        assert!(!text.contains("https://"), "{text}");
        assert!(!text.contains("secret"), "{text}");
        assert!(!text.contains("token=abc"), "{text}");
        assert!(!text.contains("2533274790395904"), "{text}");
        assert!(text.contains("<path>"), "{text}");
        assert!(text.contains("<url>"), "{text}");
        assert!(text.contains("<id>"), "{text}");
    }

    #[test]
    fn windows_paths_and_account_ids_are_redacted() {
        let text = sanitize_message("could not read C:\\Games\\data.bin for 1234567890123456");
        assert!(!text.contains("C:\\Games"), "{text}");
        assert!(!text.contains("1234567890123456"), "{text}");
        assert!(text.contains("<path>"), "{text}");
        assert!(text.contains("<id>"), "{text}");
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

    #[test]
    fn failure_messages_are_sanitized_at_construction() {
        let failure = StreamingFailure::network("failed for file:///Users/me/game.msixvc");
        assert!(!failure.message.contains("/Users/me"), "{failure:?}");
        assert!(failure.message.contains("<url>"), "{failure:?}");
    }
}
