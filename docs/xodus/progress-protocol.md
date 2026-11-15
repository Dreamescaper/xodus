# Streaming progress and control protocol

`xodus-cli streaming --progress json <source> <destination>` writes one JSON
object per line to stdout. The same command reads control commands from stdin,
so a launcher can drive pause, resume, and stop without a terminal.

This protocol is derived from Xodus Nexus's versioned streaming progress
protocol (`streaming_progress.rs`), adapted for Highball. Protocol events never
emit local paths, download URLs, tokens, query strings, or account ids. stderr
may contain detailed, path- or URL-bearing errors; stderr is for logs only.

## Enabling it

```sh
xodus-cli streaming --progress json <product-or-content-id-or-url> <destination>
```

The default is the existing human progress bar. In JSON mode the bar is not
created, so stdout carries only protocol lines. JSON mode also forces
non-interactive package selection.

## Progress lines

```json
{"schema":1,"event":"progress","sequence":0,"phase":"metadata","paused":false,"canPause":false,"bytesDone":0,"bytesTotal":0,"filesDone":0,"filesTotal":0,"bytesPerSecond":0}
{"schema":1,"event":"progress","sequence":1,"phase":"licensing","paused":false,"canPause":false,"bytesDone":0,"bytesTotal":0,"filesDone":0,"filesTotal":0,"bytesPerSecond":0}
{"schema":1,"event":"progress","sequence":2,"phase":"downloading","paused":false,"canPause":true,"bytesDone":1048576,"bytesTotal":8388608,"filesDone":0,"filesTotal":12,"bytesPerSecond":5242880}
{"schema":1,"event":"progress","sequence":8,"phase":"finalizing","paused":false,"canPause":false,"bytesDone":8388608,"bytesTotal":8388608,"filesDone":12,"filesTotal":12,"bytesPerSecond":0}
```

Every line has `"schema":1` and a monotonically increasing `sequence`.
Progress lines are throttled to at most one every 250 ms, plus an immediate
line when the phase changes.

| Field | Meaning |
| --- | --- |
| `event` | `progress`, `paused`, `resumed`, `stopped`, `done`, or `error` |
| `phase` | `metadata`, `licensing`, `downloading`, or `finalizing` |
| `paused` | Whether new HTTP reads are currently parked |
| `canPause` | True while the transfer is in the `downloading` phase |
| `bytesDone` | Bytes written, including resumed bytes counted at start |
| `bytesTotal` | Total bytes in the files selected for this run |
| `filesDone` | Files finished (including files already complete when resumed) |
| `filesTotal` | Files selected for this run |
| `bytesPerSecond` | Smoothed throughput (exponential moving average) |

When a run resumes from a journal, the checkpointed bytes are counted as done
as soon as the download phase starts; they are not downloaded again. There is
no `phase:"done"` line: successful completion is the separate `done` event.

## Control lines

Write one bounded JSON line (at most 256 bytes) to the process's stdin:

```json
{"schema":1,"command":"pause"}
{"schema":1,"command":"resume"}
{"schema":1,"command":"stop"}
```

Unknown commands, unknown schema versions, malformed JSON, and overlong lines
are ignored. `pause` is acknowledged as soon as the request is accepted; each
segment then parks at its next safe point after flushing and checkpointing
in-flight writes. `resume` continues the transfer and issues a fresh range
request from the last received offset. `stop` is terminal: later pause, resume,
or EOF lines are ignored.

If stdin reaches EOF while paused, the transfer is resumed automatically:
losing the controller must never leave a download parked forever. EOF does not
mask a dead consumer; stdout write failures are classified as follows and all
end in a checkpoint and exit 3:

- `BrokenPipe`, `ConnectionReset`, `ConnectionAborted`, or `NotConnected`:
  the consumer is gone; stop immediately.
- `WouldBlock` or `TimedOut`: retry every 10 ms for up to about 2 seconds, then
  stop.
- Any other write error: stop.

The control acknowledgements are ordinary protocol lines:

```json
{"schema":1,"event":"paused","sequence":3,"phase":"downloading","paused":true,"canPause":true,"bytesDone":2097152,"bytesTotal":8388608,"filesDone":0,"filesTotal":12,"bytesPerSecond":0}
{"schema":1,"event":"resumed","sequence":4,"phase":"downloading","paused":false,"canPause":true,"bytesDone":2097152,"bytesTotal":8388608,"filesDone":0,"filesTotal":12,"bytesPerSecond":0}
```

## Terminal lines

A successful run ends with:

```json
{"schema":1,"event":"done","sequence":9}
```

A failed run ends with an error whose `kind` follows `CommandError`. The
message is a fixed, path- and URL-free text for that kind; detailed errors are
written to stderr only:

```json
{"schema":1,"event":"error","sequence":9,"kind":"auth","message":"authentication or licensing failed"}
{"schema":1,"event":"error","sequence":9,"kind":"network","message":"a network request failed"}
{"schema":1,"event":"error","sequence":9,"kind":"other","message":"streaming failed"}
```

A `stop` command ends with:

```json
{"schema":1,"event":"stopped","sequence":7,"phase":"downloading","paused":false,"canPause":true,"bytesDone":3145728,"bytesTotal":8388608,"filesDone":0,"filesTotal":12,"bytesPerSecond":0}
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success; the streaming image was finalized |
| 1 | Any other failure |
| 3 | `{"schema":1,"command":"stop"}`, or a dead stdout consumer |
| 130 | SIGINT |
| 143 | SIGTERM |

On stop or a signal the journal (`.xodus-streaming-v1.jsonl`) and the partial
cache remain, and `.xodus-streaming.msixvc` is not put in place. A later run
with the same destination resumes from the durable offsets.

## Not implemented

Bandwidth limiting (`set-download-limit` / `kibPerSecond`) from Nexus is not
ported; it is a follow-up. `download --progress json` is not part of this
protocol yet either.
