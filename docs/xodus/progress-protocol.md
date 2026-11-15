# Streaming progress and control protocol

`xodus-cli streaming --progress json <source> <destination>` writes one JSON
object per line to stdout. The same command reads control commands from stdin,
so a launcher can drive pause, resume, and stop without a terminal.

This protocol is derived from Xodus Nexus's versioned streaming progress
protocol (`streaming_progress.rs`), adapted for Highball. It never emits local
paths, download URLs, tokens, query strings, or account ids.

## Enabling it

```sh
xodus-cli streaming --progress json <product-or-content-id-or-url> <destination>
```

The default is the existing human progress bar. In JSON mode the bar is not
created, so stdout carries only protocol lines.

## Progress lines

```json
{"schema":1,"event":"progress","sequence":0,"phase":"metadata","paused":false,"canPause":false,"bytesDone":0,"bytesTotal":0,"filesDone":0,"filesTotal":0,"bytesPerSecond":0,"completedBytes":0,"totalBytes":0}
{"schema":1,"event":"progress","sequence":1,"phase":"licensing","paused":false,"canPause":false,"bytesDone":0,"bytesTotal":0,"filesDone":0,"filesTotal":0,"bytesPerSecond":0,"completedBytes":0,"totalBytes":0}
{"schema":1,"event":"progress","sequence":2,"phase":"downloading","paused":false,"canPause":true,"bytesDone":1048576,"bytesTotal":8388608,"filesDone":0,"filesTotal":12,"bytesPerSecond":5242880,"completedBytes":1048576,"totalBytes":8388608}
{"schema":1,"event":"progress","sequence":8,"phase":"finalizing","paused":false,"canPause":false,"bytesDone":8388608,"bytesTotal":8388608,"filesDone":12,"filesTotal":12,"bytesPerSecond":0,"completedBytes":8388608,"totalBytes":8388608}
```

Every line has `"schema":1` and a monotonically increasing `sequence`.
Progress lines are throttled to at most one every 250 ms, plus an immediate
line when the phase changes.

| Field | Meaning |
| --- | --- |
| `event` | `progress`, `paused`, `resumed`, `stopped`, `done`, or `error` |
| `phase` | `metadata`, `licensing`, `downloading`, `finalizing`, or `done` |
| `paused` | Whether new HTTP reads are currently parked |
| `canPause` | True while the transfer is in the `downloading` phase |
| `bytesDone` | Bytes already durable, including bytes restored from a journal |
| `bytesTotal` | Total bytes in the files selected for this run |
| `filesDone` | Files finished (including files already complete when resumed) |
| `filesTotal` | Files selected for this run |
| `bytesPerSecond` | Smoothed throughput (exponential moving average) |
| `completedBytes`, `totalBytes` | Nexus-compatible aliases for `bytesDone`, `bytesTotal` |

When a run resumes from a journal, the checkpointed bytes are counted as done
as soon as the download phase starts; they are not downloaded again.

## Control lines

Write one bounded JSON line (at most 256 bytes) to the process's stdin:

```json
{"schema":1,"command":"pause"}
{"schema":1,"command":"resume"}
{"schema":1,"command":"stop"}
```

Unknown commands, unknown schema versions, malformed JSON, and overlong lines
are ignored. `pause` stops issuing new HTTP reads; in-flight writes are flushed
and checkpointed before the transfer parks. `resume` continues the transfer and
issues a fresh range request from the last received offset. If stdin reaches
EOF while paused, the transfer is resumed automatically: losing the controller
must never leave a download parked forever.

The control acknowledgements are ordinary protocol lines:

```json
{"schema":1,"event":"paused","sequence":3,"phase":"downloading","paused":true,"canPause":true,"bytesDone":2097152,"bytesTotal":8388608,"filesDone":0,"filesTotal":12,"bytesPerSecond":0,"completedBytes":2097152,"totalBytes":8388608}
{"schema":1,"event":"resumed","sequence":4,"phase":"downloading","paused":false,"canPause":true,"bytesDone":2097152,"bytesTotal":8388608,"filesDone":0,"filesTotal":12,"bytesPerSecond":2097152,"completedBytes":2097152,"totalBytes":8388608}
```

## Terminal lines

A successful run ends with:

```json
{"schema":1,"event":"done","sequence":9}
```

A failed run ends with an error whose `kind` follows `CommandError`:

```json
{"schema":1,"event":"error","sequence":9,"kind":"auth","message":"could not read the device token: expired"}
{"schema":1,"event":"error","sequence":9,"kind":"network","message":"could not download a package segment"}
{"schema":1,"event":"error","sequence":9,"kind":"other","message":"not enough free disk space for the package"}
```

The message is sanitized: absolute paths, URLs, long numeric account ids, and
credentials are replaced with `<path>`, `<url>`, and `<id>`.

A `stop` command ends with:

```json
{"schema":1,"event":"stopped","sequence":7,"phase":"downloading","paused":false,"canPause":true,"bytesDone":3145728,"bytesTotal":8388608,"filesDone":0,"filesTotal":12,"bytesPerSecond":0,"completedBytes":3145728,"totalBytes":8388608}
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success; the streaming image was finalized |
| 1 | Any other failure |
| 129 | `{"schema":1,"command":"stop"}` |
| 130 | SIGINT |
| 143 | SIGTERM |

On stop or a signal the journal (`.xodus-streaming-v1.jsonl`) and the partial
cache remain, and `.xodus-streaming.msixvc` is not put in place. A later run
with the same destination resumes from the durable offsets.

## Not implemented

Bandwidth limiting (`set-download-limit` / `kibPerSecond`) from Nexus is not
ported; it is a follow-up. `download --progress json` is not part of this
protocol yet either.
