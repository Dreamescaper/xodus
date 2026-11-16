# Account library

`xodus-cli library --json [--market US]` lists the stored account's Microsoft
Store entitlements. It is a read-only command: it never starts sign-in,
provisions a device, prompts, or writes to the cloud. The implementation is
ported from Xodus Nexus (`crates/xodus-cli/src/commands/library.rs`) with
credit, including its defensive validation and quarantine rules.

It renews an already registered device only when its token is missing or
expired. If no device identity is stored, the command fails instead of creating
one.

## Authentication

The command exchanges the stored MSA user token for a Store ticket through the
normal RST2 flow, using the existing device identity:

- scope: `www.microsoft.com` with `MBI_SSL`
- hosting app: `{d6d5a677-0872-4ab0-9442-bb792fce85c5}`
- resulting compact `t=` ticket is sent as `Authorization` to
  `https://beige.xboxservices.com/PCGAFD/entitlements`

The ticket is never written to stdout or stderr. The command sends:

```
GET https://beige.xboxservices.com/PCGAFD/entitlements?market=US&language=en-US&appVersion=0.2.3
Authorization: <store ticket>
X-MS-API-Version: 1.1
Calling-App-Name: Xodus-Nexus
MS-CV: <random correlation id>
x-ms-ct: <continuation cursor, when present>
```

Pagination follows the `x-ms-ct` response header. Up to 20 pages, 4 MiB per
page and 16 MiB in total are accepted.

## JSON output

`--json` prints one schema-versioned object on stdout:

```json
{
  "schema": 1,
  "items": [
    {"productId": "9NBLGGH4R315", "access": "owned", "kind": "game"},
    {"productId": "9P1J8S7CCWWT", "access": "gamepass", "kind": "addon"},
    {"productId": "9WZDNCRFJ3Q8", "access": "trial", "kind": null},
    {"productId": "9NBLGGH5R558", "access": "expired", "kind": null}
  ],
  "skipped": 0
}
```

| Field | Meaning |
| --- | --- |
| `schema` | Protocol version. Currently `1`. |
| `items` | One verified entitlement record per product ID, sorted by product ID. |
| `items[].productId` | 12-character Store product ID. |
| `items[].access` | See the access table below. |
| `items[].kind` | `game`, `addon`, `app`, `subscription`, `unknown`, or `null` when the entitlement data does not say. |
| `skipped` | Number of malformed, conflicting or dependent rows that were quarantined. |

`kind` is only reported when the entitlement row explicitly supplies a product
type; a license by itself does not prove whether a product is a game, add-on or
app. `subscription` is used for the known PC Game Pass plan product IDs.
Highball reads the public display catalog for titles and art.

### Access values

Access is derived defensively; a parent chain must itself be licensed.

| Value | Meaning |
| --- | --- |
| `owned` | Active, paid/direct license, or a child of an owned bundle. |
| `gamepass` | Active license satisfied by a known PC Game Pass plan. |
| `trial` | Active, but marked by the service as a trial. |
| `expired` | Expiry date has passed, or the service reports it as expired. |
| `shared` | Access comes from another account (`sharingSource` is not `None`). |
| `restricted` | A special licensing flag is present without recognized Positron provenance. |
| `inactive` | The service reports a non-active state such as revoked or suspended. |
| `subscription` | The record is a PC Game Pass plan itself, not a game tile. |
| `unverified` | A parent entitlement is missing, cyclic or itself unverified. |

The output never contains tokens, account identifiers, emails, XUIDs or
renewal dates.

## Validation and quarantine

A malformed row is not ownership. Rows are rejected when their product ID,
status, trial flag, sharing source, expiry, parent or policy types are invalid.
A rejected product ID is quarantined across all pages, its already-seen row is
removed, and every dependent child is removed with it. Conflicting duplicates
are quarantined the same way. Independently verified rows are kept and counted
in `skipped`.

stderr may contain bounded diagnostics:

```
XODUS_LIBRARY_DIAGNOSTIC_V1 <stage> <http-status> <count>
```

Stages are fixed; response bodies, account identifiers and credentials are never
logged.

## Human output

Without `--json`, a short table is printed:

```
PRODUCT       ACCESS        KIND
9NBLGGH4R315  owned         game
9P1J8S7CCWWT  gamepass      addon
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Network, response or other failure; `error: <message>` is written to stderr |
| 2 | Not signed in, missing/expired stored sign-in, or Microsoft refused it |

`--market` takes a two-letter Store market such as `US`, `GB` or `DE`. It
defaults to `US`.
