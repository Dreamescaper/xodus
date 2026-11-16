# Account status

`xodus-cli account --json [--market US]` reports whether an account is stored
and, when it is cheap and safe to do so, the Xbox gamertag and PC Game Pass
status. It is designed for launchers such as Highball.

The command is offline-first:

- `signedIn` and `session` come only from stored state.
- It never provisions a device, opens a sign-in prompt, or deletes credentials.
- It only refreshes an already registered device token before optional network
  reads.
- A network failure never makes the command fail; it is reported in `network`.
- It never outputs emails, PUIDs, XUIDs, tokens or renewal dates.

## JSON output

```json
{
  "schema": 1,
  "signedIn": true,
  "session": "current",
  "gamertag": "Example Gamer",
  "gamePass": "active",
  "network": "checked"
}
```

Signed out:

```json
{
  "schema": 1,
  "signedIn": false,
  "session": "missing",
  "gamertag": null,
  "gamePass": "unknown",
  "network": "skipped"
}
```

| Field | Meaning |
| --- | --- |
| `schema` | Protocol version. Currently `1`. |
| `signedIn` | A stored account exists. This is available fully offline. |
| `session` | `current`, `expired`, `invalid`, or `missing`; checked locally from the stored user token. |
| `gamertag` | Best-effort Xbox gamertag, or `null` when not available. |
| `gamePass` | `active`, `inactive`, or `unknown`. |
| `network` | `checked`, `partial`, `unavailable`, or `skipped`. |

### `network`

| Value | Meaning |
| --- | --- |
| `checked` | Every optional network read that was attempted succeeded. |
| `partial` | Exactly one of the gamertag and Game Pass reads succeeded. |
| `unavailable` | All attempted network reads failed, or the read timed out. |
| `skipped` | No usable existing session/device identity was available, or nobody is signed in. Provisioning or signing in would be required. |

`gamertag` and `gamePass` remain `null` / `unknown` when their individual checks
are skipped, partial or unavailable.

## Optional network reads

When the stored user token is current and a device identity already exists, the
command may perform up to 20 seconds of best-effort reads:

- **Gamertag**: exchange the stored user credential for an Xbox Live user
  ticket (`user.auth.xboxlive.com`, `MBI_SSL`), obtain an XSTS token for
  `http://xboxlive.com`, then request only `Gamertag` from
  `https://profile.xboxlive.com/users/me/profile/settings`.
- **PC Game Pass**: exchange the stored user credential for a Store ticket
  (`www.microsoft.com`, `MBI_SSL`) and query
  `https://beige.xboxservices.com/PCGAFD/entitlements/subscriptions?market={market}&language=en-US&appVersion=0.2.3`
  for the known PC Game Pass plan IDs. `--market` defaults to `US` and is
  uppercased before use. The implementation is ported from Xodus Nexus's
  `subscription.rs` with credit.

No tokens, account identifiers or raw service responses are emitted. Detailed
failures are at most logged to stderr through `tracing`; they do not change the
JSON contract.

`gamePass` is `active` only for an active, unexpired known PC plan. An explicit
inactive/expired plan record yields `inactive`; empty or unsupported data yields
`unknown` because it is not proof that no subscription exists.

## Human output

Without `--json`, the command prints a short status:

```
Signed in
Gamertag: Example Gamer
PC Game Pass: active
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Status was produced, including when nobody is signed in |
| 1 | A non-`NotFound` local credential-store error prevented reading the stored state; `NotFound` means signed out and still exits 0 |
| 2 | Not used by `account --json` |

`account --json` returns success for a signed-out account so a launcher can
render the signed-out state without treating it as an error. An invalid
`--market` is a usage error and exits 1.
