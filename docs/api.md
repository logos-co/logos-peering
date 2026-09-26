# peering_identity and peering_module: the contract

Both are bundled `universal` modules on `qt_remote_plain`, hosted by `logos_host_plain`.
Every method returns a JSON object (`LogosMap`): its result, or `{"error": "<CODE>[: detail]"}`.
Codes: `NOT_AUTHORISED` (also for anything unknown or denied), `NO_SUCH_METHOD`,
`INVALID_ARGUMENT`, `INVALID_CONFIG`, `IDENTITY_UNAVAILABLE`, `UNREACHABLE`,
`PAIRING_FAILED`, `LOCKED` (a YAML entry), `FAILED`.

## peering_identity — the root key (no network code)

Callable only by `peering_module`.

| Method | Returns |
|---|---|
| `runtimeId()` | `{runtime_id}` |
| `rootCertificate()` | `{root_pem}` |
| `displayId()` | `{display_id}` — 4×5 base32 of the root SPKI's SHA-256 |
| `issue(role, spki, validitySeconds)` | `{leaf_pem}`. `role` is `control`, `provider` or `client`; `spki` is base64url DER |

## peering_module — pairing, routes and the control endpoint

### Callers

| Caller | May call |
|---|---|
| `{kind:host}` (the engine) | engine methods |
| `{kind:module,name:<shell>}` (the shell named in `configure`) | management, read and write |
| `{kind:operator,name:N}`, N neither `auto` nor `@peer:*` | management, read and write |
| `{kind:operator,name:auto}`, `{kind:operator,name:@peer:*}` | management, read only |
| `{kind:module,name:X}`, X a loaded export (`exportLoaded`) | host methods |
| `{kind:module,name:core_service}` with `operator` on | host methods |
| `{kind:module,name:F}`, F a loaded facade (`facadeLoaded`) | facade methods, and `issueCertificate("client")` |

### Engine methods

| Method | Notes |
|---|---|
| `configure(config)` | The peering config below, with `"shell"`. Re-delivered after every restart. |
| `exportLoaded(module, epoch)` / `exportExited(module, epoch)` | An exported module's host came up or went away. |
| `facadeLoaded(name, epoch)` / `facadeExited(name, epoch)` | An import's facade came up or went away. |
| `imports()` | `{name: {from, module, prefer, version, allowed_callers, events, peer_alias, locked}}` |
| `importStates()` | `{name: {state, reason}}`; `configured`, `connecting`, `ready`, `error` |
| `remotePolicy()` | `{"<uuid>/<consumer>": [target…], "<uuid>/*": […]}` |

Events: `importsChanged()`, `importStateChanged(name, state, reason)`, `remotePolicyChanged()`.

### Host methods (exporting hosts, core_service)

| Method | Notes |
|---|---|
| `issueCertificate(role, csrPem)` | `{chain_pem, anchors_pem}`. Hosts get `provider`; facades get `client`, with their import's peer root as anchor. The CSR proves possession of the key. |
| `sessionAnchors()` | `{anchors_pem}`: the enrolled roots an exported endpoint trusts. |
| `redeemTicket(request)` | The session authenticator's request, unchanged. Returns its reply: `{caller, lifetime_ms, session:{peer, route, generation}}` or `{error}`. A retry from the same connection gets the same answer. |
| `noteEndpoints(endpoints)` | The host's bound listeners (`lp_provider_endpoints_json`). |
| `sessionState()` | `{anchors_pem, generations:{peer: n}}` for the periodic reconcile. |

Events hosts follow: `anchorsChanged()`, `routesRevoked(peer, generation)`,
`routeRenewed(route, lifetimeMs)`.

### Facade methods

| Method | Notes |
|---|---|
| `requestRoute(consumer, timeoutMs)` | Dial info for the facade's import: `{addresses, port, server_pin, anchors, ticket, route, lifetime_ms, max_frame}`. `consumer` must be `runtime` or one of the import's `allowed_callers`. |
| `renewRoute(route)` | `{lifetime_ms}` |
| `importDescriptor()` | `{name, from, module, events, allowed_callers, peer_alias, peer_display_name}` |
| `reportImportState(state, reason)` | `connecting`, `ready` or `error`; emits `importStateChanged`. |

### Management methods (shell, operators)

| Method | Write? |
|---|---|
| `status()` | no — `{runtime_id, display_id, name, control:{enabled, port}, exports, operator, peers, pairing_window_ms, invites}` |
| `peers()` | no — `[{runtime_id, alias, display_name, display_id, role, granted_role, status, addresses, control_port}]` |
| `nearby()` | no (discovery; empty for now) |
| `pending()` | no — pairings in progress, with codes |
| `routes()` | no — `{served:[…], imports:{…}}` |
| `exports()` | no — `{module: {events, locked, loaded, port}}` |
| `openPairingWindow(seconds)` | yes — at most 900; 0 closes it |
| `pairWith(host, port)` | yes — `{id, code, peer_display_id, state}`; confirm with `confirmPairing(id)` once the codes match |
| `confirmPairing(id)` / `rejectPairing(id)` | yes — for either direction |
| `createInvite(role, ttlSeconds)` | yes — `{invite}`; `role` is `peer` (≤ 24 h) or `operator` (≤ 15 min, needs `operator`) |
| `redeemInvite(invite)` | yes |
| `removePeer(peer)` / `renamePeer(peer, alias)` | yes — `peer` is a runtime id or an alias |
| `setExport(module, config)` / `removeExport(module)` | yes |
| `setImport(name, config)` / `removeImport(name)` | yes |
| `setPolicy(policy)` | yes — replaces the whole document |

Events: `peersChanged()`, `pairingRequested(pending)`, `nearbyChanged()`.

## The control endpoint

With `control` on, `peering_module` runs a second provider in its own image,
`peering_control`, on `tls_tcp`. Its credential is the persistent control key with a
`control` leaf; its anchors are the enrolled roots. Every client presents a control leaf
and its root, and says what it came for in its Hello:

- `{"purpose":"control"}` from an enrolled peer whose leaf is one of its enrolled keys:
  the session's caller is `{kind:"remote", peer:<uuid>, name:"peering_module"}`.
- `{"purpose":"pairing"}` from an unknown root, only while a pairing window is open or an
  invite is live (the listener then admits chains its anchors refuse): the caller is
  `{kind:"remote", peer:"pairing:<session>", name:"pairing"}`, limited to `pair*`.

| Method | Caller |
|---|---|
| `pairHello(hello)` → `{nonce}` | pairing session |
| `pairReveal(reveal)` → `{ok}` | pairing session |
| `pairConfirm(confirm)` → `{status: waiting | accepted | rejected, …}` | pairing session; polled until B decides |
| `listExports()` → `{module: {events, loaded}}` | enrolled peer |
| `establishRoute({consumer, target, client_pin})` → a ticket and dial info | enrolled peer |
| `renewRoute(route)` → `{lifetime_ms}` | enrolled peer |
| `peerUpdate(update)` | enrolled peer (not yet) |

## Configuration (the `peering_config` spawn key)

```json
{
  "name": "office-server",
  "shell": "logoscore",
  "control":  {"enabled": true, "host": "0.0.0.0", "port": 7443, "advertise": "192.168.1.5"},
  "exports":  {"enabled": true, "ports": "7450-7499",
               "modules": {"monerod_module": {"events": true}}},
  "operator": false,
  "announce": true,
  "browse":   true,
  "imports":  {"monerod_module": {"from": "<uuid>", "module": "monerod_module",
                                  "prefer": "remote", "version": "^0.1",
                                  "allowed_callers": ["monerod_ui"], "events": true}}
}
```

Unknown keys are errors. Entries given here are locked; the same kinds of entries made at
run time (`setExport`, `setImport`, `setPolicy`) persist in `peering_module`'s state.
