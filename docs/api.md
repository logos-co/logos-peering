# peering_identity and peering_module: the contract

Both are bundled `universal` modules on `qt_remote_plain`, hosted by `logos_host_plain`.
Structured arguments and results are JSON objects (`LogosMap`). A method refused to its
caller returns `{"success":false,"error":"NOT_AUTHORISED"}` (or, for maps, `{"error":…}`).

## peering_identity — the root key (no network code)

Callable only by `peering_module` (checked against `lp_current_caller_json`).

| Method | Returns |
|---|---|
| `runtimeId()` | the runtime UUID |
| `rootCertificate()` | the root certificate, PEM |
| `displayId()` | the 4×5 base32 display ID |
| `issue(role, spkiB64, validitySeconds)` | `StdLogosResult`, value = leaf PEM. `role` is `control`, `provider` or `client`; the SPKI is base64url DER |

## peering_module — pairing, routes and the control endpoint

### Callers

`peering_module` decides per caller document:

| Caller | May call |
|---|---|
| `{kind:host}` (the engine, `@runtime`) | engine methods |
| `{kind:module,name:<shell>}` (the shell named in `configure`) | management, read and write |
| `{kind:operator,name:N}` with N ≠ `auto` and not `@peer:*` | management, read and write |
| `{kind:operator,name:auto}`, `{kind:operator,name:@peer:*}` | management, read only |
| `{kind:module,name:X}`, X a registered facade | facade methods for X's own import |
| `{kind:module,name:X}`, X an exported module the engine reported loaded | host methods for X |
| `{kind:module,name:core_service}` when `operator` is on | host methods for core_service |

### Engine methods

| Method | Notes |
|---|---|
| `configure(config)` | The peering config (see below) plus `"shell"`. Re-delivered after every restart. |
| `exportLoaded(module, epoch)` / `exportExited(module, epoch)` | An exported module's host came up or went away. |
| `imports()` | `{name: {from, module, prefer, version, allowed_callers, events}}` |
| `importStates()` | `{name: {state, reason}}` |
| `remotePolicy()` | `{"<uuid>/<consumer>": ["target", …], "<uuid>/*": […]}` |

Events the engine follows: `importsChanged()`, `importStateChanged(name, state, reason)`,
`remotePolicyChanged()`.

### Host methods (exporting hosts, facades, core_service)

| Method | Notes |
|---|---|
| `issueCertificate(role, csrPem)` | `StdLogosResult`, value `{chain_pem, anchors_pem}`. Exporting hosts and core_service get `provider`, facades get `client`. The CSR proves possession of the key. |
| `sessionAnchors()` | The enrolled roots (PEM) an exported endpoint trusts. |
| `redeemTicket(request)` | The session authenticator's request (Hello, peer chain, exporter). Returns the authenticator reply: `{caller, lifetime_ms, session:{peer, route, generation}}` or `{error}`. |
| `noteEndpoints(endpoints)` | The exporting host's bound listeners (`lp_provider_endpoints_json`). |
| `sessionState()` | `{anchors_pem, generations:{peer: n}, closed_routes:[…]}` for the 30 s reconcile. |
| `requestRoute(consumer, timeoutMs)` | Facade only. Dial info for its import: `{addresses, port, server_pin, anchors, ticket, route, lifetime_ms, digest}` or `{error}`. |
| `renewRoute(route)` | Facade only. `{lifetime_ms}` or `{error}`. |
| `importDescriptor()` | Facade only: its own import's descriptor. |
| `reportImportState(state, reason)` | Facade only: `ready` / `error` / `connecting`. |

Events hosts follow: `anchorsChanged()`, `routesRevoked(peer, generation)`,
`routeRenewed(route, lifetimeMs)`.

### Management methods (shell, operators)

| Method | Write? |
|---|---|
| `status()` | no |
| `peers()` | no |
| `nearby()` | no |
| `pending()` | no |
| `routes()` | no |
| `exports()` | no |
| `openPairingWindow(seconds)` | yes |
| `pairWith(host, port)` | yes — starts code pairing; the code appears in `pending()` |
| `confirmPairing(id)` / `rejectPairing(id)` | yes |
| `createInvite(role, ttlSeconds)` | yes — `operator` only for the shell or a named operator |
| `redeemInvite(invite)` | yes |
| `removePeer(peer)` / `renamePeer(peer, alias)` | yes |
| `setExport(module, config)` / `removeExport(module)` | yes |
| `setImport(name, config)` / `removeImport(name)` | yes |
| `setPolicy(policy)` | yes |

Events: `peersChanged()`, `pairingRequested(pending)`, `nearbyChanged()`.

## The control endpoint

`peering_module` creates a second provider in its own image, `peering_control`, on
`tls_tcp` (the `control` switch). Its credential is the persistent control leaf; its
anchors are the enrolled roots; its authenticator admits:

- an enrolled peer whose leaf SPKI is one of its enrolled `subject_public_keys`, as
  `{kind:"remote", peer:<uuid>, name:"peering_module"}`;
- while a pairing window is open or an invite is live, any other presented root, as
  `{kind:"remote", peer:"pairing:<session id>", name:"pairing"}`, allowed only the
  `pair*` methods below.

Other runtimes' `peering_module`s call it with an ordinary client over `tls_tcp`:

| Method | Caller |
|---|---|
| `pairHello(hello)` → `{nonce}` | pairing session |
| `pairReveal(nonce)` → `{ok}` | pairing session |
| `pairConfirm(announceKey)` → `{status, runtime_id, display_name, announce_key, role}` | pairing session; waits for approval |
| `listExports()` → `{module: {version, digest, events}}` | enrolled peer |
| `establishRoute(request)` → dial info with a ticket | enrolled peer |
| `renewRoute(route)` → `{lifetime_ms}` | enrolled peer |
| `peerUpdate(update)` | enrolled peer (announce key rotation, enrollment revision) |

B pushes revocations as events on the same session (`routesRevoked(peer, generation)`).

## Configuration (the `peering_config` spawn key)

```json
{
  "name": "office-server",
  "control":  {"enabled": true, "host": "0.0.0.0", "port": 7443},
  "exports":  {"enabled": true, "ports": "7450-7499",
               "modules": {"monerod_module": {"events": true}}},
  "operator": false,
  "announce": true,
  "browse":   true,
  "imports":  {"monerod_module": {"from": "<uuid>", "prefer": "remote",
                                  "version": "^0.1", "allowed_callers": ["monerod_ui"]}}
}
```
