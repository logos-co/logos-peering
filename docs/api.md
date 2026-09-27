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
| `{kind:host}` (the engine) | engine methods; with `runtime_control` on, the host methods for `core_service`, which it hosts |
| `{kind:module,name:<shell>}` (the shell named in `configure`) | management, read and write |
| `{kind:operator,name:N}`, a local operator (`auto` included) | management, read and write |
| `{kind:operator,name:@peer:*}`, a remote consumer's call core_service forwarded (it forwards none here) | management, read only |
| `{kind:module,name:X}`, X a loaded export (`exportLoaded`) | host methods |
| `{kind:module,name:core_service}` with `runtime_control` on | host methods (the engine calls them as the host) |
| `{kind:module,name:F}`, F a loaded facade (`facadeLoaded`) | facade methods, and `issueCertificate("client")` |

### Engine methods

| Method | Notes |
|---|---|
| `configure(config)` | The peering config below, with `"shell"`. Re-delivered after every restart. |
| `exportLoaded(module, epoch)` / `exportExited(module, epoch)` | An exported module's host came up or went away. |
| `facadeLoaded(name, epoch)` / `facadeExited(name, epoch)` | An import's facade came up or went away. |
| `imports()` | `{name: {from, module, prefer, version, allowed_callers, events, peer_alias, locked}}` |
| `importStates()` | `{name: {state, reason}}`; `configured`, `connecting`, `ready`, `error` |
| `remotePolicy()` | `{"<uuid>/<consumer>": grants, "<uuid>/*": grants}`, as `setPolicy` takes it |
| `exports()` | as the management method below; the engine adds a tls_tcp listener to each at its next load |
| `reevaluateRoutes()` | `{ok, revoked}`: after the engine gave capability a new remote policy, a peer with a live route it no longer allows loses every route (`routesRevoked`) and asks again for what it may |

Events: `importsChanged()`, `exportsChanged()` (the engine re-reads `exports()`; an export
takes effect at the module's next load), `importStateChanged(name, state, reason)`,
`remotePolicyChanged()` (the engine hands `remotePolicy()` to capability, then calls
`reevaluateRoutes()`).

**Who decides a route.** `capability_module`, the runtime's authority: `peering_module` asks
core_service's `peering` scope, `evaluateRemoteAccess(peer, consumer, target)`, for each
route, and the engine keeps capability's copy of the policy current. A consumer the policy
does not list is refused, and so is every route while no answer comes. The engine also
confines each import's facade to calling `peering_module` alone.

### Host methods (exporting hosts, core_service)

| Method | Notes |
|---|---|
| `issueCertificate(role, csrPem)` | `{chain_pem, anchors_pem, session_options?}`. Hosts get `provider`; facades get `client`, with their import's peer root as anchor. The CSR proves possession of the key. An exporting host also gets `session_options` (`port_min`, `port_max` from `exports.ports`) to apply before its listener starts. |
| `sessionAnchors()` | `{anchors_pem}`: the enrolled roots an exported endpoint trusts. |
| `redeemTicket(request)` | The session authenticator's request, unchanged. Returns its reply: `{caller, lifetime_ms, session:{peer, route, generation}}` or `{error}`. A retry from the same connection gets the same answer. For `core_service` it admits Runtime Control Hellos instead (below). |
| `noteEndpoints(endpoints)` | The host's bound listeners (`lp_provider_endpoints_json`). |
| `sessionState()` | `{anchors_pem, generations:{peer: n}}` for the periodic reconcile. |

Events hosts follow: `anchorsChanged()`, `routesRevoked(peer, generation)`,
`routeRenewed(route, lifetimeMs)`.

### Facade methods

| Method | Notes |
|---|---|
| `requestRoute(consumer, timeoutMs)` | Dial info for the facade's import: `{addresses, port, server_pin, anchors, ticket, route, lifetime_ms, max_frame}`. `consumer` must be `runtime` or one of the import's `allowed_callers`. The facade's own `runtime` session fetches the interface and carries the events; unless the peer's policy lets `runtime` call, it gets a look-only route (session metadata `"calls": false`). |
| `renewRoute(route)` | `{lifetime_ms}` |
| `importDescriptor()` | `{name, from, module, events, allowed_callers, peer_alias, peer_display_name}` |
| `reportImportState(state, reason)` | `connecting`, `ready` or `error`; emits `importStateChanged`. |

### Management methods (shell, operators)

| Method | Write? |
|---|---|
| `status()` | no — `{runtime_id, display_id, name, control:{enabled, port, error?}, exports, runtime_control, peers, pairing_window_ms, invites}`; `error` says why an enabled endpoint is not listening |
| `peers()` | no — `{peers: [{runtime_id, alias, display_name, display_id, uses, granted_uses, status, addresses, control_port}]}`; `uses` is what the peer may do here, `granted_uses` what this runtime may do there: `provider-access`, plus `runtime-control` |
| `nearby()` | no — `{nearby: []}` (discovery comes later) |
| `pending()` | no — `{pending: [...]}`, pairings in progress with their codes and the `uses` they would grant |
| `routes()` | no — `{served:[…], imports:{…}}` |
| `exports()` | no — `{module: {events, locked, loaded, port}}` |
| `peerExports(peer)` | no, but asks the peer, so only managers call it — `{peer, exports: {module: {events, loaded}}}`, what the peer's policy lets this runtime reach |
| `openPairingWindow(seconds)` | yes — at most 900; 0 closes it |
| `pairWith(host, port)` | yes — `{id, code, peer_display_id, state}`; confirm with `confirmPairing(id)` once the codes match |
| `confirmPairing(id)` / `rejectPairing(id)` | yes — for either direction |
| `createInvite(role, ttlSeconds)` | yes — `{invite}`; `role` is `peer` (≤ 24 h) or `runtime-control` (≤ 15 min, needs `runtime_control`) |
| `redeemInvite(invite)` | yes |
| `removePeer(peer)` / `renamePeer(peer, alias)` | yes — `peer` is a runtime id or an alias |
| `setExport(module, config)` / `removeExport(module)` | yes |
| `setImport(name, config)` / `removeImport(name)` | yes |
| `setPolicy(policy)` | yes — replaces the whole document; see "Remote policy" |

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
| `runtimeControlEndpoint()` → `{port, server_pin}` | a peer enrolled with `runtime-control`, while `runtime_control` is on |
| `renewRoute(route)` → `{lifetime_ms}` | enrolled peer |
| `peerUpdate(update)` | enrolled peer (not yet) |

## Remote policy

`setPolicy` takes `{"<uuid>/<consumer>": grants, "<uuid>/*": grants}`. Grants are a list of
targets, each granted whole, or `{target: "*" | [method…] | []}`. The exact
`<uuid>/<consumer>` key wins over `<uuid>/*`, and the exact target over `"*"`; entries
never merge, so `[]` under an exact key denies what `<uuid>/*` grants. Targets are exports,
`"*"` (every export), or `core_service`, which `"*"` never covers. A route needs a grant
that is not empty; each Runtime Control call needs `"*"` or a list naming its method.

## Remote Runtime Control (logos-lips runtime §9)

With `runtime_control` on, the runtime also serves `core_service` on `tls_tcp`, the logical
endpoint `logos_runtime_control`: it gets a `provider` leaf, authenticates each session
with `redeemTicket` and notes the listener, all as the host. There is no ticket. A client
asks for the endpoint with `runtimeControlEndpoint()` over the control link, dials it with
a `client` leaf of its runtime's root, and says which of its module instances it acts for:

```json
{"module": "logos_runtime_control",
 "consumer": {"runtime_instance_id": "<its uuid>", "module_instance_id": "logosctl"}}
```

The session is admitted when that runtime is enrolled here with `runtime-control`, its
root is the chain's, and the name is valid. Its caller is
`{kind:"remote", peer:<uuid>, name:<consumer>}`, for at most an hour, with the peer's
revocation generation. Removing the peer ends it. core_service then decides each call with
the remote policy: `{"<uuid>/logosctl": {"core_service": ["getStatus", "listModules"]}}`.
A call it forwards (`callModuleMethod`) needs a grant on the target method too, and never
reaches the runtime's own modules, this one included.

Only `createInvite("runtime-control", …)` enrolls a runtime for it; its redemption waits
for `confirmPairing` here, showing the redeemer's display ID. A tool with no runtime of its
own pairs with libpeering in-process: `LocalIdentity` keeps its root in a directory,
`PeeringService` (configured with no control endpoint) redeems the invite, and
`PeeringService::runtimeControlSession(peer, consumer)` returns the dial answer, the Hello
and a client credential made for that session alone.

## Configuration (the `peering_config` spawn key)

```json
{
  "name": "office-server",
  "shell": "logoscore",
  "control":  {"enabled": true, "host": "0.0.0.0", "port": 7443, "advertise": "192.168.1.5",
               "local_invite": {"path": "/home/me/.config/logoscore/peering/local-invite",
                                "allow": ["monerod_module"]}},
  "exports":  {"enabled": true, "ports": "7450-7499",
               "modules": {"monerod_module": {"events": true}}},
  "runtime_control": false,
  "announce": true,
  "browse":   true,
  "imports":  {"monerod_module": {"from": "<uuid>", "module": "monerod_module",
                                  "prefer": "remote", "version": "^0.1",
                                  "allowed_callers": ["monerod_ui"], "events": true}}
}
```

Unknown keys are errors. Entries given here are locked; the same kinds of entries made at
run time (`setExport`, `setImport`, `setPolicy`) persist in `peering_module`'s state.

A control endpoint that cannot listen (its port still held, say by the runtime's previous
process) does not fail the rest: `configure` answers `ok` with `control_error`,
`peering_module` tries again every second, and `status().control.error` says why meanwhile.

`control.local_invite` (`true`, or `{path, runtime_control, allow}`) keeps a single-use invite for a
same-user app on this machine in a 0600 file (default `<state>/local-invite`; the
`logoscore` daemon passes `<config dir>/peering/local-invite`), naming
`127.0.0.1`. It is redeemable over loopback only, and a new one replaces it once used or
expired (with `runtime_control`, which needs the top-level switch, 15 minutes at a time). `allow`
(module names, or `"*"` for every export) becomes the policy entry `"<uuid>/*"` of each
runtime that pairs through it; without it, pairing grants nothing, as elsewhere.

An import's `allowed_callers` may hold `"*"`: any local consumer may use it.

## Facades

`logos_host_remote --name <import>` hosts one facade, the local stand-in for an import. It
takes its credential on stdin like `logos_host_plain`, calls `peering_module` as the import
(`importDescriptor`, `issueCertificate("client")`, `requestRoute`, `renewRoute`,
`reportImportState`), serves the import's name to local consumers, and forwards each call
upstream on a session per consumer. A failed upstream call returns
`{"code":"dispatch_failed","message":"remote/<code>: …","origin":<import>}`.

The import's state follows the facade's own `runtime` session. It is `error` as soon as
that session's event stream is lost, or a route for it is refused (the reason is then the
peer's refusal), and `ready` again when the stream re-arms. Without shared events, a health
check every 15 s and each failed call keep it current.
