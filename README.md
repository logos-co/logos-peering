# logos-peering

Module calls between Logos runtimes. A module on one runtime (a Basecamp, a
`logosctl` daemon) calls a module on another as it calls a local one. The two
runtimes pair once, the providing side exports the module, and the consuming
side imports it. Every call between them is a module call over `tls_tcp`
(mutual TLS 1.3, pinned keys, one-shot route tickets), from logos-protocol 0.14.

## What is here

| Path | What |
|---|---|
| `lib/` | **libpeering**, Qt-free: runtime identity and role certificates, pairing (6-digit code or invite), enrollments, the peering service (control endpoint, routes, tickets, policy), and the facade that stands in for an import |
| `modules/peering_identity` | Bundled module holding the runtime's UUID and root key. It answers only `peering_module` |
| `modules/peering_module` | Bundled module for pairing, exports, imports and route tickets. Its second provider, `peering_control`, is the endpoint other runtimes call |
| `host/logos_host_remote.cpp` | The host process for one facade, started by the runtime for a `peer-facade` module record |
| `docs/api.md` | The contract: methods, callers, events and the `peering_config` document |

The runtime side lives elsewhere:

- logos-liblogos loads the two modules, turns imports into facade records and gives exported modules a `tls_tcp` listener.
- logos-module-loader-qt hosts facades and exported modules.
- logos-logoscore-cli adds `logosctl peer …` and the daemon's `peering:` section.

## Build and test

```bash
nix build .#libpeering          # runs the unit tests (two services pair and route over real TLS)
nix build .#peering_identity .#peering_module .#logos_host_remote
```

For a local build: `nix develop`, then `cmake -S . -B build -G Ninja && ninja -C build && build/logos_peering_tests`.

## Using it

On the providing runtime:

```yaml
peering:
  name: office
  control: { enabled: true, host: 0.0.0.0, port: 7443 }
  exports: { enabled: true, modules: { monerod_module: { events: true } } }
```

On the consuming runtime, first pair with the provider. Either run
`logosctl peer pair HOST PORT` and compare the codes on both screens, or redeem
an invite with `logosctl peer redeem FILE`. On one machine, the provider's
`control.local_invite` file does this with no code. Then:

```bash
logosctl peer import monerod_module --from office --allow monerod_ui
```

The providing side decides which of the consumer's modules may call what, with
`logosctl peer policy set FILE`. It holds `{"<runtime id>/<consumer>": ["module"]}`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE-v2) or
[MIT license](LICENSE-MIT) at your option.
