# vynil-core

A Rust toolbox for bootstrapping projects that combine a **Rhai** scripting engine and a
**Handlebars** templating engine, with optional Kubernetes / OCI / S3 handlers.

`vynil-core` is the generic layer extracted from [vynil](https://github.com/vynil-org/vynil) so it
can be reused by other projects (kuberest, kydah, …) without pulling in vynil's business
abstractions (CRDs, package model, instance controllers).

> **Status:** extracted from the vynil workspace and published independently. The public API is
> not yet stable — expect breaking changes before 1.0.

## What it provides

- **Rhai engine** — `Script::new_bare(resolver_paths)` with the generic helpers (datetime, hashes,
  password, ed25519 keys, semver, glob, shell, serde-YAML, base64/json, file I/O).
- **Handlebars engine** — `HandleBars::new()` with the generic helpers (base64, bcrypt, argon,
  password, encoding, concat, plus the `handlebars_misc_helpers` set) and `engine_mut()` to extend it.
- **HTTP** — `RestClient` (reqwest) and its mock `RestClientMock`.

A plain `vynil-core = "x"` dependency (default features) gets all three, unchanged from previous
releases. Each is independently optional for a consumer that only needs one — see below.

The Rhai functions come in domain modules — `core` (no host authority), `host` (environment, logs,
and under `fs`/`shell` the disk and processes), `crypto`, `semver`, `password`, `oci`, `http`, `s3`,
`k8s` and `feeds` — each with a public, additive `X_rhai_register(engine)` registrar that `new_bare` calls
for the always-on modules, so a consumer granting a script only part of them composes those
registrars onto a plain `rhai::Engine::new` instead. Every registrar also has a `X_module()` twin
registrable through `Engine::register_static_module` under a namespace of your choosing, and under
the optional `metadata` feature each registered function carries its
comment and parameter names for introspection. The `prometheus` and `loki` connectors invert the
wiring: **the host configures, the script queries** — the host builds a configured `QueryClient`
and registers a module under a name of its choice, and the script never passes (or can reach) a
URL, tenant or token. `cancel::CancelToken` + `cancel::scope` make the
crate's blocking native calls (`sleep`, network waits) interruptable per thread, completing
`rhai::Engine::on_progress`. See [docs/rhai_helpers.md](docs/rhai_helpers.md).

## Features

| Feature | Default | Adds | Pulls in |
|---------|---------|------|----------|
| `rhai` | on | The Rhai scripting engine (`Script`) and every other module's Rhai bindings | `rhai` |
| `hbs` | on | The Handlebars templating engine (`HandleBars`) | `handlebars`, `handlebars_misc_helpers`, `jmespath`, `toml` |
| `hbs-scripting` | on | `register_helper_dir`/`rhai_register_helper_dir` (loading `*.rhai` files as Handlebars script helpers). Implies `hbs` and `rhai`. Split out because Handlebars's `script_helper` feature drags in its own `rhai` -> `smartstring`, whose orphan trait impl breaks `String + &String` resolution anywhere else in the build graph (e.g. `async-graphql`'s `export_sdl.rs`, see [bodil/smartstring#7](https://github.com/bodil/smartstring/issues/7)) — disable it to keep `hbs` free of `rhai`/`smartstring` entirely | `handlebars/script_helper` |
| `http` | on | `RestClient` (reqwest) + its mock. Implies `rhai` — `RestClient` stores its headers as a Rhai `Map` internally | `reqwest`, `schemars`, `tokio`, `rhai` |
| `crypto` | on | `argon_hash`/`bcrypt_hash`/`gen_private_key` (Handlebars "always" helpers) and the matching Rhai bindings | `openssl`, `argon2`, `bcrypt` |
| `k8s` | off | generic K8s handlers + their mocks. Implies `rhai` — `K8sGeneric` is a Rhai-facing API throughout | `kube`, `k8s-openapi`, `futures`, `tokio`, `rhai` |
| `oci` | off | `Registry` + OCI mock. Implies `rhai`, same reasoning as `k8s` | `oci-client`, `tokio`, `rhai` |
| `s3` | off | `S3` client. Implies `rhai`, same reasoning as `k8s` | `object_store`, `futures`, `tokio`, `rhai` |
| `fs` | off | Filesystem access from Rhai scripts | — |
| `shell` | off | Shell command execution | — |
| `password` | off | `gen_password`/`gen_password_alphanum` (off by default to avoid a name collision with a consumer's own password semantics) | — |
| `quantity` | off | Kubernetes `Quantity` parser: `cpu_millis_of` / `memory_bytes_of` (exact integer arithmetic). Their Rhai glue is in the `core` module and exists only when `rhai` is on too | — |
| `metadata` | off | Rhai introspection metadata: `///` comments + parameter names on registered script functions, consumed by `gen_fn_signatures`/`gen_fn_metadata_to_json`. Implies `rhai` — metadata alone has no engine to register on. Pure metadata: registrations behave identically without it | `rhai/metadata` |
| `rt` | off | Async → sync bridge `rt::block_on` for consumers calling async code from synchronous Rhai natives (public; `http`, `oci`, `s3` and `k8s` depend on it). Does not imply `rhai` | `tokio` |
| `feeds` | off | RSS/Atom feed reader — stateless `feed_read` and cursor-based `feed_poll`, plus their mock. Implies `http`, `rt` and `rhai` | `feed-rs` |
| `prometheus` | off | Read connector for Prometheus-compatible APIs (Prometheus, Mimir, Thanos, VictoriaMetrics): a host module — the host configures the client, the script only queries. Implies `rhai` through the internal `query_client` kernel | — |
| `loki` | off | Read connector for Loki: same host-module principle as `prometheus`, no shared code with it (the two features stay independent). Implies `rhai` through the internal `query_client` kernel | — |

`query_client` is a cargo feature that exists in `Cargo.toml` but is **internal**: it is the shared
read kernel (host-configured client, bounded streaming reads, typed errors) that `prometheus` and
`loki` are built on — `query_client = ["http", "rt", "rhai"]`. A consumer activates one of the two
connectors, which implies it; never it alone.

```toml
# default: Rhai + Handlebars + HTTP + crypto helpers, same as previous releases
vynil-core = "0.10"

# Kubernetes project
vynil-core = { version = "0.10", features = ["k8s"] }

# Handlebars only (e.g. rendering MCP tool output), no Rhai engine at all — and no rhai/smartstring
# in the graph either, since "hbs" alone doesn't pull in "hbs-scripting" (e.g. safe to combine
# with async-graphql, see the `hbs-scripting` row above)
vynil-core = { version = "0.10", default-features = false, features = ["hbs", "crypto"] }
```

## Client identity

`vynil-core` performs HTTP calls (and, with the `k8s` feature, Server-Side-Apply calls) on
behalf of the consuming application. It does not assume an identity for you — call
`vynil_core::set_client_name(...)` once at startup, before issuing any request:

```rust
vynil_core::set_client_name(|| "my-app.example.com".to_string());
```

Any `RestClient` or `k8s` call made before this is configured will panic with a message
explaining what to do.

## Minimal example

```rust
let mut script = vynil_core::Script::new_bare(vec!["scripts/".into()]);
script.engine.register_fn("my_fn", my_fn);          // register your own helpers
script.run_file(&std::path::PathBuf::from("scripts/run.rhai"))?;

let mut hbs = vynil_core::HandleBars::new();
hbs.engine_mut().register_helper("my_helper", Box::new(my_helper));
let output = hbs.render(template_str, &data)?;
```

## Rust API (async-first)

The protocol clients are also usable from Rust, without going through Rhai. Each one is async.
For `feeds`, `prometheus` and `loki`, the Rhai face is a synchronous projection of the same
client; the `s3` Rhai helpers are separate and only read (see `docs/rhai_helpers.md`):

- `feeds::FeedClient` (feature `feeds`): `read`, `poll`;
- `prometheus::PrometheusClient` and `loki::LokiClient` (features `prometheus`, `loki`);
- `s3::S3Store`, built from `s3::S3Config` (feature `s3`);
- `http::RestClient::http_get_async` (feature `http`).

The `object_store` and `bytes` crates are re-exported by the `s3` module
(`vynil_core::s3::object_store`, `vynil_core::s3::bytes`), so a consumer uses the exact versions
the crate was built with.

## What it does NOT include

The vynil-specific layer stays in vynil: CRDs, `VynilContext`, `VynilPackage`, the instance
macros, the order-preserving `YamlDoc`, and the context-aware Handlebars helpers
(`selector_from_ctx`, `labels_from_ctx`, `image_from_ctx`, …). Consumers add their own on top of
the `Script`/`HandleBars` engines.

## License

BSD 3-Clause (same as vynil).
