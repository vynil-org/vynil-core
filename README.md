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

The sixteen core helpers `new_bare` always registers come in three public, additive groups —
`core_pure_rhai_register`, `core_host_rhai_register`, `core_sleep_rhai_register` (plus
`fs_rhai_register` under `fs`) — so a consumer granting a script only part of them composes
those groups onto a plain `rhai::Engine::new` instead. Every public `*_rhai_register` also has a
`*_module()` twin registrable through `Engine::register_static_module` under a namespace of your
choosing, and under the optional `metadata` feature each registered function carries its
comment and parameter names for introspection. `cancel::CancelToken` + `cancel::scope` make the
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
| `metadata` | off | Rhai introspection metadata: `///` comments + parameter names on registered script functions, consumed by `gen_fn_signatures`/`gen_fn_metadata_to_json`. Implies `rhai` — metadata alone has no engine to register on. Pure metadata: registrations behave identically without it | `rhai/metadata` |
| `rt` | off | Async → sync bridge `rt::block_on` for consumers calling async code from synchronous Rhai natives (public; `http`, `oci`, `s3` and `k8s` depend on it). Does not imply `rhai` | `tokio` |

```toml
# default: Rhai + Handlebars + HTTP + crypto helpers, same as previous releases
vynil-core = "0.9"

# Kubernetes project
vynil-core = { version = "0.9", features = ["k8s"] }

# Handlebars only (e.g. rendering MCP tool output), no Rhai engine at all — and no rhai/smartstring
# in the graph either, since "hbs" alone doesn't pull in "hbs-scripting" (e.g. safe to combine
# with async-graphql, see the `hbs-scripting` row above)
vynil-core = { version = "0.9", default-features = false, features = ["hbs", "crypto"] }
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

## What it does NOT include

The vynil-specific layer stays in vynil: CRDs, `VynilContext`, `VynilPackage`, the instance
macros, the order-preserving `YamlDoc`, and the context-aware Handlebars helpers
(`selector_from_ctx`, `labels_from_ctx`, `image_from_ctx`, …). Consumers add their own on top of
the `Script`/`HandleBars` engines.

## License

BSD 3-Clause (same as vynil).
