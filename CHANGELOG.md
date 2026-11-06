# Changelog

All notable changes to `vynil-core` are documented here. The crate is pre-1.0: minor versions
may break the public API, and every breaking change is listed explicitly.

## 0.9.1

A consolidation of the 0.9.0 surface: the Rhai registrars are regrouped by domain into a
catalogue, and a few functions are added. No consumer of 0.9.0 existed, so the regrouping is
published as-is; the breaking changes are listed below.

### Added

- **`regex_is_match(pattern, text)`** in the `core` module: unanchored match with the syntax of
  the `regex` crate, linear-time. An invalid pattern is a script error.
- **Feature `quantity`** (off by default): `cpu_millis_of` (millicores) and `memory_bytes_of`
  (bytes), for Kubernetes resource quantities — the whole quantity grammar (sign, decimal and
  exponent forms, `n u m k M G T P E` and `Ki`…`Ei` suffixes). Rounding is away from zero; `()`
  is returned outside the grammar or on overflow. In Rust: `quantity::cpu_millis_of` and
  `quantity::memory_bytes_of`, returning `Option<i64>`.
- **`ReadMethod::Post`**: `RestClient::obj_read` can read with a `POST` with an empty body, on the
  same path and with the same headers as `Get`; the response is handled as for `Get`.
- **`json_subset(observed, wanted)` and `json_equal(observed, wanted)`** in the `http` module,
  for scripts and Rust. `json_subset` ignores extra keys in `observed`; `json_equal` is strict
  equality. Both compare typed values strictly (`1`, `1.0` and `"1"` differ).
- **Module catalogue**: nine public registrars `X_rhai_register(engine)` — `core`, `host`,
  `crypto`, `password`, `semver`, `http`, `oci`, `s3`, `k8s` — each with a `X_module()` twin
  for `Engine::register_static_module`. The twins share their registrar's list of functions.

### Changed

- The module catalogue replaces the 0.9.0 grouping. `Script::new_bare` calls the `core`, `host`,
  `crypto`, `semver` registrars, plus `password` (feature `password`) and `oci` (feature `oci`);
  the set of functions it registers under the global namespace is the same as in 0.9.0, plus
  `regex_is_match` and, under `quantity`, `cpu_millis_of` and `memory_bytes_of`. The registrars
  keep the 0.9.0 global names.
- Cancellation no longer polls. `sleep` and `rt::block_on` are woken directly by
  `CancelToken::cancel()`: the 25 ms slices are gone. A consumer's runtime does not need
  `enable_all()` or `enable_time()` any more, and the "timers are disabled" panic is gone. The
  error is still `Error::Cancelled` (`CANCEL-001 operation cancelled`).
- Dependencies, with no change to the public API: `serde_yaml` 0.9 is replaced by `yaml_serde`
  0.10 (imported under the old alias); the `sha256` crate is replaced by `sha2` 0.11 and `hex`,
  with the same digest; `tar` and `flate2` are compiled only under `oci`; `regex` only under
  `rhai`; the duplicated `cpufeatures` is gone. Rhai's default features are kept.

### Breaking changes

- **Removed registrars and twins** (0.9.0 names, no consumer known): `engine::core_pure_rhai_register`,
  `core_host_rhai_register`, `core_sleep_rhai_register`, `fs_rhai_register`, `chrono_rhai_register`,
  `glob_rhai_register`, `yaml_rhai_register`, `shell_rhai_register`, `hashes_rhai_register`,
  `crypto_hashes_rhai_register`, `key_rhai_register`, `k8sgeneric_rhai_register`,
  `k8sraw_rhai_register`, `k8sworkload_rhai_register`, and their `*_module()` twins. Their
  functions are in `core`, `host`, `crypto` and `k8s`. `k8s` is registered by the single
  `k8s::k8s_rhai_register` / `k8s::k8s_module`.
- **Twin names**: the free functions of the twins are qualified only, and some are shortened
  (`semver::from`, `password::gen`, `password::gen_alphanum`, `http::new_client`,
  `http::get_yaml`, `s3::get_yaml`, `s3::list_keys`, `k8s::resource`, `k8s::new_raw`,
  `k8s::update_crd_cache`). The registrars keep the 0.9.0 global names.
- **`ReadMethod`** gains a variant, `Post`. It is not `#[non_exhaustive]`: a `match` on it without a
  wildcard arm stops compiling until the arm is added.

## 0.9.0

The composable-engine release (issues #18–#22): the always-registered core helpers are now
three public groups you can pick from, every public registrar gained a module twin, script
functions carry introspection metadata, and the blocking native calls became cancellable.

### Added

- **Public core groups** (#18): the sixteen common helpers are split into three public,
  additive registrars — `engine::core_pure_rhai_register` (`sha256`, `url_encode`,
  `to_decimal`, `base64_*`, `json_*`, `basename`, `dirname`), `engine::core_host_rhai_register`
  (`get_env`, `log_debug`/`log_info`/`log_warn`/`log_error`) and `engine::core_sleep_rhai_register`
  (`sleep`) — callable in any order on a bare `rhai::Engine::new`; `engine::fs_rhai_register`
  (feature `fs`) joins them as the public filesystem group. `Script::new_bare` registers all
  of them exactly as before.
- **Module twins** (#19): every public `*_rhai_register` has a `*_module() -> rhai::Module`
  twin with the same names and semantics, registrable through `Engine::register_static_module`
  under a name of the consumer's choosing — the four engine groups, plus `chrono`, `glob`,
  `semver`, `yaml`, `hashes`/`crypto_hashes`, `password`, `key`, `shell`, `http`, `oci`, `s3`
  and the three `k8s` sub-registrars. The test-double registrars have no twin by design.
- **Feature `metadata`** (#22): off by default, implies `rhai`. Under it, each registered
  script function carries its `///` comment and its parameter names through
  `rhai::FuncRegistration`, surfaced by `Engine::gen_fn_signatures` and
  `Engine::gen_fn_metadata_to_json` (`docComments`, named `params`, return type in script vocabulary). Registrations behave
  identically without it — documentation is pure metadata.
- **Cancellation** (#21): `cancel::CancelToken` + `cancel::scope` — a thread-local token the
  crate's blocking native calls read, completing `Engine::on_progress` (which only gets the
  hand between two script operations, never inside a native call).
- **Feature `rt`** (#23): off by default, pulls `tokio` only and does not imply `rhai`. Under
  it, the async → sync bridge `rt::block_on` is public (`vynil_core::rt::block_on`, same
  signature, same strategies and cancellation as before) for consumers that call async code
  from synchronous Rhai native functions: a multi-thread runtime is blocked on in place, a
  runtime-less thread gets a temporary `current_thread` runtime, a `current_thread` runtime
  gets an explicit error. `http`, `oci`, `s3` and `k8s` now depend on `rt` instead of `tokio`.
- **`Error::Cancelled`** (#28): a unit variant, ungated, displayed `CANCEL-001 operation
  cancelled`. `CANCEL-001` is a stable searchable identifier, frozen in the format like
  `KEY-ALGO-001` and `KEY-OPENSSL-001`. Match on the variant rather than on the text.

### Changed

- `sleep` and the async → sync bridge `rt::block_on` (used by `http`, `oci`, `s3` and `k8s`)
  now honour the thread's cancel token: they wait in 25 ms slices and return
  `Error::Cancelled` (`CANCEL-001 operation cancelled`) as soon as the token is cancelled (the
  pending future is dropped, not left running). Without an open scope the behaviour is
  unchanged. Previously the error was `Error::Other` of text `cancelled`.
- `cancel` is compiled without any feature (#23): `cancel::CancelToken` and `cancel::scope`
  are available under `--no-default-features`, as is the token read by `rt::block_on`. Only
  `sleep` stays behind `rhai`.
- The `rhai` dependency floor is raised to `1.23.3` — the oldest version exposing
  `FuncRegistration::with_comments` / `with_params_info`, verified by compiling against it.
- `HandleBars::new_restricted()` is now built from an allow-list (only helpers that cannot reach
  the host are registered) instead of removing six helpers from `new()`: a host helper added
  upstream, such as `http_get` / `gitignore_io`, is never registered. The registered set is
  unchanged, and consumers no longer need an exclusion list of their own (#27).

No behaviour change for consumers that only call `Script::new_bare` (vynil, kuberest): the
same names with the same semantics are registered, and the frozen order of the new public
groups (pure, host, waiting) is what `new_bare` always applied.

## 0.8.0

First release since `0.7.7`. Mostly a hardening release: the code base was reviewed module by
module against a written contract (`*.sdd` specs), every documented behaviour now has a test,
and the strict clippy harness (`pedantic`, `cargo`, no `unwrap`/`expect`/`panic`) is enforced
on every feature combination.

### Added

- `HandleBars::new_restricted()`: same engine as `HandleBars::new()` without the helpers that
  touch the host (`read_to_str`, `env_var`, `canonicalize`, `parent`, `file_name`,
  `extension`). Intended for templates fed by untrusted data (#13).

### Breaking changes

- **bcrypt**: `bcrypt_hash` (Rust, Rhai and the Handlebars helper) now refuses inputs of
  72 bytes or more instead of silently truncating them; the longest accepted input is 71
  bytes. The Handlebars helper renders an empty string on refusal, after a `warn`.
- **TLS**: `reqwest` and `oci-client` now use rustls only (`native-tls` is gone from the
  `http`, `oci`, `s3` and `k8s` graphs; OpenSSL is confined to the `crypto` feature). An
  invalid CA PEM is still an error at client construction.
- **Argon**: `Argon::new()` is fallible (`Result<Self>`) and `Default for Argon` is removed;
  entropy failures are reported instead of panicking.
- **k8s**: `K8sGeneric::new` and `new_api_version` return `crate::Result<Self>`; the three
  Rhai `k8s_resource` constructors return a Rhai error instead of panicking. An empty
  namespace is now treated as absent.
- **chrono**: `format` returns `crate::Result<String>` (Rhai: a script error) instead of
  panicking on an invalid pattern.
- **hbs**: the `core_helpers::*` structs are no longer public (`CORE_HBS_HELPERS` stays).
- **hbs_json**: `sort_toml_map` is removed.
- **yaml**: `yaml_decode_multi` no longer ignores documents of 5 characters or fewer; an empty
  document decodes to the unit value.
- **Error values**: `Error::UnsupportedKeyAlgorithm` carries the algorithm with its original
  case; `oci` errors are typed (missing push digest, scalar-only annotations, `cosign` not
  found, malformed docker auth).

### Fixed

- `gen_password`/`generate` refuse lengths above 4096 and no longer overflow on the sum of the
  class minima (a panic could cross the Rhai boundary).
- `semver` mutators clear build metadata; the manual comparator ignores the cosmetic `v`
  prefix consistently for equality, ordering and hashing.
- `http`: header names are case-insensitive in `add_header`, `http_get_yaml` is faithful to
  its input, a real `HEAD` is issued, `rhai_*` failures are hard errors.
- `oci`: `list_tags` is paginated (pages of 1000).
- `k8s`: `ownerReferences` are de-duplicated by `uid` only, the discovery warning states the
  real 60 s timeout.

### Internal

- The `http`, `oci`, `k8s` and `s3` handlers share one private panic-free async → sync
  bridge instead of ad-hoc `block_in_place` calls.

### Tooling

- CI matrix now covers `crypto`, `rhai`, `hbs,crypto`, `rhai,shell`, `rhai,fs`,
  `rhai,password` and `cargo hack --each-feature`; rustdoc lints are a gate.
- Toolchain pinned to stable 1.99.0.

### Not in this release

Dependabot bumps of `oci-client` (0.18), `object_store` (0.14), `toml` (1.x), `kube` (4.x) and
`k8s-openapi` (0.28) are deferred to the next release.
