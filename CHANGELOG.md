# Changelog

All notable changes to `vynil-core` are documented here. The crate is pre-1.0: minor versions
may break the public API, and every breaking change is listed explicitly.

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
