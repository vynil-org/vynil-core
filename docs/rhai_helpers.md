# Rhai helpers

Reference for every Rhai function, type, and method `vynil-core` registers into a
[`rhai::Engine`](https://rhai.rs). For the Handlebars side see [handlebars_helpers.md](handlebars_helpers.md);
for the test doubles that mirror the network/cluster-facing APIs below, see [mocking.md](mocking.md).

## Cargo feature required

Everything in this document — the Rhai engine itself (`Script`, `engine.rs`) included — lives
behind the `rhai` Cargo feature. It's on by default, so nothing below changes for an existing
`vynil-core = "x"` dependency; it only matters if a consumer opts out with
`default-features = false` to get a Rhai-free build (e.g. Handlebars-only — see
[handlebars_helpers.md](handlebars_helpers.md)).

## How registration works

`vynil_core::engine::Script::new_bare(resolver_paths)` builds an `Engine` and auto-registers a
fixed set of modules. Not everything below is wired in automatically — three different tiers:

| Tier | Modules | Wired in by `Script::new_bare` |
|---|---|---|
| Always (given `rhai`) | core utilities, `chrono`, `hashes` (crc32 only), `semver`, `yaml`, `glob` | Yes, unconditionally |
| Cargo-feature-gated, auto-wired | `fs`, `password`, `crypto` (`hashes`'s bcrypt/argon + `key`), `oci`, `shell` | Yes, when the matching Cargo feature is enabled |
| Never auto-wired | `http`, `k8s` (all three sub-modules), `s3` | **No** — call the `*_rhai_register` function yourself on `script.engine` |

The third tier is opt-in regardless of Cargo features — `http`/`k8s`/`s3` each pull in `rhai`
themselves (their core types are built as Rhai-facing APIs, not a plain-Rust API with a Rhai
wrapper on top), so enabling one of those three features is enough to make the type available;
it's registration into a *given* `Engine` that stays a manual call. This crate never assumes a
consumer wants live network or cluster access baked into every script engine, so those are opt-in
calls:

```rust
let mut script = vynil_core::Script::new_bare(vec!["scripts/".into()]);
vynil_core::http::http_rhai_register(&mut script.engine);
#[cfg(feature = "k8s")]
{
    vynil_core::k8s::k8sgeneric_rhai_register(&mut script.engine);
    vynil_core::k8s::k8sraw_rhai_register(&mut script.engine);
    vynil_core::k8s::k8sworkload_rhai_register(&mut script.engine);
}
#[cfg(feature = "s3")]
vynil_core::s3::s3_rhai_register(&mut script.engine);
```

`k8s` additionally needs runtime context before any script can use it — see the "Feature `k8s`"
section further down in this document.

### Why this tier is opt-in

Beyond just avoiding unwanted network/cluster access by default, leaving `http`/`k8s`/`s3` out of
`new_bare` is what makes them mockable at the call site instead of at the crate level. Mock
modules ship for `http`, `k8s` and `oci` (`http_mock`, `k8s_mock`, `oci_mock` — see
[mocking.md](mocking.md)); `s3` is deliberately the one network-facing module without a Rhai mock,
tested through `object_store`'s in-memory store instead. Each mock registers (mostly) the same
Rhai type and function names (`RestClient`, `K8sGeneric`, …) against fixture data or fixed canned
values instead of a live endpoint, and none of them is wired in by `Script::new_bare` — even
`oci`, whose *real* registration is auto-wired when its feature is on, keeps its mock manual.
Because registration is an explicit call rather than something baked into `Script::new_bare`, a
consumer can build two engines from the very same `.rhai` script source — one wired to the real
`*_rhai_register` for production, one wired to the matching `*_mock_rhai_register` for a unit
test — and run that script against both without touching a real cluster, registry, or HTTP
endpoint in the test. If registration were automatic, that swap wouldn't be possible without
threading a runtime flag through `Script::new_bare` itself.

### Static module twins (`*_module`)

Every public `X_rhai_register` has a twin `X_module() -> rhai::Module`: the same function names,
the same semantics, defined once and shared by both paths (a twin that drifts from its registrar
is a defect). The twin is registered through `Engine::register_static_module` under whatever
namespace the consumer picks:

```rust
script.engine.register_static_module("net", vynil_core::http::http_module());
// script: net::get("…")
```

This is the alternative registration path, not a replacement: the registrar keeps putting its
functions directly on the engine, exactly as before, so `Engine::gen_fn_signatures` still lists
them the same way. The module path is what lets introspection and per-agent filtering attribute
functions to their group by namespace instead of comparing before/after signatures. The three
test-double registrars (`httpmock_rhai_register`, `oci_mock_rhai_register`,
`k8s_mock_rhai_register`) have no twin — by decision: `http` and `k8s` take fixtures as
parameters, `oci` is a constant double without fixtures, and none has a per-group consumer.

| Registrar | Module twin |
|---|---|
| `engine::core_pure_rhai_register` | `engine::core_pure_module` |
| `engine::core_host_rhai_register` | `engine::core_host_module` |
| `engine::core_sleep_rhai_register` | `engine::core_sleep_module` |
| `engine::fs_rhai_register` *(feature `fs`)* | `engine::fs_module` |
| `chrono::chrono_rhai_register` | `chrono::chrono_module` |
| `hashes::hashes_rhai_register` | `hashes::hashes_module` |
| `hashes::crypto_hashes_rhai_register` *(feature `crypto`)* | `hashes::crypto_hashes_module` |
| `key::key_rhai_register` *(feature `crypto`)* | `key::key_module` |
| `password::password_rhai_register` *(feature `password`)* | `password::password_module` |
| `semver::semver_rhai_register` | `semver::semver_module` |
| `yaml::yaml_rhai_register` | `yaml::yaml_module` |
| `glob::glob_rhai_register` | `glob::glob_module` |
| `shell::shell_rhai_register` *(feature `shell`)* | `shell::shell_module` |
| `http::http_rhai_register` *(feature `http`)* | `http::http_module` |
| `oci::oci_rhai_register` *(feature `oci`)* | `oci::oci_module` |
| `s3::s3_rhai_register` *(feature `s3`)* | `s3::s3_module` |
| `k8s::k8sgeneric_rhai_register` *(feature `k8s`)* | `k8s::k8sgeneric_module` |
| `k8s::k8sraw_rhai_register` *(feature `k8s`)* | `k8s::k8sraw_module` |
| `k8s::k8sworkload_rhai_register` *(feature `k8s`)* | `k8s::k8sworkload_module` |

### Introspection metadata (feature `metadata`)

Under the `metadata` cargo feature (off by default, implies `rhai` — see the table below),
every registered script function carries its `///` comment and the *name* of each of its
parameters through `rhai::FuncRegistration`. What that gives an introspecting consumer:
`Engine::gen_fn_signatures` lists functions with named parameters — `json_encode(value:
Dynamic)`, not `json_encode(Dynamic)` — and `Engine::gen_fn_metadata_to_json` reports, per
function, a `docComments` array and named `params`. Without the feature the behaviour is
identical: the documentation is pure metadata, with no second copy of the registrations.

## Cargo feature reference

| Feature | Unlocks | Auto-wired into `new_bare`? |
|---|---|---|
| `rhai` *(default)* | this entire document — core utilities, chrono, hashes' `crc32_hash`, semver, yaml, glob | always |
| `fs` | filesystem access (`file_read`, …) | yes |
| `password` | `gen_password`, `gen_password_alphanum` | yes |
| `crypto` *(default)* | hashes' `bcrypt_hash`/`Argon`, `key`'s `gen_private_key` | yes |
| `shell` | `shell_run`, `shell_output` | yes |
| `oci` *(implies `rhai`)* | `Registry` OCI client | yes |
| `k8s` *(implies `rhai`)* | `DynamicObject`, `K8sObject`, `K8sGeneric`, `K8sRaw`, `K8sDeploy`, `K8sDaemonSet`, `K8sStatefulSet`, `K8sJob` | **no** — manual |
| `http` *(default, implies `rhai`)* | `RestClient` (HTTP) | **no** — manual |
| `s3` *(implies `rhai`)* | `s3_get_yaml`, `s3_list_keys` | **no** — manual |
| `metadata` *(implies `rhai`)* | introspection metadata on registered script functions — `///` comments + parameter names (`gen_fn_signatures`, `gen_fn_metadata_to_json`, see above) | n/a — pure metadata, registers nothing of its own |

---

## 1. Core utilities (always available)

Sixteen names, always present under `rhai`, split into three public, additive groups —
`core_pure_rhai_register`, `core_host_rhai_register` and `core_sleep_rhai_register`
(`engine.rs`). `Script::new_bare` calls all three, in that order; a consumer that wants to
grant a script only part of them builds a plain `rhai::Engine::new` and calls just the group
registrars it grants — each is additive, idempotent under repeated calls, and registers
nothing outside its own names. The fourth public group registrar, `fs_rhai_register`, is
gated by the `fs` cargo feature and covered in section 8.

### Pure group — `core_pure_rhai_register`

Computes on its arguments alone and grants no host access (`basename`/`dirname` split a
string, they never touch the disk).

| Signature | Returns | Notes |
|---|---|---|
| `sha256(text: string)` | `string` | Hex digest |
| `url_encode(text: string)` | `string` | Percent-encodes for use in a query string |
| `to_decimal(octal: string)` | `int` | Parses the string as base-8; any non-octal string raises a Rhai error — never a `0` indistinguishable from the legitimate `0` |
| `base64_encode(text: string)` | `string` | Standard base64 |
| `base64_decode(text: string)` | `string` | Errors if the input isn't valid base64/UTF-8 |
| `json_encode(value)` | `string` | Serializes any Rhai value to JSON |
| `json_encode_escape(value)` | `string` | Same, then wraps the result in a second layer of JSON-string escaping (`format!("{:?}", …)`) — for embedding JSON inside JSON |
| `json_decode(text: string)` | dynamic | Errors on invalid JSON |
| `basename(path: string)` | `string` | |
| `dirname(path: string)` | `string` | |

### Host group — `core_host_rhai_register`

What a script reads from the process environment and writes into its logs.

| Signature | Returns | Notes |
|---|---|---|
| `get_env(name: string)` | `string` | Empty string if unset (defaults are a use case); errors if the variable exists but isn't UTF-8 |
| `log_debug(text: string)` / `log_info` / `log_warn` / `log_error` | `()` | Forwards to `tracing` |

### Waiting group — `core_sleep_rhai_register`

`sleep` grants no authority over anything (it blocks; it reads and writes nothing), so it
travels on its own and not with the host group.

| Signature | Returns | Notes |
|---|---|---|
| `sleep(seconds: int)` | `()` | Blocks the current thread for `seconds`; a non-positive value returns immediately. Under an open cancellation scope it sleeps in 25 ms slices and raises `cancelled` (section 15). For hand-rolled poll loops (`get` + check + `sleep`) when `<K8sObject>.wait_for` doesn't fit |

### Script-level helpers (`add_common`)

Also always present — these are Rhai source injected via `add_code`, not native functions:

| Signature | Behavior |
|---|---|
| `assert(cond, message)` | Throws `message` if `cond` is falsy |
| `import_run(name, instance, context, args)` / `import_run(name, instance, context)` / `import_run(name, args)` | `import`s the module `name` and calls its `run(...)` function with the matching arity. If the module or the function doesn't exist, logs a debug message and returns instead of throwing; any other error is rethrown. |
| `import_template(name, instance, context, args)` / `import_template(name, instance, context)` / `import_template(name, args)` | Same as `import_run`, but calls `template(...)` first, falling back to `run(...)` if the module has no `template` function |

The shims' skip path calls `log_debug`, which belongs to the **host** group: on an engine
hand-built without `core_host_rhai_register`, `import_run`/`import_template` fail on that
path with unknown function `log_debug` (documented on `add_common`). Grant the host group
before calling `add_common` — that also gives you `get_env`; if you want `log_debug` without
`get_env`, register a `log_debug` yourself before `add_common`.

---

## 2. `chrono`

| Signature | Returns | Notes |
|---|---|---|
| `date_now()` | `DateTimeHandler` | Current local time |
| `<DateTimeHandler>.format(fmt: string)` | `string` | `fmt` is a [chrono strftime pattern](https://docs.rs/chrono/latest/chrono/format/strftime/index.html) |

## 3. `hashes`

`crc32_hash` needs only `rhai`. The other three need `crypto` too (default on, like `rhai`).

| Signature | Returns | Notes |
|---|---|---|
| `crc32_hash(text: string)` | `int` | CRC-32 |
| `bcrypt_hash(text: string)` | `string` | bcrypt, `DEFAULT_COST` — needs `crypto`. Inputs of `72` bytes or more are rejected with a Rhai error rather than silently truncated: the accepted ceiling is `71` bytes (`71` passes, `72` is the first refusal) |
| `new_argon()` | `Argon` | Generates a fresh random salt for this instance — needs `crypto` |
| `<Argon>.hash(password: string)` | `string` | Argon2 PHC string (salt + hash), using the salt captured at `new_argon()` time — needs `crypto` |

## 4. `key`

Needs `crypto` (default on, like `rhai`) in addition to `rhai` — the whole module is gated by it.

| Signature | Returns | Notes |
|---|---|---|
| `gen_private_key(algo: string)` | `string` | PKCS8 PEM. `algo`: `"rsa"` (4096 bits) or `"ed25519"` (bit count ignored) |
| `gen_private_key(algo: string, bits: int)` | `string` | Same, explicit RSA bit size |

## 5. `semver`

| Signature | Returns | Notes |
|---|---|---|
| `semver_from(text: string)` | `Semver` | Accepts an optional leading `v`, which is remembered and reproduced by `to_string` |
| `<Semver>.inc_major()` | `()` | Bumps major, resets minor/patch, clears prerelease and build metadata |
| `<Semver>.inc_minor()` | `()` | Bumps minor, resets patch, clears prerelease and build metadata |
| `<Semver>.inc_patch()` | `()` | Bumps patch and clears build metadata — unless already on a prerelease, in which case it clears the prerelease tag and build metadata without bumping patch |
| `<Semver>.inc_beta()` | `()` | From stable: bumps patch and sets `beta.1`. From `beta.N`: increments `N` (patch unchanged). Any other prerelease — a bare `beta`, a foreign label, or `alpha.N` — counts as non-beta: patch bumped, counter reset to `1`. Clears build metadata on success |
| `<Semver>.inc_alpha()` | `()` | Same as `inc_beta`, mirrored for `alpha.N`: the counter advances; a bare `alpha`, a foreign label, or `beta.N` count as non-alpha — patch bumped, `alpha.1` set. Build metadata cleared on success |
| `a == b`, `a != b`, `a < b`, `a > b`, `a <= b`, `a >= b` | `bool` | Standard semver ordering (prerelease < stable). All six take two `Semver` operands — no mixed coercion (`"1.2.3" < semver_from("4.5.6")` fails as an unknown function) and no `<=>`; wrap each operand in `semver_from` |
| `to_string(sv)` | `string` | |

## 6. `yaml`

| Signature | Returns | Notes |
|---|---|---|
| `yaml_encode(value)` | `string` | |
| `yaml_decode(text: string)` | dynamic | |
| `yaml_decode_multi(text: string)` | `array` of dynamic | One element per YAML document, short inputs included. Empty, comment-only and null (`~`) documents yield unit values, never an error. |

## 7. `glob`

| Signature | Returns | Notes |
|---|---|---|
| `glob(text: string, pattern: string)` | `bool` | Shell-style wildcard match (`wildmatch` — `*` and `?`) |

---

## 8. Feature `fs` — filesystem access

Gated at the function-definition level (`fs_rhai_register` only exists in the binary when this
feature is on), auto-wired into `new_bare`.

> Off by default deliberately: a consumer embedding untrusted or multi-tenant scripts may not
> want to grant filesystem access on the host running them.

| Signature | Returns |
|---|---|
| `file_read(path: string)` | `string` |
| `file_write(path: string, content: string)` | `()` |
| `file_copy(source: string, dest: string)` | `()` |
| `create_dir(path: string)` | `()` — recursive (`create_dir_all`) |
| `read_dir(path: string)` | `array` of path strings |
| `is_file(path: string)` | `bool` |
| `is_dir(path: string)` | `bool` |

## 9. Feature `password`

Off by default so consumers with their own password-generation semantics (e.g. a weight-based
one exposed through a public API) don't get a name collision. Auto-wired when enabled.

| Signature | Returns | Notes |
|---|---|---|
| `gen_password(len: int)` | `string` | At least 1 lowercase, 1 uppercase, 1 digit, 1 symbol |
| `gen_password(len: int, spec: map)` | `string` | `spec` keys `lower`/`upper`/`digits`/`symbols` set the **minimum** count per class (default `1` for an omitted key; a negative value counts as `0` — that class is excluded) |
| `gen_password_alphanum(len: int)` | `string` | Same as `gen_password(len)` but 0 symbols |

Errors (Rhai exception) if the sum of class minimums exceeds `len`, or if every class is
disabled. Symbol set is shell/quoting-safe: `! # % * + - . : = ? @ _`.

## 10. Feature `shell`

| Signature | Returns | Notes |
|---|---|---|
| `shell_run(command: string)` | `int` | Runs via `sh -c`; stdout/stderr are inherited (go straight to the process's own streams); returns the exit code — `128 + signal` when killed by a signal on unix, `-1` when neither is available |
| `shell_output(command: string)` | `string` | Runs via `sh -c`, captures stdout; **errors** if the exit code is non-zero *or* if anything was written to stderr (even on exit 0); the failure message carries that same verdict as `rc=<n>` |

Command execution carries risk: there is no whitelist, no timeout and no sandbox — the
cargo opt-in on the `shell` feature is the only guard. Unix-only by assumption: `sh` is
hard-coded and there is no windows branch.

## 11. Feature `oci` (auto-wired)

`Registry` — a client for an OCI/Docker registry, backed by `oci-client`.

| Signature | Returns | Notes |
|---|---|---|
| `new_registry(registry: string, username: string, password: string)` | `Registry` | Anonymous auth if either credential is empty |
| `<Registry>.push_image(source_dir: string, repository: string, tag: string, annotations: map)` | `string` (digest) | Tars + gzips `source_dir` as a single layer and pushes an OCI image manifest |
| `<Registry>.sign_image(repository: string, tag: string, digest: string, key_path: string)` | `()` | No-op if `key_path` is empty; otherwise shells out to the `cosign` binary |
| `<Registry>.list_tags(repository: string)` | `array` of strings | |
| `<Registry>.get_manifest(repository: string, tag: string)` | dynamic | |

Standalone:

| Signature | Returns | Notes |
|---|---|---|
| `get_auth_from_file(path: string, registry: string)` | `map` `{user, pass}` | Reads a Docker `config.json`-style file; empty strings if the registry/entry isn't found |

### Plain Rust API (not registered in Rhai)

Beyond the script surface above, `oci` exposes public Rust faces that are **not** registered into
the engine — the `list_tags` a script calls is a sync bridge over the async Rust function below.
These faces are adopted as durable API (decision on record):

| Function | Needs | Returns |
|---|---|---|
| `Registry::pull_image(dest_dir, repository, tag)` | `oci` | `crate::Result<()>` — pulls and unpacks the image's gzip layers under `dest_dir`; plain `Result`, not a Rhai error type |
| `Registry::list_tags(repository)` — `async` | `oci` | `crate::Result<Vec<String>>` — all the tags of the repository, paged to exhaustion in pages of `1000` (`last` = last tag received), in registry order, unsorted; more than `10000` tags is refused with `Error::Other` |
| `verify_tag_in_registry(registry, image, tag, auth)` — `async` | `oci` | `crate::Result<bool>` — `true` when the manifest exists, `false` on a not-found answer, `Err` on anything else |
| `resolve_registry_auth(secret_name, registry, client, ns)` — `async` | `oci` **and** `k8s` | `crate::Result<OciRegistryAuth>` — reads a dockerconfigjson `Secret` through a caller-supplied `kube::Client`; any missing entry → `Anonymous`; malformed data (invalid base64 / non-UTF-8 / a decoded value without a `:`) → a typed error, never a fallback |

`OciRegistryAuth` is `oci_client::secrets::RegistryAuth`, re-exported by `vynil_core::oci`.

---

## 12. HTTP client — `http::http_rhai_register` (call manually)

Gated by the `http` Cargo feature (on by default; it implies `rhai`, and `reqwest` is an
optional dependency of this crate), but it is **not** called by `Script::new_bare` — register
it yourself:

```rust
vynil_core::http::http_rhai_register(&mut script.engine);
```

`RestClient` — a reqwest-backed client with optional server CA / mTLS identity.

| Signature | Notes |
|---|---|
| `new_http_client(baseurl: string)` / `new_client(baseurl: string)` | Both construct a `RestClient` |
| `<RestClient>.set_baseurl(base: string)` | |
| `<RestClient>.set_server_ca(pem: string)` | Enables rustls + custom root CA |
| `<RestClient>.set_mtls_cert_key(cert_pem: string, key_pem: string)` | Client identity for mTLS |
| `<RestClient>.headers_reset()` | Clears all headers |
| `<RestClient>.add_header(key: string, value: string)` | |
| `<RestClient>.add_header_json()` | Adds `Content-Type: application/json; charset=utf-8` and `Accept: application/json`, only if not already set |
| `<RestClient>.add_header_bearer(token: string)` | Sets `Authorization: Bearer <token>` |
| `<RestClient>.add_header_basic(username: string, password: string)` | Sets `Authorization: Basic <base64>` |

Request methods — each pair (`x` / `http_x`) is the same function registered under two names:

| Signature | Returns |
|---|---|
| `.head(path)` | `map` `{code, headers}` |
| `.get(path)` / `.http_get(path)` | `map` `{code, headers, body, json}` |
| `.post(path, body)` / `.http_post(path, body)` | `map` `{code, headers, body, json}` |
| `.put(path, body)` / `.http_put(path, body)` | same |
| `.patch(path, body)` / `.http_patch(path, body)` | same |
| `.delete(path)` / `.http_delete(path)` | same |
| `.delete_with_body(path, body)` / `.http_delete_with_body(path, body)` | same |
| `.post_form(path, params: map)` | same — sends `params` as `application/x-www-form-urlencoded`, and drops any `Content-Type` header you'd set manually so the form encoder can set its own |

`body` for `post`/`put`/`patch`/`delete_with_body` may be a Rhai string (sent verbatim) or any
other value (JSON-serialized).

> **Status codes are never treated as errors.** These methods only raise a Rhai exception on a
> transport-level failure (DNS, TLS, connection refused, …). A 404 or 500 comes back as a normal
> `Ok` result with `code` set accordingly — check `.code` yourself. This differs from the plain
> Rust API (`body_get`/`json_get`/…), which does return an `Err` on non-2xx.

Standalone functions:

| Signature | Returns | Notes |
|---|---|---|
| `http_get_yaml(url: string, auth_type: string, credential: string)` | dynamic | One-shot GET-and-parse-as-YAML, own client (not tied to a `RestClient`). `auth_type`: `""`, `"bearer"`, or `"basic"` (in which case `credential` is `"user:pass"`, base64-encoded for you). Errors on non-2xx. |
| `headers_get(headers: array, name: string)` | value or `()` | Case-insensitive lookup into the opaque `headers` array returned as part of a request result (it has no Rhai-visible indexing/iteration of its own) |
| `headers_has(headers: array, name: string)` | `bool` | Case-insensitive presence check |

---

## 13. Feature `k8s` — `k8sgeneric_rhai_register`, `k8sraw_rhai_register`, `k8sworkload_rhai_register` (call manually)

Not auto-wired even with the feature on — register the pieces you need:

```rust
vynil_core::k8s::k8sgeneric_rhai_register(&mut script.engine);
vynil_core::k8s::k8sraw_rhai_register(&mut script.engine);
vynil_core::k8s::k8sworkload_rhai_register(&mut script.engine);
```

### Runtime context (required before any call)

Unlike everything else in this document, the `k8s` module needs process-wide context injected
once at startup, *before* any script runs — these are `OnceLock`s, not part of the `Engine`:

| Function | Purpose |
|---|---|
| `vynil_core::set_client_name(f)` | Identity used as the Server-Side-Apply field manager (and the HTTP User-Agent) |
| `vynil_core::k8s::set_get_client(f)` | Supplies the `kube::Client` |
| `vynil_core::k8s::set_get_labels(f)` | Labels auto-injected into objects created/patched/applied through `K8sGeneric` |
| `vynil_core::k8s::set_get_owner(f)` / `set_get_owner_ns(f)` | Owner reference auto-injected for namespaced objects created in the owner's own namespace |
| `vynil_core::k8s::context_is_wired()` | Returns `true` once all of the above (+ client name) are set |

Calling any `k8s` function before this wiring is done will panic (client-name/client lookups use
`.expect(...)`).

### `DynamicObject`

| Signature | Returns |
|---|---|
| `<DynamicObject>.data` (get) | dynamic — the raw object body |

### `K8sGeneric` — dynamically-discovered resource client

Resolves `name` (kind or plural) against the cluster's API discovery cache to find the right
group/version/kind and scope.

| Signature | Returns | Notes |
|---|---|---|
| `k8s_resource(name: string)` | `K8sGeneric` | No namespace restriction: cluster-scoped kinds query cluster-wide, and namespaced kinds query **all namespaces** (`Api::all_with`, like `kubectl -A`) |
| `k8s_resource(name: string, ns: string)` | `K8sGeneric` | Namespaced |
| `k8s_resource(api_version: string, name: string, ns: string)` | `K8sGeneric` | With a `/` in `api_version` (e.g. `"acme.io/v1"`), resolves by **exact** group and version — for resources whose kind/plural exists in multiple API groups. Without a `/` (e.g. `"v1"`), the version is silently ignored and resolution falls back to the plain `k8s_resource(name, ns)` path: `k8s_resource("v9", "mod", "ns")` succeeds as long as `mod` resolves at *any* version — the version is never checked |
| `<K8sGeneric>.scope` (get) | `string` | `"cluster"` or `"namespace"` — the *resource's* discovery scope, not the query's: a `k8s_resource(name)` handle on a namespaced kind reports `"namespace"` while its queries span every namespace |
| `<K8sGeneric>.exist` (get) | `bool` | Whether discovery actually found the resource |
| `<K8sGeneric>.list()` | dynamic | Full object list |
| `<K8sGeneric>.list(labels: string)` | dynamic | Label-selector-filtered list |
| `<K8sGeneric>.list_meta()` | dynamic | Metadata-only list (cheaper) |
| `<K8sGeneric>.get(name: string)` | dynamic | Full object |
| `<K8sGeneric>.get_meta(name: string)` | dynamic | Metadata-only |
| `<K8sGeneric>.get_obj(name: string)` | `K8sObject` | Handle for `delete`/`wait_*` operations |
| `<K8sGeneric>.delete(name: string)` | `()` | Foreground deletion |
| `<K8sGeneric>.create(data)` | dynamic | Injects labels/owner-reference (see context above) before creating |
| `<K8sGeneric>.replace(name: string, data)` | dynamic | Same injection, then `PUT` |
| `<K8sGeneric>.patch(name: string, data)` | dynamic | Server-Side-Apply, forced |
| `<K8sGeneric>.apply(name: string, data)` | dynamic | Server-Side-Apply, forced; for `Job` objects specifically, an "immutable field" error is swallowed (returns the existing object) if the Job has already completed |
| `update_k8s_crd_cache()` | `()` | Refreshes the process-wide API-discovery cache (60s timeout; keeps the old cache on timeout) |

### `K8sObject` — handle returned by `get_obj`

| Signature | Returns | Notes |
|---|---|---|
| `<K8sObject>.kind` (get) | `string` | Kind read from the object's own runtime type fields as fetched; an empty string when those fields are absent |
| `<K8sObject>.original_kind` (get) | `string` | Kind the `K8sGeneric` was resolved to when this handle was built — reliable where `.kind` can come back empty; prefer this one (decision on record) |
| `<K8sObject>.metadata` (get) | dynamic | |
| `<K8sObject>.delete()` | `()` | Foreground deletion |
| `<K8sObject>.wait_deleted(timeout: int)` | `()` | Waits (seconds) until the object's UID is gone |
| `<K8sObject>.wait_condition(condition: string, timeout: int)` | `()` | Waits until `status.conditions[].type == condition && status == "True"` |
| `<K8sObject>.wait_status(prop: string, timeout: int)` | `()` | Waits until `status.<prop>` is boolean `true` |
| `<K8sObject>.wait_status_prop(prop: string, timeout: int)` | `()` | Waits until `status.<prop>` merely exists (non-null) |
| `<K8sObject>.wait_status_string(prop: string, value: string, timeout: int)` | `()` | Waits until `status.<prop> == value` |
| `<K8sObject>.wait_for(predicate: Fn, timeout: int)` | `()` | Re-evaluates `predicate` on every watch event until it returns `true` or `timeout` seconds pass. `predicate` gets the object as a map (`o.metadata` / `o.spec` / `o.status` / …, same shape as `<K8sGeneric>.get`) so it can test arbitrarily nested fields — e.g. `\|o\| o.status.ceph.versions.overall.len() == 1 && o.status.ceph.health != "HEALTH_ERR"`. A `predicate` raise is not fatal: the wait continues, and a later event returning `true` succeeds with the exception forgotten; only at timeout is the **last** predicate exception returned, in place of a misleading `Elapsed wait error` |

All `wait_*` methods take `timeout` in **seconds**; a negative value is clamped to `0` and the
timeout fires immediately (never an argument error). Each wait opens a `kube` watch on the object,
re-checks its condition on every watch event, and returns `()` once the condition holds; transient
watch errors are retried with backoff while the global timeout still runs, and the timeout itself
or a definitive watch error surfaces as a Rhai error (see below). `wait_deleted`
waits until the object's `uid` is observed as deleted; on a handle with no `uid` it fails
immediately, before any timeout, with `cannot wait for deletion of <name>: uid is missing`.

All `wait_*` methods share one private retry helper (decision on record, now implemented).
Transient watch failures (HTTP 429, any 5xx, request timeouts, connection drops, expired
`410 Gone` — the watch restarts from a fresh list, `resourceVersion` refreshed by `kube`) are
retried with exponential backoff until the global timeout expires, which then surfaces as
`Elapsed wait error: …`. Definitive failures (401, 403, 404, invalid request) fail immediately
as a `K8s wait error: …`. An object deleted mid-wait (a `Deleted` watch event, or absence after
the object had been seen) fails immediately with `object <name> was deleted while waiting` —
except for `wait_deleted`, for which that is the success condition. `wait_for` predicate errors
are non-fatal: the wait continues, and a later event satisfying the predicate succeeds with the
exception forgotten; only at timeout is the **last** predicate exception returned, in place of a
misleading `Elapsed`.

`wait_for` under the mock (tests / `agent package test`) does not poll: it evaluates `predicate` once against the seeded object and errors if it returns `false` — seed the object in its converged state, or assert the failure explicitly.

### `K8sRaw` — unstructured client for cluster-level endpoints

| Signature | Returns | Notes |
|---|---|---|
| `new_k8s_raw()` | `K8sRaw` | |
| `<K8sRaw>.get_url(url: string)` | dynamic | Raw authenticated GET — relative URLs are resolved against the API server's base URL, absolute ones pass verbatim. Returns the **JSON body alone** (a map/value), with no `{code, headers, body, json}` wrapper like `RestClient`'s: this is the JSON accessor into the Kubernetes API, not a generic HTTP client (decision on record). A non-2xx answer is an error whose message already carries the `Status` message, reason and code (e.g. `ApiError: … (404)`); a non-JSON body fails as an error rather than surfacing as a string |
| `<K8sRaw>.get_cluster_version()` | dynamic | Returns the JSON body of the server's `/version` endpoint (cluster version info). This is the script name for the Rust method `get_api_version` — no `get_api_version` name is registered in script, and there is no alias (intentional mapping, decision on record) |
| `<K8sRaw>.get_api_resources()` | dynamic | `GET /apis` raw, requesting the `APIGroupDiscoveryList` format — the discovery cache is not consulted and nothing is filtered or flattened |

### Workload helpers — `K8sDeploy` / `K8sDaemonSet` / `K8sStatefulSet` / `K8sJob`

Typed convenience wrappers (not going through discovery) for the four common workload kinds. Each
exposes the same shape:

| Signature | Returns | Notes |
|---|---|---|
| `get_deployment(ns: string, name: string)` → `K8sDeploy` | | |
| `get_deamonset(ns: string, name: string)` → `K8sDaemonSet` | | |
| `get_statefulset(ns: string, name: string)` → `K8sStatefulSet` | | |
| `get_job(ns: string, name: string)` → `K8sJob` | | |
| `<T>.metadata` / `<T>.spec` / `<T>.status` (get) | dynamic | |
| `<K8sDeploy/K8sDaemonSet/K8sStatefulSet>.wait_available(timeout: int)` | `()` | Deploy: `status.conditions[type=Available].status == "True"`. DaemonSet: `desired_number_scheduled == number_available`. StatefulSet: `spec.replicas == status.available_replicas` |
| `<K8sJob>.wait_done(timeout: int)` | `()` | Uses `kube`'s built-in `is_job_completed` condition |

---

## 14. Feature `s3` — `s3::s3_rhai_register` (call manually)

Not auto-wired even with the feature on:

```rust
#[cfg(feature = "s3")]
vynil_core::s3::s3_rhai_register(&mut script.engine);
```

Backed by `object_store`'s S3-compatible client (AWS S3 or any S3-compatible endpoint, e.g. MinIO).

| Signature | Returns | Notes |
|---|---|---|
| `s3_get_yaml(bucket, region, prefix, endpoint, access_key, secret_key, key)` | dynamic | Fetches `<prefix><key>` and parses it as YAML. Empty `access_key` skips explicit credentials (falls back to the store's default credential chain). Empty `endpoint` targets AWS S3; a non-empty `endpoint` is used as a custom endpoint with `allow_http` enabled (for local/self-hosted S3-compatible stores) |
| `s3_list_keys(bucket, region, prefix, endpoint, access_key, secret_key)` | `array` of strings | Lists all object keys under `prefix` |

All parameters are `string`.

---

## 15. Cancellation — `cancel::CancelToken` and `cancel::scope`

Lives behind the `rhai` feature (module `vynil_core::cancel`; no new error variant — the
cancellation error is `Error::Other` of text `cancelled`). It lets a consumer driving a
script (typically an LLM session) interrupt the crate's *blocking native calls* — `sleep`
and the network waits made by `http`, `oci`, `s3` and `k8s` through the crate's shared
async → sync bridge — without waiting for them to return.

**Relation to `rhai::Engine::on_progress`:** the progress callback only gets the hand
*between* two script operations; a native call that sleeps or waits on the network doesn't
hand control back until it returns. `on_progress` stays the consumer's stop mechanism for
the script itself and is not replaced — the token is what makes a native call *already in
flight* return early, so the engine comes back to `on_progress` instead of only once that
call finishes.

| Item | Behavior |
|---|---|
| `CancelToken::new()` | Fresh, not-yet-cancelled flag; `Clone` (all clones designate the **same** flag), `Debug`, `Default`, `Send + Sync`. Once cancelled a token stays cancelled — no reset |
| `token.cancel()` | Sets the flag — callable from any thread (e.g. a watchdog holding a clone) |
| `token.is_cancelled()` | Whether the flag is set |
| `cancel::scope(&token, closure)` | Installs the token on the **current thread** for the duration of `closure` and returns the closure's value; the thread's previous token (or its absence) is restored on exit, normal return *or* panic alike. Nested scopes stack — the innermost wins while it lasts |

A native call reads the token of the thread it runs on: already cancelled at entry, it
starts nothing and returns the `cancelled` error (a Rhai error a script can catch with
`try`); cancelled during a wait, it returns within one 25 ms slice — the common wait slice
shared by `sleep` and the bridge — and a pending network future is *dropped*, not continued
in the background. `sleep(0)` and `sleep(-3)` are immediate no-ops with nothing to cancel
and succeed even under a cancelled token.

**What does not cross threads:** the token is thread-local. A `scope` opened on one thread
is visible to native calls made on *that* thread only — another thread, a `tokio::task::spawn`
task or a `tokio::task::spawn_blocking` closure does not inherit it. A consumer evaluating on
such a thread opens its own `scope` there.
