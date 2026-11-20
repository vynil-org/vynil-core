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

`vynil_core::engine::Script::new_bare(resolver_paths)` builds an `Engine` and calls, in this order,
the `core`, `host`, `crypto`, `password` (feature `password`), `semver` and `oci` (feature `oci`)
registrars, then `add_common`. Not everything is wired in automatically — four tiers:

| Tier | Modules | Wired in by `Script::new_bare` |
|---|---|---|
| Always (given `rhai`) | `core` (no host authority), `host` (environment and logs), `crypto` (`sha256`, `crc32_hash`), `semver` | Yes, unconditionally |
| Cargo-feature-gated, auto-wired | `host` with `fs` / `shell`, `crypto` with `crypto`, `password`, `oci` | Yes, when the matching Cargo feature is enabled |
| Never auto-wired | `http`, `k8s`, `s3`, `feeds` | **No** — call the `*_rhai_register` function yourself on `script.engine` |
| Host modules — no registrar at all | `prometheus`, `loki` | **No** — the host builds the module from a configured `QueryClient` and registers it under a name of its own |

The third tier is opt-in regardless of Cargo features — `http`/`k8s`/`s3`/`feeds` each pull in
`rhai` themselves (their core types are built as Rhai-facing APIs, not a plain-Rust API with a
Rhai wrapper on top), so enabling one of those four features is enough to make the type available;
it's registration into a *given* `Engine` that stays a manual call. This crate never assumes a
consumer wants live network or cluster access baked into every script engine, so those are opt-in
calls:

```rust
let mut script = vynil_core::Script::new_bare(vec!["scripts/".into()]);
vynil_core::http::http_rhai_register(&mut script.engine);
#[cfg(feature = "k8s")]
vynil_core::k8s::k8s_rhai_register(&mut script.engine);
#[cfg(feature = "s3")]
vynil_core::s3::s3_rhai_register(&mut script.engine);
#[cfg(feature = "feeds")]
vynil_core::feeds::feeds_rhai_register(&mut script.engine);
```

`k8s` additionally needs runtime context before any script can use it — see the "Runtime context"
subsection of section 13.

### Why this tier is opt-in

Beyond just avoiding unwanted network/cluster access by default, leaving `http`/`k8s`/`s3`/`feeds`
out of `new_bare` is what makes them mockable at the call site instead of at the crate level. Mock
modules ship for `http`, `k8s`, `oci`, `feeds`, `prometheus` and `loki` (`http_mock`, `k8s_mock`,
`oci_mock`, `feeds_mock`, `prometheus_mock`, `loki_mock` — see [mocking.md](mocking.md)); `s3` is
deliberately the one network-facing module without a Rhai mock,
tested through `object_store`'s in-memory store instead. Each mock registers (mostly) the same
Rhai type and function names (`RestClient`, `K8sGeneric`, …) against fixture data or fixed canned
values instead of a live endpoint, and none of them is wired in by `Script::new_bare` — even
`oci`, whose *real* registration is auto-wired when its feature is on, keeps its mock manual.
Because registration is an explicit call rather than something baked into `Script::new_bare`, a
consumer can build two engines from the very same `.rhai` script source — one wired to the real
module for production, one wired to the matching test double for a unit
test — and run that script against both without touching a real cluster, registry, RSS feed, or
HTTP endpoint in the test. If registration were automatic, that swap wouldn't be possible without
threading a runtime flag through `Script::new_bare` itself.

### The module catalogue

The public registrars are grouped by domain, one module per domain and per authority. Each
registrar `X_rhai_register(engine)` has a twin `X_module() -> rhai::Module` with the same
functions and semantics (a twin that drifts from its registrar is a defect). The twin is
registered through `Engine::register_static_module` under the namespace the consumer picks:

```rust
script.engine.register_static_module("core", vynil_core::engine::core_module());
// script: core::base64_encode("a")   (or, under new_bare, the bare base64_encode("a"))
```

| Module | Registrar → twin | Authority over the host | Contents (Cargo feature) |
|---|---|---|---|
| `core` | `engine::core_rhai_register` → `engine::core_module` | none | encoding, text, `glob`, time, YAML; `cpu_millis_of` / `memory_bytes_of` (`quantity`) |
| `host` | `engine::host_rhai_register` → `engine::host_module` | environment, logs; disk (`fs`); processes (`shell`) | `get_env`, `log_*`; `file_*`, `create_dir`, `read_dir`, `is_file`, `is_dir` (`fs`); `shell_run`, `shell_output` (`shell`) |
| `crypto` | `hashes::crypto_rhai_register` → `hashes::crypto_module` | none | `sha256`, `crc32_hash`; `bcrypt_hash`, `Argon`, `gen_private_key` (`crypto`) |
| `semver` | `semver::semver_rhai_register` → `semver::semver_module` | none | `Semver` type and its functions |
| `password` | `password::password_rhai_register` → `password::password_module` (`password`) | none | `gen_password`, `gen_password_alphanum` |
| `oci` | `oci::oci_rhai_register` → `oci::oci_module` (`oci`) | registry network; `cosign` process (`sign_image`) | `Registry` type, `new_registry`, `get_auth_from_file` |
| `http` | `http::http_rhai_register` → `http::http_module` (`http`) | network | `RestClient`, `http_get_yaml`, headers helpers, `json_subset`, `json_equal` |
| `s3` | `s3::s3_rhai_register` → `s3::s3_module` (`s3`) | object-store network | `s3_get_yaml`, `s3_list_keys` |
| `k8s` | `k8s::k8s_rhai_register` → `k8s::k8s_module` (`k8s`) | cluster | `K8sGeneric`, `K8sObject`, `DynamicObject`, `K8sRaw`, workload types |
| `feeds` | `feeds::feeds_rhai_register` → `feeds::feeds_module` (`feeds`) | network | `feed_read`, `feed_poll` |

`prometheus` and `loki` are deliberately outside this table: they are **host modules** — their
twin takes a host-configured `vynil_core::query_client::QueryClient` and there is no registrar at
all (a client is bound to one configured instance, with no handle type script-side; a motivated
exception to the registrar-and-twin rule). The host registers the module through
`Engine::register_static_module` under the name it chooses; the script passes only a query and a
time range and never sees a URL, a tenant or a token — see sections 17 and 18.

The test-double registrars (`httpmock_rhai_register`, `k8s_mock_rhai_register`,
`oci_mock_rhai_register`, `feeds_mock_rhai_register`) are not part of the catalogue, by decision —
they stay out of it as registrars. They do have module twins, though: `httpmock_module(mocks)`,
`k8s_mock_module(mocks, created)`, `oci_mock_module()` and `feeds_mock_module(fixtures)`,
registrable under the real module's name in place of its twin. The `prometheus` and `loki`
doubles (`prometheus_mock_module(fixtures)`, `loki_mock_module(fixtures)`) mirror the host-module
shape: modules only, no registrar — see [mocking.md](mocking.md).

#### Naming rule

- **The registrar** puts the historical names on the engine's global namespace (`s3_get_yaml`,
  `new_http_client`, `k8s_resource`, `semver_from`, `gen_password_alphanum`, …). Its free
  functions are callable bare, as before.
- **The twin** puts its free functions (those without a custom type as first parameter) in a
  namespace the script must qualify: they are callable as `module::name` only, never bare. Where
  the module name already says the domain, the name is shortened:

  | Registrar (global) | Twin (qualified) |
  |---|---|
  | `semver_from` | `semver::from` |
  | `gen_password`, `gen_password_alphanum` | `password::gen`, `password::gen_alphanum` |
  | `new_http_client`, `new_client` | `http::new_client` |
  | `http_get_yaml` | `http::get_yaml` |
  | `s3_get_yaml`, `s3_list_keys` | `s3::get_yaml`, `s3::list_keys` |
  | `feed_read`, `feed_poll` | `feeds::read`, `feeds::poll` |
  | `k8s_resource`, `new_k8s_raw`, `update_k8s_crd_cache` | `k8s::resource`, `k8s::new_raw`, `k8s::update_crd_cache` |

  The `core`, `host` and `crypto` twins keep the names as they are (`core::base64_encode`,
  `host::shell_run`, `crypto::sha256`): `shell_` there names a sub-domain, not the module.
  The `k8s` workload constructors (`get_deployment`, `get_deamonset`, `get_statefulset`, `get_job`)
  keep their names too, qualified in the twin.
- **Methods** (`client.get(...)`, `<K8sGeneric>.list()`, …) stay on the global namespace on both
  sides; they are not affected by the twin.
- **Aliases** of the registrar (`http_get`, `http_head`, `http_post`, `http_put`, `http_patch`,
  `http_delete`, `http_delete_with_body`, `http_post_form`, `new_http_client`) are posted by the
  registrar only. The twin carries no redundant alias: `get`, `post`, … are methods.

#### Names removed in 0.9.1

The 0.9.0 registrars and twins below no longer exist. Their functions moved to the catalogue
modules above, under the names listed in the tables of this document:

`core_pure_*`, `core_host_*`, `core_sleep_*`, `fs_*`, `chrono_*`, `glob_*`, `yaml_*`, `shell_*`,
`hashes_*`, `crypto_hashes_*`, `key_*`, `k8sgeneric_*`, `k8sraw_*`, `k8sworkload_*`.

`k8sgeneric_rhai_register`, `k8sraw_rhai_register` and `k8sworkload_rhai_register` are replaced by
the single `k8s::k8s_rhai_register`. The content of a module varies with its Cargo features, not
with its name.

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
| `rhai` *(default)* | this entire document — the `core`, `host`, `crypto` and `semver` registrars, plus `sha256`/`crc32_hash` | always |
| `fs` | filesystem access (`file_read`, …) in `host` | yes |
| `password` | `gen_password`, `gen_password_alphanum` | yes |
| `crypto` *(default)* | `crypto`'s `bcrypt_hash`, `Argon`, `gen_private_key` | yes |
| `shell` | `shell_run`, `shell_output` in `host` | yes |
| `quantity` | `cpu_millis_of`, `memory_bytes_of` in `core` (Kubernetes `Quantity` parser; the Rhai glue also needs `rhai`) | yes, through `core` |
| `oci` *(implies `rhai`)* | `Registry` OCI client | yes |
| `k8s` *(implies `rhai`)* | `DynamicObject`, `K8sObject`, `K8sGeneric`, `K8sRaw`, `K8sDeploy`, `K8sDaemonSet`, `K8sStatefulSet`, `K8sJob` | **no** — manual |
| `http` *(default, implies `rhai`)* | `RestClient` (HTTP), `json_subset`, `json_equal` | **no** — manual |
| `s3` *(implies `rhai`)* | `s3_get_yaml`, `s3_list_keys` | **no** — manual |
| `metadata` *(implies `rhai`)* | introspection metadata on registered script functions — `///` comments + parameter names (`gen_fn_signatures`, `gen_fn_metadata_to_json`, see above) | n/a — pure metadata, registers nothing of its own |
| `rt` | public async → sync bridge `rt::block_on` for consumers (see section 15); pulls `tokio` only, does not imply `rhai` | n/a — no Rhai registration |
| `feeds` *(implies `http`, `rt`, `rhai`)* | the `feeds` module — `feed_read`, `feed_poll` (see section 16) | **no** — manual |
| `query_client` *(internal; implies `http`, `rt`, `rhai`)* | the shared read kernel the `prometheus` and `loki` connectors are built on (sections 17, 18) — a consumer activates one of those, never this one alone | n/a — Rust API only, registers nothing of its own |
| `prometheus` *(implies `query_client` → `http`, `rt`, `rhai`)* | the `prometheus` host module — `query`, `query_range` (see section 17) | **no** — the host registers the configured module under its own name |
| `loki` *(implies `query_client` → `http`, `rt`, `rhai`)* | the `loki` host module — `query_range` (see section 18) | **no** — the host registers the configured module under its own name |

---

## 1. Core utilities — module `core` (always available under `rhai`)

The `core` registrar (`engine::core_rhai_register`, twin `engine::core_module`) grants no authority
over the host: it computes on its arguments, and `sleep` blocks but reads and writes nothing.
`Script::new_bare` calls it first. It is additive and idempotent: callable alone on a fresh
`rhai::Engine::new`, in any order with `host_rhai_register`.

Encoding, text and YAML functions (no disk access, no environment):

| Signature | Returns | Notes |
|---|---|---|
| `url_encode(text: string)` | `string` | Percent-encodes for use in a query string |
| `to_decimal(octal: string)` | `int` | Parses the string as base-8; any non-octal string raises a Rhai error — never a `0` indistinguishable from the legitimate `0` |
| `base64_encode(text: string)` | `string` | Standard base64 |
| `base64_decode(text: string)` | `string` | Errors if the input isn't valid base64/UTF-8 |
| `json_encode(value)` | `string` | Serializes any Rhai value to JSON |
| `json_encode_escape(value)` | `string` | Same, then wraps the result in a second layer of JSON-string escaping (`format!("{:?}", …)`) — for embedding JSON inside JSON |
| `json_decode(text: string)` | dynamic | Errors on invalid JSON |
| `basename(path: string)` | `string` | String split, no disk access |
| `dirname(path: string)` | `string` | String split, no disk access; absent yields empty |
| `regex_is_match(pattern: string, text: string)` | `bool` | `true` when `pattern` matches anywhere in `text` (unanchored: use `^` / `$` to anchor). Syntax of the [`regex`](https://docs.rs/regex) crate (no look-around, no back-references); matching runs in linear time. An invalid pattern raises a script error carrying the `regex` message. The pattern is compiled on each call (no cache) |

Waiting:

| Signature | Returns | Notes |
|---|---|---|
| `sleep(seconds: int)` | `()` | Blocks the current thread for `seconds`; zero and negative values return immediately. Without a cancel token on the thread it sleeps the whole duration (no ceiling). With one (section 15) it waits on the token and raises `Error::Cancelled` (`CANCEL-001 operation cancelled`) as soon as the token is cancelled; a token already cancelled at entry fails at once. For hand-rolled poll loops (`get` + check + `sleep`) when `<K8sObject>.wait_for` doesn't fit |

`glob`, time and the `quantity` helpers are documented in sections 7, 2 and the subsection below.

### Quantity helpers — feature `quantity`

Under the feature `quantity` (off by default) and `rhai`, the `core` module adds two conversions of
Kubernetes resource quantities. In Rust they are `vynil_core::quantity::cpu_millis_of(&str)` and
`vynil_core::quantity::memory_bytes_of(&str)`, both returning `Option<i64>`.

| Signature | Returns | Notes |
|---|---|---|
| `cpu_millis_of(q)` | `int` or `()` | Millicores: `"500m"` → `500`, `"2"` → `2000`, `"0.1"` → `100`, `"100000n"` → `1` |
| `memory_bytes_of(q)` | `int` or `()` | Bytes: `"2Gi"` → `2147483648`, `"1500m"` → `2`, `"129e6"` → `129000000` |

Input `q` is a string, an integer (its decimal digits), or a finite float (its shortest decimal
representation); any other value gives `()`. The grammar is the whole grammar of a Kubernetes
quantity, applied with no trimming and no case folding (`" 1"`, `"1K"`, `"1mi"` are rejected):

- an optional sign `+` or `-`, then digits with an optional single decimal point (`.5`, `0.5`);
- then **either** a unit suffix **or** an exponent, never both:
  - decimal suffixes `n`, `u`, `m` (sub-units), `k`, `M`, `G`, `T`, `P`, `E`; the empty suffix is the unit;
  - binary suffixes `Ki`, `Mi`, `Gi`, `Ti`, `Pi`, `Ei` (powers of 1024);
  - an exponent `e` or `E` followed by a signed integer (`1e3`, `1E-3`). A lone `E` is the exa suffix.

Rounding is away from zero: `"0.4"` memory → `1`, `"-0.4"` → `-1`, `"1u"` cpu → `1`.

`()` is returned for any input outside the grammar, for a result that does not fit an `i64`
(`"9Ei"` and `"8Ei"` for memory, which overflow), and when the significand does not fit an
unsigned 128-bit integer (about 38 significant digits).

> **Known limit.** When a binary suffix and fraction digits are combined, the intermediate product
> can exceed the 128-bit working range for a very long significand, and the function then returns
> `()` although the value would fit in an `i64`. This is an open point, not a documented guarantee.

### Script-level helpers (`add_common`)

Also always present — these are Rhai source injected via `add_code`, not native functions:

| Signature | Behavior |
|---|---|
| `assert(cond, message)` | Throws `message` if `cond` is falsy |
| `import_run(name, instance, context, args)` / `import_run(name, instance, context)` / `import_run(name, args)` | `import`s the module `name` and calls its `run(...)` function with the matching arity. If the module or the function doesn't exist, logs a debug message and returns instead of throwing; any other error is rethrown. |
| `import_template(name, instance, context, args)` / `import_template(name, instance, context)` / `import_template(name, args)` | Same as `import_run`, but calls `template(...)` first, falling back to `run(...)` if the module has no `template` function |

The shims' skip path calls `log_debug`, which belongs to the **host** module: on an engine
hand-built without `host_rhai_register`, `import_run`/`import_template` fail on that
path with unknown function `log_debug` (documented on `add_common`). Register the host module
before calling `add_common` — that also gives you `get_env`; if you want `log_debug` without
`get_env`, register a `log_debug` yourself before `add_common`.

---

## 2. Time — module `core`

| Signature | Returns | Notes |
|---|---|---|
| `date_now()` | `DateTimeHandler` | Current local time |
| `<DateTimeHandler>.format(fmt: string)` | `string` | `fmt` is a [chrono strftime pattern](https://docs.rs/chrono/latest/chrono/format/strftime/index.html); an invalid pattern raises a script error |

## 3. Hashes — module `crypto`

The `crypto` registrar (`hashes::crypto_rhai_register`, twin `hashes::crypto_module`). `sha256` and
`crc32_hash` need only `rhai`; `bcrypt_hash`, `Argon` and `gen_private_key` need `crypto` too
(default on, like `rhai`).

| Signature | Returns | Notes |
|---|---|---|
| `sha256(text: string)` | `string` | SHA-256 digest, lowercase hexadecimal. No errors |
| `crc32_hash(text: string)` | `int` | CRC-32 |
| `bcrypt_hash(text: string)` | `string` | bcrypt, `DEFAULT_COST` — needs `crypto`. Inputs of `72` bytes or more are rejected with a Rhai error rather than silently truncated: the accepted ceiling is `71` bytes (`71` passes, `72` is the first refusal) |
| `new_argon()` | `Argon` | Generates a fresh random salt for this instance — needs `crypto` |
| `<Argon>.hash(password: string)` | `string` | Argon2 PHC string (salt + hash), using the salt captured at `new_argon()` time — needs `crypto` |

## 4. Keys — module `crypto`

`gen_private_key` is part of the `crypto` module and needs the `crypto` feature (default on).

| Signature | Returns | Notes |
|---|---|---|
| `gen_private_key(algo: string)` | `string` | PKCS8 PEM. `algo`: `"rsa"` (4096 bits) or `"ed25519"` (bit count ignored) |
| `gen_private_key(algo: string, bits: int)` | `string` | Same, explicit RSA bit size |

## 5. `semver` — module `semver`

| Signature | Returns | Notes |
|---|---|---|
| `semver_from(text: string)` | `Semver` | Accepts an optional leading `v`, which is remembered and reproduced by `to_string`. Twin name: `semver::from` |
| `<Semver>.inc_major()` | `()` | Bumps major, resets minor/patch, clears prerelease and build metadata |
| `<Semver>.inc_minor()` | `()` | Bumps minor, resets patch, clears prerelease and build metadata |
| `<Semver>.inc_patch()` | `()` | Bumps patch and clears build metadata — unless already on a prerelease, in which case it clears the prerelease tag and build metadata without bumping patch |
| `<Semver>.inc_beta()` | `()` | From stable: bumps patch and sets `beta.1`. From `beta.N`: increments `N` (patch unchanged). Any other prerelease — a bare `beta`, a foreign label, or `alpha.N` — counts as non-beta: patch bumped, counter reset to `1`. Clears build metadata on success |
| `<Semver>.inc_alpha()` | `()` | Same as `inc_beta`, mirrored for `alpha.N`: the counter advances; a bare `alpha`, a foreign label, or `beta.N` count as non-alpha — patch bumped, `alpha.1` set. Build metadata cleared on success |
| `a == b`, `a != b`, `a < b`, `a > b`, `a <= b`, `a >= b` | `bool` | Standard semver ordering (prerelease < stable). All six take two `Semver` operands — no mixed coercion (`"1.2.3" < semver_from("4.5.6")` fails as an unknown function) and no `<=>`; wrap each operand in `semver_from` |
| `to_string(sv)` | `string` | |

## 6. `yaml` — module `core`

| Signature | Returns | Notes |
|---|---|---|
| `yaml_encode(value)` | `string` | |
| `yaml_decode(text: string)` | dynamic | |
| `yaml_decode_multi(text: string)` | `array` of dynamic | One element per YAML document, short inputs included. Empty, comment-only and null (`~`) documents yield unit values, never an error. |

## 7. `glob` — module `core`

| Signature | Returns | Notes |
|---|---|---|
| `glob(text: string, pattern: string)` | `bool` | Shell-style wildcard match (`wildmatch` — `*` and `?`) |

---

## 8. Feature `fs` — module `host`, filesystem access

Gated at the function-definition level (the `host` registrar only has these functions when this
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

The environment and log functions of the `host` module (`get_env`, `log_debug`, `log_info`,
`log_warn`, `log_error`) are always present under `rhai`: `get_env` returns an empty string when the
variable is unset (defaults are a use case) and errors if it exists but isn't UTF-8; the `log_*`
functions return `()` and forward to `tracing`.

## 9. Feature `password` — module `password`

Off by default so consumers with their own password-generation semantics (e.g. a weight-based
one exposed through a public API) don't get a name collision. Auto-wired when enabled.

| Signature | Returns | Notes |
|---|---|---|
| `gen_password(len: int)` | `string` | At least 1 lowercase, 1 uppercase, 1 digit, 1 symbol. Twin: `password::gen` |
| `gen_password(len: int, spec: map)` | `string` | `spec` keys `lower`/`upper`/`digits`/`symbols` set the **minimum** count per class (default `1` for an omitted key; a negative value counts as `0` — that class is excluded) |
| `gen_password_alphanum(len: int)` | `string` | Same as `gen_password(len)` but 0 symbols. Twin: `password::gen_alphanum` |

Errors (Rhai exception) if the sum of class minimums exceeds `len`, or if every class is
disabled. Symbol set is shell/quoting-safe: `! # % * + - . : = ? @ _`.

## 10. Feature `shell` — module `host`

| Signature | Returns | Notes |
|---|---|---|
| `shell_run(command: string)` | `int` | Runs via `sh -c`; stdout/stderr are inherited (go straight to the process's own streams); returns the exit code — `128 + signal` when killed by a signal on unix, `-1` when neither is available |
| `shell_output(command: string)` | `string` | Runs via `sh -c`, captures stdout; **errors** if the exit code is non-zero *or* if anything was written to stderr (even on exit 0); the failure message carries that same verdict as `rc=<n>` |

Command execution carries risk: there is no whitelist, no timeout and no sandbox — the
cargo opt-in on the `shell` feature is the only guard. Unix-only by assumption: `sh` is
hard-coded and there is no windows branch. Neither function reads the cancel token (section 15).

## 11. Feature `oci` (auto-wired) — module `oci`

`Registry` — a client for an OCI/Docker registry, backed by `oci-client`.

| Signature | Returns | Notes |
|---|---|---|
| `new_registry(registry: string, username: string, password: string)` | `Registry` | Anonymous auth if either credential is empty |
| `<Registry>.push_image(source_dir: string, repository: string, tag: string, annotations: map)` | `string` (digest) | Tars + gzips `source_dir` as a single layer and pushes an OCI image manifest |
| `<Registry>.sign_image(repository: string, tag: string, digest: string, key_path: string)` | `()` | No-op if `key_path` is empty; otherwise shells out to the `cosign` binary (not cancellable, section 15) |
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

## 12. HTTP client — module `http` (call manually)

Gated by the `http` Cargo feature (on by default; it implies `rhai`, and `reqwest` is an
optional dependency of this crate), but it is **not** called by `Script::new_bare` — register
it yourself:

```rust
vynil_core::http::http_rhai_register(&mut script.engine);
// or, under a namespace of your choice:
script.engine.register_static_module("http", vynil_core::http::http_module());
```

`RestClient` — a reqwest-backed client with optional server CA / mTLS identity. Under the twin,
its constructor is `http::new_client`; the registrar also accepts `new_http_client` and `new_client`.

| Signature | Notes |
|---|---|
| `new_http_client(baseurl: string)` / `new_client(baseurl: string)` | Both construct a `RestClient` (registrar). The twin has `http::new_client` only |
| `<RestClient>.set_baseurl(base: string)` | |
| `<RestClient>.set_server_ca(pem: string)` | Enables rustls + custom root CA |
| `<RestClient>.set_mtls_cert_key(cert_pem: string, key_pem: string)` | Client identity for mTLS |
| `<RestClient>.headers_reset()` | Clears all headers |
| `<RestClient>.add_header(key: string, value: string)` | |
| `<RestClient>.add_header_json()` | Adds `Content-Type: application/json; charset=utf-8` and `Accept: application/json`, only if not already set |
| `<RestClient>.add_header_bearer(token: string)` | Sets `Authorization: Bearer <token>` |
| `<RestClient>.add_header_basic(username: string, password: string)` | Sets `Authorization: Basic <base64>` |

Request methods — on the registrar, each pair (`x` / `http_x`) is the same function registered
under two names; on the twin only `x` exists (methods are global on both sides):

| Signature | Returns |
|---|---|
| `.head(path)` | `map` `{code, headers}` |
| `.get(path)` / `.http_get(path)` | `map` `{code, headers, body, json}` |
| `.post(path, body)` / `.http_post(path, body)` | `map` `{code, headers, body, json}` |
| `.put(path, body)` / `.http_put(path, body)` | same |
| `.patch(path, body)` / `.http_patch(path, body)` | same |
| `.delete(path)` / `.http_delete(path)` | same |
| `.delete_with_body(path, body)` / `.http_delete_with_body(path, body)` | same |
| `.post_form(path, params: map)` / `.http_post_form(path, params: map)` | same — sends `params` as `application/x-www-form-urlencoded`, and drops any `Content-Type` header you'd set manually so the form encoder can set its own |

`body` for `post`/`put`/`patch`/`delete_with_body` may be a Rhai string (sent verbatim) or any
other value (JSON-serialized).

> **Status codes are never treated as errors.** These methods only raise a Rhai exception on a
> transport-level failure (DNS, TLS, connection refused, …). A 404 or 500 comes back as a normal
> `Ok` result with `code` set accordingly — check `.code` yourself. This differs from the plain
> Rust API (`body_get`/`json_get`/…), which does return an `Err` on non-2xx.

Standalone functions:

| Signature | Returns | Notes |
|---|---|---|
| `http_get_yaml(url: string, auth_type: string, credential: string)` | dynamic | Twin: `http::get_yaml`. One-shot GET-and-parse-as-YAML, own client (not tied to a `RestClient`). `auth_type`: `""`, `"bearer"`, or `"basic"` (in which case `credential` is `"user:pass"`, base64-encoded for you). Errors on non-2xx. |
| `headers_get(headers: array, name: string)` | value or `()` | Case-insensitive lookup into the opaque `headers` array returned as part of a request result (it has no Rhai-visible indexing/iteration of its own) |
| `headers_has(headers: array, name: string)` | `bool` | Case-insensitive presence check |
| `json_subset(observed, wanted)` | `bool` | See "JSON comparators" below |
| `json_equal(observed, wanted)` | `bool` | See "JSON comparators" below |

### JSON comparators

`json_subset` and `json_equal` compare two JSON-like values, in Rhai (arguments converted to JSON
first; a value that cannot be converted raises a script error) and in Rust
(`vynil_core::http::json_subset(&Value, &Value)`, `json_equal`). Both are pure: no I/O.

- **`json_subset(observed, wanted)`** — true when `observed` satisfies every expectation of
  `wanted`: each key of a `wanted` object must exist in `observed`, with a value that satisfies it
  recursively when both are objects. Keys added to `observed` are ignored. A key of `wanted` absent
  from `observed` is a difference, even when its value is `null`. An empty `wanted` object is
  satisfied by any object. Arrays compare strictly (order and length).
- **`json_equal(observed, wanted)`** — strict equality, extra keys on either side included.

Typing is strict for both: `"1"` is not `1`, and `1` is not `1.0`.

### Plain Rust API: `ReadMethod::Post`

`RestClient::obj_read(method: ReadMethod, path, key)` reads one object. `ReadMethod` has two
variants:

- `ReadMethod::Get` (the default): a `GET` on `path/key` (or `path` when `key` is empty).
- `ReadMethod::Post`: a `POST` with an empty body on the same path, with the same headers as `Get`.
  The response is handled as for `Get` (parsed as JSON). It reads without creating anything.

`ReadMethod` is not `#[non_exhaustive]`: a `match` on it without a wildcard arm must add the new
arm. The signature of `obj_read` is unchanged.

---

## 13. Feature `k8s` — module `k8s` (call manually)

Not auto-wired even with the feature on — register the whole group with one call:

```rust
vynil_core::k8s::k8s_rhai_register(&mut script.engine);
// or, under a namespace of your choice (free names are then qualified: k8s::resource(...)):
script.engine.register_static_module("k8s", vynil_core::k8s::k8s_module());
```

The registrar covers `K8sGeneric`, `K8sObject`, `DynamicObject`, `K8sRaw` and the typed workloads
`K8sDeploy`, `K8sDaemonSet`, `K8sStatefulSet`, `K8sJob`. Free names under the registrar are the
historical ones (`k8s_resource`, `new_k8s_raw`, `update_k8s_crd_cache`); under the twin they are
`k8s::resource`, `k8s::new_raw`, `k8s::update_crd_cache` (see the naming rule in section "The module
catalogue").

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
group/version/kind and scope. Constructor under the registrar: `k8s_resource`; under the twin:
`k8s::resource`.

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
| `update_k8s_crd_cache()` | `()` | Twin: `k8s::update_crd_cache()`. Refreshes the process-wide API-discovery cache (60s timeout; keeps the old cache on timeout) |

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

Constructor under the registrar: `new_k8s_raw()`; under the twin: `k8s::new_raw()`.

| Signature | Returns | Notes |
|---|---|---|
| `new_k8s_raw()` | `K8sRaw` | |
| `<K8sRaw>.get_url(url: string)` | dynamic | Raw authenticated GET — relative URLs are resolved against the API server's base URL, absolute ones pass verbatim. Returns the **JSON body alone** (a map/value), with no `{code, headers, body, json}` wrapper like `RestClient`'s: this is the JSON accessor into the Kubernetes API, not a generic HTTP client (decision on record). A non-2xx answer is an error whose message already carries the `Status` message, reason and code (e.g. `ApiError: … (404)`); a non-JSON body fails as an error rather than surfacing as a string |
| `<K8sRaw>.get_cluster_version()` | dynamic | Returns the JSON body of the server's `/version` endpoint (cluster version info). This is the script name for the Rust method `get_api_version` — no `get_api_version` name is registered in script, and there is no alias (intentional mapping, decision on record) |
| `<K8sRaw>.get_api_resources()` | dynamic | `GET /apis` raw, requesting the `APIGroupDiscoveryList` format — the discovery cache is not consulted and nothing is filtered or flattened |

### Workload helpers — `K8sDeploy` / `K8sDaemonSet` / `K8sStatefulSet` / `K8sJob`

Typed convenience wrappers (not going through discovery) for the four common workload kinds. Each
exposes the same shape. The constructors keep their names in both the registrar and the twin
(`k8s::get_job(...)`):

| Signature | Returns | Notes |
|---|---|---|
| `get_deployment(ns: string, name: string)` → `K8sDeploy` | | |
| `get_deamonset(ns: string, name: string)` → `K8sDaemonSet` | | Spelling kept as is |
| `get_statefulset(ns: string, name: string)` → `K8sStatefulSet` | | |
| `get_job(ns: string, name: string)` → `K8sJob` | | |
| `<T>.metadata` / `<T>.spec` / `<T>.status` (get) | dynamic | |
| `<K8sDeploy/K8sDaemonSet/K8sStatefulSet>.wait_available(timeout: int)` | `()` | Deploy: `status.conditions[type=Available].status == "True"`. DaemonSet: `desired_number_scheduled == number_available`. StatefulSet: `spec.replicas == status.available_replicas` |
| `<K8sJob>.wait_done(timeout: int)` | `()` | Uses `kube`'s built-in `is_job_completed` condition |

---

## 14. Feature `s3` — module `s3` (call manually)

Not auto-wired even with the feature on:

```rust
#[cfg(feature = "s3")]
vynil_core::s3::s3_rhai_register(&mut script.engine);
```

Backed by `object_store`'s S3-compatible client (AWS S3 or any S3-compatible endpoint, e.g. MinIO).
Under the registrar the names are `s3_get_yaml` and `s3_list_keys`; under the twin
(`s3::s3_module()`) they are `s3::get_yaml` and `s3::list_keys`.

| Signature | Returns | Notes |
|---|---|---|
| `s3_get_yaml(bucket, region, prefix, endpoint, access_key, secret_key, key)` | dynamic | Fetches `<prefix><key>` and parses it as YAML. Empty `access_key` skips explicit credentials (falls back to the store's default credential chain). Empty `endpoint` targets AWS S3; a non-empty `endpoint` is used as a custom endpoint with `allow_http` enabled (for local/self-hosted S3-compatible stores) |
| `s3_list_keys(bucket, region, prefix, endpoint, access_key, secret_key)` | `array` of strings | Lists all object keys under `prefix` |

All parameters are `string`.

**Rust (async).** The Rust client is `vynil_core::s3::S3Store`, built from an `S3Config`
(`bucket`, `region`, `endpoint`, `credentials`, `prefix`; `Default` is available) with
`S3Store::new(config)?`, or wrapped around any `object_store` store with
`S3Store::from_object_store(store, prefix)`. Tests need no network: an `InMemory` store, reached
through the re-exports `vynil_core::s3::object_store` and `vynil_core::s3::bytes`, does the job.

```rust,ignore
use std::sync::Arc;
use vynil_core::s3::{S3Config, S3Condition, S3Store, bytes::Bytes, object_store::memory::InMemory};

// Production: `credentials: None` uses the default credential chain.
let store = S3Store::new(S3Config {
    bucket: "my-bucket".to_string(),
    region: "eu-west-3".to_string(),
    prefix: "filestore/".to_string(),
    ..S3Config::default()
})?;
store.put("docs/a.txt", Bytes::from_static(b"hello")).await?;
let body = store.get("docs/a.txt").await?;
let head = store.head("docs/a.txt").await?;               // S3Meta, size in bytes
let part = store.get_range("docs/a.txt", 0..3).await?;    // semi-open byte range
let names = store.list("docs").await?;                    // Vec<S3Meta>

// Tests: in memory, no network.
let test_store = S3Store::from_object_store(Arc::new(InMemory::new()), "");
```

Methods, all `async`:

- reads: `get(key) -> Bytes`, `get_range(key, Range<u64>) -> Bytes`, `get_stream(key)` (a
  `BoxStream` of `Bytes`, the body is not loaded in memory), `head(key) -> S3Meta`;
- writes: `put(key, data)`, `put_stream(key, stream, chunk_size)` (multipart upload),
  `put_if(key, data, S3Condition::IfNotExists | S3Condition::IfMatch(etag))`, all returning
  `S3PutResult { etag }`; `delete(key)`;
- listing: `list(prefix) -> Vec<S3Meta>`.

Keys are relative to the store prefix and joined to it with a single `/`. `list` matches its
prefix by path segment, as a directory would: `list("doc")` returns `doc/y` but not `docs/x`.
Its keys are relative to the store prefix and sorted in byte order.

Keys are raw UTF-8 strings: what you pass to `put` is what `list` and `head` return, and the key
stored in the bucket is that same string (`aws s3 ls` shows `é.txt`, not `%C3%A9.txt`). A key with a
`.` or `..` segment or an ASCII control character is refused with an error. A store prefix is
normalized (empty segments are dropped), so `/x//y/` stands for `x/y`. Keys are normalized the
same way: `put("a//b")` and `put("a/b/")` both store `a/b`, and `list` returns `a/b`.

`put_stream` refuses a `chunk_size` of zero before any write. An error of the input stream aborts
the upload and leaves no object under the key. A stream that yields no byte writes an empty
object. At most 8 parts are in flight.

Failures are `vynil_core::Error::S3(S3Error)`: `S3-001` (`NotFound`), `S3-002` (`AlreadyExists`),
`S3-003` (`PreconditionFailed`), `S3-004` (`Backend`).

The Rhai helpers `s3_get_yaml` and `s3_list_keys` share the store-building rules of `S3Config`
(an empty string stands for `None`, or for the AWS default endpoint). Each call builds its own
store, and they expose only those two reads: they are not a projection of `S3Store`. They keep
their historical key handling, which percent-encodes non-ASCII and special characters in keys
(unchanged, so existing scripts keep working): the two faces agree only on plain ASCII key names,
so a bucket shared between them should stick to those.

---

## 15. Cancellation — `cancel::CancelToken` and `cancel::scope`

Module `vynil_core::cancel`, compiled without any feature. The cancellation error is the
variant `Error::Cancelled`, displayed `CANCEL-001 operation cancelled` (match on the variant,
not on the text). It lets a consumer driving a script (typically an LLM session) interrupt the
crate's *blocking native calls* — `sleep` (feature `rhai`) and the network waits made by `http`,
`oci`, `s3` and `k8s` through the crate's shared async → sync bridge — without waiting for them to
return.

**Relation to `rhai::Engine::on_progress`:** the progress callback only gets the hand
*between* two script operations; a native call that sleeps or waits on the network doesn't
hand control back until it returns. `on_progress` stays the consumer's stop mechanism for
the script itself and is not replaced — the token is what makes a native call *already in
flight* return early, so the engine comes back to `on_progress` instead of only once that
call finishes.

| Item | Behavior |
|---|---|
| `CancelToken::new()` | Fresh, not-yet-cancelled flag; `Clone` (all clones designate the **same** flag), `Debug`, `Default`, `Send + Sync`. Once cancelled a token stays cancelled — no reset |
| `token.cancel()` | Sets the flag and wakes the calls waiting on it at once — callable from any thread (e.g. a watchdog holding a clone) |
| `token.is_cancelled()` | Whether the flag is set |
| `cancel::scope(&token, closure)` | Installs the token on the **current thread** for the duration of `closure` and returns the closure's value; the thread's previous token (or its absence) is restored on exit, normal return *or* panic alike. Nested scopes stack — the innermost wins while it lasts |

**How the wake-up works.** There is no polling and no time slice: `cancel()` wakes the waiting
calls directly. A `sleep` waits on a condition variable bounded by its duration; a network wait
is a future that the cancellation wakes through its waker. A native call reads the token of the
thread it runs on: already cancelled at entry, it starts nothing and returns `Error::Cancelled`
(a Rhai error a script can catch with `try`); cancelled during a wait, it returns as soon as the
cancellation is observed, and a pending network future is *dropped*, not continued in the
background. `sleep(0)` and `sleep(-3)` are immediate no-ops with nothing to cancel and succeed
even under a cancelled token.

**What is not cancellable:** only `sleep` and the network waits go through the token. Calls that
block on a *child process* — `shell_run` / `shell_output` (feature `shell`) and `sign_image`
(`cosign`, feature `oci`) — do not read it and return only when the process ends.

**No time driver needed.** A consumer's runtime does not have to be built with `enable_time()` or
`enable_all()` for the token to work: the cancellation is a wake-up, not a timer. The temporary
runtime of the `rt::block_on` fallback (below) is still built with `enable_all()`.

**What does not cross threads:** the token is thread-local. A `scope` opened on one thread
is visible to native calls made on *that* thread only — another thread, a `tokio::task::spawn`
task or a `tokio::task::spawn_blocking` closure does not inherit it. A consumer evaluating on
such a thread opens its own `scope` there.

**The public bridge (feature `rt`, no `rhai`):** a consumer whose own native functions call
async code from a synchronous Rhai script uses `vynil_core::rt::block_on(future)` — the same
function the `http`, `oci`, `s3` and `k8s` modules use, with the same strategies (multi-thread
runtime: `block_in_place`; no runtime: a temporary `current_thread` runtime, a fallback that
pays one runtime per call; `current_thread` runtime: an explicit error, the future is never
polled) and the same token reading: a token installed on the calling thread by `scope` makes
`block_on` refuse an already-cancelled future, or abandon a running one as soon as the cancellation
wakes it, with `Error::Cancelled`. The race is a `tokio::select!` between the future and the
token's cancellation, on the same runtime. The `cancel` module is read without `rhai`, so `rt`
alone is enough to honour the token.

---

## 16. Feature `feeds` — module `feeds` (call manually)

RSS/Atom feed reading (feature `feeds`, off by default; it implies `http`, `rt` and `rhai`).
Not auto-wired by `Script::new_bare` — the network is never auto-wired:

```rust
vynil_core::feeds::feeds_rhai_register(&mut script.engine);
// or, under a namespace of your choice (free names are then qualified: feeds::read(...)):
script.engine.register_static_module("feeds", vynil_core::feeds::feeds_module());
```

| Signature | Returns | Notes |
|---|---|---|
| `feed_read(url, since)` | `array` of entry maps | Twin: `feeds::read`. The whole stream is downloaded every call (no conditional fetch). `since` is `()` (everything), an `i64` of UTC milliseconds, or a `DateTimeHandler`; the filter compares `published`, falling back to `updated`, **strictly** greater than `since` — an entry with no date at all is **kept** (a duplicate is better than a lost novelty; final deduplication is the caller's). `feed_read` is `feed_poll` with an empty cursor, without the conditional, plus this filter |
| `feed_poll(url, cursor)` | `map` `{entries, cursor, status}` | Twin: `feeds::poll`. `cursor` is `()` on the first pass or the map returned by the previous pass; `status` is `"new"` or `"not_modified"`. A `304 Not Modified` answers `entries = []` with the cursor **unchanged**; the request sends `If-None-Match` / `If-Modified-Since` from the cursor when they exist |

Entry maps (`FeedEntry`) carry the same seven fields for Atom and RSS alike — `guid`, `url`,
`title`, `published`, `updated`, `content`, `source` (the URL of the stream the entry came from) —
same fields, same types. The dates are `i64` in **MILLISECONDS** since the UTC epoch (the same
convention as the `prometheus` and `loki` modules), `()` when absent, never an invented date. An
entry with no guid gets a derived one: `sha256:` + lowercase hex SHA-256 of `url`, one `\n` byte,
then `title`; an entry with no guid **and** no `url` **and** no `title` is dropped with a
`tracing::warn`. Duplicate guids within one stream yield a single entry (the first wins). An empty
stream yields `entries = []` with the cursor updated (`seen` empty).

The cursor is a **map opaque and versioned**, `{ v: 1, etag, last_modified, seen, since }`: the
caller persists it as-is and replays it, and never interprets it. An entry is held NEW when its
guid is not in `seen`, whatever its date (this covers streams that republish with old dates);
each pass `seen` is **pruned** to the guids still present in the current stream, which bounds the
cursor naturally. A cursor of unknown version (a `v` other than `1`), or one with a
wrongly-typed field, is refused — never a panic. Treat the cursor as a **transport optimisation,
not a guarantee**: lost or corrupted (reset to `()`), it costs one full re-download, never an
error or a loss. Final deduplication belongs to the caller's storage, by `(source, guid)`.

Errors carry stable codes: `FEED-001` (invalid feed or non-XML body), `FEED-002` (invalid feed
cursor). A timeout or an unreachable source arrives as the crate's transport error (the
`RestClient`'s own failure path), and any non-2xx status other than the `304` as a method failure.
The double — `feeds_mock_module(fixtures)` / `feeds_mock_rhai_register(engine, fixtures)` — serves
fixture streams and simulates ETag / Last-Modified without network: see [mocking.md](mocking.md).

**Rust (async).** `vynil_core::feeds::FeedClient` is the async-first client of the same kernel:
`read(url, since)` and `poll(url, &cursor)` are awaited directly, without the `rt` bridge.
`FeedClient::new()` uses a default HTTP client; `FeedClient::with_rest_client(template)` builds
its requests from a configured `RestClient` (headers, CA, mTLS; the template's base URL is
ignored). The cursor stays with the caller.

```rust,ignore
use vynil_core::feeds::{FeedClient, FeedCursor};

let client = FeedClient::new();
let entries = client.read("https://example.com/feed.xml", None).await?; // since: Option<i64>, UTC ms
let poll = client.poll("https://example.com/feed.xml", &FeedCursor::default()).await?;
// persist `poll.cursor` as-is and replay it on the next pass
```

The Rhai face is a synchronous projection of this client: `feed_read` and `feed_poll` run the
same fetch, parse, filter and cursor logic, bridged to sync.

---

## 17. Feature `prometheus` — host module (the host registers it)

Read connector for Prometheus-compatible APIs (Prometheus, Mimir, Thanos, VictoriaMetrics),
feature `prometheus` (off by default; `prometheus = ["query_client"]`, which implies `http`, `rt`
and `rhai`). The principle behind it: **the host configures, the script queries.** The host builds
a `vynil_core::query_client::QueryClient` (base URL and path prefix, tenant, authentication,
server CA, timeout, volume ceilings), derives a Rhai `Module` from it, and registers that module
under the name it chooses. The script passes only the query and the time range — it never sees a
token, a URL or another tenant, and has no way to read or change any of that.

```rust
let client = vynil_core::query_client::QueryClient::new(config)?;   // host-side, once
script.engine.register_static_module("metrics", vynil_core::prometheus::prometheus_module(client));
// script: metrics::query("up", t)
```

There is deliberately **no** `prometheus_rhai_register` global registrar: a client is bound to one
configured instance, with no handle type script-side (a motivated exception to the
registrar-and-twin rule). The two functions therefore exist only qualified under the chosen name
(`metrics::query(...)`).

| Signature | Returns | Notes |
|---|---|---|
| `<host>::query(expr, time)` | `map` `{series, truncated}` | Instant query — one series per vector element, a single point `[t, v]`; a scalar result gives a series without labels; a string result is refused (`BadResponse`) |
| `<host>::query_range(expr, start, end, step)` | `map` `{series, truncated}` | Range query. `time`, `start`, `end`: an `i64` of **milliseconds** since the UTC epoch or a `DateTimeHandler`; `step`: `"auto"` or a Prometheus duration (`"30s"`, `"5m"`, `"1h"`, `"1d"`, `"500ms"`). An invalid bound, or `end < start`, is a script failure — never a panic. `"auto"` computes a step that fits the points ceiling; an explicit step too fine is refused (`StepTooFine`, carrying the minimum accepted step) |

Output is the normalized form `{ series: [{ labels, points: [[t, v]] }], truncated }` (aligned by
design with the vanyline widget engine's `timeseries` type): `labels` is a map of strings (empty
when the server sent none); `t` is an `i64` of **UTC MILLISECONDS, strictly increasing** within a
series; `v` is a finite `f64` or `()` (null). A server `NaN` becomes `()` — a hole, the series is
still returned; an infinite value (`+Inf` or `-Inf`) is **never** passed through: it fails the
call in `NonFinite`. The numeric
conversion of Prometheus's text values (`"1.5"`, `"NaN"`, `"+Inf"`) happens here, never in the
script. `truncated` is the **only** read path of a ceiling being hit (series, points, bytes):
`false` when the result is complete, `true` when it was cut short — never a silent truncation. An
empty result yields `series: []`; several series keep the server's order.

Errors are typed, carried by the crate's query error with stable codes `QUERY-001` … `QUERY-009`:
`Timeout` (001), `Syntax` (002 — the server's message is kept, and never carries the token),
`RateLimited` (003, HTTP 429 with `Retry-After` when present), `Unauthorized` (004, HTTP 401 and
403), `TooLarge` (005, the first element alone exceeds the byte ceiling), `StepTooFine` (006),
`NonFinite` (007), `Unreachable` (008), `BadResponse` (009). Invalid script input is a plain
script failure. The double `prometheus_mock_module(fixtures)` serves the same functions from
fixtures: see [mocking.md](mocking.md).

**Rust (async).** `vynil_core::prometheus::PrometheusClient` wraps a host-configured
`QueryClient` (built from a `query_client::QueryClientConfig`) and offers `query(expr, time_ms)`
and `query_range(expr, start_ms, end_ms, step)`, both `async`. Times are UTC milliseconds; `step`
is an `Option<Duration>`, `None` for the automatic step. They return the same `SeriesResult` as the
script map, and run the synchronous kernel on the blocking pool. Under a `current_thread` runtime
the kernel refuses explicitly instead of panicking.

```rust,ignore
use std::time::Duration;
use vynil_core::{prometheus::PrometheusClient, query_client::{QueryClient, QueryClientConfig}};

let config = QueryClientConfig {
    base_url: "https://mimir.example.com".to_string(),
    path_prefix: "/prometheus".to_string(),
    ..QueryClientConfig::default()
};
let client = PrometheusClient::new(QueryClient::new(config)?);
let (start_ms, end_ms) = (1_700_000_000_000_i64, 1_700_003_600_000_i64);
let now = client.query("up", end_ms).await?;
let range = client.query_range("up", start_ms, end_ms, Some(Duration::from_secs(30))).await?;
```

The Rhai face is a synchronous projection of this client: `<host>::query` and `<host>::query_range`
call the same kernel functions.

---

## 18. Feature `loki` — host module (the host registers it)

Read connector for Loki, feature `loki` (off by default; `loki = ["query_client"]`, implying
`http`, `rt` and `rhai`) — the same host-module principle as section 17, **no shared code with
it** (the two features are independent). The host builds the `QueryClient`, derives the module
and registers it under the name it chooses; the script passes only the LogQL query, the time
range, the line limit and the direction — never a token, a URL or a tenant.

```rust
let client = vynil_core::query_client::QueryClient::new(config)?;   // host-side, once
script.engine.register_static_module("logs", vynil_core::loki::loki_module(client));
// script: logs::query_range("{app=\"x\"}", s, e, 100, "backward")
```

There is no global registrar here either (same pattern as `prometheus`), so the function exists
only qualified under the chosen name. There is no instant `query` and no label exploration —
range reads only.

| Signature | Returns | Notes |
|---|---|---|
| `<host>::query_range(expr, start, end, limit, direction)` | `map` `{streams, truncated}` | `start`, `end`: an `i64` of **milliseconds** since the UTC epoch or a `DateTimeHandler`; `limit`: a positive integer of lines, **capped by the host's `max_lines`** — the smaller of the two wins, and `truncated` is `true` when the server had more lines than the retained cap; `direction`: `"forward"` or `"backward"` — any other value fails as a script error, without a network request. The request goes to the host's `path_prefix` + `loki/api/v1/query_range` (a bare Loki under `/`, Mimir under its prefix) |

Output is the normalized form `{ streams: [{ labels, lines: [[t, text]] }], truncated }`:
`labels` is a map of strings; `t` is an `i64` of UTC milliseconds — Loki's nanosecond timestamps
are **truncated** to the millisecond, so several lines of one stream can share a `t` (millisecond
equalities are tolerated for log lines, unlike metric points in section 17); the order is the
server's, per `direction`. The line text is exactly what Loki rendered, untransformed and
unmasked (secret-masking is the caller's). An empty result yields `streams: []`; streams keep the
server's order. `truncated` is again the **only** read path of a ceiling being hit (streams,
lines, bytes) — never a silent truncation.

Errors are the same typed `QUERY-001` … `QUERY-009` family as section 17; invalid script input is
a plain script failure. The double `loki_mock_module(fixtures)` serves the same function from
fixtures: see [mocking.md](mocking.md).

**Rust (async).** `vynil_core::loki::LokiClient` wraps a host-configured `QueryClient` (built from
a `query_client::QueryClientConfig`) and offers `async fn query_range(expr, start_ms, end_ms,
limit, direction)`. Times are UTC milliseconds; `limit` is a `usize` capped by the host's
`max_lines`; `direction` is `loki::Direction::Forward` or `Direction::Backward`. It returns the same
`LogsResult` as the script map. A zero `limit` or `end_ms < start_ms` is refused with
`Error::Other` before any request. The synchronous kernel runs on the blocking pool, and under a
`current_thread` runtime it refuses explicitly instead of panicking.

```rust,ignore
use vynil_core::{loki::{Direction, LokiClient}, query_client::{QueryClient, QueryClientConfig}};

let config = QueryClientConfig {
    base_url: "https://loki.example.com".to_string(),
    ..QueryClientConfig::default()
};
let client = LokiClient::new(QueryClient::new(config)?);
let logs = client
    .query_range("{app=\"x\"}", start_ms, end_ms, 100, Direction::Backward)
    .await?;
```

The Rhai face is a synchronous projection of this client: `<host>::query_range` calls the same
kernel function.
