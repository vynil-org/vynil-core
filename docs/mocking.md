# Mocking

`vynil-core` ships three Rhai test doubles, one per network/cluster-facing module: HTTP, `k8s`,
and OCI. Each mock re-registers (mostly) the same Rhai type and function names as its real
counterpart, in place of a live network call or cluster — `http_mock` and `k8s_mock` are backed by
in-memory fixtures; `oci_mock` has no fixtures at all, every method returning a fixed canned value
(section 3) — so a script written against the real API can run against a mock in a unit test with
little or no change. There is no Handlebars equivalent; mocking only applies to the Rhai side.

See [rhai_helpers.md](rhai_helpers.md) for the real APIs these mirror.

## Shared shape

None of the three mock registration functions are called automatically by
`Script::new_bare` — call them yourself, the same way you would the real `*_rhai_register`
functions, but passing fixture data instead of (or in addition to) an `Engine`:

```rust
let mut script = vynil_core::Script::new_bare(vec![]);

#[cfg(feature = "http")]
vynil_core::http_mock::httpmock_rhai_register(&mut script.engine, my_http_fixtures);

#[cfg(feature = "k8s")]
vynil_core::k8s_mock::k8s_mock_rhai_register(&mut script.engine, mocks.clone(), created.clone());

#[cfg(feature = "oci")]
vynil_core::oci_mock::oci_mock_rhai_register(&mut script.engine);
```

A given `Engine` should get *either* the real registration *or* the mock one for a given module,
never both — they claim the same Rhai type/function names and the second registration would
shadow the first.

### Module twins

Each mock registrar also has a module twin — a `Module` built from the same single registration
list, with the same semantics (a twin that drifts from its registrar is a defect):

```rust
let mut script = vynil_core::Script::new_bare(vec![]);

#[cfg(feature = "http")]
script.engine.register_static_module("http", vynil_core::http_mock::httpmock_module(my_http_fixtures));

#[cfg(feature = "k8s")]
script.engine.register_static_module("k8s", vynil_core::k8s_mock::k8s_mock_module(mocks.clone(), created.clone()));

#[cfg(feature = "oci")]
script.engine.register_static_module("oci", vynil_core::oci_mock::oci_mock_module());
```

Registered under the name of the *real* module (`http`, `k8s`, `oci`), the twin takes its place:
free functions carry the real twin's short, qualified names (`http::new_client`,
`k8s::resource`, `k8s::new_raw`, `k8s::update_crd_cache`, `oci::new_registry`,
`oci::get_auth_from_file`), and methods keep their names — see the naming rule in
[rhai_helpers.md](rhai_helpers.md). The criterion is that **one and the same script, written in
qualified names, runs unmodified under the real module and under its double**: the production
engine gets `http_module` / `k8s_module` / `oci_module`, the test engine gets
`httpmock_module` / `k8s_mock_module` / `oci_mock_module`, and the `.rhai` source is untouched.

The one exception is the accepted holes of the `http` double: `http::get_yaml`,
`http::json_subset` and `http::json_equal` are **not** registered by `httpmock_module`
(section 1) — a script calling them is not source-compatible with the mock.

---

## 1. `http_mock` — feature `http` (implies `rhai`)

Mirrors `RestClient` (see the "HTTP client" section of [rhai_helpers.md](rhai_helpers.md)) under
the **exact same Rhai type name**, `RestClient` — a script that only talks to `RestClient` is
source-compatible between the real and mocked engine.

```rust
pub fn httpmock_rhai_register(engine: &mut Engine, mocks: Vec<HttpMockItem>)

// module twin
pub fn httpmock_module(mocks: Vec<HttpMockItem>) -> Module
```

Under the twin the mock constructor answers to the short qualified name `http::new_client`,
`headers_get`/`headers_has` keep their names, and the `http_`-prefixed verb aliases are
registrar-only (methods are global on both sides). The real twin's `get_yaml`/`json_subset`/
`json_equal` are absent from the mock — the gaps below.

Fixtures, supplied up front instead of via context wiring:

```rust
pub struct HttpMockItem {
    pub path: String,
    pub method: HttpMethod,     // Get | Head | Delete | Patch | Post | Put
    pub return_obj: rhai::Map,  // returned verbatim as the call's result
}
```

### Registered surface

| Signature | Behavior |
|---|---|
| `new_http_client(base)` | Constructs a `RestClientMock` carrying a clone of the fixture list |
| `.set_baseurl(base)` | Stored but otherwise unused by matching (matching is by `path` only) |
| `.set_server_ca(pem)`, `.set_mtls_cert_key(cert, key)`, `.headers_reset()`, `.add_header(k, v)`, `.add_header_json()`, `.add_header_bearer(t)`, `.add_header_basic(u, p)` | No-ops — accepted for source compatibility, have no effect on matching or the returned value |
| `.head(path)` | Finds an `HttpMockItem` with `method == Head` and matching `path`; returns its `return_obj` |
| `.get(path)` / `.http_get(path)` | Same, `method == Get` |
| `.post(path, _body)` / `.http_post(path, _body)` | Same, `method == Post`; the body argument is accepted but ignored |
| `.post_form(path, _params)` / `.http_post_form(path, _params)` | Same, `method == Post` — matches the same fixtures as `.post`, since the real client also sends both as an HTTP `POST`; the form map is accepted but ignored |
| `.put(path, _body)` / `.http_put(path, _body)` | Same, `method == Put` |
| `.patch(path, _body)` / `.http_patch(path, _body)` | Same, `method == Patch` |
| `.delete(path)` / `.http_delete(path)` | Same, `method == Delete` |
| `.delete_with_body(path, _body)` / `.http_delete_with_body(path, _body)` | Same, `method == Delete` — matches the same fixtures as `.delete`; the body argument is accepted but ignored |
| `headers_get(headers, name)` / `headers_has(headers, name)` | The exact same standalone functions as the real client (`http::headers_get`/`headers_has`) — they only operate on the `headers` array shape of a result map, so they work unmodified against a mock result as long as your fixture's `return_obj` includes one |

No match → a Rhai error: `"Failed to find <METHOD> <path> in the Mock database"`.

### Gap vs. the real `RestClient`

The mock registers 26 of the real client's 29 names. The three missing ones are an accepted
decision — the mock will not change:

- `new_client` — the real client registers its constructor under two names, `new_http_client` and
  `new_client`; the mock registers only `new_http_client`, so `new_client(...)` is an
  unknown-function error on the mock engine.
- `http_head` — the real `.head` is also registered under the `http_head` alias; the mock
  registers only `.head`.
- `http_get_yaml` — not registered at all. Unlike the methods above, the real `http_get_yaml` isn't
  a `RestClient` method — it takes a full URL and fetches it with its own throwaway client,
  independent of any `RestClient`/fixture list. Consumers redefine it in script for mock runs
  (as vynil does); this crate does not mock it.

Also by design: `return_obj` is exactly the map you configured — the real client's `{code, headers,
body, json}` shape is a convention you must reproduce yourself in the fixture if your script expects
it (e.g. set `return_obj = #{code: 200, json: #{...}}`).

---

## 2. `k8s_mock` — feature `k8s`

Registers the mock structs under the **exact same Rhai type names** as the real client:
`K8sObject`, `K8sGeneric`, `K8sRaw`, `K8sDeploy`, `K8sDaemonSet`, `K8sStatefulSet`, `K8sJob`.
The surface is defined once, in a single registration list shared by the registrar and its
module twin (the `register_k8s_object!`/`register_k8s_generic!`/`register_k8s_raw!` macros are no
longer the mechanism — they are only replayed against the mocks in this crate's own equivalence
tests). A script written against the real `k8s` module runs unmodified against the mock.

```rust
pub fn k8s_mock_rhai_register(
    engine: &mut Engine,
    mocks: Arc<Mutex<Vec<Dynamic>>>,    // fixture objects
    created: Arc<Mutex<Vec<Dynamic>>>,  // write-log for assertions
)

// module twin
pub fn k8s_mock_module(
    mocks: Arc<Mutex<Vec<Dynamic>>>,
    created: Arc<Mutex<Vec<Dynamic>>>,
) -> Module
```

Under the twin the free names are the real twin's short names — `k8s::resource`,
`k8s::new_raw`, `k8s::update_crd_cache` — and the workload constructors keep their names
(`k8s::get_deployment`, …), exactly as under the real `k8s_module`.

Unlike the real module, **no runtime context wiring is required**: `k8s_mock` never touches
`set_client_name`/`set_get_client`/the discovery cache, so it's safe to use in a plain unit test
with no cluster, no `set_client_name` call, nothing.

### Fixtures

`mocks` is a flat list of full object maps, each expected to carry `kind`, `metadata.name`, and
(for namespaced kinds) `metadata.namespace` — the same shape a real `kubectl get -o json` object
would have. `K8sGeneric`/`K8sObject`/workload lookups filter this list by kind + name(+
namespace). The kind match is an **exact, case-sensitive** string comparison against the name
passed to `k8s_resource(...)` — where the real client resolves kind *or* plural, case-insensitively
(in the mock, a fixture with `kind: "pods"` is not found by `k8s_resource("Pod", ...)`).

### Behavior notes — known differences from the real client

The surface (type and function names) is complete; the differences below are semantic, and they
are all accepted — the mock will not change (decision on record).

| Operation | Mock behavior |
|---|---|
| `k8s_resource(...)`, `get_deployment`/`get_deamonset`/`get_statefulset`/`get_job` | Constructs the mock handle immediately (no discovery round-trip); a `k8s_resource` handle snapshots the fixtures whose `kind` equals the requested name into the handle at that point and doesn't fail if nothing matches yet — that failure happens on the subsequent `get`/lookup; `k8s_resource(api_version, name, ns)` ignores group and version entirely (mocks are keyed by kind only). The four workload constructors are the exception: they search the fixture store **at construction** and fail immediately when none matches (see the `K8sDeploy`/… row below) |
| `.list()` / `.list(labels)` / `.list_meta()` | Return the **snapshot taken at handle construction**, shaped `{"items": [...]}` (no list metadata; the labels selector is ignored). Objects written after the handle was built never appear here — only `get`/`get_obj` fall back to the live store |
| `.get(name)` / `.get_meta(name)` / `.get_obj(name)` | Look up `name` in the snapshot first, then fall back to the live `mocks` store (matching kind + name + the handle's namespace); no match → the Rhai error `Failed to find <kind> <name> in the Mock database`. `get_meta` returns the **full object**, where the real client returns metadata only |
| `.create(data)` / `.replace(name, data)` / `.apply(name, data)` | Backfill `kind` from the handle; `apply` alone also fills `metadata.namespace` from the handle's ns **when absent** (and only when the body already carries `metadata` as a map — `create`/`replace` never touch the namespace). Deep-merge `data` onto any matching existing entry (kind + name + namespace) and record that **merged view** in `created` (an upsert: a second write for the same kind/name/ns merges into the existing `created` entry rather than appending), then upsert the written object into `mocks`. Inspect `created` after running a script to assert what would have been sent to the cluster |
| `.patch(name, data)` | Deep-merges `data` into the matching `mocks` entry (or inserts it) and **never records anything in `created`** — the one write that leaves no trace in the write-log, unlike create/replace/apply |
| `.delete(name)`, `.wait_deleted(...)` | No-ops that always succeed (the object stays in `mocks`) |
| `<K8sObject>.wait_condition`/`wait_status`/`wait_status_prop`/`wait_status_string` | Always immediately satisfied |
| `<K8sObject>.wait_for(predicate, timeout)` | Evaluates `predicate` **once** against the seeded object (no polling, `timeout` ignored): `Ok` if it returns `true`, error otherwise. Seed the object converged, or assert the error |
| `<K8sObject>.kind` / `.original_kind` | Both return the kind of the `k8s_resource(...)` handle the object came from |
| `<K8sGeneric>.exist` | Always `true` |
| `<K8sGeneric>.scope` | Always `"namespace"`, whatever the kind's real discovery scope |
| `update_k8s_crd_cache()` | Overridden to a no-op — the real macro-registered version would try to reach a live cluster to refresh discovery, which would panic without a wired client |
| `<K8sRaw>.get_url`/`get_cluster_version`/`get_api_resources` | Always return `{}` |
| `K8sDeploy`/`K8sDaemonSet`/`K8sStatefulSet`/`K8sJob` | All backed by one shared `K8sWorkloadMock` struct; construction matches a fixture on kind + name **and** namespace exactly (no fixture → `Failed to find <kind> <name> in namespace <ns> in the Mock database`); `.metadata`/`.spec`/`.status` read the matching sub-key straight out of the fixture object (`Dynamic::UNIT` if absent); `wait_available`/`wait_done` are no-ops |

---

## 3. `oci_mock` — feature `oci`

```rust
pub fn oci_mock_rhai_register(engine: &mut Engine)

// module twin
pub fn oci_mock_module() -> Module
```

No fixtures — every method returns a fixed canned value regardless of its arguments. Under the
twin the names are the same as under the registrar, qualified: `oci::new_registry` and
`oci::get_auth_from_file` (both were already short — no renaming on either side).

> **Caveat:** the mock registers the **same** Rhai type name as the real client —
> `Registry` — like `http_mock` and `k8s_mock` do for their types: a script that only does
> `let r = new_registry(reg, user, pass);` and calls methods on `r` sees an indistinguishable
> type (`type_of(r)` is `"Registry"` in both worlds). Only the Rust struct keeps a distinct
> name (`OciRegistryMock`).

| Signature | Always returns |
|---|---|
| `new_registry(registry, user, pass)` | `OciRegistryMock` (all three arguments ignored) |
| `.list_tags(repository)` | `[]` |
| `.get_manifest(repository, tag)` | `#{ "annotations": #{} }` |
| `.push_image(dir, repository, tag, annotations)` | `"sha256:mock-digest-for-testing"` |
| `.sign_image(repository, tag, digest, key_path)` | `()` (always succeeds, never actually shells out to `cosign`) |
| `get_auth_from_file(path, registry)` | `#{ "user": "", "pass": "" }` (both arguments ignored, never reads the file) |
