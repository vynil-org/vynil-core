# Handlebars helpers

Reference for every Handlebars helper available through `vynil_core::hbs::HandleBars`. For the
Rhai side see [rhai_helpers.md](rhai_helpers.md); for test doubles see [mocking.md](mocking.md).

## Cargo feature required

`vynil_core::hbs::HandleBars` and everything in this document live behind the `hbs` Cargo
feature. It's on by default, so nothing below changes for an existing `vynil-core = "x"`
dependency; it only matters if a consumer opts out with `default-features = false` to get a
Handlebars-only build (no Rhai engine at all — see [rhai_helpers.md](rhai_helpers.md)) or a
Rhai-only one (no Handlebars).

`register_helper_dir`/`rhai_register_helper_dir` (see below) additionally need the
`hbs-scripting` sub-feature, on by default alongside `hbs`. It's kept separate because it turns
on Handlebars's own `script_helper` feature, which pulls in Handlebars's own `rhai` ->
`smartstring`; `smartstring`'s orphan `impl Add<SmartString> for String` breaks `String +
&String` resolution anywhere else in the same build graph
([bodil/smartstring#7](https://github.com/bodil/smartstring/issues/7)) — notably
`async-graphql`'s `export_sdl.rs`. A consumer combining `hbs` with `async-graphql` (or anything
else hitting that pattern) should disable `hbs-scripting` (`default-features = false, features =
["hbs", ...]`) to keep `rhai`/`smartstring` out of their graph entirely.

## How registration works

`HandleBars::new()` builds on `handlebars_misc_helpers::new_hbs()` — strict mode on, HTML
auto-escaping disabled (`no_escape`, since output is usually YAML/JSON, not HTML) — then layers
`vynil-core`'s own helpers on top. Everything in this document is available on every
`HandleBars` instance out of the box (modulo the Cargo features noted below); there is no manual
registration step (unlike the Rhai `http`/`k8s`/`s3` modules).

Two more entry points let a consumer extend a `HandleBars` instance at runtime rather than at
compile time:

| Method | Loads |
|---|---|
| `register_helper_dir(dir)` | Every `*.rhai` file in `dir` as a Handlebars **script helper** (Handlebars' `script_helper` feature — the helper body is Rhai code; needs the `hbs-scripting` feature, see above) |
| `register_partial_dir(dir)` | Every `*.hbs` file in `dir` as a named template/partial |

## Restricted engine: `HandleBars::new_restricted()`

`HandleBars::new_restricted()` builds the engine from an **allow-list**: it registers only the
helpers that cannot reach the host (the Handlebars built-ins and case helpers, the `string`,
`regex`, `uuid` and `jsonnet` groups, and the vynil core helpers: JSON/JMESPath, `base64_*`,
`url_encode`, `to_decimal`, `header_basic`, `concat`, `crc32_hash` and the feature-gated
`crypto` / `password` ones). It does not start from `new()` and remove helpers, so a host helper
added upstream by a dependency bump, or by a feature enabled elsewhere in your dependency graph,
never leaks in. The helpers below are never registered:

| Never registered | Why it touches the host |
|---|---|
| `read_to_str` | Reads a file |
| `env_var` | Reads the process environment |
| `canonicalize` | Resolves the filesystem |
| `parent`, `file_name`, `extension` | Canonicalize their input first, so they probe file existence |
| `http_get`, `gitignore_io` | Make network requests (upstream feature `http_attohttpc`) |

A template calling one of them fails with `Error::HbsRenderError` (strict mode) and renders
no host data. Every registered helper behaves as under `new()`.

Use it for templates fed by untrusted third-party data, where a template must not read files or
environment variables of the process rendering it.

This is a restriction of the constructor only. `engine_mut()` gives direct access to the
underlying `Handlebars` and can register those helpers again, and `register_helper_dir`
(feature `hbs-scripting`) loads script helpers from a directory the caller chooses. Whatever
registered after construction is outside the guarantee: do not rely on `new_restricted()` alone
where the template author or the helper directory is not trusted.

## Feature tags

Two helper groups are gated by a `vynil-core` Cargo feature beyond `hbs` itself:

- `gen_password` / `gen_password_alphanum`, behind feature **`password`** (off by default, unlike
  the other two below — same reasoning as the Rhai side: a consumer with its own password
  semantics doesn't get a name collision).
- `argon_hash` / `bcrypt_hash` / `gen_private_key`, behind feature **`crypto`** (on by default,
  like `hbs` — see section 12 below). `crc32_hash` in that same section needs only `hbs`.

Everything else in this document — including every `handlebars_misc_helpers` sub-group below
(string / jsonnet / regex / uuid) — is compiled in unconditionally. Those sub-groups are
themselves Cargo features, but of the `handlebars_misc_helpers` *dependency*, fixed once in
`vynil-core`'s own `Cargo.toml`; a consumer of `vynil-core` cannot toggle them independently. They
are grouped below by origin for orientation, not because you can turn them off.

The json group (section 8 below) is the one exception to "grouped by `handlebars_misc_helpers`
origin": it's vendored directly in `vynil-core` (`src/hbs_json.rs`), not pulled from that crate.
`handlebars_misc_helpers` 0.17.0 still pins `jmespath 0.3.0`, whose `Function` trait lacks a
`Send` bound — a hard compile failure for any consumer whose dependency graph also unifies in
`lazy_static`'s `spin_no_std` feature (seen via `rsa`/`num-bigint-dig`, e.g. behind an OIDC
stack). `vynil-core` depends on `jmespath 0.5.0` directly instead, which fixed that bound
upstream, and reimplements the six helpers against it.

> **Note on `CORE_HBS_HELPERS`:** `vynil_core::hbs::CORE_HBS_HELPERS` is a curated `&[&str]`
> constant listing helper names, meant for consumers that need to introspect "what's available"
> (e.g. to validate user-supplied templates). It is not exhaustive — in particular it omits most
> of the `cruet`-based case-conversion family documented further down, in the
> "`handlebars_misc_helpers` — string feature" section (only
> `to_lower_case`/`to_upper_case`/`trim*`/`replace`/`quote`/`unquote`/`first_non_empty`
> are listed there, even though the rest are registered and callable). This document reflects what
> is actually registered, not just what's in that constant.

---

## 1. Handlebars-rs built-ins (always)

Standard control-flow, from the `handlebars` crate itself, no feature involved:

| Helper | Purpose |
|---|---|
| `{{#if cond}}…{{else}}…{{/if}}` | Conditional |
| `{{#unless cond}}…{{/unless}}` | Inverted conditional |
| `{{#each items}}…{{/each}}` | Iteration (`this`, `@index`, `@key`, …) |
| `{{#with value}}…{{/with}}` | Rescopes the block context |
| `{{lookup obj "key"}}` | Dynamic property/index lookup |
| `{{{{raw}}}}…{{{{/raw}}}}` | Emits its contents unprocessed |
| `{{log value}}` | Logs at the configured level |
| `{{*inline "name"}}…{{/inline}}` | Decorator — defines an inline partial named `name` for the rest of the template |

## 2. Comparison / logic extras (always)

Also from `handlebars` core (`helper_extras`), always registered:

| Helper | Signature | Notes |
|---|---|---|
| `eq` | `(a, b)` | |
| `ne` | `(a, b)` | |
| `gt` / `gte` / `lt` / `lte` | `(a, b)` | Numeric/lexicographic comparison |
| `and` / `or` | `(a, b, …)` | |
| `not` | `(a)` | |
| `len` | `(collection)` | Length of a string, array, or object |

Typically used inside `{{#if (eq a b)}}`.

## 3. Case-conversion — `handlebars` crate's `string_helpers` feature (always, via Cargo.toml)

Backed by [`heck`](https://docs.rs/heck):

| Helper | Example |
|---|---|
| `lowerCamelCase` | `lower camel case` → `lowerCamelCase` |
| `upperCamelCase` | → `UpperCamelCase` |
| `snakeCase` | → `snake_case` |
| `kebabCase` | → `kebab-case` |
| `shoutySnakeCase` | → `SHOUTY_SNAKE_CASE` |
| `shoutyKebabCase` | → `SHOUTY-KEBAB-CASE` |
| `titleCase` | → `Title Case` |
| `trainCase` | → `Train-Case` |

Each takes a single string argument, e.g. `{{snakeCase "Hello World"}}`.

> There's a second, independent case-conversion family further down, in the
> "`handlebars_misc_helpers` — string feature" section (`to_snake_case`, `to_camel_case`, …,
> backed by `cruet` instead of `heck`). Both are registered;
> pick whichever naming/behavior you need — they aren't identical in edge-case handling.

## 4. `handlebars_misc_helpers` — path (always)

| Helper | Example (on `/hello/bar/foo.txt`) |
|---|---|
| `parent` | `/hello/bar` |
| `file_name` | `foo.txt` |
| `extension` | `txt` |
| `canonicalize` | Resolves `.`/`..` and symlinks via the filesystem; empty string if the path doesn't exist |

`parent`/`file_name`/`extension` canonicalize the path first *if it exists on disk*, so relative
inputs like `.` behave sensibly; if the path doesn't exist they operate on the literal string.

## 5. `handlebars_misc_helpers` — env (always)

| Helper | Returns |
|---|---|
| `env_var "NAME"` | The environment variable's value, or `""` if unset. A few names are special-cased to Rust's `std::env::consts`/`USER` lookup instead of a real env var: `ARCH`, `OS`, `FAMILY`, `DLL_EXTENSION`, `DLL_PREFIX`, `DLL_SUFFIX`, `EXE_EXTENSION`, `EXE_SUFFIX`, `USERNAME` (tries `USERNAME`/`username`/`USER`/`user`, else `"noname"`) |

## 6. `handlebars_misc_helpers` — file (always)

| Helper | Returns |
|---|---|
| `read_to_str "path"` | File contents as a string; `""` (with a warning) if the path doesn't exist |

## 7. `handlebars_misc_helpers` — string feature

Trim/replace/quote basics:

| Helper | Signature | Notes |
|---|---|---|
| `to_lower_case` | `(s)` | |
| `to_upper_case` | `(s)` | |
| `trim` | `(s)` | |
| `trim_start` | `(s)` | |
| `trim_end` | `(s)` | |
| `replace` | `(s, from, to)` | |
| `quote` | `(quote_char, s)` | Wraps `s` in `quote_char` (first char of that arg), escaping as needed |
| `unquote` | `(s)` | Strips a matching pair of quotes; returns `s` unchanged if unquoting fails |
| `first_non_empty` | `(a, b, …)` | First argument that is a non-empty string (nulls/non-strings are skipped); `""` if none match |

Case-conversion family (`cruet`-backed; each is a `to_*`/`is_*` pair, `is_*` returns a bool):

| `to_*` helper | `is_*` helper | Example output |
|---|---|---|
| `to_camel_case` | `is_camel_case` | `helloFooBars` |
| `to_pascal_case` | `is_pascal_case` | `HelloFooBars` |
| `to_snake_case` | `is_snake_case` | `hello_foo_bars` |
| `to_screaming_snake_case` | `is_screaming_snake_case` | `HELLO_FOO_BARS` |
| `to_kebab_case` | `is_kebab_case` | `hello-foo-bars` |
| `to_train_case` | `is_train_case` | `Hello-Foo-Bars` |
| `to_sentence_case` | `is_sentence_case` | `Hello foo bars` |
| `to_title_case` | `is_title_case` | `Hello Foo Bars` |
| `to_class_case` | `is_class_case` | `HelloFooBar` (singularized) |
| `to_table_case` | `is_table_case` | `hello_foo_bars` (pluralized snake_case) |
| `to_foreign_key` | `is_foreign_key` | e.g. `Message` → `message_id` |

Plus, with no `is_*` counterpart:

| Helper | Purpose |
|---|---|
| `ordinalize` | `1` → `1st` |
| `deordinalize` | `1st` → `1` |
| `deconstantize` | Strips the last `::`-separated segment (`Foo::Bar::Baz` → `Foo::Bar`) |
| `demodulize` | Keeps only the last `::`-separated segment (`Foo::Bar::Baz` → `Baz`) |
| `to_plural` | `bar` → `bars` |
| `to_singular` | `bars` → `bar` |

## 8. json (vendored in `vynil-core`, always)

Vendored from `handlebars_misc_helpers` 0.17.0's json feature (CC0-1.0) into `src/hbs_json.rs`,
against `jmespath 0.5.0` directly rather than the crate's own pinned `jmespath 0.3.0` — see
"Feature tags" above for why.

Five of the six accept an optional `format=` hash argument (hash argument only, never positional):
`"json"` (default), `"json_pretty"`, `"yaml"`, `"toml"`, or `"toml_pretty"`. An absent or
non-string `format` means `json`; the value is matched case-insensitively (`format="YAML"` works),
and any other string value — the empty string included — fails the render with
`data format unknown '<value>'` rather than falling back to `json`. `json_query` is the one
exception: it never reads `format` — see its row below.

| Helper | Form | Purpose |
|---|---|---|
| `str_to_json` | `(s)` | Parses `s` (in `format`) into a JSON value |
| `json_to_str` | `(value)` | Serializes `value` to a string in `format` |
| `{{#from_json}}…{{/from_json}}` | block | Parses the block's rendered content as JSON, re-emits it in `format` |
| `{{#to_json}}…{{/to_json}}` | block | Parses the block's rendered content as `format`, re-emits it as pretty JSON |
| `json_query` | `(expr, data)` | [JMESPath](https://jmespath.org/) query against a JSON value; renders the result as a JSON value (navigable in the template), not a string; `null` if nothing matches. Does **not** read `format` — passing one is a no-op |
| `json_str_query` | `(expr, s)` | Same JMESPath query, but parses `s` first (as `format`); container results (arrays/objects) are re-serialized in `format`, any other result falls back to trimmed plain JSON |

Whether empty input is tolerated depends on the *nature of the parameter*, not on emptiness alone:

- Empty strings short-circuit without reaching a parser: `{{ str_to_json "" }}`,
  `{{ json_to_str "" }}`, `{{ json_query "foo" "" }}`, `{{ json_str_query "foo" "" }}` and an
  empty (or absent) block body all render an empty string, in any of the five recognized formats.
- `null` in a JSON-*value* parameter renders an empty string too: `{{ json_to_str null }}` → `""`
  in any of the five recognized formats, and `{{ json_query "foo" null }}` renders
  the null result — empty output.
- `null` in a *string* parameter is an error, not an empty string: the string parameters
  (`str_to_json`'s `s`, `json_str_query`'s `expr` and `s`) reject every non-string —
  `{{ str_to_json null }}` and `{{ str_to_json 5 }}` both fail the render with
  `param 0 (the string) is not a string`. A missing parameter says so as well:
  `param <N> (the string) not found`, and `param 0 (the json) not found` for `json_to_str`'s
  value.

Apart from those empty/`null` short-circuits there is no silent fallback: unparsable content, an
unknown `format` value or an invalid JMESPath expression all fail the render — even on empty or
`null` input. On the five helpers that read `format`, the short-circuits spare the *rendering*,
never the `format` validation: `{{ json_to_str null format="zzz" }}` fails with
`data format unknown 'zzz'` rather than rendering `""` (same on the empty and `json_str_query`
sides). `json_query` reads no `format` at all and validates nothing:
`{{ json_query "foo" "" format="zzz" }}` renders `""`.

The short-circuit is on the *data*, never on the *expression*: an empty expression is simply an
invalid JMESPath expression, so `{{ json_query "" "" }}` and `{{ json_str_query "" "" }}` fail
with `query failure for expression ''` even though their data is empty too.

A non-string *first* parameter of `json_query` is rejected too, but by a different error family:
it is not read by the path above — it is a typed `handlebars_helper` parameter (`expr: str`), so
the failure is a Handlebars `ParamTypeMismatchForName`, not a `param <N> (the string) is not a
string` message.

A JMESPath non-match is not an error, but the two query helpers render it asymmetrically:
`json_query` yields a *null value* in the template — falsy, so
`{{#if (json_query "missing" data)}}…{{else}}…{{/if}}` takes the `else` branch — while
`json_str_query` renders the *empty string*: its result goes through the same writer as
`json_to_str`, whose `null` branch precedes the *dispatch* on `format` — not its validation.

## 9. `handlebars_misc_helpers` — jsonnet feature

| Helper | Form | Purpose |
|---|---|---|
| `{{#jsonnet}}…{{/jsonnet}}` | block | Evaluates the block's rendered content as a [Jsonnet](https://jsonnet.org/) snippet, emits the resulting JSON |

## 10. `handlebars_misc_helpers` — regex feature

| Helper | Signature | Returns |
|---|---|---|
| `regex_captures` | `pattern=".."  on=".."` (hash args, both required) | An object mapping each named capture group to its match, plus positional `_0`, `_1`, … for every group (named or not); `null` if the pattern doesn't match |
| `regex_is_match` | `pattern=".."  on=".."` | `bool` |

## 11. `handlebars_misc_helpers` — uuid feature

| Helper | Returns |
|---|---|
| `uuid_new_v4` | A random UUID v4 |
| `uuid_new_v7` | ⚠ Also generates a v4, not a real v7 — that's a bug in `handlebars_misc_helpers` 0.17.0's `uuid_new_v7_fct` (it calls `Uuid::new_v4()`), not a `vynil-core` behavior. Don't rely on v7's time-ordering property from this helper. |

---

## 12. `vynil-core`'s own helpers (always given `hbs`, three need `crypto` too)

| Helper | Signature | Returns |
|---|---|---|
| `concat` | `(a, b)` | String concatenation |
| `to_decimal` | `(octal: string)` | The string parsed as base-8, as a decimal string. A non-octal string and a non-string argument alike render `0` after a `tracing::warn!` — `0`, not the `""` the other helpers here fall back to — and neither path ever raises a `RenderError` |
| `base64_encode` | `(s)` | |
| `base64_decode` | `(s)` | `""` and a warning on invalid input, rather than erroring the render |
| `url_encode` | `(s)` | Percent-encoding |
| `header_basic` | `(username, password)` | `"Basic <base64(user:pass)>"` — a ready-to-use `Authorization` header value |
| `argon_hash` | `(password)` | Argon2 hash (fresh random salt each call) — needs `crypto` |
| `bcrypt_hash` | `(password)` | bcrypt hash, `DEFAULT_COST` — needs `crypto`. Passwords of `72` bytes or more are refused by the hashing backend (the accepted ceiling is `71` bytes: `71` passes, `72` is the first refusal); here the error is swallowed after a `tracing::warn!` and renders as `""` rather than failing the render |
| `crc32_hash` | `(text)` | CRC-32, as a number |
| `gen_private_key` | `(algo, {bits=4096})` | PKCS8 PEM. `algo`: `"rsa"` or `"ed25519"` (bits ignored for ed25519) — needs `crypto` |

All of the string-typed arguments above tolerate non-string JSON input by falling back to `""`
(with a `tracing::warn!`) rather than failing the render — except `to_decimal`, which falls back
to `0` instead (see its row above), and `gen_private_key`, whose `algo` is a typed parameter:
there a non-string fails the render with a Handlebars parameter-type error, with no warn and no
fallback (an unknown algorithm *name* is a different case and renders `""` after a warn).

## 13. `vynil-core`'s own helpers — feature `password`

| Helper | Signature | Returns |
|---|---|---|
| `gen_password` | `(len, {lower=1, upper=1, digits=1, symbols=1})` | Password with at least that many of each class |
| `gen_password_alphanum` | `(len)` | Same as `gen_password` with `symbols=0` |

Both return `""` (with a warning) instead of failing the render if the generation spec is
invalid (e.g. minimums exceeding `len`).
