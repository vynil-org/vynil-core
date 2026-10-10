//! Kubernetes handlers.
//!
//! Feature `k8s` only (implies `rhai`). Provides `K8sGeneric` (CRUD via SSA + discovery cache),
//! `K8sObject` (per-object helpers), `K8sRaw` (raw API discovery) and typed workload helpers
//! (`K8sDeploy`, `K8sJob`, …). The API is Rhai-facing throughout (methods return [`crate::RhaiRes`]).
//!
//! The discovery cache is wired via `OnceLock` function pointers injected by the consumer (see
//! `context_is_wired` / `set_get_client` …) — the crate itself does not assume a kubeconfig.

use std::sync::{LazyLock, OnceLock};

use crate::{Error, Result, RhaiRes, rhai_err, rhai_err_str};
use k8s_openapi::api::{
    apps::v1::{DaemonSet, Deployment, StatefulSet},
    batch::v1::Job,
};
use kube::{
    Client, Resource, ResourceExt,
    api::{
        Api, DeleteParams, DynamicObject, ListParams, ObjectList, PartialObjectMeta, Patch, PatchParams,
        PostParams,
    },
    discovery::{ApiCapabilities, ApiResource, Discovery, Scope},
    runtime::wait::{Condition, await_condition, conditions},
};
use rhai::{Dynamic, Engine, serde::to_dynamic};
use serde_json::json;
use tokio::sync::RwLock;

// ── Context function pointers (initialized by common at startup) ─────────────

/// Injected kube [`Client`] factory, set by the consumer via [`set_get_client`].
pub static GET_CLIENT: OnceLock<Box<dyn Fn() -> Client + Send + Sync>> = OnceLock::new();
/// Injected common-labels accessor, set by the consumer via [`set_get_labels`].
pub static GET_LABELS: OnceLock<Box<dyn Fn() -> Option<serde_json::Value> + Send + Sync>> = OnceLock::new();
/// Injected owner-reference accessor, set by the consumer via [`set_get_owner`].
pub static GET_OWNER: OnceLock<Box<dyn Fn() -> Option<serde_json::Value> + Send + Sync>> = OnceLock::new();
/// Injected owner-namespace accessor, set by the consumer via [`set_get_owner_ns`].
pub static GET_OWNER_NS: OnceLock<Box<dyn Fn() -> Option<String> + Send + Sync>> = OnceLock::new();

/// Injects the kube-client factory; first call wins, later calls are ignored.
pub fn set_get_client(f: Box<dyn Fn() -> Client + Send + Sync>) {
    GET_CLIENT.set(f).ok();
}
/// Injects the common-labels accessor; first call wins, later calls are ignored.
pub fn set_get_labels(f: Box<dyn Fn() -> Option<serde_json::Value> + Send + Sync>) {
    GET_LABELS.set(f).ok();
}
/// Injects the owner-reference accessor; first call wins, later calls are ignored.
pub fn set_get_owner(f: Box<dyn Fn() -> Option<serde_json::Value> + Send + Sync>) {
    GET_OWNER.set(f).ok();
}
/// Injects the owner-namespace accessor; first call wins, later calls are ignored.
pub fn set_get_owner_ns(f: Box<dyn Fn() -> Option<String> + Send + Sync>) {
    GET_OWNER_NS.set(f).ok();
}

/// True if the client name (`crate::set_client_name`) and the 4 context accessors have been
/// injected (see `common::context::wire_core_k8s`).
pub fn context_is_wired() -> bool {
    GET_CLIENT.get().is_some()
        && crate::client_name_is_set()
        && GET_LABELS.get().is_some()
        && GET_OWNER.get().is_some()
        && GET_OWNER_NS.get().is_some()
}

fn call_get_labels() -> Option<serde_json::Value> {
    GET_LABELS.get().and_then(|f| f())
}
fn call_get_owner() -> Option<serde_json::Value> {
    GET_OWNER.get().and_then(|f| f())
}
fn call_get_owner_ns() -> Option<String> {
    GET_OWNER_NS.get().and_then(|f| f())
}

/// Builds the shared kube client from the injected [`GET_CLIENT`] factory.
///
/// # Panics
///
/// Panics if the k8s context was not wired (see [`context_is_wired`]).
#[allow(clippy::expect_used)] // panic by design: no error channel in the CLIENT/RAW_CLIENT static initializers (vyvil-core.sdd)
fn build_client() -> Client {
    let f = GET_CLIENT.get().expect("k8s context not initialized");
    crate::rt::block_on(async move { f() }).expect("k8s client factory requires a multi-thread tokio runtime")
}

/// Wait timeout as a [`std::time::Duration`]; a negative timeout clamps to zero (immediate timeout).
fn timeout_duration(timeout: i64) -> std::time::Duration {
    std::time::Duration::from_secs(u64::try_from(timeout).unwrap_or(0))
}

/// Normalizes a requested namespace: an empty string is treated as absent (k8s.sdd `Must`,
/// décision actée), so a handle falls back to all-namespaces instead of an invalid URL.
fn normalize_ns(ns: Option<String>) -> Option<String> {
    ns.filter(|s| !s.is_empty())
}

// ── Helper de wait unique (k8s.sdd `Must` l.183-199, décision actée) ─────────
//
// Les dix `await_condition` du module (six de `K8sObject`, quatre workloads) passent
// désormais par `wait_object` — seul appelant du module (le `Must not` « Réessayer une
// erreur hors des waits » interdit tout autre retry). Forme mesurée sur kube/kube-runtime
// 3.1.0 : la fonction libre `watcher::watch` n'existe plus et `watch_object` renvoie un
// `impl Stream` que le crate ne peut pas dérouler sans `futures` — sortie de la feature
// `k8s` (tâche Cargo close) et non ré-exportée par `kube`. `await_condition` 3.1 rend
// pourtant toute la matière du contrat : la PREMIÈRE erreur du watch sous
// `wait::Error::ProbeFailed(watcher::Error)`, et les événements « `Deleted` ou absence
// après l'avoir vu » par le `Ok(None)` de `watch_object` (mesuré : `Event::Delete(_)` et
// `InitDone if !obj_seen` → `None`) que la `Condition` reçoit comme `None`. Le retry est
// donc une boucle d'appels successifs à `await_condition`, avec le backoff posé par le
// helper — la lib documente d'ailleurs « You can apply your own backoff by not polling
// the stream ». Le `410 Gone` est traité en transitoire : mesuré, l'`ERROR` event 410
// resurface en `WatchError(Status)` ET remet la machine d'état à la re-LISTE (« HTTP
// GONE, means we have desynced and need to start over and re-list ») — le helper
// recommence donc sur une liste fraîche, resourceVersion renouvelée par la lib.

/// Backoff exponentiel entre deux tentatives de watch après erreur transitoire. Le
/// contrat impose la forme (« backoff exponentiel », tant que le timeout global n'est
/// pas écoulé), pas les constantes — valeurs mesurables par les tests (timeout de test
/// en secondes, granularité du contrat).
const WAIT_BACKOFF_INITIAL: std::time::Duration = std::time::Duration::from_millis(100);
const WAIT_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(10);

/// Verdict du classement d'une erreur de watch (k8s.sdd `Must`) : réessai avec backoff
/// ou échec immédiat.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WatchFailure {
    Transient,
    Definitive,
}

/// Codes HTTP transitoires (k8s.sdd) : `429`, `5xx`, timeout de requête (`408`) et
/// `410 Gone` de `resourceVersion` périmée.
fn transient_wait_code(code: u16) -> bool {
    matches!(code, 408 | 410 | 429) || (500..=599).contains(&code)
}

/// Classe un `kube::Error` porté par une erreur de watch : statut HTTP par code ;
/// erreurs de transport (hyper, service tower, lecture du flux d'événements) = coupure
/// de connexion ou timeout → transitoire ; tout le reste (désérialisation, requête mal
/// formée…) = famille « requête invalide » → définitive.
fn transient_kube_wait_error(err: &kube::Error) -> WatchFailure {
    match err {
        kube::Error::Api(status) if transient_wait_code(status.code) => WatchFailure::Transient,
        kube::Error::HyperError(_) | kube::Error::Service(_) | kube::Error::ReadEvents(_) => {
            WatchFailure::Transient
        }
        _ => WatchFailure::Definitive,
    }
}

/// Classe l'erreur rendue par `await_condition` (k8s.sdd « classe les erreurs »).
fn classify_wait_error(err: &kube::runtime::wait::Error) -> WatchFailure {
    match err {
        kube::runtime::wait::Error::ProbeFailed(watcher_err) => match watcher_err {
            kube::runtime::watcher::Error::InitialListFailed(e)
            | kube::runtime::watcher::Error::WatchStartFailed(e)
            | kube::runtime::watcher::Error::WatchFailed(e) => transient_kube_wait_error(e),
            kube::runtime::watcher::Error::WatchError(status) => {
                if transient_wait_code(status.code) {
                    WatchFailure::Transient
                } else {
                    WatchFailure::Definitive
                }
            }
            // réponse sans resourceVersion : la resource ne supporte pas le watch,
            // réessayer ne peut rien changer — famille requête invalide.
            kube::runtime::watcher::Error::NoResourceVersion => WatchFailure::Definitive,
        },
    }
}

/// Attend que `cond` soit satisfaite sur l'objet `name`, timeout global en main propre
/// (toutes les waits du module quantifient via [`timeout_duration`]). Rend :
///
/// * `Ok(())` — condition satisfaite sur un objet du watch, ou (absence) acceptée par la
///   condition — c'est le succès de `wait_deleted` (`is_deleted` valide `None`) ;
/// * `Err(Error::Other)` chaîne exacte `object {name} was deleted while waiting` —
///   événement `Deleted` ou absence APRÈS l'avoir vu ; l'objet pas encore vu reste en
///   attente (comportement d'avant, hors du contrat de suppression) ;
/// * `Err(Error::KubeWaitError)` — erreur définitive du watch (401, 403, 404, requête
///   invalide), immédiate ;
/// * `Err(Error::Elapsed)` — timeout global écoulé (réessais à backoff exponentiel
///   autant que le temps reste : 429, 5xx, timeout, coupure, `410`).
async fn wait_object<T, C>(
    api: Api<T>,
    name: &str,
    timeout: std::time::Duration,
    cond: C,
) -> Result<(), Error>
where
    T: Clone + std::fmt::Debug + Send + serde::de::DeserializeOwned + Resource + 'static,
    C: Condition<T>,
{
    // L'objet a-t-il été vu au moins une fois : distingue « absence après l'avoir vu »
    // (suppression → échec) de « pas encore là » (on continue d'attendre).
    let seen = std::cell::Cell::new(false);
    // Budget temps restant tenu en Duration (jamais d'addition d'Instant : le
    // `arithmetic_side_effects` du harnais, et `timeout` peut être un nombre de secondes
    // énorme après clamp bas seulement — le budget ne déborde jamais, il se soldera en
    // Elapsed).
    let mut remaining = timeout;
    let mut backoff = WAIT_BACKOFF_INITIAL;
    loop {
        let attempt = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(
            remaining,
            await_condition(api.clone(), name, |obj: Option<&T>| match obj {
                Some(_) => {
                    seen.set(true);
                    cond.matches_object(obj)
                }
                // L'absence satisfait les conditions qui l'acceptent (`wait_deleted`) ;
                // sinon elle ne clôt la wait comme suppression que si l'objet avait été
                // vu — sinon ce n'est pas une suppression subie, c'est l'objet attendu
                // qui n'est pas encore né.
                None => cond.matches_object(None) || seen.get(),
            }),
        )
        .await;
        match outcome {
            Err(elapsed) => return Err(Error::Elapsed(elapsed)),
            Ok(Ok(Some(_))) => return Ok(()),
            Ok(Ok(None)) => {
                if cond.matches_object(None) {
                    return Ok(());
                }
                return Err(Error::Other(format!("object {name} was deleted while waiting")));
            }
            Ok(Err(err)) => {
                if classify_wait_error(&err) == WatchFailure::Definitive {
                    return Err(Error::KubeWaitError(err));
                }
                // Transitoire : backoff borné par le temps restant ; si le délai
                // d'échéance coupe le sommeil, c'est le timeout global qui a gagné.
                remaining = remaining.saturating_sub(attempt.elapsed());
                let slept = tokio::time::Instant::now();
                if let Err(elapsed) = tokio::time::timeout(remaining, tokio::time::sleep(backoff)).await {
                    return Err(Error::Elapsed(elapsed));
                }
                remaining = remaining.saturating_sub(slept.elapsed());
                backoff = backoff.saturating_mul(2).min(WAIT_BACKOFF_MAX);
            }
        }
    }
}

// ── k8sgeneric ───────────────────────────────────────────────────────────────

/// Shared kube client, built from the injected factory on first access.
///
/// Panics on first access if the k8s context was not wired (see [`context_is_wired`]).
pub static CLIENT: LazyLock<Client> = LazyLock::new(build_client);

fn aggregated_apiservice_group(spec: &serde_json::Value) -> Option<String> {
    spec.get("service").filter(|s| !s.is_null())?;
    spec.get("group")
        .and_then(|g| g.as_str())
        .filter(|g| !g.is_empty())
        .map(std::string::ToString::to_string)
}

async fn excluded_apiservice_groups() -> Vec<String> {
    let ar = ApiResource {
        group: "apiregistration.k8s.io".to_string(),
        version: "v1".to_string(),
        api_version: "apiregistration.k8s.io/v1".to_string(),
        kind: "APIService".to_string(),
        plural: "apiservices".to_string(),
    };
    let api: Api<DynamicObject> = Api::all_with(CLIENT.clone(), &ar);
    match api.list(&ListParams::default()).await {
        Ok(list) => list
            .items
            .iter()
            .filter_map(|obj| aggregated_apiservice_group(obj.data.get("spec")?))
            .collect(),
        Err(e) => {
            tracing::warn!("E_DISCOVERY_WARN: cannot list APIServices ({e}), proceeding without exclusions");
            vec![]
        }
    }
}

async fn async_populate_cache() -> Result<Discovery> {
    let excluded = excluded_apiservice_groups().await;
    let excluded_refs: Vec<&str> = excluded.iter().map(std::string::String::as_str).collect();
    Discovery::new(CLIENT.clone())
        .exclude(&excluded_refs)
        .run()
        .await
        .map_err(Error::KubeError)
}

#[allow(clippy::expect_used)] // panic by design: no error channel in the CACHE static initializer (vyvil-core.sdd)
fn populate_cache() -> Discovery {
    crate::rt::block_on(async_populate_cache())
        .and_then(|r| r)
        .expect("create discovery (excluding api-services)")
}

/// Discovery cache, populated from the cluster on first access.
///
/// Panics on first access if discovery fails; use [`update_cache`] for a graceful refresh.
pub static CACHE: LazyLock<RwLock<Discovery>> = LazyLock::new(|| RwLock::new(populate_cache()));

/// Refreshes the discovery cache from the cluster, keeping the previous one on timeout or failure.
///
/// Exposed to Rhai as `update_k8s_crd_cache`.
pub fn update_cache() {
    // La voie secours `rt::block_on` rend une erreur typée que `update_cache` n'a pas de
    // canal pour rendre (rend unité, k8s.sdd) : l'échec du pont est tracé par un warn de la
    // famille `E_DISCOVERY_WARN` nommant son exception, l'ancien cache est gardé (décision
    // du développeur principal 2026-10-10 — le silence du `.ok()` ne contractait rien).
    if let Err(e) = crate::rt::block_on(async move {
        match tokio::time::timeout(std::time::Duration::from_mins(1), async_populate_cache()).await {
            Ok(Ok(discovery)) => {
                *CACHE.write().await = discovery;
            }
            Ok(Err(e)) => {
                tracing::warn!("E_DISCOVERY_WARN: update_k8s_crd_cache failed ({e}), keeping old cache");
            }
            Err(_) => {
                tracing::warn!("E_DISCOVERY_TIMEOUT: update_k8s_crd_cache exceeded 60s, keeping old cache");
            }
        }
    }) {
        tracing::warn!("E_DISCOVERY_WARN: update_k8s_crd_cache bridge failed ({e}), keeping old cache");
    }
}

/// A single live Kubernetes object: its API handle plus the metadata fetched at creation.
#[derive(Clone, Debug)]
pub struct K8sObject {
    /// API handle used for every operation on this object.
    pub api: Api<DynamicObject>,
    /// Partial metadata fetched when the object was obtained (via `get_obj`).
    pub obj: PartialObjectMeta,
    /// Kind recorded on the [`K8sGeneric`] this object came from.
    pub kind: String,
}
impl K8sObject {
    /// Deletes the object with foreground propagation.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::KubeError`] if the API call fails.
    pub fn rhai_delete(&mut self) -> RhaiRes<()> {
        crate::rt::block_on(async move {
            self.api
                .delete(&self.obj.name_any(), &DeleteParams::foreground())
                .await
                .map_err(Error::KubeError)
                .map(|_| ())
        })
        .and_then(|r| r)
        .map_err(rhai_err)
    }

    /// Waits until this object's uid is observed as deleted, up to `timeout` seconds.
    ///
    /// A `Deleted` watch event (or the object's absence) is this wait's success, where it
    /// fails the other waits (see the shared `wait_object` helper, k8s.sdd `Must`).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the object has no uid, if `timeout` elapses ([`Error::Elapsed`])
    /// or if the watch fails definitively ([`Error::KubeWaitError`]).
    pub fn rhai_wait_deleted(&mut self, timeout: i64) -> RhaiRes<()> {
        let name = self.obj.name_any();
        let uid = self
            .obj
            .uid()
            .ok_or_else(|| rhai_err_str(format!("cannot wait for deletion of {name}: uid is missing")))?;
        crate::rt::block_on(wait_object(
            self.api.clone(),
            &name,
            timeout_duration(timeout),
            conditions::is_deleted(&uid),
        ))
        .and_then(|r| r)
        .map_err(rhai_err)
    }

    /// This object's metadata rendered as a Rhai value.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`] if the metadata cannot be
    /// converted to a Rhai value.
    pub fn get_metadata(&mut self) -> RhaiRes<Dynamic> {
        let v = serde_json::to_value(self.obj.metadata.clone())
            .map_err(|e| rhai_err(Error::SerializationError(e)))?;
        to_dynamic(v)
    }

    /// Runtime kind read from the object's own type fields (empty when absent).
    pub fn get_kind(&mut self) -> String {
        if let Some(t) = self.obj.types.clone() {
            t.kind
        } else {
            String::new()
        }
    }

    /// Kind recorded on the [`K8sGeneric`] this object was fetched from.
    pub fn original_kind(&mut self) -> String {
        self.kind.clone()
    }

    /// Condition matching when `status.conditions` contains `cond` with `status: "True"`.
    #[must_use]
    pub fn is_condition(cond: String) -> impl Condition<DynamicObject> {
        move |obj: Option<&DynamicObject>| {
            let Some(conditions) = obj
                .and_then(|o| o.data.get("status"))
                .and_then(|s| s.get("conditions"))
                .and_then(|c| c.as_array())
            else {
                return false;
            };
            conditions.iter().any(|c| {
                c.get("type").and_then(|t| t.as_str()) == Some(cond.as_str())
                    && c.get("status").and_then(|s| s.as_str()) == Some("True")
            })
        }
    }

    /// Waits up to `timeout` seconds for `condition` to become `True` on this object.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if `timeout` elapses ([`Error::Elapsed`]), the object is
    /// deleted mid-wait, or the watch fails definitively ([`Error::KubeWaitError`]).
    /// Transient watch errors (429, 5xx, timeouts, connection drops, `410 Gone`) are
    /// retried with exponential backoff until the global timeout (shared `wait_object`
    /// helper, k8s.sdd `Must`).
    pub fn wait_condition(&mut self, condition: String, timeout: i64) -> RhaiRes<()> {
        let name = self.obj.name_any();
        crate::rt::block_on(wait_object(
            self.api.clone(),
            &name,
            timeout_duration(timeout),
            Self::is_condition(condition),
        ))
        .and_then(|r| r)
        .map_err(rhai_err)
    }

    /// Condition matching when `status.<prop>` is the boolean `true`.
    #[must_use]
    pub fn is_status(prop: String) -> impl Condition<DynamicObject> {
        move |obj: Option<&DynamicObject>| {
            obj.and_then(|o| o.data.get("status"))
                .and_then(|s| s.get(prop.as_str()))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        }
    }

    /// Condition matching when `status.<prop>` is present and not null.
    #[must_use]
    pub fn have_status(prop: String) -> impl Condition<DynamicObject> {
        move |obj: Option<&DynamicObject>| {
            obj.and_then(|o| o.data.get("status"))
                .and_then(|s| s.get(prop.as_str()))
                .is_some_and(|v| !v.is_null())
        }
    }

    /// Condition matching when `status.<prop>` equals the string `value`.
    #[must_use]
    pub fn have_status_value(prop: String, value: String) -> impl Condition<DynamicObject> {
        move |obj: Option<&DynamicObject>| {
            obj.and_then(|o| o.data.get("status"))
                .and_then(|s| s.get(prop.as_str()))
                .and_then(|v| v.as_str())
                .is_some_and(|v| v == value.as_str())
        }
    }

    /// Waits up to `timeout` seconds for `status.<prop>` to become the boolean `true`.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if `timeout` elapses ([`Error::Elapsed`]), the object is
    /// deleted mid-wait, or the watch fails definitively ([`Error::KubeWaitError`]).
    /// See the shared `wait_object` helper (k8s.sdd `Must`) for the retry contract.
    pub fn wait_status(&mut self, prop: String, timeout: i64) -> RhaiRes<()> {
        let name = self.obj.name_any();
        tracing::debug!("wait_status({}) for {} {}", &prop, self.kind, name);
        crate::rt::block_on(wait_object(
            self.api.clone(),
            &name,
            timeout_duration(timeout),
            Self::is_status(prop),
        ))
        .and_then(|r| r)
        .map_err(rhai_err)
    }

    /// Waits up to `timeout` seconds for `status.<prop>` to appear (non-null).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if `timeout` elapses ([`Error::Elapsed`]), the object is
    /// deleted mid-wait, or the watch fails definitively ([`Error::KubeWaitError`]).
    /// See the shared `wait_object` helper (k8s.sdd `Must`) for the retry contract.
    pub fn wait_status_prop(&mut self, prop: String, timeout: i64) -> RhaiRes<()> {
        let name = self.obj.name_any();
        tracing::debug!("wait_status({}) for {} {}", &prop, self.kind, name);
        crate::rt::block_on(wait_object(
            self.api.clone(),
            &name,
            timeout_duration(timeout),
            Self::have_status(prop),
        ))
        .and_then(|r| r)
        .map_err(rhai_err)
    }

    /// Waits up to `timeout` seconds for `status.<prop>` to equal the string `value`.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if `timeout` elapses ([`Error::Elapsed`]), the object is
    /// deleted mid-wait, or the watch fails definitively ([`Error::KubeWaitError`]).
    /// See the shared `wait_object` helper (k8s.sdd `Must`) for the retry contract.
    pub fn wait_status_string(&mut self, prop: String, value: String, timeout: i64) -> RhaiRes<()> {
        let name = self.obj.name_any();
        tracing::debug!("wait_status({}) for {} {}", &prop, self.kind, name);
        crate::rt::block_on(wait_object(
            self.api.clone(),
            &name,
            timeout_duration(timeout),
            Self::have_status_value(prop, value),
        ))
        .and_then(|r| r)
        .map_err(rhai_err)
    }

    /// Wait until a caller-supplied Rhai predicate returns `true` for this object.
    ///
    /// The predicate is called with the object rendered as a map (`metadata` / `spec` /
    /// `status` / …, exactly the shape `<K8sGeneric>.get(name)` returns) and must return a
    /// boolean. It is re-evaluated on every watch event until it returns `true` or `timeout`
    /// seconds elapse. Unlike `wait_status*`, the predicate can inspect arbitrarily nested
    /// fields (`obj.status.ceph.versions.overall.len() == 1`, …). A predicate that raises is
    /// NOT fatal (k8s.sdd `Must`, décision actée): the exception may be transient (a
    /// `status` not yet populated), so the wait continues; a later satisfying event succeeds
    /// and the exception is forgotten. Only when the timeout expires is the LAST predicate
    /// exception returned, in place of a misleading [`Error::Elapsed`].
    ///
    /// # Errors
    ///
    /// Returns the predicate's last Rhai error at timeout (if any raised), otherwise a Rhai
    /// error if `timeout` elapses ([`Error::Elapsed`]), the object is deleted mid-wait, or
    /// the watch fails definitively ([`Error::KubeWaitError`]).
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn wait_for(
        ctx: rhai::NativeCallContext,
        obj: &mut K8sObject,
        predicate: rhai::FnPtr,
        timeout: i64,
    ) -> RhaiRes<()> {
        let name = obj.obj.name_any();
        let api = obj.api.clone();
        tracing::debug!("wait_for({}) for {} {}", predicate.fn_name(), obj.kind, name);
        // `wait_object` only sees booleans; stash the LAST predicate exception here (an
        // earlier one is overwritten, a satisfying event makes it moot) so the timeout can
        // surface it instead of a misleading Elapsed (k8s.sdd `Must`, Handles l.411-413).
        let pred_err: std::cell::RefCell<Option<Box<rhai::EvalAltResult>>> = std::cell::RefCell::new(None);
        let cond = |o: Option<&DynamicObject>| -> bool {
            let Some(dynobj) = o else { return false };
            let value = match to_dynamic(dynobj) {
                Ok(v) => v,
                Err(e) => {
                    *pred_err.borrow_mut() = Some(e);
                    return false;
                }
            };
            match predicate.call_within_context::<Dynamic>(&ctx, (value,)) {
                Ok(r) => r.as_bool().unwrap_or(false),
                Err(e) => {
                    *pred_err.borrow_mut() = Some(e);
                    false
                }
            }
        };
        let outcome =
            crate::rt::block_on(wait_object(api, &name, timeout_duration(timeout), cond)).and_then(|r| r);
        if matches!(outcome, Err(Error::Elapsed(_)))
            && let Some(e) = pred_err.into_inner()
        {
            return Err(e);
        }
        outcome.map_err(rhai_err)
    }
}

/// Generic resource handle resolved from the discovery cache (`K8sGeneric` in Rhai).
#[derive(Clone, Debug)]
pub struct K8sGeneric {
    /// Resolved API handle, `None` when the kind/plural was not found in the discovery cache.
    pub api: Option<Api<DynamicObject>>,
    /// Namespace requested at construction, if any.
    pub ns: Option<String>,
    /// Discovery scope of the resolved resource.
    pub scope: Scope,
    /// Resolved kind (empty when unresolved).
    pub kind: String,
}

impl K8sGeneric {
    /// Resolves a resource by kind or plural (case-insensitive) from the discovery cache.
    ///
    /// On ambiguity the lexicographically smallest group wins (the core group in practice).
    /// Returns a handle with `api: None` when nothing matches.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] (“requires a multi-thread tokio runtime”) when called from a
    /// `current_thread` tokio runtime: the cache read rides `crate::rt::block_on` (rt.sdd),
    /// which refuses without polling the future (k8s.sdd `Raises`, décision du développeur
    /// principal 2026-10-10). Returns [`Error::Stdio`] if the no-runtime fallback cannot
    /// build its temporary runtime.
    pub fn new(name: &str, ns: Option<String>) -> Result<Self> {
        // Un ns vide est traité comme absent (k8s.sdd `Must`, décision actée) : pas d'URL
        // invalide, repli all-namespaces ; le `ns` stocké sur le handle suit la même règle.
        let ns = normalize_ns(ns);
        crate::rt::block_on(async move {
            if let Some((res, cap)) = CACHE
                .read()
                .await
                .groups()
                .flat_map(|group| {
                    group
                        .resources_by_stability()
                        .into_iter()
                        .map(move |res: (ApiResource, ApiCapabilities)| (group, res))
                })
                .filter(|(_, (res, _))| {
                    name.eq_ignore_ascii_case(&res.kind) || name.eq_ignore_ascii_case(&res.plural)
                })
                .min_by_key(|(group, _res)| group.name())
                .map(|(_, res)| res)
            {
                tracing::debug!("K8sGeneric::new Using {}/{}/{}", res.group, res.version, res.kind);
                // Scope retenu (k8s.sdd `Must`) : Cluster OU ns absent OU ns vide →
                // all_with ; sinon namespaced_with. `default_namespaced_with` était
                // inatteignable (exigeait ns.is_none() faux et ns == None) — supprimé.
                let api = match ns.as_ref().filter(|_| cap.scope != Scope::Cluster) {
                    Some(namespace) => Api::namespaced_with(CLIENT.clone(), namespace, &res),
                    None => Api::all_with(CLIENT.clone(), &res),
                };
                K8sGeneric {
                    api: Some(api),
                    ns,
                    scope: cap.scope,
                    kind: res.kind,
                }
            } else {
                K8sGeneric {
                    api: None,
                    ns: None,
                    scope: Scope::Cluster,
                    kind: String::new(),
                }
            }
        })
    }

    /// Resolves a resource by api group, version and kind/plural from the discovery cache.
    ///
    /// Returns a handle with `api: None` when nothing matches.
    ///
    /// # Errors
    ///
    /// Same bridge errors as [`Self::new`]: [`Error::Other`] when called from a
    /// `current_thread` tokio runtime, [`Error::Stdio`] if the no-runtime fallback cannot
    /// build its temporary runtime (k8s.sdd `Raises`).
    pub fn new_api_version(api_group: &str, version: &str, name: &str, ns: Option<String>) -> Result<Self> {
        // Un ns vide est traité comme absent (k8s.sdd `Must`, décision actée), même règle que
        // dans `Self::new`.
        let ns = normalize_ns(ns);
        crate::rt::block_on(async move {
            if let Some((res, cap)) = CACHE
                .read()
                .await
                .groups()
                .flat_map(|group| {
                    group
                        .resources_by_stability()
                        .into_iter()
                        .map(move |res: (ApiResource, ApiCapabilities)| (group, res))
                })
                .filter(|(group, (res, _))| {
                    group.name() == api_group
                        && res.version == version
                        && (name.eq_ignore_ascii_case(&res.kind) || name.eq_ignore_ascii_case(&res.plural))
                })
                .min_by_key(|(group, _res)| group.name())
                .map(|(_, res)| res)
            {
                tracing::debug!(
                    "K8sGeneric::new_api_version Using {}/{}/{}",
                    res.group,
                    res.version,
                    res.kind
                );
                // Même scope retenu que `Self::new` (k8s.sdd `Must`) ; branche
                // `default_namespaced_with` inatteignable supprimée.
                let api = match ns.as_ref().filter(|_| cap.scope != Scope::Cluster) {
                    Some(namespace) => Api::namespaced_with(CLIENT.clone(), namespace, &res),
                    None => Api::all_with(CLIENT.clone(), &res),
                };
                K8sGeneric {
                    api: Some(api),
                    ns,
                    scope: cap.scope,
                    kind: res.kind,
                }
            } else {
                K8sGeneric {
                    api: None,
                    ns: None,
                    scope: Scope::Cluster,
                    kind: String::new(),
                }
            }
        })
    }

    /// Rhai constructor `k8s_resource(name, ns)`: namespaced [`Self::new`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the bridge error of [`Self::new`] (converted by
    /// [`crate::rhai_err`], k8s.sdd `Raises`).
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn new_ns(name: String, ns: String) -> RhaiRes<K8sGeneric> {
        K8sGeneric::new(name.as_str(), Some(ns)).map_err(rhai_err)
    }

    /// Rhai constructor `k8s_resource(name)`: cluster-wide [`Self::new`] lookup.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the bridge error of [`Self::new`] (converted by
    /// [`crate::rhai_err`], k8s.sdd `Raises`).
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn new_global(name: String) -> RhaiRes<K8sGeneric> {
        K8sGeneric::new(name.as_str(), None).map_err(rhai_err)
    }

    /// Rhai constructor `k8s_resource(api_version, name, ns)`: splits `api_version` on `/`
    /// and delegates to [`Self::new_api_version`] (or [`Self::new`] when no group is present).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the bridge error of the delegated constructor
    /// (converted by [`crate::rhai_err`], k8s.sdd `Raises`).
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn new_group_ns(api_version: String, name: String, ns: String) -> RhaiRes<K8sGeneric> {
        let arr = api_version.split('/').collect::<Vec<&str>>();
        if arr.len() > 1 {
            K8sGeneric::new_api_version(arr[0], arr[1], name.as_str(), Some(ns)).map_err(rhai_err)
        } else {
            K8sGeneric::new(name.as_str(), Some(ns)).map_err(rhai_err)
        }
    }

    /// Discovery scope as `"cluster"` or `"namespace"` for Rhai.
    pub fn rhai_get_scope(&mut self) -> String {
        if self.scope == Scope::Cluster {
            "cluster".to_string()
        } else {
            "namespace".to_string()
        }
    }

    /// True when the resource was resolved at construction ([`Self::api`] is set).
    #[must_use]
    pub fn exist(&self) -> bool {
        self.api.is_some()
    }

    /// [`Self::exist`] as a Rhai value.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the boolean cannot be converted to a Rhai value (never in
    /// practice, kept for the `RhaiRes` shape).
    pub fn rhai_exist(&mut self) -> RhaiRes<Dynamic> {
        to_dynamic(self.api.is_some())
    }

    /// Lists all objects of this resource.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMethod`] if the resource was not resolved, or
    /// [`Error::KubeError`] if the API call fails.
    pub fn list(&self) -> Result<ObjectList<DynamicObject>> {
        if let Some(api) = self.api.clone() {
            crate::rt::block_on(
                async move { api.list(&ListParams::default()).await.map_err(Error::KubeError) },
            )
            .and_then(|r| r)
        } else {
            Err(Error::UnsupportedMethod)
        }
    }

    /// [`Self::list`] as a Rhai value.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Self::list`] errors or
    /// [`Error::SerializationError`].
    pub fn rhai_list(&mut self) -> RhaiRes<Dynamic> {
        let res = self.list().map_err(rhai_err)?;
        let v = serde_json::to_value(res).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        to_dynamic(v)
    }

    /// Lists objects of this resource matching a label selector (invalid selectors fail at
    /// request time).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMethod`] if the resource was not resolved, or
    /// [`Error::KubeError`] if the API call fails.
    pub fn list_labels(&self, labels: String) -> Result<ObjectList<DynamicObject>> {
        if let Some(api) = self.api.clone() {
            crate::rt::block_on(async move {
                let mut lp = ListParams::default();
                lp = lp.labels(&labels);
                api.list(&lp).await.map_err(Error::KubeError)
            })
            .and_then(|r| r)
        } else {
            Err(Error::UnsupportedMethod)
        }
    }

    /// [`Self::list_labels`] as a Rhai value.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Self::list_labels`] errors or
    /// [`Error::SerializationError`].
    pub fn rhai_list_labels(&mut self, labels: String) -> RhaiRes<Dynamic> {
        let res = self.list_labels(labels).map_err(rhai_err)?;
        let v = serde_json::to_value(res).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        to_dynamic(v)
    }

    /// Lists only the object metadata of this resource (cheaper full listing).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMethod`] if the resource was not resolved, or
    /// [`Error::KubeError`] if the API call fails.
    pub fn list_meta(&self) -> Result<ObjectList<PartialObjectMeta>> {
        if let Some(api) = self.api.clone() {
            crate::rt::block_on(async move {
                api.list_metadata(&ListParams::default())
                    .await
                    .map_err(Error::KubeError)
            })
            .and_then(|r| r)
        } else {
            Err(Error::UnsupportedMethod)
        }
    }

    /// [`Self::list_meta`] as a Rhai value.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Self::list_meta`] errors or
    /// [`Error::SerializationError`].
    pub fn rhai_list_meta(&mut self) -> RhaiRes<Dynamic> {
        let res = self.list_meta().map_err(rhai_err)?;
        let v = serde_json::to_value(res).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        to_dynamic(v)
    }

    /// Gets a single object by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMethod`] if the resource was not resolved, or
    /// [`Error::KubeError`] if the API call fails.
    pub fn get(&self, name: &str) -> Result<DynamicObject> {
        if let Some(api) = self.api.clone() {
            crate::rt::block_on(async move { api.get(name).await.map_err(Error::KubeError) }).and_then(|r| r)
        } else {
            Err(Error::UnsupportedMethod)
        }
    }

    /// [`Self::get`] as a Rhai value.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Self::get`] errors or [`Error::SerializationError`].
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_get(&mut self, name: String) -> RhaiRes<Dynamic> {
        let res = self.get(&name).map_err(rhai_err)?;
        let v = serde_json::to_value(res).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        to_dynamic(v)
    }

    /// Gets a single object's metadata by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMethod`] if the resource was not resolved, or
    /// [`Error::KubeError`] if the API call fails.
    pub fn get_meta(&self, name: &str) -> Result<PartialObjectMeta> {
        if let Some(api) = self.api.clone() {
            crate::rt::block_on(async move { api.get_metadata(name).await.map_err(Error::KubeError) })
                .and_then(|r| r)
        } else {
            Err(Error::UnsupportedMethod)
        }
    }

    /// [`Self::get_meta`] as a Rhai value.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Self::get_meta`] errors or
    /// [`Error::SerializationError`].
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_get_meta(&mut self, name: String) -> RhaiRes<Dynamic> {
        let res = self.get_meta(&name).map_err(rhai_err)?;
        let v = serde_json::to_value(res).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        to_dynamic(v)
    }

    /// Fetches the object's metadata and wraps it in a [`K8sObject`] bound to this resource.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::UnsupportedMethod`] (resource unresolved) or the
    /// [`Self::get_meta`] errors.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_get_obj(&mut self, name: String) -> RhaiRes<K8sObject> {
        let Some(api) = self.api.clone() else {
            return Err(rhai_err(Error::UnsupportedMethod));
        };
        let res = self.get_meta(&name).map_err(rhai_err)?;
        Ok(K8sObject {
            api,
            obj: res,
            kind: self.kind.clone(),
        })
    }

    /// Deletes an object by name with foreground propagation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMethod`] if the resource was not resolved, or
    /// [`Error::KubeError`] if the API call fails.
    pub fn delete(&self, name: &str) -> Result<()> {
        if let Some(api) = self.api.clone() {
            crate::rt::block_on(async move {
                api.delete(name, &DeleteParams::foreground())
                    .await
                    .map_err(Error::KubeError)
                    .map(|_| ())
            })
            .and_then(|r| r)
        } else {
            Err(Error::UnsupportedMethod)
        }
    }

    /// [`Self::delete`] variant for Rhai.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Self::delete`] errors.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_delete(&mut self, name: String) -> RhaiRes<()> {
        self.delete(&name).map_err(rhai_err)
    }

    fn inject_labels_and_owner(
        &self,
        handle: serde_json::Map<String, serde_json::Value>,
    ) -> serde_json::Map<String, serde_json::Value> {
        prepare_handle(
            handle,
            call_get_labels(),
            call_get_owner(),
            call_get_owner_ns(),
            self.ns.clone(),
            self.scope == Scope::Namespaced,
        )
    }
}

// ── Pure helper — testable without a live K8s client ─────────────────────────

/// Normalizes a handle before create/replace/patch/apply: guarantees an object `metadata`,
/// injects missing common labels (never overriding existing ones) and, for a namespaced
/// resource in the owner's namespace, appends the owner reference — unless an entry with the
/// same `uid` is already present (dedup, k8s.sdd `Must`).
fn prepare_handle(
    mut handle: serde_json::Map<String, serde_json::Value>,
    labels: Option<serde_json::Value>,
    owner: Option<serde_json::Value>,
    owner_ns: Option<String>,
    my_ns: Option<String>,
    is_namespaced: bool,
) -> serde_json::Map<String, serde_json::Value> {
    if !handle.get("metadata").is_some_and(serde_json::Value::is_object) {
        handle.insert("metadata".to_string(), json!({}));
    }
    let Some(metadata) = handle
        .get_mut("metadata")
        .and_then(serde_json::Value::as_object_mut)
    else {
        // unreachable: the branch above just forced metadata to be an object
        return handle;
    };
    if let Some(labels) = labels {
        if !metadata.get("labels").is_some_and(serde_json::Value::is_object) {
            metadata.insert("labels".to_string(), json!({}));
        }
        if let Some(label_map) = labels.as_object()
            && let Some(existing) = metadata
                .get_mut("labels")
                .and_then(serde_json::Value::as_object_mut)
        {
            for (k, v) in label_map {
                if !existing.contains_key(k.as_str()) {
                    existing.insert(k.clone(), v.clone());
                }
            }
        }
    }
    if is_namespaced
        && let Some(owner) = owner
        && let Some(ns) = owner_ns
        && let Some(mine) = my_ns
        && ns == mine
    {
        let references = metadata
            .entry("ownerReferences".to_string())
            .or_insert_with(|| json!([]));
        match references {
            serde_json::Value::Array(items) => {
                // Dédoublonnage par `uid` (k8s.sdd `Must`, décision actée) : APPENDU par
                // défaut, SAUF si une entrée de même uid figure déjà. Un owner sans `uid`
                // n'a rien à faire correspondre : appendu telle quelle (jamais jeté).
                let uid = owner.get("uid");
                if uid.is_none() || !items.iter().any(|existing| existing.get("uid") == uid) {
                    items.push(owner);
                }
            }
            // malformed (non-array) references are replaced rather than panicking
            other => *other = vec![owner].into(),
        }
    }
    handle
}

impl K8sGeneric {
    /// Creates a resource from a handle map (labels/owner refs injected first).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMethod`] if the resource was not resolved,
    /// [`Error::SerializationError`] if the handle is not a valid object, or
    /// [`Error::KubeError`] if the API call fails.
    pub fn create(&self, data: serde_json::Map<String, serde_json::Value>) -> Result<DynamicObject> {
        if let Some(api) = self.api.clone() {
            let handle = self.inject_labels_and_owner(data);
            crate::rt::block_on(async move {
                match serde_json::from_value(handle.into()) {
                    Ok(obj) => api
                        .create(&PostParams::default(), &obj)
                        .await
                        .map_err(Error::KubeError),
                    Err(e) => Err(Error::SerializationError(e)),
                }
            })
            .and_then(|r| r)
        } else {
            Err(Error::UnsupportedMethod)
        }
    }

    /// [`Self::create`] variant for Rhai, taking the handle as a Rhai map.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the map cannot be deserialized, or wrapping the
    /// [`Self::create`] errors and [`Error::SerializationError`].
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_create(&mut self, data: rhai::Dynamic) -> RhaiRes<Dynamic> {
        let data = rhai::serde::from_dynamic(&data)?;
        let res = self.create(data).map_err(|e: Error| rhai_err(e))?;
        let v = serde_json::to_value(res).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        to_dynamic(v)
    }

    /// Replaces (full update) a named resource from a handle map.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMethod`] if the resource was not resolved,
    /// [`Error::SerializationError`] if the handle is not a valid object, or
    /// [`Error::KubeError`] if the API call fails.
    pub fn replace(
        &self,
        name: &str,
        data: serde_json::Map<String, serde_json::Value>,
    ) -> Result<DynamicObject> {
        if let Some(api) = self.api.clone() {
            let handle = self.inject_labels_and_owner(data);
            crate::rt::block_on(async move {
                match serde_json::from_value(handle.into()) {
                    Ok(obj) => api
                        .replace(name, &PostParams::default(), &obj)
                        .await
                        .map_err(Error::KubeError),
                    Err(e) => Err(Error::SerializationError(e)),
                }
            })
            .and_then(|r| r)
        } else {
            Err(Error::UnsupportedMethod)
        }
    }

    /// [`Self::replace`] variant for Rhai.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the map cannot be deserialized, or wrapping the
    /// [`Self::replace`] errors and [`Error::SerializationError`].
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_replace(&mut self, name: String, data: rhai::Dynamic) -> RhaiRes<Dynamic> {
        let data = rhai::serde::from_dynamic(&data)?;
        let res = self.replace(&name, data).map_err(|e: Error| rhai_err(e))?;
        let v = serde_json::to_value(res).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        to_dynamic(v)
    }

    /// Server-side applies a patch as the configured field manager (forced).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMethod`] if the resource was not resolved, or
    /// [`Error::KubeError`] if the API call fails.
    pub fn patch(
        &self,
        name: &str,
        patch_data: serde_json::Map<String, serde_json::Value>,
    ) -> Result<DynamicObject> {
        if let Some(api) = self.api.clone() {
            let handle = self.inject_labels_and_owner(patch_data);
            crate::rt::block_on(async move {
                api.patch(
                    name,
                    &PatchParams::apply(&crate::get_client_name()).force(),
                    &Patch::Apply(handle),
                )
                .await
                .map_err(Error::KubeError)
            })
            .and_then(|r| r)
        } else {
            Err(Error::UnsupportedMethod)
        }
    }

    /// [`Self::patch`] variant for Rhai.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the map cannot be deserialized, or wrapping the
    /// [`Self::patch`] errors and [`Error::SerializationError`].
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_patch(&mut self, name: String, data: rhai::Dynamic) -> RhaiRes<Dynamic> {
        let data = rhai::serde::from_dynamic(&data)?;
        let res = self.patch(&name, data).map_err(|e: Error| rhai_err(e))?;
        let v = serde_json::to_value(res).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        to_dynamic(v)
    }

    /// Server-side applies a patch (as [`Self::patch`]), tolerating the immutable-spec error of
    /// an already-completed `Job` by returning the current object instead of failing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMethod`] if the resource was not resolved, or
    /// [`Error::KubeError`] if the API call fails and the completed-Job fallback does not apply.
    pub fn apply(
        &self,
        name: &str,
        patch_data: serde_json::Map<String, serde_json::Value>,
    ) -> Result<DynamicObject> {
        if let Some(api) = self.api.clone() {
            let kind = patch_data
                .get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or("")
                .to_string();
            let handle = self.inject_labels_and_owner(patch_data);
            let api_for_get = api.clone();
            crate::rt::block_on(async move {
                match api
                    .patch(
                        name,
                        &PatchParams::apply(&crate::get_client_name()).force(),
                        &Patch::Apply(handle),
                    )
                    .await
                {
                    Ok(obj) => Ok(obj),
                    Err(e) => {
                        if kind == "Job"
                            && e.to_string().contains("immutable")
                            && let Ok(current) = api_for_get.get(name).await
                            && job_is_completed(&current.data)
                        {
                            tracing::debug!(
                                "Job {name} spec.template immutable but already completed — skipping"
                            );
                            return Ok(current);
                        }
                        Err(Error::KubeError(e))
                    }
                }
            })
            .and_then(|r| r)
        } else {
            Err(Error::UnsupportedMethod)
        }
    }

    /// [`Self::apply`] variant for Rhai.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the map cannot be deserialized, or wrapping the [`Self::apply`]
    /// errors and [`Error::SerializationError`].
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_apply(&mut self, name: String, data: rhai::Dynamic) -> RhaiRes<Dynamic> {
        let data = rhai::serde::from_dynamic(&data)?;
        let res = self.apply(&name, data).map_err(|e: Error| rhai_err(e))?;
        let v = serde_json::to_value(res).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        to_dynamic(v)
    }
}

/// Vrai si le Job est terminé : condition `Complete` à `"True"` OU `status.completionTime`
/// présent (k8s.sdd `Must`, décision actée). `status.succeeded > 0` seul ne compte plus —
/// un Job à `completions` multiples encore actif ne doit pas voir son erreur d'apply masquée.
/// Le `wait_done` du workload `Job` (kube `is_job_completed`, condition `Complete`) concorde.
fn job_is_completed(data: &serde_json::Value) -> bool {
    let Some(status) = data.get("status") else {
        return false;
    };
    if status
        .get("conditions")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|conditions| {
            conditions.iter().any(|c| {
                c.get("type").and_then(serde_json::Value::as_str) == Some("Complete")
                    && c.get("status").and_then(serde_json::Value::as_str) == Some("True")
            })
        })
    {
        return true;
    }
    status.get("completionTime").is_some()
}

// ── k8sraw ───────────────────────────────────────────────────────────────────

/// Shared kube client dedicated to raw API calls, built like [`CLIENT`].
///
/// Panics on first access if the k8s context was not wired (see [`context_is_wired`]).
pub static RAW_CLIENT: LazyLock<Client> = LazyLock::new(build_client);

/// Raw HTTP access to the Kubernetes API server through the kube client (`K8sRaw` in Rhai).
#[derive(Clone)]
pub struct K8sRaw {
    /// Underlying kube client (the shared [`RAW_CLIENT`] by default).
    pub client: Client,
}

impl Default for K8sRaw {
    fn default() -> Self {
        Self::new()
    }
}

impl K8sRaw {
    /// Builds a [`K8sRaw`] bound to the shared [`RAW_CLIENT`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: RAW_CLIENT.clone(),
        }
    }

    /// GETs a path on the API server and returns the JSON body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RawHTTP`] if the request cannot be built, or [`Error::KubeError`] if the
    /// call fails or the body is not valid JSON.
    pub async fn get_url(&self, url: String) -> Result<serde_json::Value> {
        let req = http::Request::get(url)
            .body(Vec::default())
            .map_err(Error::RawHTTP)?;
        let resp = self
            .client
            .request::<serde_json::Value>(req)
            .await
            .map_err(Error::KubeError)?;
        Ok(resp)
    }

    /// GETs a path with the aggregated-discovery `Accept` header (v2/v2beta1 JSON).
    ///
    /// # Errors
    ///
    /// Returns [`Error::RawHTTP`] if the request cannot be built, or [`Error::KubeError`] if the
    /// call fails or the body is not valid JSON.
    pub async fn get_url_as_disco(&self, url: String) -> Result<serde_json::Value> {
        let req = http::Request::get(url)
            .header("Accept", "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList,application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList,application/json")
            .body(Vec::default()).map_err(Error::RawHTTP)?;
        let resp = self
            .client
            .request::<serde_json::Value>(req)
            .await
            .map_err(Error::KubeError)?;
        Ok(resp)
    }

    /// Cluster version information (server `/version` endpoint).
    ///
    /// # Errors
    ///
    /// Forwards the [`Self::get_url`] errors.
    pub async fn get_api_version(&self) -> Result<serde_json::Value> {
        self.get_url("/version".to_string()).await
    }

    /// Full API group discovery list (server `/apis` endpoint).
    ///
    /// # Errors
    ///
    /// Forwards the [`Self::get_url_as_disco`] errors.
    pub async fn get_api_resources(&self) -> Result<serde_json::Value> {
        self.get_url_as_disco("/apis".to_string()).await
    }

    /// [`Self::get_url`] rendered as a Rhai value (direct conversion, no JSON string
    /// round-trip — k8s.sdd `Must`, décision actée).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Self::get_url`] errors or a conversion failure.
    pub fn rhai_get_url(&mut self, url: String) -> RhaiRes<Dynamic> {
        crate::rt::block_on(async move {
            let res = self.get_url(url).await.map_err(rhai_err)?;
            to_dynamic(res)
        })
        .map_err(rhai_err)?
    }

    /// [`Self::get_api_version`] rendered as a Rhai value (direct conversion, no JSON string
    /// round-trip — k8s.sdd `Must`, décision actée).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Self::get_api_version`] errors or a conversion
    /// failure.
    pub fn rhai_get_api_version(&mut self) -> RhaiRes<Dynamic> {
        crate::rt::block_on(async move {
            let ver = self.get_api_version().await.map_err(rhai_err)?;
            to_dynamic(ver)
        })
        .map_err(rhai_err)?
    }

    /// [`Self::get_api_resources`] rendered as a Rhai value (direct conversion, no JSON
    /// string round-trip — k8s.sdd `Must`, décision actée).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Self::get_api_resources`] errors or a conversion
    /// failure.
    pub fn rhai_get_api_resources(&mut self) -> RhaiRes<Dynamic> {
        crate::rt::block_on(async move {
            let ver = self.get_api_resources().await.map_err(rhai_err)?;
            to_dynamic(ver)
        })
        .map_err(rhai_err)?
    }
}

// ── k8sworkload ──────────────────────────────────────────────────────────────

/// Typed `DaemonSet` handle fetched from a namespace (`K8sDaemonSet` in Rhai).
#[derive(Clone, Debug)]
pub struct K8sDaemonSet {
    /// Namespace-scoped API handle for this `DaemonSet`.
    pub api: Api<DaemonSet>,
    /// The `DaemonSet` as fetched.
    pub obj: DaemonSet,
}
impl K8sDaemonSet {
    /// Condition matching when `number_available` reached `desired_number_scheduled`.
    #[must_use]
    pub fn is_deamonset_available() -> impl Condition<DaemonSet> {
        |obj: Option<&DaemonSet>| {
            if let Some(ds) = &obj
                && let Some(s) = &ds.status
            {
                return s.desired_number_scheduled == s.number_available.unwrap_or(0);
            }
            false
        }
    }

    /// Fetches a `DaemonSet` by namespace and name (`new_deamonset` entry point in Rhai).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::KubeError`] if the API call fails.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn get_deamonset(namespace: String, name: String) -> RhaiRes<K8sDaemonSet> {
        // Un seul `Api` construit (k8s.sdd `Must`, nettoyage) : le handle porté réutilise
        // l'`Api` de la lecture.
        let api: Api<DaemonSet> = Api::namespaced(CLIENT.clone(), &namespace);
        let d = crate::rt::block_on(async { api.get(&name).await.map_err(Error::KubeError) })
            .and_then(|r| r)
            .map_err(rhai_err)?;
        Ok(K8sDaemonSet { api, obj: d })
    }

    /// Metadata rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_metadata(&mut self) -> RhaiRes<Dynamic> {
        let v =
            serde_json::to_string(&self.obj.metadata).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Spec rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_spec(&mut self) -> RhaiRes<Dynamic> {
        let v = serde_json::to_string(&self.obj.spec).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Status rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_status(&mut self) -> RhaiRes<Dynamic> {
        let v =
            serde_json::to_string(&self.obj.status).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Waits up to `timeout` seconds until all desired pods are available.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if `timeout` elapses ([`Error::Elapsed`]), the object is
    /// deleted mid-wait, or the watch fails definitively ([`Error::KubeWaitError`]).
    /// Transient watch errors are retried with backoff (shared `wait_object` helper,
    /// k8s.sdd `Must`).
    pub fn wait_available(&mut self, timeout: i64) -> RhaiRes<()> {
        let name = self.obj.name_any();
        crate::rt::block_on(wait_object(
            self.api.clone(),
            &name,
            timeout_duration(timeout),
            Self::is_deamonset_available(),
        ))
        .and_then(|r| r)
        .map_err(rhai_err)
    }
}

/// Typed `StatefulSet` handle fetched from a namespace (`K8sStatefulSet` in Rhai).
#[derive(Clone, Debug)]
pub struct K8sStatefulSet {
    /// Namespace-scoped API handle for this `StatefulSet`.
    pub api: Api<StatefulSet>,
    /// The `StatefulSet` as fetched.
    pub obj: StatefulSet,
}
impl K8sStatefulSet {
    /// Condition matching when `available_replicas` reached `spec.replicas` (defaults 1/0).
    #[must_use]
    pub fn is_sts_available() -> impl Condition<StatefulSet> {
        |obj: Option<&StatefulSet>| {
            if let Some(sts) = &obj
                && let Some(spec) = &sts.spec
                && let Some(s) = &sts.status
            {
                return spec.replicas.unwrap_or(1) == s.available_replicas.unwrap_or(0);
            }
            false
        }
    }

    /// Fetches a `StatefulSet` by namespace and name (`get_statefulset` entry point in Rhai).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::KubeError`] if the API call fails.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn get_sts(namespace: String, name: String) -> RhaiRes<K8sStatefulSet> {
        // Un seul `Api` construit (k8s.sdd `Must`, nettoyage).
        let api: Api<StatefulSet> = Api::namespaced(CLIENT.clone(), &namespace);
        let d = crate::rt::block_on(async { api.get(&name).await.map_err(Error::KubeError) })
            .and_then(|r| r)
            .map_err(rhai_err)?;
        Ok(K8sStatefulSet { api, obj: d })
    }

    /// Metadata rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_metadata(&mut self) -> RhaiRes<Dynamic> {
        let v =
            serde_json::to_string(&self.obj.metadata).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Spec rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_spec(&mut self) -> RhaiRes<Dynamic> {
        let v = serde_json::to_string(&self.obj.spec).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Status rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_status(&mut self) -> RhaiRes<Dynamic> {
        let v =
            serde_json::to_string(&self.obj.status).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Waits up to `timeout` seconds until `available_replicas` reaches the desired count.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if `timeout` elapses ([`Error::Elapsed`]), the object is
    /// deleted mid-wait, or the watch fails definitively ([`Error::KubeWaitError`]).
    /// Transient watch errors are retried with backoff (shared `wait_object` helper,
    /// k8s.sdd `Must`).
    pub fn wait_available(&mut self, timeout: i64) -> RhaiRes<()> {
        let name = self.obj.name_any();
        crate::rt::block_on(wait_object(
            self.api.clone(),
            &name,
            timeout_duration(timeout),
            Self::is_sts_available(),
        ))
        .and_then(|r| r)
        .map_err(rhai_err)
    }
}

/// Typed `Deployment` handle fetched from a namespace (`K8sDeploy` in Rhai).
#[derive(Clone, Debug)]
pub struct K8sDeploy {
    /// Namespace-scoped API handle for this Deployment.
    pub api: Api<Deployment>,
    /// The Deployment as fetched.
    pub obj: Deployment,
}
impl K8sDeploy {
    /// Condition matching when the `Available` status condition is `"True"`.
    #[must_use]
    pub fn is_deploy_available() -> impl Condition<Deployment> {
        |obj: Option<&Deployment>| {
            if let Some(job) = &obj
                && let Some(s) = &job.status
                && let Some(conds) = &s.conditions
                && let Some(pcond) = conds.iter().find(|c| c.type_ == "Available")
            {
                return pcond.status == "True";
            }
            false
        }
    }

    /// Fetches a `Deployment` by namespace and name (Rhai `get_deployment` entry point).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::KubeError`] if the API call fails.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn get_deployment(namespace: String, name: String) -> RhaiRes<K8sDeploy> {
        // Un seul `Api` construit (k8s.sdd `Must`, nettoyage).
        let api: Api<Deployment> = Api::namespaced(CLIENT.clone(), &namespace);
        let d = crate::rt::block_on(async { api.get(&name).await.map_err(Error::KubeError) })
            .and_then(|r| r)
            .map_err(rhai_err)?;
        Ok(K8sDeploy { api, obj: d })
    }

    /// Metadata rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_metadata(&mut self) -> RhaiRes<Dynamic> {
        let v =
            serde_json::to_string(&self.obj.metadata).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Spec rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_spec(&mut self) -> RhaiRes<Dynamic> {
        let v = serde_json::to_string(&self.obj.spec).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Status rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_status(&mut self) -> RhaiRes<Dynamic> {
        let v =
            serde_json::to_string(&self.obj.status).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Waits up to `timeout` seconds until the `Available` condition turns `"True"`.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if `timeout` elapses ([`Error::Elapsed`]), the object is
    /// deleted mid-wait, or the watch fails definitively ([`Error::KubeWaitError`]).
    /// Transient watch errors are retried with backoff (shared `wait_object` helper,
    /// k8s.sdd `Must`).
    pub fn wait_available(&mut self, timeout: i64) -> RhaiRes<()> {
        let name = self.obj.name_any();
        crate::rt::block_on(wait_object(
            self.api.clone(),
            &name,
            timeout_duration(timeout),
            Self::is_deploy_available(),
        ))
        .and_then(|r| r)
        .map_err(rhai_err)
    }
}

/// Typed `Job` handle fetched from a namespace (`K8sJob` in Rhai).
#[derive(Clone, Debug)]
pub struct K8sJob {
    /// Namespace-scoped API handle for this Job.
    pub api: Api<Job>,
    /// The Job as fetched.
    pub obj: Job,
}
impl K8sJob {
    /// Fetches a `Job` by namespace and name (Rhai `get_job` entry point).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::KubeError`] if the API call fails.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn get_job(namespace: String, name: String) -> RhaiRes<K8sJob> {
        // Un seul `Api` construit (k8s.sdd `Must`, nettoyage).
        let api: Api<Job> = Api::namespaced(CLIENT.clone(), &namespace);
        let j = crate::rt::block_on(async { api.get(&name).await.map_err(Error::KubeError) })
            .and_then(|r| r)
            .map_err(rhai_err)?;
        Ok(K8sJob { api, obj: j })
    }

    /// Metadata rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_metadata(&mut self) -> RhaiRes<Dynamic> {
        let v =
            serde_json::to_string(&self.obj.metadata).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Spec rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_spec(&mut self) -> RhaiRes<Dynamic> {
        let v = serde_json::to_string(&self.obj.spec).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Status rendered as a Rhai value (JSON string round-trip).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`].
    pub fn get_status(&mut self) -> RhaiRes<Dynamic> {
        let v =
            serde_json::to_string(&self.obj.status).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }

    /// Waits up to `timeout` seconds for the Job's `Completed` condition.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if `timeout` elapses ([`Error::Elapsed`]), the object is
    /// deleted mid-wait, or the watch fails definitively ([`Error::KubeWaitError`]).
    /// Transient watch errors are retried with backoff (shared `wait_object` helper,
    /// k8s.sdd `Must`).
    pub fn wait_done(&mut self, timeout: i64) -> RhaiRes<()> {
        let name = self.obj.name_any();
        crate::rt::block_on(wait_object(
            self.api.clone(),
            &name,
            timeout_duration(timeout),
            conditions::is_job_completed(),
        ))
        .and_then(|r| r)
        .map_err(rhai_err)
    }
}

// ── Rhai registration ────────────────────────────────────────────────────────

/// Registers `K8sGeneric`, `K8sObject` and `DynamicObject` types on a Rhai engine.
pub fn k8sgeneric_rhai_register(engine: &mut Engine) {
    use crate::{register_k8s_generic, register_k8s_object};
    engine
        .register_type_with_name::<DynamicObject>("DynamicObject")
        .register_get("data", |obj: &mut DynamicObject| -> Dynamic {
            Dynamic::from(obj.data.clone())
        });
    register_k8s_object!(engine, K8sObject);
    register_k8s_generic!(
        engine,
        K8sGeneric,
        K8sObject,
        K8sGeneric::new_global,
        K8sGeneric::new_ns,
        K8sGeneric::new_group_ns
    );
}

/// Registers the `K8sRaw` type (raw API access) on a Rhai engine.
pub fn k8sraw_rhai_register(engine: &mut Engine) {
    use crate::register_k8s_raw;
    register_k8s_raw!(engine, K8sRaw, K8sRaw::new);
}

/// Registers the typed workload helpers (`K8sDeploy`, `K8sDaemonSet`, `K8sStatefulSet`,
/// `K8sJob`) on a Rhai engine.
pub fn k8sworkload_rhai_register(engine: &mut Engine) {
    engine
        .register_type_with_name::<K8sDeploy>("K8sDeploy")
        .register_fn("get_deployment", K8sDeploy::get_deployment)
        .register_get("metadata", K8sDeploy::get_metadata)
        .register_get("spec", K8sDeploy::get_spec)
        .register_get("status", K8sDeploy::get_status)
        .register_fn("wait_available", K8sDeploy::wait_available);
    engine
        .register_type_with_name::<K8sDaemonSet>("K8sDaemonSet")
        .register_fn("get_deamonset", K8sDaemonSet::get_deamonset)
        .register_get("metadata", K8sDaemonSet::get_metadata)
        .register_get("spec", K8sDaemonSet::get_spec)
        .register_get("status", K8sDaemonSet::get_status)
        .register_fn("wait_available", K8sDaemonSet::wait_available);
    engine
        .register_type_with_name::<K8sStatefulSet>("K8sStatefulSet")
        .register_fn("get_statefulset", K8sStatefulSet::get_sts)
        .register_get("metadata", K8sStatefulSet::get_metadata)
        .register_get("spec", K8sStatefulSet::get_spec)
        .register_get("status", K8sStatefulSet::get_status)
        .register_fn("wait_available", K8sStatefulSet::wait_available);
    engine
        .register_type_with_name::<K8sJob>("K8sJob")
        .register_fn("get_job", K8sJob::get_job)
        .register_get("metadata", K8sJob::get_metadata)
        .register_get("spec", K8sJob::get_spec)
        .register_get("status", K8sJob::get_status)
        .register_fn("wait_done", K8sJob::wait_done);
}

// ── Macros ───────────────────────────────────────────────────────────────────

/// Registers `$type` as the Rhai type `"K8sObject"`: kind/metadata getters plus `delete` and
/// the `wait_*` methods.
#[macro_export]
macro_rules! register_k8s_object {
    ($engine:expr, $type:ty) => {{
        let _delete: fn(&mut $type) -> $crate::RhaiRes<()> = <$type>::rhai_delete;
        let _wait_deleted: fn(&mut $type, i64) -> $crate::RhaiRes<()> = <$type>::rhai_wait_deleted;
        let _get_kind: fn(&mut $type) -> String = <$type>::get_kind;
        let _original_kind: fn(&mut $type) -> String = <$type>::original_kind;
        let _get_metadata: fn(&mut $type) -> $crate::RhaiRes<rhai::Dynamic> = <$type>::get_metadata;
        let _wait_condition: fn(&mut $type, String, i64) -> $crate::RhaiRes<()> = <$type>::wait_condition;
        let _wait_status: fn(&mut $type, String, i64) -> $crate::RhaiRes<()> = <$type>::wait_status;
        let _wait_status_prop: fn(&mut $type, String, i64) -> $crate::RhaiRes<()> = <$type>::wait_status_prop;
        let _wait_status_string: fn(&mut $type, String, String, i64) -> $crate::RhaiRes<()> =
            <$type>::wait_status_string;
        $engine
            .register_type_with_name::<$type>("K8sObject")
            .register_get("kind", _get_kind)
            .register_get("original_kind", _original_kind)
            .register_get("metadata", _get_metadata)
            .register_fn("delete", _delete)
            .register_fn("wait_condition", _wait_condition)
            .register_fn("wait_status", _wait_status)
            .register_fn("wait_status_prop", _wait_status_prop)
            .register_fn("wait_status_string", _wait_status_string)
            .register_fn("wait_for", <$type>::wait_for)
            .register_fn("wait_deleted", _wait_deleted)
    }};
}

/// Registers `$type` as the Rhai type `"K8sGeneric"`: the three `k8s_resource` constructors
/// (`$new_global`, `$new_ns`, `$new_group_ns`) plus CRUD/list/scope methods. Takes `$obj_type`
/// as the object type returned by `get_obj`.
#[macro_export]
macro_rules! register_k8s_generic {
    ($engine:expr, $type:ty, $obj_type:ty,
     $new_global:expr, $new_ns:expr, $new_group_ns:expr) => {{
        let _scope: fn(&mut $type) -> String = <$type>::rhai_get_scope;
        let _exist: fn(&mut $type) -> $crate::RhaiRes<rhai::Dynamic> = <$type>::rhai_exist;
        let _list: fn(&mut $type) -> $crate::RhaiRes<rhai::Dynamic> = <$type>::rhai_list;
        let _list_labels: fn(&mut $type, String) -> $crate::RhaiRes<rhai::Dynamic> =
            <$type>::rhai_list_labels;
        let _list_meta: fn(&mut $type) -> $crate::RhaiRes<rhai::Dynamic> = <$type>::rhai_list_meta;
        let _get: fn(&mut $type, String) -> $crate::RhaiRes<rhai::Dynamic> = <$type>::rhai_get;
        let _get_meta: fn(&mut $type, String) -> $crate::RhaiRes<rhai::Dynamic> = <$type>::rhai_get_meta;
        let _get_obj: fn(&mut $type, String) -> $crate::RhaiRes<$obj_type> = <$type>::rhai_get_obj;
        let _delete: fn(&mut $type, String) -> $crate::RhaiRes<()> = <$type>::rhai_delete;
        let _create: fn(&mut $type, rhai::Dynamic) -> $crate::RhaiRes<rhai::Dynamic> = <$type>::rhai_create;
        let _replace: fn(&mut $type, String, rhai::Dynamic) -> $crate::RhaiRes<rhai::Dynamic> =
            <$type>::rhai_replace;
        let _patch: fn(&mut $type, String, rhai::Dynamic) -> $crate::RhaiRes<rhai::Dynamic> =
            <$type>::rhai_patch;
        let _apply: fn(&mut $type, String, rhai::Dynamic) -> $crate::RhaiRes<rhai::Dynamic> =
            <$type>::rhai_apply;
        $engine
            .register_type_with_name::<$type>("K8sGeneric")
            .register_fn("k8s_resource", $new_global)
            .register_fn("k8s_resource", $new_ns)
            .register_fn("k8s_resource", $new_group_ns)
            .register_fn("list", _list)
            .register_fn("list", _list_labels)
            .register_fn("update_k8s_crd_cache", $crate::k8s::update_cache)
            .register_fn("list_meta", _list_meta)
            .register_fn("get", _get)
            .register_fn("get_meta", _get_meta)
            .register_fn("get_obj", _get_obj)
            .register_fn("delete", _delete)
            .register_fn("create", _create)
            .register_fn("replace", _replace)
            .register_fn("patch", _patch)
            .register_fn("apply", _apply)
            .register_fn("exist", _exist)
            .register_get("scope", _scope)
    }};
}

/// Registers `$type` as the Rhai type `"K8sRaw"` with the `$new` constructor and the
/// `get_url` / `get_cluster_version` / `get_api_resources` methods.
#[macro_export]
macro_rules! register_k8s_raw {
    ($engine:expr, $type:ty, $new:expr) => {{
        let _get_url: fn(&mut $type, String) -> $crate::RhaiRes<rhai::Dynamic> = <$type>::rhai_get_url;
        let _get_version: fn(&mut $type) -> $crate::RhaiRes<rhai::Dynamic> = <$type>::rhai_get_api_version;
        let _get_api_resources: fn(&mut $type) -> $crate::RhaiRes<rhai::Dynamic> =
            <$type>::rhai_get_api_resources;
        $engine
            .register_type_with_name::<$type>("K8sRaw")
            .register_fn("new_k8s_raw", $new)
            .register_fn("get_url", _get_url)
            .register_fn("get_cluster_version", _get_version)
            .register_fn("get_api_resources", _get_api_resources)
    }};
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_excludes_aggregated_keeps_local_apiservices() {
        let aggregated = serde_json::json!({
            "group": "metrics.k8s.io",
            "service": { "name": "metrics-server", "namespace": "kube-system" }
        });
        assert_eq!(
            aggregated_apiservice_group(&aggregated),
            Some("metrics.k8s.io".to_string())
        );

        let local_null = serde_json::json!({ "group": "storage.k8s.io", "service": null });
        assert_eq!(aggregated_apiservice_group(&local_null), None);
        let local_absent = serde_json::json!({ "group": "apps" });
        assert_eq!(aggregated_apiservice_group(&local_absent), None);

        let empty_group = serde_json::json!({ "group": "", "service": { "name": "x" } });
        assert_eq!(aggregated_apiservice_group(&empty_group), None);
    }

    // Contrat unifié « Job terminé » (k8s.sdd Must, décision actée) : `status.succeeded > 0`
    // seul ne suffit plus — Scenario « apply replie un Job immuable déjà complet » : avec
    // `completions: 3`, sans condition `Complete` ni completionTime, l'erreur d'apply reste
    // telle quelle (« un Job à completions multiples encore actif ne doit pas voir son
    // erreur d'apply masquée »).
    #[test]
    fn test_job_is_completed_succeeded_alone_not_completed() {
        let data = serde_json::json!({"spec": {"completions": 3}, "status": {"succeeded": 1}});
        assert!(!job_is_completed(&data));
    }

    #[test]
    fn test_job_is_completed_zero_succeeded() {
        let data = serde_json::json!({"status": {"succeeded": 0}});
        assert!(!job_is_completed(&data));
    }

    #[test]
    fn test_job_is_completed_completion_time() {
        let data = serde_json::json!({"status": {"completionTime": "2024-01-01T00:00:00Z"}});
        assert!(job_is_completed(&data));
    }

    // Vrai si la condition `Complete` a `status: "True"` (k8s.sdd Must, décision actée).
    #[test]
    fn test_job_is_completed_complete_condition_true() {
        let data = serde_json::json!({"status": {"conditions": [{"type": "Complete", "status": "True"}]}});
        assert!(job_is_completed(&data));
    }

    // La disjonction est indépendante : `Complete=False` n'invalide pas la branche
    // `completionTime` présent.
    #[test]
    fn test_job_is_completed_complete_false_with_completion_time() {
        let data = serde_json::json!({"status": {
            "conditions": [{"type": "Complete", "status": "False"}],
            "completionTime": "2024-01-01T00:00:00Z"
        }});
        assert!(job_is_completed(&data));
    }

    // Scenario k8s.sdd : « status.conditions Complete=False sans completionTime → l'erreur
    // @variant-Error::KubeError reste telle quelle — job_is_completed ne ment pas ».
    #[test]
    fn test_job_is_completed_complete_false_no_completion_time() {
        let data = serde_json::json!({
            "status": {"conditions": [{"type": "Complete", "status": "False"}], "active": 2}
        });
        assert!(!job_is_completed(&data));
    }

    #[test]
    fn test_job_is_completed_no_status() {
        let data = serde_json::json!({});
        assert!(!job_is_completed(&data));
    }

    #[test]
    fn test_job_is_completed_still_running() {
        let data = serde_json::json!({"status": {"active": 1, "succeeded": 0}});
        assert!(!job_is_completed(&data));
    }

    // ── prepare_handle ────────────────────────────────────────────────────────

    fn map(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        match v {
            serde_json::Value::Object(m) => m,
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn prepare_handle_inserts_metadata_when_absent() {
        let input = map(serde_json::json!({"kind": "ConfigMap", "spec": {}}));
        let out = prepare_handle(input, None, None, None, None, false);
        assert!(out.contains_key("metadata"), "metadata must be added");
        assert!(out["metadata"].is_object());
    }

    #[test]
    fn prepare_handle_inserts_metadata_when_not_object() {
        let input = map(serde_json::json!({"metadata": "bad-string", "kind": "ConfigMap"}));
        let out = prepare_handle(input, None, None, None, None, false);
        assert!(
            out["metadata"].is_object(),
            "non-object metadata must be replaced with {{}}"
        );
    }

    #[test]
    fn prepare_handle_preserves_existing_metadata() {
        let input = map(serde_json::json!({"metadata": {"name": "foo"}, "kind": "ConfigMap"}));
        let out = prepare_handle(input, None, None, None, None, false);
        assert_eq!(out["metadata"]["name"], "foo");
    }

    #[test]
    fn prepare_handle_injects_labels_when_missing() {
        let input = map(serde_json::json!({"kind": "ConfigMap"}));
        let labels = serde_json::json!({"app": "myapp", "tier": "backend"});
        let out = prepare_handle(input, Some(labels), None, None, None, false);
        assert_eq!(out["metadata"]["labels"]["app"], "myapp");
        assert_eq!(out["metadata"]["labels"]["tier"], "backend");
    }

    #[test]
    fn prepare_handle_labels_do_not_override_existing() {
        let input = map(serde_json::json!({"metadata": {"labels": {"app": "existing"}}}));
        let labels = serde_json::json!({"app": "override-attempt", "extra": "v"});
        let out = prepare_handle(input, Some(labels), None, None, None, false);
        assert_eq!(
            out["metadata"]["labels"]["app"], "existing",
            "existing label must not be overridden"
        );
        assert_eq!(
            out["metadata"]["labels"]["extra"], "v",
            "new label must be injected"
        );
    }

    #[test]
    fn prepare_handle_owner_ref_injected_when_same_ns() {
        let input = map(serde_json::json!({"kind": "ConfigMap"}));
        let owner = serde_json::json!({"apiVersion": "v1", "kind": "Pod", "name": "owner", "uid": "abc"});
        let out = prepare_handle(
            input,
            None,
            Some(owner.clone()),
            Some("mynamespace".to_string()),
            Some("mynamespace".to_string()),
            true,
        );
        let refs = out["metadata"]["ownerReferences"].as_array().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0]["uid"], "abc");
    }

    #[test]
    fn prepare_handle_owner_ref_not_injected_when_different_ns() {
        let input = map(serde_json::json!({"kind": "ConfigMap"}));
        let owner = serde_json::json!({"apiVersion": "v1", "kind": "Pod", "name": "owner", "uid": "abc"});
        let out = prepare_handle(
            input,
            None,
            Some(owner),
            Some("other-ns".to_string()),
            Some("mynamespace".to_string()),
            true,
        );
        assert!(
            out["metadata"]
                .as_object()
                .unwrap()
                .get("ownerReferences")
                .is_none()
        );
    }

    // Dédoublonnage par `uid` (k8s.sdd Must, décision actée) : « l'owner est APPENDU à
    // l'array ownerReferences existante SAUF si une entrée de même uid y figure déjà ».
    // Deux injections du même owner (deux écritures successives sur le même handle) ne
    // produisent qu'une entrée.
    #[test]
    fn prepare_handle_owner_ref_deduped_by_uid() {
        let owner = serde_json::json!({"apiVersion": "v1", "kind": "Pod", "name": "owner", "uid": "abc"});
        let first = prepare_handle(
            map(serde_json::json!({"kind": "ConfigMap"})),
            None,
            Some(owner.clone()),
            Some("mynamespace".to_string()),
            Some("mynamespace".to_string()),
            true,
        );
        let second = prepare_handle(
            first,
            None,
            Some(owner),
            Some("mynamespace".to_string()),
            Some("mynamespace".to_string()),
            true,
        );
        let refs = second["metadata"]["ownerReferences"].as_array().unwrap();
        assert_eq!(refs.len(), 1, "une entrée de même uid n'est pas dupliquée");
        assert_eq!(refs[0]["uid"], "abc");
    }

    #[test]
    fn prepare_handle_owner_ref_different_uid_appended() {
        let input = map(serde_json::json!({
            "kind": "ConfigMap",
            "metadata": {"ownerReferences": [{"apiVersion": "v1", "kind": "Pod", "name": "o1", "uid": "abc"}]}
        }));
        let owner = serde_json::json!({"apiVersion": "v1", "kind": "Pod", "name": "o2", "uid": "def"});
        let out = prepare_handle(
            input,
            None,
            Some(owner),
            Some("mynamespace".to_string()),
            Some("mynamespace".to_string()),
            true,
        );
        let refs = out["metadata"]["ownerReferences"].as_array().unwrap();
        assert_eq!(refs.len(), 2, "un uid différent est appendu en fin d'array");
        assert_eq!(refs[1]["uid"], "def");
    }

    // Face par défaut du Must (k8s.sdd l.145-147) : « l'owner est APPENDU à l'array
    // ownerReferences existante SAUF si une entrée de MÊME uid y figure déjà ». Un owner
    // sans clé `uid` n'a pas de uid à faire correspondre : l'exception ne peut pas porter,
    // l'entrée est appendue telle quelle (jamais jetée en silence).
    #[test]
    fn prepare_handle_owner_ref_without_uid_appended() {
        let input = map(serde_json::json!({"kind": "ConfigMap"}));
        let owner = serde_json::json!({"apiVersion": "v1", "kind": "Pod", "name": "owner-no-uid"});
        let out = prepare_handle(
            input,
            None,
            Some(owner),
            Some("mynamespace".to_string()),
            Some("mynamespace".to_string()),
            true,
        );
        let refs = out["metadata"]["ownerReferences"].as_array().unwrap();
        assert_eq!(refs.len(), 1, "un owner sans uid est appendu, pas jeté");
        assert_eq!(refs[0]["name"], "owner-no-uid");
    }

    // Le contrat ne dédoublonne QUE par uid : deux owners sans uid → deux entrées
    // (aucune correspondance de uid possible entre eux).
    #[test]
    fn prepare_handle_two_owners_without_uid_both_appended() {
        let owner_a = serde_json::json!({"apiVersion": "v1", "kind": "Pod", "name": "a"});
        let owner_b = serde_json::json!({"apiVersion": "v1", "kind": "Pod", "name": "b"});
        let first = prepare_handle(
            map(serde_json::json!({"kind": "ConfigMap"})),
            None,
            Some(owner_a),
            Some("mynamespace".to_string()),
            Some("mynamespace".to_string()),
            true,
        );
        let out = prepare_handle(
            first,
            None,
            Some(owner_b),
            Some("mynamespace".to_string()),
            Some("mynamespace".to_string()),
            true,
        );
        let refs = out["metadata"]["ownerReferences"].as_array().unwrap();
        assert_eq!(
            refs.len(),
            2,
            "sans uid, aucune déduplication possible : les deux restent"
        );
        assert_eq!(refs[0]["name"], "a");
        assert_eq!(refs[1]["name"], "b");
    }

    // Scenario « new_global = toutes les namespaces » (k8s.sdd) : `k8s_resource("pods", "")`
    // (ns vide) « se comporte comme sans ns, sans URL invalide ». Seam de la normalisation
    // appliquée par `K8sGeneric::new`/`new_api_version` AVANT la construction du handle (les
    // constructeurs eux-mêmes touchent le LazyLock CACHE — hors seam sans cluster, consigné
    // aux Tasks) ; le `ns` stocké sur le handle suit la même normalisation.
    #[test]
    fn empty_ns_is_treated_as_absent() {
        assert_eq!(normalize_ns(None), None);
        assert_eq!(normalize_ns(Some(String::new())), None);
        assert_eq!(normalize_ns(Some("app".to_string())), Some("app".to_string()));
    }

    // ── Condition closures ────────────────────────────────────────────────────

    fn dynobj(extra: serde_json::Value) -> DynamicObject {
        let mut base = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Foo",
            "metadata": {"name": "test"}
        });
        if let (Some(obj), serde_json::Value::Object(fields)) = (base.as_object_mut(), extra) {
            obj.extend(fields);
        }
        serde_json::from_value(base).unwrap()
    }

    #[test]
    fn is_condition_matches_ready_true() {
        let obj = dynobj(serde_json::json!({
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}
        }));
        assert!(K8sObject::is_condition("Ready".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn is_condition_no_match_wrong_type() {
        let obj = dynobj(serde_json::json!({
            "status": {"conditions": [{"type": "Available", "status": "True"}]}
        }));
        assert!(!K8sObject::is_condition("Ready".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn is_condition_no_match_status_false() {
        let obj = dynobj(serde_json::json!({
            "status": {"conditions": [{"type": "Ready", "status": "False"}]}
        }));
        assert!(!K8sObject::is_condition("Ready".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn is_condition_missing_conditions_returns_false() {
        let obj = dynobj(serde_json::json!({"status": {}}));
        assert!(!K8sObject::is_condition("Ready".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn is_condition_missing_status_returns_false() {
        let obj = dynobj(serde_json::json!({}));
        assert!(!K8sObject::is_condition("Ready".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn is_condition_on_none_returns_false() {
        assert!(!K8sObject::is_condition("Ready".to_string()).matches_object(None));
    }

    #[test]
    fn is_status_true_boolean() {
        let obj = dynobj(serde_json::json!({"status": {"healthy": true}}));
        assert!(K8sObject::is_status("healthy".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn is_status_false_boolean() {
        let obj = dynobj(serde_json::json!({"status": {"healthy": false}}));
        assert!(!K8sObject::is_status("healthy".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn is_status_missing_prop() {
        let obj = dynobj(serde_json::json!({"status": {}}));
        assert!(!K8sObject::is_status("healthy".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn have_status_non_null() {
        let obj = dynobj(serde_json::json!({"status": {"phase": "Running"}}));
        assert!(K8sObject::have_status("phase".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn have_status_null_value() {
        let obj = dynobj(serde_json::json!({"status": {"phase": null}}));
        assert!(!K8sObject::have_status("phase".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn have_status_missing_prop() {
        let obj = dynobj(serde_json::json!({"status": {}}));
        assert!(!K8sObject::have_status("phase".to_string()).matches_object(Some(&obj)));
    }

    #[test]
    fn have_status_value_matches() {
        let obj = dynobj(serde_json::json!({"status": {"phase": "Running"}}));
        assert!(
            K8sObject::have_status_value("phase".to_string(), "Running".to_string())
                .matches_object(Some(&obj))
        );
    }

    #[test]
    fn have_status_value_no_match() {
        let obj = dynobj(serde_json::json!({"status": {"phase": "Pending"}}));
        assert!(
            !K8sObject::have_status_value("phase".to_string(), "Running".to_string())
                .matches_object(Some(&obj))
        );
    }

    // ── Scenario « ponts async → sync sans panique » (k8s.sdd, Raises) ──
    // Seam minimal : `tower_test::mock` (dev-dep déjà employée par ./oci.rs) sert de faux
    // API server à `kube::Client::new`, et le handle `K8sGeneric` est construit à la main
    // (champs PUBLICS) SANS toucher les LazyLock CLIENT/CACHE (aucun cluster). Face choisie :
    // `K8sGeneric::get`, typée `crate::Result` — l'erreur du pont y est verrouillable typée.
    use kube::client::Body;

    fn mocked_generic() -> (
        K8sGeneric,
        tower_test::mock::Handle<http::Request<Body>, http::Response<Body>>,
    ) {
        let (mock_service, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let ar = ApiResource {
            group: String::new(),
            version: "v1".to_string(),
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            plural: "configmaps".to_string(),
        };
        let api: Api<DynamicObject> = Api::all_with(kube::Client::new(mock_service, "ns"), &ar);
        (
            K8sGeneric {
                api: Some(api),
                ns: Some("ns".to_string()),
                scope: Scope::Namespaced,
                kind: "ConfigMap".to_string(),
            },
            handle,
        )
    }

    fn json_ok_response() -> http::Response<Body> {
        http::Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .body(Body::from(
                br#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x"}}"#.to_vec(),
            ))
            .unwrap()
    }

    // Voix « hors runtime » : le runtime temporaire de `crate::rt::block_on` sert la requête
    // (répondue par le mock resté vivant sur un runtime multi-thread dédié), sans panique.
    // Avant la migration, `Handle::current()` panique ici.
    #[test]
    fn get_outside_runtime_is_served_by_the_temporary_runtime() {
        let server_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        // `kube::Client::new` emballe le service dans un `tower::Buffer` dont le worker se
        // spawn À LA CONSTRUCTION : le handle est donc bâti sur le runtime dédié, puis
        // `get` est appelé depuis le fil principal SANS runtime (voie runtime temporaire).
        let (generic, handle) = server_rt.block_on(async { mocked_generic() });
        let responder = server_rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            let (_req, send) = handle.next_request().await.expect("service not called");
            send.send_response(json_ok_response());
        });
        let obj = generic
            .get("x")
            .expect("hors runtime, la voie runtime temporaire doit servir sans panique");
        assert_eq!(obj.types.expect("TypeMeta servi").kind, "ConfigMap");
        server_rt.block_on(responder).unwrap();
    }

    // Voix `current_thread` : le pont rend l'@variant-Error::Other explicite de rt.sdd (typée,
    // face `crate::Result`) et AUCUNE requête n'atteint le faux API server.
    #[tokio::test(flavor = "current_thread")]
    async fn get_on_current_thread_returns_error_without_reaching_the_api() {
        let (generic, mut handle) = mocked_generic();
        match generic.get("x") {
            Err(crate::Error::Other(msg)) => assert!(
                msg.contains("requires a multi-thread tokio runtime"),
                "message attendu explicite, obtenu : {msg}"
            ),
            other => panic!("Error::Other attendu, rendu : {other:?}"),
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), handle.next_request())
                .await
                .is_err(),
            "le futur interne ne doit pas être exécuté : aucune requête attendue"
        );
    }

    // ── Scenario « pont du résolveur : Err typé, plus de panique » (k8s.sdd `Raises`,
    // décision du développeur principal 2026-10-10) ──
    // Seam verrouillable SANS cluster : sous `current_thread`, `rt::block_on` refuse AVANT
    // de polliner le futur — le LazyLock CACHE (et sa panic d'initialisation) ne sont
    // jamais touchés. Les cinq faces jouent par `k8s_resource` surchargé par arité :
    // `new_global` (1 chaîne), `new_ns` (2), `new_group_ns` (3, avec et sans `/` — le cas
    // avec `/` route vers `new_api_version`). Les faces Rust directes `new`/
    // `new_api_version` ne sont verrouillables qu'avec la signature `Result` (leur test
    // voyage avec la conversion). `catch_unwind` rend le test rouge sous l'ancien code :
    // la panique `expect` y est capturée et tombe sous le `panic!` du troisième bras.
    #[tokio::test(flavor = "current_thread")]
    async fn k8s_resource_constructors_render_bridge_error_not_panic_on_current_thread() {
        let mut engine = Engine::new();
        k8sgeneric_rhai_register(&mut engine);
        for script in [
            r#"k8s_resource("pods")"#,
            r#"k8s_resource("pods", "app")"#,
            r#"k8s_resource("v1", "mod", "app")"#,
            r#"k8s_resource("acme.io/v1", "widget", "app")"#,
        ] {
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| engine.eval::<Dynamic>(script)));
            match outcome {
                Ok(Err(e)) => assert!(
                    e.to_string().contains("requires a multi-thread tokio runtime"),
                    "l'exception script doit porter l'erreur du pont ({script}) : {e}"
                ),
                Ok(Ok(v)) => panic!("une erreur était attendue, rendu : {v:?} ({script})"),
                Err(payload) => panic!(
                    "panique capturée sur {script} : le pont doit rendre Err, jamais paniquer ({payload:?})"
                ),
            }
        }
    }

    // Face Rust directe, verrouillable SANS cluster sous `current_thread` (le futur n'est
    // jamais polliné, le LazyLock CACHE n'est pas touché). Hors runtime, la résolution
    // d'abord le CACHE — voie `populate_cache` (panic d'infrastructure contractée,
    // k8s.sdd) — donc non verrouillable sans cluster : consigné aux Tasks de k8s.sdd.
    #[tokio::test(flavor = "current_thread")]
    async fn new_on_current_thread_returns_typed_bridge_error() {
        match K8sGeneric::new("pods", Some("app".to_string())) {
            Err(crate::Error::Other(msg)) => assert!(
                msg.contains("requires a multi-thread tokio runtime"),
                "message attendu explicite, obtenu : {msg}"
            ),
            other => panic!("Error::Other attendu, rendu : {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn new_api_version_on_current_thread_returns_typed_bridge_error() {
        match K8sGeneric::new_api_version("acme.io", "v1", "widget", None) {
            Err(crate::Error::Other(msg)) => assert!(
                msg.contains("requires a multi-thread tokio runtime"),
                "message attendu explicite, obtenu : {msg}"
            ),
            other => panic!("Error::Other attendu, rendu : {other:?}"),
        }
    }

    #[test]
    fn have_status_value_missing_prop() {
        let obj = dynobj(serde_json::json!({"status": {}}));
        assert!(
            !K8sObject::have_status_value("phase".to_string(), "Running".to_string())
                .matches_object(Some(&obj))
        );
    }

    // ── Seam `rhai_*` de K8sRaw ───────────────────────────────────────────────
    // Face verrou : le corps JSON du serveur rendu en Dynamic par l'appel (k8s.sdd Must,
    // décision actée : « les wrappers rhai_* convertissent en Dynamic directement
    // (to_dynamic), sans le double round-trip identité actuel »). Ces verrous sont écrits
    // AVANT le nettoyage et verrouillent le comportement attendu identique après (la
    // conversion directe n'est pas observable de l'extérieur — signalée au rapport comme
    // characterization, aucun test échouant n'existe pour un nettoyage à comportement
    // inchangé).
    fn mocked_raw() -> (
        K8sRaw,
        tower_test::mock::Handle<http::Request<Body>, http::Response<Body>>,
    ) {
        let (mock_service, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        (
            K8sRaw {
                client: kube::Client::new(mock_service, "ns"),
            },
            handle,
        )
    }

    // Le handle est bâti sur un runtime dédié (le `tower::Buffer` de `Client::new` se spawn
    // à la construction), l'appel `rhai_*` part du fil principal SANS runtime (voie secours
    // `rt::block_on`, runtime temporaire) — même patron que `mocked_generic` ci-dessus.
    fn raw_dynamic_served(
        body: &'static str,
        call: impl FnOnce(&mut K8sRaw) -> RhaiRes<Dynamic>,
    ) -> serde_json::Value {
        let server_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut raw, handle) = server_rt.block_on(async { mocked_raw() });
        let responder = server_rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            let (_req, send) = handle.next_request().await.expect("service not called");
            send.send_response(
                http::Response::builder()
                    .status(200)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.as_bytes().to_vec()))
                    .unwrap(),
            );
        });
        let out = call(&mut raw).expect("le corps JSON doit être servi en Dynamic");
        server_rt.block_on(responder).unwrap();
        serde_json::to_value(&out).expect("le Dynamic rendu est sérialisable")
    }

    #[test]
    fn rhai_get_url_returns_json_body_as_dynamic() {
        let rendered = raw_dynamic_served(
            r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x"},"data":{"k":"v"},"count":42}"#,
            |raw| raw.rhai_get_url("/api/v1/namespaces/ns/configmaps".to_string()),
        );
        assert_eq!(rendered["kind"], "ConfigMap");
        assert_eq!(rendered["data"]["k"], "v");
        assert_eq!(rendered["count"], 42, "l'entier traverse la conversion");
    }

    #[test]
    fn rhai_get_api_version_returns_version_body() {
        let rendered = raw_dynamic_served(
            r#"{"major":"1","minor":"31","gitVersion":"v1.31.0"}"#,
            K8sRaw::rhai_get_api_version,
        );
        assert_eq!(rendered["gitVersion"], "v1.31.0");
    }

    #[test]
    fn rhai_get_api_resources_returns_discovery_body() {
        let rendered = raw_dynamic_served(
            r#"{"kind":"APIGroupDiscoveryList","apiVersion":"apidiscovery.k8s.io/v2","items":[]}"#,
            K8sRaw::rhai_get_api_resources,
        );
        assert_eq!(rendered["kind"], "APIGroupDiscoveryList");
        assert!(rendered["items"].is_array());
    }

    // ── Seam `tower-test` des waits (helper unique, k8s.sdd `Must` l.183-199, décision
    // actée) ────────────────────────────────────────────────────────────────────
    // Scenarios verrouillés : « waits — erreur transitoire réessayée, objet supprimé
    // fail-fast », « wait_for — l'exception du predicate n'est pas fatale », « waits —
    // secondes clamp, Elapsed, KubeWaitError, uid seul message local ».
    //
    // Faux API server `tower-test` (même patron que `mocked_generic` : handle et
    // `tower::Buffer` du client bâtis sur un runtime dédié, l'appel part du fil principal
    // SANS runtime — voie secours `rt::block_on`). Une tentative de watch = un LIST (le
    // `watch_object` de kube 3.1 démarre par une liste filtrée sur le nom) puis un WATCH ;
    // le corps du watch est du JSON à un événement par ligne (mesuré : `LinesCodec` de
    // `Client::request_events`), et la fin du corps est un EOF que le watcher re-watche EN
    // SILENCE (mesuré : `None => State::InitListed` dans `watcher.rs`).
    // Les timeouts de test sont en i64 secondes (granularité du contrat, `Accepts`) : 1 s
    // en pratique, backoff initial 100 ms.

    fn mocked_object() -> (
        K8sObject,
        tower_test::mock::Handle<http::Request<Body>, http::Response<Body>>,
    ) {
        let (mock_service, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let ar = ApiResource {
            group: String::new(),
            version: "v1".to_string(),
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            plural: "configmaps".to_string(),
        };
        let api: Api<DynamicObject> = Api::namespaced_with(kube::Client::new(mock_service, "ns"), "ns", &ar);
        let obj: PartialObjectMeta = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "x", "uid": "uid-1", "resourceVersion": "1" }
        }))
        .unwrap();
        (
            K8sObject {
                api,
                obj,
                kind: "ConfigMap".to_string(),
            },
            handle,
        )
    }

    fn http_json(status: u16, body: &str) -> http::Response<Body> {
        http::Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Body::from(body.as_bytes().to_vec()))
            .unwrap()
    }

    /// Sert les responses dans l'ordre aux requêtes entrantes ; quand la liste est épuisée,
    /// la prochaine requête reste sans réponse (watch pendant — le timeout global tranche).
    fn served_wait(
        responses: Vec<(u16, String)>,
        call: impl FnOnce(&mut K8sObject) -> RhaiRes<()>,
    ) -> RhaiRes<()> {
        let server_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut obj, handle) = server_rt.block_on(async { mocked_object() });
        let responder = server_rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            let mut responses = std::collections::VecDeque::from(responses);
            loop {
                let Some((_req, send)) = handle.next_request().await else {
                    return;
                };
                let Some((status, body)) = responses.pop_front() else {
                    // responses épuisées : la requête suivante reste à jamais sans réponse
                    // (watch pendant — le timeout global du wait tranche).
                    loop {
                        std::future::pending::<()>().await;
                    }
                };
                send.send_response(http_json(status, &body));
            }
        });
        let out = call(&mut obj);
        responder.abort();
        out
    }

    // Scénario : l'objet vu par le LIST initial, puis DELETED pendant le watch.
    const OBJ_NOT_READY: &str = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","uid":"uid-1","resourceVersion":"11"}}"#;
    const OBJ_READY: &str = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","uid":"uid-1","resourceVersion":"11"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}"#;

    fn list_of(item: &'static str) -> String {
        format!(
            r#"{{"apiVersion":"v1","kind":"ConfigMapList","metadata":{{"resourceVersion":"10"}},"items":[{item}]}}"#
        )
    }
    fn list_empty() -> String {
        r#"{"apiVersion":"v1","kind":"ConfigMapList","metadata":{"resourceVersion":"10"},"items":[]}"#
            .to_string()
    }
    fn watch_events(events: &[&'static str]) -> String {
        format!("{}\n", events.join("\n"))
    }
    fn status_body(code: u16, reason: &str) -> String {
        format!(
            r#"{{"kind":"Status","apiVersion":"v1","metadata":{{}},"status":"Failure","message":"{reason}","reason":"{reason}","code":{code}}}"#
        )
    }

    // ── Verdicts de classement (k8s.sdd `Must` : « classe les erreurs ») ──────
    // Le classement est verrouillé ici sur les types mesurés de kube-runtime 3.1 :
    // `wait::Error::ProbeFailed(watcher::Error)`, dont les variantes portent soit un
    // `kube::Error` (list/watch transportés), soit un `Status` (`WatchEvent::Error` —
    // c'est par là que tombe le `410 Gone`).

    fn probe(w: kube::runtime::watcher::Error) -> kube::runtime::wait::Error {
        kube::runtime::wait::Error::ProbeFailed(w)
    }
    fn api_status(code: u16) -> kube::Error {
        kube::Error::Api(Box::new(kube::core::Status {
            code,
            ..std::default::Default::default()
        }))
    }

    #[test]
    fn watch_verdicts_transient_and_definitive_classes() {
        use kube::runtime::watcher::Error as WatcherError;
        // Transitoires (k8s.sdd : 429, 5xx, timeout, coupure, 410) :
        for code in [408_u16, 410, 429, 500, 502, 503, 599] {
            assert_eq!(
                classify_wait_error(&probe(WatcherError::InitialListFailed(api_status(code)))),
                WatchFailure::Transient,
                "HTTP {code} doit être transitoire"
            );
        }
        assert_eq!(
            classify_wait_error(&probe(WatcherError::WatchStartFailed(api_status(503)))),
            WatchFailure::Transient,
            "5xx au démarrage du watch : transitoire"
        );
        assert_eq!(
            classify_wait_error(&probe(WatcherError::WatchFailed(kube::Error::ReadEvents(
                std::io::Error::other("pipe fermé"),
            )))),
            WatchFailure::Transient,
            "coupure du flux d'événements : transitoire"
        );
        assert_eq!(
            classify_wait_error(&probe(WatcherError::WatchFailed(kube::Error::Service(
                "connection reset".into(),
            )))),
            WatchFailure::Transient,
            "erreur de service (transport) : transitoire"
        );
        assert_eq!(
            classify_wait_error(&probe(WatcherError::WatchError(Box::new(kube::core::Status {
                code: 410,
                ..std::default::Default::default()
            },)))),
            WatchFailure::Transient,
            "410 Gone reçu comme événement ERROR : transitoire (reprise de la resourceVersion par re-liste)"
        );
        // Définitives (k8s.sdd : 401, 403, 404, requête invalide) :
        for code in [400_u16, 401, 403, 404, 409] {
            assert_eq!(
                classify_wait_error(&probe(WatcherError::InitialListFailed(api_status(code)))),
                WatchFailure::Definitive,
                "HTTP {code} doit être définitive"
            );
        }
        assert_eq!(
            classify_wait_error(&probe(WatcherError::WatchFailed(kube::Error::SerdeError(
                serde_json::from_str::<serde_json::Value>("{ pas du json").unwrap_err(),
            )))),
            WatchFailure::Definitive,
            "réponse non désérialisable : famille requête invalide"
        );
        assert_eq!(
            classify_wait_error(&probe(WatcherError::NoResourceVersion)),
            WatchFailure::Definitive,
            "resourceVersion absente : la resource ne supporte pas le watch, réessayer ne peut rien"
        );
    }

    // ── Scénario « erreur transitoire réessayée » ─────────────────────────────

    // Given un client tower-test dont le watch répond d'abord 429 puis un event
    // satisfaisant la condition ; When wait_condition("Ready", 30) ; Then la wait réussit
    // après un réessai avec backoff, sans erreur. (Ici le 429 tombe sur le LIST de la
    // 1ʳᵉ tentative ; timeout 1 s au lieu de 30 pour la vitesse du test.)
    #[test]
    fn wait_condition_retries_429_then_succeeds() {
        let out = served_wait(
            vec![
                (429, status_body(429, "TooManyRequests")),
                (200, list_of(OBJ_READY)),
            ],
            |obj| obj.wait_condition("Ready".to_string(), 1),
        );
        assert!(
            out.is_ok(),
            "le 429 est transitoire, la wait doit aboutir : {out:?}"
        );
    }

    // 410 Gone reçu comme ERROR event en cours de watch : transitoire, et la reprise
    // (nouvelle liste, resourceVersion renouvelée par la lib) mène au succès.
    #[test]
    fn wait_condition_retries_410_gone_then_succeeds() {
        let gone = watch_events(&[
            r#"{"type":"ERROR","object":{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"too old","reason":"Gone","code":410}}"#,
        ]);
        let out = served_wait(
            vec![
                (200, list_of(OBJ_NOT_READY)),
                (200, gone),
                (200, list_of(OBJ_READY)),
            ],
            |obj| obj.wait_condition("Ready".to_string(), 1),
        );
        assert!(
            out.is_ok(),
            "le 410 est transitoire, la wait doit aboutir : {out:?}"
        );
    }

    // Given un watch qui répond des 5xx jusqu'à l'écoulement du timeout ; Then l'échec
    // est Error::Elapsed (« Elapsed wait error: … » rendu par rhai_err).
    #[test]
    fn wait_condition_5xx_until_timeout_is_elapsed() {
        let out = served_wait(vec![(503, status_body(503, "ServiceUnavailable")); 30], |obj| {
            obj.wait_condition("Ready".to_string(), 1)
        });
        let err = out.expect_err("les 5xx jusqu'au timeout doivent échouer");
        assert!(
            err.to_string().contains("Elapsed wait error"),
            "le timeout global est Elapsed, obtenu : {err}"
        );
    }

    // Given un watch coupé par une erreur de connexion, puis rétabli avant le timeout ;
    // Then la wait réussit de même. (Mesuré : une fin de corps de watch est un EOF que
    // le watcher re-watche en SILENCE — `(None, State::InitListed)` — sans article
    // d'erreur ; le réessai visible est la 2ᵉ requête de watch.)
    #[test]
    fn watch_eof_reconnect_then_satisfying_event_succeeds() {
        let not_ready = watch_events(&[
            r#"{"type":"MODIFIED","object":{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","uid":"uid-1","resourceVersion":"11"}}}"#,
        ]);
        let ready = watch_events(&[
            r#"{"type":"MODIFIED","object":{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","uid":"uid-1","resourceVersion":"12"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}}"#,
        ]);
        let out = served_wait(
            vec![(200, list_of(OBJ_NOT_READY)), (200, not_ready), (200, ready)],
            |obj| obj.wait_condition("Ready".to_string(), 1),
        );
        assert!(
            out.is_ok(),
            "coupure puis rétablissement avant le timeout : succès sans erreur : {out:?}"
        );
    }

    // ── Scénario « erreur définitive : échec immédiat, sans second watch » ────

    // Given un watch qui répond 403 à wait_condition ; Then l'échec est immédiat en
    // Error::KubeWaitError via rhai_err, sans attendre le timeout ni resservir une requête.
    #[test]
    fn wait_condition_403_fails_immediately_without_second_request() {
        let server_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut obj, handle) = server_rt.block_on(async { mocked_object() });
        let responder = server_rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            let Some((_req, send)) = handle.next_request().await else {
                return false;
            };
            send.send_response(http_json(403, &status_body(403, "Forbidden")));
            // Verrou du compte de requêtes : aucune 2ᵉ requête dans la foulée.
            tokio::time::timeout(std::time::Duration::from_millis(200), handle.next_request())
                .await
                .is_err()
        });
        let out = obj.wait_condition("Ready".to_string(), 1);
        let quiet = server_rt.block_on(responder).unwrap();
        let err = out.expect_err("le 403 est définitif");
        assert!(
            err.to_string().contains("K8s wait error"),
            "définitive → KubeWaitError, obtenu : {err}"
        );
        assert!(quiet, "aucun second watch après une erreur définitive");
    }

    // ── Scénario « objet supprimé pendant l'attente » ─────────────────────────

    #[test]
    fn deleted_mid_wait_fails_fast_with_exact_string() {
        let deleted = watch_events(&[
            r#"{"type":"DELETED","object":{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","uid":"uid-1","resourceVersion":"12"}}}"#,
        ]);
        let out = served_wait(vec![(200, list_of(OBJ_NOT_READY)), (200, deleted)], |obj| {
            obj.wait_condition("Ready".to_string(), 1)
        });
        let err = out.expect_err("Deleted pendant la wait doit échouer");
        assert!(
            err.to_string().contains("object x was deleted while waiting"),
            "la chaîne exacte doit être rendue, obtenu : {err}"
        );
    }

    #[test]
    fn deleted_counts_as_success_for_wait_deleted() {
        let deleted = watch_events(&[
            r#"{"type":"DELETED","object":{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","uid":"uid-1","resourceVersion":"12"}}}"#,
        ]);
        let out = served_wait(vec![(200, list_of(OBJ_NOT_READY)), (200, deleted)], |obj| {
            obj.rhai_wait_deleted(1)
        });
        assert!(out.is_ok(), "pour wait_deleted, Deleted est le succès : {out:?}");
    }

    // ── Scénario « wait_for — l'exception du predicate n'est pas fatale » ─────
    // Full Rhai : le VRAI K8sObject, enregistré sur un engine nu (wait_for est câblé par
    // la macro `register_k8s_object` ; pas de LazyLock touché).

    fn wait_for_script(obj: &K8sObject, script: &str) -> RhaiRes<()> {
        let mut engine = Engine::new();
        engine
            .register_type_with_name::<K8sObject>("K8sObject")
            .register_fn("wait_for", K8sObject::wait_for);
        let mut scope = rhai::Scope::new();
        scope.push("o", Dynamic::from(obj.clone()));
        engine.eval_with_scope::<Dynamic>(&mut scope, script).map(|_| ())
    }

    // Given un predicate qui lève au 1er event puis retourne vrai au 2ᵉ ; Then la wait
    // RÉUSSIT : l'exception du 1ᵉʳ event est oubliée.
    #[test]
    fn wait_for_predicate_raise_then_satisfy_succeeds() {
        let events = watch_events(&[
            r#"{"type":"MODIFIED","object":{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","uid":"uid-1","resourceVersion":"11"},"spec":{"n":1}}}"#,
            r#"{"type":"MODIFIED","object":{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","uid":"uid-1","resourceVersion":"12"},"spec":{"n":2}}}"#,
        ]);
        let out = served_wait(vec![(200, list_empty()), (200, events)], |obj| {
            wait_for_script(
                obj,
                r#"o.wait_for(|x| { if x.spec.n == 1 { throw "boom1" } x.spec.n == 2 }, 1)"#,
            )
        });
        assert!(
            out.is_ok(),
            "un event satisfaisant après une exception doit réussir (exception oubliée) : {out:?}"
        );
    }

    // Given un predicate qui lève à chaque event jusqu'au timeout ; Then c'est la
    // DERNIÈRE exception qui est rendue (deux messages distincts, la dernière gagne),
    // et non un Elapsed trompeur.
    #[test]
    fn wait_for_predicate_last_exception_wins_at_timeout() {
        let events = watch_events(&[
            r#"{"type":"MODIFIED","object":{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","uid":"uid-1","resourceVersion":"11"},"spec":{"n":1}}}"#,
            r#"{"type":"MODIFIED","object":{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","uid":"uid-1","resourceVersion":"12"},"spec":{"n":2}}}"#,
        ]);
        let out = served_wait(vec![(200, list_empty()), (200, events)], |obj| {
            wait_for_script(
                obj,
                r#"o.wait_for(|x| { if x.spec.n == 1 { throw "boom1" } throw "boom2" }, 1)"#,
            )
        });
        let err = out.expect_err("le predicate lève jusqu'au timeout");
        let msg = err.to_string();
        assert!(
            msg.contains("boom2"),
            "la DERNIÈRE exception doit être rendue, obtenu : {msg}"
        );
        assert!(
            !msg.contains("boom1"),
            "la première exception doit avoir été effacée, obtenu : {msg}"
        );
        assert!(
            !msg.contains("Elapsed wait error"),
            "pas d'Elapsed trompeur quand une exception existe, obtenu : {msg}"
        );
    }

    // ── Quanta et chaînes locales (scénario « waits — secondes clamp… ») ──────

    // Le `-5` seul devient timeout `0 s` immédiat Elapsed (jamais une erreur d'argument).
    #[test]
    fn negative_timeout_is_immediate_elapsed() {
        let out = served_wait(vec![], |obj| obj.wait_condition("Ready".to_string(), -5));
        let err = out.expect_err("timeout négatif = 0 s = Elapsed immédiat");
        assert!(
            err.to_string().contains("Elapsed wait error"),
            "clamp à 0 s puis Elapsed, obtenu : {err}"
        );
    }

    // L'unique chaîne locale du vrai (Rhai) : wait_deleted sans uid échoue AVANT le
    // timeout, quel que soit le timeout.
    #[test]
    fn wait_deleted_without_uid_is_local_string_before_any_timeout() {
        let server_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut obj = server_rt.block_on(async {
            let (mock_service, _handle) =
                tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
            let ar = ApiResource {
                group: String::new(),
                version: "v1".to_string(),
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                plural: "configmaps".to_string(),
            };
            K8sObject {
                api: Api::namespaced_with(kube::Client::new(mock_service, "ns"), "ns", &ar),
                obj: serde_json::from_value(serde_json::json!({ "metadata": { "name": "gone" } })).unwrap(),
                kind: "ConfigMap".to_string(),
            }
        });
        let err = obj
            .rhai_wait_deleted(-5)
            .expect_err("uid absent → erreur locale, pas de timeout");
        assert!(
            err.to_string()
                .contains("cannot wait for deletion of gone: uid is missing"),
            "la chaîne locale doit être rendue, obtenu : {err}"
        );
    }

    // ── Migration workload : la face typée passe par le même helper ───────────
    #[test]
    fn workload_wait_available_satisfied_on_initial_list() {
        let server_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut dep, handle) = server_rt.block_on(async {
            let (mock_service, handle) =
                tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
            let api: Api<Deployment> = Api::namespaced(kube::Client::new(mock_service, "ns"), "ns");
            let obj: Deployment = serde_json::from_value(serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": { "name": "d", "resourceVersion": "1" },
                "status": { "conditions": [{ "type": "Available", "status": "True" }] }
            }))
            .unwrap();
            (K8sDeploy { api, obj }, handle)
        });
        let list = r#"{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"resourceVersion":"2"},"items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"d","resourceVersion":"1"},"status":{"conditions":[{"type":"Available","status":"True"}]}}]}"#;
        let responder = server_rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            let Some((_req, send)) = handle.next_request().await else {
                return;
            };
            send.send_response(http_json(200, list));
            std::future::pending::<()>().await;
        });
        let out = dep.wait_available(1);
        responder.abort();
        assert!(out.is_ok(), "condition satisfaie dès la liste initiale : {out:?}");
    }
}

/// Verrou du warn d'échec du pont de [`update_cache`] (k8s.sdd `Must`, décision du
/// développeur principal 2026-10-10) : le `.ok()` muet devient voie douce tracée. Le
/// captureur reprend le précédent `to_decimal` de ./hbs.rs (`warn_tests`) : couche de
/// capture du seul champ `message`, subscriber confiné au fil courant par
/// `tracing::subscriber::with_default` (thread-local), jamais `set_global_default`.
#[cfg(test)]
mod warn_tests {
    use super::update_cache;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

    /// Couche de capture minimale : ne retient que le texte formaté du champ `message` de
    /// chaque événement — le strict nécessaire pour assertionner le texte et le nombre du
    /// warn du contrat.
    struct MessageCapture(Arc<Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> Layer<S> for MessageCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = MessageOnly(Vec::new());
            event.record(&mut visitor);
            self.0.lock().unwrap().extend(visitor.0);
        }
    }

    /// Ne visite que `message` : le warn du contrat n'a que ce champ.
    struct MessageOnly(Vec<String>);

    impl Visit for MessageOnly {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0.push(format!("{value:?}"));
            }
        }
    }

    /// Scenario (k8s.sdd `Must`, amendé 2026-10-10) : appel de `update_cache` sur runtime
    /// `current_thread` — le pont `rt::block_on` refuse sans polliner le futur → UN warn de
    /// la famille `E_DISCOVERY_WARN` nommant l'exception du pont, rendu unité, sans panic.
    /// CACHE intact : sous `current_thread` le futur n'est jamais polliné, donc le `LazyLock`
    /// n'est pas touché — et tout touch hors cluster paniquerait « create discovery » (voie
    /// `populate_cache`) : l'absence de panic EST la preuve observable de l'intégrité.
    #[tokio::test(flavor = "current_thread")]
    async fn update_cache_bridge_failure_emits_one_family_warn_and_keeps_cache() {
        let captured: Arc<Mutex<Vec<String>>> = Arc::default();
        let subscriber =
            tracing_subscriber::registry::Registry::default().with(MessageCapture(Arc::clone(&captured)));
        tracing::subscriber::with_default(subscriber, || {
            update_cache(); // rend unité ; toute panique ferait échouer le test.
        });
        let warns = captured.lock().unwrap().clone();
        assert_eq!(
            warns.len(),
            1,
            "un seul warn attendu pour l'échec du pont, capturés : {warns:?}"
        );
        assert!(
            warns[0].contains("E_DISCOVERY_WARN: update_k8s_crd_cache")
                && warns[0].contains("requires a multi-thread tokio runtime"),
            "le warn doit porter la famille E_DISCOVERY_WARN et nommer l'exception du pont, obtenu : {:?}",
            warns[0]
        );
    }
}
