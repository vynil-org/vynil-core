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
        // l'`Api` de la lecture. Le `ns` vide est TRAITÉ COMME ABSENT (k8s.sdd Scenario
        // « workloads — ns/name obligatoires », l. 674-677, rendu à la tâche de conversion
        // où verrou @tower-test et implémentation voyagent ensemble, Tasks l. 446-451) :
        // aucune URL `/namespaces//…`, repli toutes namespaces comme chez le resolveur.
        let api: Api<DaemonSet> = match normalize_ns(Some(namespace)) {
            Some(ns) => Api::namespaced(CLIENT.clone(), &ns),
            None => Api::all(CLIENT.clone()),
        };
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
        // Un seul `Api` construit (k8s.sdd `Must`, nettoyage) ; `ns` vide traité comme
        // absent (Scenario « workloads », l. 674-677 — voir `get_deamonset`).
        let api: Api<StatefulSet> = match normalize_ns(Some(namespace)) {
            Some(ns) => Api::namespaced(CLIENT.clone(), &ns),
            None => Api::all(CLIENT.clone()),
        };
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
        // Un seul `Api` construit (k8s.sdd `Must`, nettoyage) ; `ns` vide traité comme
        // absent (Scenario « workloads », l. 674-677 — voir `get_deamonset`).
        let api: Api<Deployment> = match normalize_ns(Some(namespace)) {
            Some(ns) => Api::namespaced(CLIENT.clone(), &ns),
            None => Api::all(CLIENT.clone()),
        };
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
        // Un seul `Api` construit (k8s.sdd `Must`, nettoyage) ; `ns` vide traité comme
        // absent (Scenario « workloads », l. 674-677 — voir `get_deamonset`).
        let api: Api<Job> = match normalize_ns(Some(namespace)) {
            Some(ns) => Api::namespaced(CLIENT.clone(), &ns),
            None => Api::all(CLIENT.clone()),
        };
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
    use std::sync::Arc;
    use tracing_subscriber::layer::SubscriberExt as _;

    // Capture de warn partagée (patron ./hbs.rs `warn_tests`, repris des tests
    // clos de k8s.sdd) : couche qui enregistre le seul champ `message` des events,
    // subscriber confiné au fil courant par `tracing::subscriber::with_default`
    // (jamais `set_global_default`).
    #[derive(Clone)]
    struct WarnSink(Arc<std::sync::Mutex<Vec<String>>>);

    struct WarnMsg(Vec<String>);
    impl tracing::field::Visit for WarnMsg {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0.push(format!("{value:?}"));
            }
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::layer::Layer<S> for WarnSink {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
            let mut v = WarnMsg(Vec::new());
            event.record(&mut v);
            self.0.lock().unwrap().extend(v.0);
        }
    }

    /// Subscriber de capture + journal des messages (à vider après `with_default`).
    fn warn_capture() -> (impl tracing::Subscriber, Arc<std::sync::Mutex<Vec<String>>>) {
        let sink: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let sub = tracing_subscriber::registry::Registry::default().with(WarnSink(Arc::clone(&sink)));
        (sub, sink)
    }

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

    // ══ Conversion des Scenario sans test (k8s.sdd Tasks, lot 2026-10-11) ═══════
    // Deux seams, aucun cluster :
    // - in-process : handles `K8sGeneric`/`K8sRaw`/workloads construits À LA MAIN sur
    //   `tower_test::mock` (mêmes champs publics que `mocked_generic`) — les LazyLock
    //   CLIENT/RAW_CLIENT/CACHE ne sont jamais touchés par ces tests ;
    // - fils auto-ré-exécutés (patron ./oci.rs, marqueur + `current_exe` + `--exact`) :
    //   tout ce qui requiert un état global frais (providers non posés, `CLIENT_NAME`
    //   jamais posé) ou hydrate un LazyLock (CLIENT/RAW_CLIENT sur mock, CACHE peuplé
    //   par une discovery servie par mock).

    const CHILD_ASSERTED: &str = "VYVIL_K8S_CHILD_ASSERTED";

    /// Ligne de requête capturée par le faux API server : `METHODE chemin?query`,
    /// suffixée du `Content-Type` et du corps (utile aux verrous SSA/injection).
    type Seen = Arc<std::sync::Mutex<Vec<String>>>;

    /// Faux API server servant `responses` dans l'ordre (puis pendant), handle
    /// `K8sGeneric` cœur v1/pods (namespacé `app` si `ns`, sinon toutes namespaces),
    /// construit sur un runtime dédié — le handle de mock (`tower::Buffer`) se spawn À
    /// la construction. L'appel part du fil de test SANS runtime (voie secours
    /// `rt::block_on`, patron `get_outside_runtime…`).
    fn generic_over_mock(
        ns: Option<&str>,
        responses: Vec<(u16, String)>,
    ) -> (
        K8sGeneric,
        Seen,
        tokio::runtime::Runtime,
        tokio::task::JoinHandle<()>,
    ) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let seen: Seen = Arc::default();
        let (mock_service, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let ar = ApiResource {
            group: String::new(),
            version: "v1".to_string(),
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
            plural: "pods".to_string(),
        };
        let client = rt.block_on(async { kube::Client::new(mock_service, "ns") });
        let api: Api<DynamicObject> = match ns {
            Some(ns) => Api::namespaced_with(client, ns, &ar),
            None => Api::all_with(client, &ar),
        };
        let generic = K8sGeneric {
            api: Some(api),
            ns: ns.map(str::to_string),
            scope: if ns.is_none() {
                Scope::Cluster
            } else {
                Scope::Namespaced
            },
            kind: "Pod".to_string(),
        };
        let seen2 = Arc::clone(&seen);
        let responder = rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            let mut responses = std::collections::VecDeque::from(responses);
            loop {
                let Some((req, send)) = handle.next_request().await else {
                    return;
                };
                let method = req.method().clone();
                let path = req.uri().path().to_string();
                let query = req.uri().query().map_or_else(String::new, |q| format!("?{q}"));
                let ctype = req
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body = req.into_body().collect_bytes().await.unwrap_or_default();
                let body_text = String::from_utf8_lossy(&body).into_owned();
                seen2.lock().unwrap().extend(std::iter::once(format!(
                    "{method} {path}{query}|{ctype}|{body_text}"
                )));
                let Some((status, body)) = responses.pop_front() else {
                    loop {
                        std::future::pending::<()>().await;
                    }
                };
                send.send_response(http_json(status, &body));
            }
        });
        (generic, seen, rt, responder)
    }

    fn seen_lines(seen: &Seen) -> Vec<String> {
        seen.lock().unwrap().clone()
    }

    fn pod_body(name: &str) -> String {
        format!(r#"{{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"{name}","namespace":"app"}}}}"#)
    }

    fn pod_list(items: &[&str]) -> String {
        let items: Vec<String> = items.iter().map(|n| pod_body(n)).collect();
        format!(
            r#"{{"apiVersion":"v1","kind":"PodList","metadata":{{"resourceVersion":"1"}},"items":[{}]}}"#,
            items.join(",")
        )
    }

    // ── Scenario « 404 est une erreur, exist est un ouï-dire du cache » ──────
    // Les trois faces typées (`get`, `get_meta`, `delete`) rendent la chaîne
    // « K8s error: … » (préfixe seul contracté) ; la face script (`rhai_get`) la
    // porte aussi via `rhai_err`.
    #[test]
    fn get_get_meta_delete_404_render_the_kube_error_prefix() {
        for call in 0..4 {
            let (generic, _seen, rt, responder) =
                generic_over_mock(Some("app"), vec![(404, status_body(404, "Not Found"))]);
            let outcome = match call {
                0 => generic.get("absent").map(|_| ()).map_err(|e| e.to_string()),
                1 => generic.get_meta("absent").map(|_| ()).map_err(|e| e.to_string()),
                2 => generic.delete("absent").map_err(|e| e.to_string()),
                _ => {
                    let mut g = generic;
                    g.rhai_get("absent".to_string())
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                }
            };
            responder.abort();
            drop(rt);
            let err = outcome.expect_err("le 404 doit rendre une erreur");
            if call < 3 {
                assert!(
                    err.starts_with("K8s error: "),
                    "préfixe « K8s error: » attendu (face typée), obtenu : {err}"
                );
            } else {
                assert!(
                    err.contains("K8s error"),
                    "le préfixe traverse la conversion Rhai (face script), obtenu : {err}"
                );
            }
        }
    }

    // Scénario (l. 590) : `exist` regarde la RÉSOLUTION du handle, jamais le contenu
    // du cluster — AUCUNE requête n'est émise (le mock sans réponse n'est jamais
    // sollicité : `next_request` reste vide).
    #[tokio::test(flavor = "current_thread")]
    async fn exist_is_resolution_hearsay_and_never_calls_the_api() {
        let (generic, mut handle) = mocked_generic();
        assert!(
            generic.exist(),
            "handle résolu : exist vrai sans regarder d'objet"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), handle.next_request())
                .await
                .is_err(),
            "exist ne doit émettre AUCUNE requête API"
        );
    }

    // Handle non résolu (api: None) : `exist` rend faux SANS erreur (jamais
    // `UnsupportedMethod`), l'usage des autres méthodes rend « Unsupported method ».
    #[test]
    fn unresolved_handle_renders_unsupported_method_at_use_not_construction() {
        let unresolved = K8sGeneric {
            api: None,
            ns: None,
            scope: Scope::Cluster,
            kind: String::new(),
        };
        assert!(!unresolved.exist());
        let mut g = unresolved;
        assert!(
            !g.rhai_exist()
                .expect("exist ne doit jamais lever")
                .as_bool()
                .unwrap(),
            "exist non résolu : faux, jamais UnsupportedMethod"
        );
        let errs: Vec<String> = vec![
            g.get("x").map(|_| ()).unwrap_err().to_string(),
            g.list().map(|_| ()).unwrap_err().to_string(),
            g.get_meta("x").map(|_| ()).unwrap_err().to_string(),
            g.list_meta().map(|_| ()).unwrap_err().to_string(),
            g.delete("x").unwrap_err().to_string(),
            g.create(serde_json::Map::new())
                .map(|_| ())
                .unwrap_err()
                .to_string(),
            g.replace("x", serde_json::Map::new())
                .map(|_| ())
                .unwrap_err()
                .to_string(),
            g.patch("x", serde_json::Map::new())
                .map(|_| ())
                .unwrap_err()
                .to_string(),
            g.apply("x", serde_json::Map::new())
                .map(|_| ())
                .unwrap_err()
                .to_string(),
        ];
        for e in errs {
            assert!(
                e.contains("Unsupported method"),
                "« Unsupported method » attendu, obtenu : {e}"
            );
        }
    }

    // ── Scenario « new_global = toutes les namespaces » (face typée) ──────────
    // Handle sans ns : `Api::all` → URL sans segment `namespaces`, couverture de
    // toutes les namespaces ; le sélecteur de labels passe VERBATIM dans la query.
    #[test]
    fn list_on_all_namespaces_handle_omits_the_namespaces_segment() {
        let (generic, seen, rt, responder) = generic_over_mock(None, vec![(200, pod_list(&["a", "b"]))]);
        let out = generic.list().expect("la liste doit être servie");
        responder.abort();
        drop(rt);
        assert_eq!(out.items.len(), 2, "les deux objets traversent");
        let lines = seen_lines(&seen);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("GET /api/v1/pods") && !lines[0].contains("/namespaces/"),
            "toutes namespaces = URL sans « /namespaces/ », obtenu : {}",
            lines[0]
        );
    }

    #[test]
    fn list_labels_passes_the_selector_verbatim_in_the_query() {
        let (generic, seen, rt, responder) = generic_over_mock(Some("app"), vec![(200, pod_list(&[]))]);
        generic
            .list_labels("app=web".to_string())
            .expect("la liste filtrée doit être servie");
        responder.abort();
        drop(rt);
        let lines = seen_lines(&seen);
        let query = lines[0].split('|').next().expect("segment méthode+URL");
        assert!(
            query.starts_with("GET /api/v1/namespaces/app/pods?")
                && query.contains("labelSelector=app")
                && query.contains("web"),
            "le sélecteur passe verbatim dans la query, obtenu : {query}"
        );
    }

    // ── Scenario « labels et ownerReferences injectés à chaque écriture » ─────
    // Providers posés GLOBALEMENT (valeurs fixes, seule la face wire les lit en
    // in-process — les tests `prepare_handle` passent leurs valeurs directes).
    const PROVIDER_LABELS: &str = r#"{"app":"web","team":"platform"}"#;
    const PROVIDER_OWNER_UID: &str = "owner-uid-1";

    fn wire_providers_once() {
        set_get_labels(Box::new(|| {
            Some(serde_json::from_str(PROVIDER_LABELS).unwrap_or(serde_json::Value::Null))
        }));
        set_get_owner(Box::new(|| {
            Some(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap", "name": "owner-cm", "uid": PROVIDER_OWNER_UID
            }))
        }));
        set_get_owner_ns(Box::new(|| Some("app".to_string())));
    }

    // create sur handle ns `app` (== ownerNs) : labels FUSIONNÉS (clés existantes
    // gardées, absentes ajoutées), owner APPENDU en fin d'array — lu sur le corps
    // réellement parti au serveur.
    #[test]
    fn create_sends_merged_labels_and_appended_owner_on_the_wire() {
        wire_providers_once();
        let (generic, seen, rt, responder) = generic_over_mock(Some("app"), vec![(201, pod_body("c1"))]);
        let data: serde_json::Map<String, serde_json::Value> = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": { "name": "c1", "labels": { "app": "mine" } }
        }))
        .unwrap();
        generic.create(data).expect("le create est servi");
        responder.abort();
        drop(rt);
        let lines = seen_lines(&seen);
        let body: serde_json::Value =
            serde_json::from_str(lines[0].split('|').nth(2).expect("corps capturé")).expect("corps JSON");
        assert_eq!(body["metadata"]["labels"]["app"], "mine", "clé existante GARDÉE");
        assert_eq!(
            body["metadata"]["labels"]["team"], "platform",
            "clé absente AJOUTÉE depuis le provider"
        );
        let owners = body["metadata"]["ownerReferences"]
            .as_array()
            .expect("ownerReferences présente");
        assert_eq!(owners.last().expect("appendu EN FIN")["uid"], PROVIDER_OWNER_UID);
        assert!(lines[0].starts_with("POST /api/v1/namespaces/app/pods"));
    }

    // FACE SCRIPT (Tasks k8s.sdd : « injection labels/owner EN SCRIPT ») — même
    // `prepare_handle` partagé, joué ici par `create` enregistré sur l'engine.
    #[test]
    fn rhai_script_injects_merged_labels_and_appended_owner_on_the_wire() {
        wire_providers_once();
        let (generic, seen, rt, responder) = generic_over_mock(Some("app"), vec![(201, pod_body("c1"))]);
        let mut engine = Engine::new();
        k8sgeneric_rhai_register(&mut engine);
        let mut scope = rhai::Scope::new();
        scope.push("h", generic);
        let _ = engine
            .eval_with_scope::<Dynamic>(
                &mut scope,
                r#"h.create(#{
                    apiVersion: "v1", kind: "ConfigMap",
                    metadata: #{ name: "c1", labels: #{ app: "mine" } }
                })"#,
            )
            .expect("le create du script est servi");
        responder.abort();
        drop(rt);
        let lines = seen_lines(&seen);
        let body: serde_json::Value =
            serde_json::from_str(lines[0].split('|').nth(2).expect("corps capturé")).expect("corps JSON");
        assert_eq!(
            body["metadata"]["labels"]["app"], "mine",
            "clé existante GARDÉE (script)"
        );
        assert_eq!(
            body["metadata"]["labels"]["team"], "platform",
            "clé absente AJOUTÉE depuis le provider (script)"
        );
        assert_eq!(
            body["metadata"]["ownerReferences"]
                .as_array()
                .expect("ownerReferences présente (script)")
                .last()
                .expect("appendu EN FIN")["uid"],
            PROVIDER_OWNER_UID
        );
    }

    // Les `rhai_*` lecture rendent le DOCOBJET COMPLET / la LISTE ENTIÈRE (apiVersion/
    // kind/metadata/items inclus) — jamais le `data` nu (k8s.sdd `Returns`).
    #[test]
    fn rhai_get_and_list_return_the_complete_docobjects_not_bare_data() {
        let (generic, _seen, rt, responder) =
            generic_over_mock(Some("app"), vec![(200, pod_list(&["a", "b"]))]);
        let mut engine = Engine::new();
        k8sgeneric_rhai_register(&mut engine);
        let mut scope = rhai::Scope::new();
        scope.push("h", generic);
        let listed = engine
            .eval_with_scope::<Dynamic>(&mut scope, "h.list()")
            .expect("la liste du script est servie");
        let lv = serde_json::to_value(&listed).expect("liste sérialisable");
        assert_eq!(lv["apiVersion"], "v1", "la LISTE ENTIÈRE : apiVersion inclus");
        assert_eq!(lv["kind"], "PodList", "la LISTE ENTIÈRE : kind inclus");
        assert!(lv["metadata"].is_object(), "la LISTE ENTIÈRE : metadata incluse");
        assert_eq!(lv["items"].as_array().expect("items").len(), 2);
        responder.abort();
        drop(rt);
    }

    // ownerNs ≠ ns du handle : ownerReferences ABSENT — silent ; labels TOUJOURS.
    #[test]
    fn owner_namespace_mismatch_drops_the_owner_and_keeps_labels() {
        wire_providers_once();
        let (generic, seen, rt, responder) = generic_over_mock(Some("other"), vec![(201, pod_body("c1"))]);
        let data: serde_json::Map<String, serde_json::Value> = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "ConfigMap", "metadata": { "name": "c1" }
        }))
        .unwrap();
        generic.create(data).expect("le create est servi");
        responder.abort();
        drop(rt);
        let body: serde_json::Value =
            serde_json::from_str(seen_lines(&seen)[0].split('|').nth(2).expect("corps")).unwrap();
        assert!(
            body["metadata"].get("ownerReferences").is_none(),
            "ownerNs ({}) ≠ ns du handle (other) : ownerReferences ABSENT",
            "app"
        );
        assert_eq!(body["metadata"]["labels"]["team"], "platform", "labels TOUJOURS");
    }

    // ── Scenario « patch et apply = SSA forcé fieldManager client_name » ──────
    // La valeur exacte posée par le consumer (« my-app.example.com ») et la PANIC
    // client_name jamais posé voyagent au FILS `field_manager…` (État global frais).
    // In-process : forme des params (force, content-type SSA, PUT nu, 409 nu).
    #[test]
    fn patch_is_forced_ssa_apply_with_the_client_name_as_manager() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let manager = crate::get_client_name();
        let (generic, seen, rt, responder) = generic_over_mock(Some("app"), vec![(200, pod_body("n1"))]);
        let data: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({"apiVersion":"v1","kind":"Pod"})).unwrap();
        generic.patch("n1", data).expect("le patch SSA est servi");
        responder.abort();
        drop(rt);
        let line = seen_lines(&seen).remove(0);
        let head = line.split('|').next().expect("méthode+URL");
        assert!(
            head.starts_with("PATCH "),
            "jamais MergePatch/JSONPatch : PATCH attendu : {head}"
        );
        assert!(head.contains("force=true"), "force posé : {head}");
        assert!(
            head.contains(&format!("fieldManager={manager}")),
            "fieldManager = client_name ({manager}) : {head}"
        );
        assert!(
            line.contains("application/apply-patch+yaml"),
            "content-type SSA Apply : {line}"
        );
    }

    // replace = PUT nu : aucun param SSA, et le 409 d'un objet concurrent (sans
    // resourceVersion) remonte NU — AUCUNE prélecture (une seule requête vue).
    #[test]
    fn replace_is_a_plain_put_and_the_409_is_bare_without_preread() {
        let (generic, seen, rt, responder) =
            generic_over_mock(Some("app"), vec![(409, status_body(409, "Conflict"))]);
        let data: serde_json::Map<String, serde_json::Value> = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod", "metadata": { "name": "n1" }
        }))
        .unwrap();
        let err = generic
            .replace("n1", data)
            .expect_err("le 409 sans resourceVersion doit remonter");
        responder.abort();
        drop(rt);
        assert!(err.to_string().starts_with("K8s error: "), "conflit nu : {err}");
        let lines = seen_lines(&seen);
        assert_eq!(lines.len(), 1, "aucune prélecture, aucun retry");
        let head = lines[0].split('|').next().expect("tête");
        assert!(head.starts_with("PUT "), "PUT attendu : {head}");
        assert!(
            !head.contains("fieldManager") && !head.contains("force="),
            "PUT nu, jamais de params SSA : {head}"
        );
    }

    // ── Scenario « apply replie un Job immuable déjà complet, pas un autre » ──
    // Faux serveur « jobs » : le PATCH (apply) rate toujours sur « immutable » ; le
    // GET de repli sert `served_job`. La décision (repli ou erreur) est rendue par
    // `job_is_completed` sur ce GET.
    fn jobs_over_mock(
        served_job: &'static str,
    ) -> (
        K8sGeneric,
        Seen,
        tokio::runtime::Runtime,
        tokio::task::JoinHandle<()>,
    ) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let seen: Seen = Arc::default();
        let (mock_service, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let ar = ApiResource {
            group: "batch".to_string(),
            version: "v1".to_string(),
            api_version: "batch/v1".to_string(),
            kind: "Job".to_string(),
            plural: "jobs".to_string(),
        };
        let client = rt.block_on(async { kube::Client::new(mock_service, "ns") });
        let api: Api<DynamicObject> = Api::namespaced_with(client, "app", &ar);
        let generic = K8sGeneric {
            api: Some(api),
            ns: Some("app".to_string()),
            scope: Scope::Namespaced,
            kind: "Job".to_string(),
        };
        let seen2 = Arc::clone(&seen);
        let responder = rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            loop {
                let Some((req, send)) = handle.next_request().await else {
                    return;
                };
                let method = req.method().clone();
                let path = req.uri().path().to_string();
                seen2
                    .lock()
                    .unwrap()
                    .extend(std::iter::once(format!("{method} {path}")));
                if method == http::Method::PATCH {
                    send.send_response(http_json(
                        422,
                        r#"{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Job.batch \"j1\" is invalid: field spec.template: Invalid value: field spec.template is immutable","reason":"Invalid","code":422}"#,
                    ));
                } else {
                    send.send_response(http_json(200, served_job));
                }
            }
        });
        (generic, seen, rt, responder)
    }

    fn job_data(kind: &str) -> serde_json::Map<String, serde_json::Value> {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "batch/v1", "kind": kind, "metadata": { "name": "j1" },
            "spec": { "template": { "spec": {
                "containers": [{ "name": "c", "image": "i" }], "restartPolicy": "Never"
            } } }
        }))
        .unwrap()
    }

    const JOB_COMPLETED: &str = r#"{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"j1"},"status":{"completionTime":"2026-01-01T00:00:00Z"}}"#;
    const JOB_SUCCEEDED_ALONE: &str = r#"{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"j1"},"status":{"succeeded":1,"completions":3}}"#;
    const JOB_NOT_COMPLETED: &str = r#"{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"j1"},"status":{"conditions":[{"type":"Complete","status":"False"}]}}"#;

    // Repli : l'apply rate sur « immutable » ET le GET actuel est complété → RETOUR
    // Ok de l'objet GET (avec completionTime), pas de la version envoyée (sans status).
    #[test]
    fn apply_falls_back_to_the_current_object_on_a_completed_immutable_job() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let (generic, seen, rt, responder) = jobs_over_mock(JOB_COMPLETED);
        let out = generic
            .apply("j1", job_data("Job"))
            .expect("le Job déjà complet ne doit pas faire échouer l'apply");
        responder.abort();
        drop(rt);
        assert_eq!(
            out.data["status"]["completionTime"],
            serde_json::json!("2026-01-01T00:00:00Z"),
            "c'est l'objet GET actuel qui est rendu (pas la version envoyée)"
        );
        let lines = seen_lines(&seen);
        assert_eq!(lines, vec![
            "PATCH /apis/batch/v1/namespaces/app/jobs/j1",
            "GET /apis/batch/v1/namespaces/app/jobs/j1"
        ]);
    }

    // `succeeded > 0` seul ne suffit plus à masquer l'erreur (décision actée), et
    // `Complete=False` sans completionTime non plus.
    #[test]
    fn apply_keeps_the_error_when_completion_is_not_proven() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        for served in [JOB_SUCCEEDED_ALONE, JOB_NOT_COMPLETED] {
            let (generic, _seen, rt, responder) = jobs_over_mock(served);
            let err = generic
                .apply("j1", job_data("Job"))
                .expect_err("la complétude n'est pas prouvée : l'erreur reste");
            responder.abort();
            drop(rt);
            let text = err.to_string();
            assert!(
                text.contains("K8s error") && text.contains("immutable"),
                "l'erreur KubeError d'origine est rendue telle quelle, obtenu : {text}"
            );
        }
    }

    // Comparaison du `kind` EXACTE, sensible à la casse : `kind: job` minuscule ne
    // déclenche AUCUN repli (le GET de repli, même complet, ne doit pas être lu).
    #[test]
    fn apply_lowercase_job_kind_gets_no_fallback() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let (generic, _seen, rt, responder) = jobs_over_mock(JOB_COMPLETED);
        let err = generic
            .apply("j1", job_data("job"))
            .expect_err("le repli compare le kind en exact");
        responder.abort();
        drop(rt);
        assert!(err.to_string().contains("immutable"), "erreur conservée : {err}");
    }

    // ══ Fils ════════════════════════════════════════════════════════════════════
    // État global frais exigé (providers/`CLIENT_NAME` jamais posés, LazyLock à
    // hydrater sur mock) : patron ./oci.rs.

    fn spawn_k8s_child(marker: &'static str, test_path: &str) -> String {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(test_path)
            .arg("--exact")
            .arg("--nocapture")
            .env_clear()
            .env(marker, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success() && stdout.contains(CHILD_ASSERTED),
            "le fils {test_path} doit avoir passé ses assertions : statut {:?}\n--- stdout ---{stdout}\n--- stderr ---{stderr}",
            out.status
        );
        stdout
    }

    // ── Scenario « provider premier gagne, context_is_wired complet seul suffit »
    // + « sans provider, chaque premier touch panique avec son message » (CLIENT).
    #[test]
    fn unwired_context_and_provider_first_wins_lock_in_a_fresh_process() {
        const MARKER: &str = "VYVIL_K8S_UNWIRED_CHILD";
        if std::env::var_os(MARKER).is_some() {
            assert!(!context_is_wired(), "processus frais : rien de câblé");
            let boom = std::panic::catch_unwind(|| {
                let _ = &*CLIENT;
            });
            let payload = boom.expect_err("touch de CLIENT sans provider : panic contractée");
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            assert!(
                msg.contains("k8s context not initialized"),
                "message de panic attendu, obtenu : {msg}"
            );
            let f: Box<dyn Fn() -> Client + Send + Sync> =
                Box::new(|| unreachable!("le provider posé ne doit jamais être lu ici"));
            set_get_client(f);
            // Premier gagne, second SILENCIEUSEMENT ignoré (`OnceLock::set().ok()`).
            set_get_client(Box::new(|| {
                unreachable!("le second provider ne doit jamais être lu")
            }));
            set_get_labels(Box::new(|| None));
            set_get_owner(Box::new(|| None));
            set_get_owner_ns(Box::new(|| None));
            assert!(
                !context_is_wired(),
                "les 4 providers sans client_name ne suffisent PAS (un seul manque → faux)"
            );
            crate::set_client_name(|| "child.example.com".to_string());
            assert!(context_is_wired(), "les cinq posés : vrai");
            println!("{CHILD_ASSERTED}");
            return;
        }
        spawn_k8s_child(
            MARKER,
            "k8s::tests::unwired_context_and_provider_first_wins_lock_in_a_fresh_process",
        );
    }

    // ── Scenario « sans provider… CACHE » + garde de cache de `update_cache`.
    // Le timeout 60 s (`E_DISCOVERY_TIMEOUT`) n'est PAS verrouillable ici : la
    // constante `from_mins(1)` est codée et `tokio/time` sans `test-util` (pas
    // d'horloge figée) — mesuré, consigné au rapport. La voie échec (ancien cache
    // gardé, aucune panic, CACHE jamais peuplé par un update raté) est verrouillée.
    #[test]
    fn cache_panic_is_final_and_update_cache_keeps_the_cache_in_a_fresh_process() {
        const MARKER: &str = "VYVIL_K8S_CACHE_CHILD";
        if std::env::var_os(MARKER).is_some() {
            // Discovery TOUJOURS entravée : /apis répond 500 (après le 403 du
            // listage APIService, voie douce déjà verrouillée in-process).
            let (mock_service, handle) =
                tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
            let factory: Box<dyn Fn() -> Client + Send + Sync> = {
                let svc = mock_service.clone();
                Box::new(move || kube::Client::new(svc.clone(), "ns"))
            };
            set_get_client(factory);
            set_get_labels(Box::new(|| None));
            set_get_owner(Box::new(|| None));
            set_get_owner_ns(Box::new(|| None));
            crate::set_client_name(|| "child.example.com".to_string());
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let responder = rt.spawn(async move {
                let mut handle = std::pin::pin!(handle);
                loop {
                    let Some((req, send)) = handle.next_request().await else {
                        return;
                    };
                    let path = req.uri().path().to_string();
                    if path == "/apis" {
                        send.send_response(http_json(500, &status_body(500, "InternalFailure")));
                    } else {
                        send.send_response(http_json(403, &status_body(403, "Forbidden")));
                    }
                }
            });
            let boom1 = rt
                .block_on(rt.spawn(async {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _ = &*CACHE;
                    }))
                }))
                .unwrap();
            let p1 = boom1.expect_err("CACHE sans discovery : panic contractée");
            let m1 = p1
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p1.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            assert!(
                m1.contains("create discovery (excluding api-services)"),
                "message de la panic d'infrastructure, obtenu : {m1}"
            );
            // `update_cache` sur le pont jouable (worker multi-thread) : discovery
            // rate → warn famille E_DISCOVERY_WARN « keeping old cache », AUCUNE
            // panic, CACHE jamais écrit.
            let (warn_sub, captured) = warn_capture();
            rt.block_on(rt.spawn(async move {
                tracing::subscriber::with_default(warn_sub, || {
                    update_cache();
                });
            }))
            .unwrap();
            let warns = captured.lock().unwrap().clone();
            assert!(
                warns
                    .iter()
                    .any(|w| w.contains("E_DISCOVERY_WARN: update_k8s_crd_cache failed")
                        && w.contains("keeping old cache")),
                "le warn de l'échec (garde de l'ancien cache) est attendu, capturés : {warns:?}"
            );
            // La garde est Observable : CACHE n'a jamais été peuplé (un update raté
            // n'y écrit pas) — le prochain touch panique à nouveau, sur le poison
            // définitif du LazyLock (« previously poisoned »), seconde preuve que
            // rien n'a été écrit dans le cache.
            let boom2 = rt
                .block_on(rt.spawn(async {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _ = &*CACHE;
                    }))
                }))
                .unwrap();
            let p2 = boom2.expect_err("la panique CACHE est définitive");
            let m2 = p2
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p2.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            assert!(
                m2.contains("LazyLock") && m2.contains("poisoned"),
                "seconde panique : poison définitif du LazyLock attendu, obtenu : {m2}"
            );
            responder.abort();
            drop(rt);
            println!("{CHILD_ASSERTED}");
            return;
        }
        spawn_k8s_child(
            MARKER,
            "k8s::tests::cache_panic_is_final_and_update_cache_keeps_the_cache_in_a_fresh_process",
        );
    }

    // ── Scenarios « discovery survit au listage APIService » (voie échec, en
    // in-process impossible sans hydrater CLIENT globalement : fils dédié qui la
    // joue AVANT tout CACHE) + « new_ns insensible et pluriel, min-lexicographique
    // tranche, zéro appel » + « new_global = toutes les namespaces » face CACHE +
    // l'usage du handle non résolu en script.

    /// Faux API server du fils résolution : listage `APIService` RATE (403, voie
    /// douce), `/apis` sert le groupe `acme.io`, `/api/v1` le cœur (pods/Pod
    /// namespaced, nodes/Node cluster, mods/Mod namespaced), `/apis/acme.io/v1`
    /// le CRD `Pod`/`pods` ; tout le reste est un List vide.
    fn spawn_cache_child_api(
        rt: &tokio::runtime::Runtime,
        handle: tower_test::mock::Handle<http::Request<Body>, http::Response<Body>>,
        seen: Seen,
    ) -> tokio::task::JoinHandle<()> {
        rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            loop {
                let Some((req, send)) = handle.next_request().await else { return };
                let path = req.uri().path().to_string();
                seen.lock()
                    .unwrap()
                    .extend(std::iter::once(format!("GET {path}")));
                let body: (&str, u16) = match path.as_str() {
                    "/apis/apiregistration.k8s.io/v1/apiservices" => {
                        (&status_body(403, "Forbidden"), 403)
                    }
                    "/apis" => (
                        r#"{"kind":"APIGroupList","apiVersion":"v1","groups":[{"name":"acme.io","versions":[{"groupVersion":"acme.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"acme.io/v1","version":"v1"}}]}"#,
                        200,
                    ),
                    "/apis/acme.io/v1" => (
                        r#"{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"acme.io/v1","resources":[{"name":"pods","singularName":"","namespaced":true,"kind":"Pod","verbs":["get","list"]}]}"#,
                        200,
                    ),
                    "/api" => (r#"{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[]}"#, 200),
                    "/api/v1" => (
                        r#"{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[{"name":"pods","singularName":"","namespaced":true,"kind":"Pod","verbs":["get","list"]},{"name":"nodes","singularName":"","namespaced":false,"kind":"Node","verbs":["get","list"]},{"name":"mods","singularName":"","namespaced":true,"kind":"Mod","verbs":["get","list"]}]}"#,
                        200,
                    ),
                    _ => (
                        r#"{"apiVersion":"v1","kind":"List","metadata":{"resourceVersion":"9"},"items":[]}"#,
                        200,
                    ),
                };
                send.send_response(http_json(body.1, body.0));
            }
        })
    }

    /// Phase 1 du fils résolution : les faces CACHE jouent par l'engine sur un
    /// worker (unique pont jouable sans cluster, le CACHE s'hydrate là).
    fn run_cache_child_script_faces(rt: &tokio::runtime::Runtime) {
        rt.block_on(rt.spawn(async {
            let mut engine = Engine::new();
            k8sgeneric_rhai_register(&mut engine);
            // l. 571-575 : PODS/Pod/pods, ns app → TOUS le cœur min-lex.
            for name in ["PODS", "Pod", "pods"] {
                let _ = engine
                    .eval::<Dynamic>(&format!("let g = k8s_resource(\"{name}\", \"app\"); g.list();"))
                    .unwrap_or_else(|e| panic!("résolution {name} : {e}"));
            }
            // scope de la RESOURCE, et `nodes` cluster-wide :
            assert_eq!(
                engine
                    .eval::<String>(r#"k8s_resource("PODS","app").scope"#)
                    .unwrap(),
                "namespace"
            );
            let _ = engine.eval::<Dynamic>(r#"k8s_resource("nodes").list()"#).unwrap();
            // l. 580-588 : global = toutes namespaces ; ns vide = sans ns ;
            // « v1 » sans `/` résout simple (mod → cœur) ; groupe/version
            // explicite → URL du groupe.
            let _ = engine.eval::<Dynamic>(r#"k8s_resource("pods").list()"#).unwrap();
            let _ = engine
                .eval::<Dynamic>(r#"k8s_resource("pods", "").list()"#)
                .unwrap();
            let _ = engine
                .eval::<Dynamic>(r#"k8s_resource("v1", "mod", "app").list()"#)
                .unwrap();
            let _ = engine
                .eval::<Dynamic>(r#"k8s_resource("acme.io/v1", "Pod", "app").list()"#)
                .unwrap();
            // l. 576-578 : handle non résolu — construction OK, `get` rate
            // À L'USAGE en « Unsupported method », `exist` rend faux.
            assert!(
                !engine
                    .eval::<bool>(r#"k8s_resource("nope","app").exist()"#)
                    .unwrap(),
                "non résolu : exist faux SANS erreur"
            );
            let err = engine
                .eval::<()>(r#"k8s_resource("nope","app").get("x")"#)
                .expect_err("l'usage du non résolu rate à l'usage");
            assert!(
                err.to_string().contains("Unsupported method"),
                " Unsupported method attendu à l'usage, obtenu : {err}"
            );
        }))
        .unwrap();
    }

    #[test]
    fn cache_resolution_ambiguity_and_scripts_lock_in_a_fresh_process() {
        const MARKER: &str = "VYVIL_K8S_RESOLVE_CHILD";
        if std::env::var_os(MARKER).is_some() {
            // CACHE artificiel servi par faux API server (table dans
            // `spawn_cache_child_api`). Le listage APIService RATE (403) : la
            // voie douce « warn + sans exclusions » est verrouillée en phase 0.
            let (mock_service, handle) =
                tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
            let factory: Box<dyn Fn() -> Client + Send + Sync> = {
                let svc = mock_service.clone();
                Box::new(move || kube::Client::new(svc.clone(), "ns"))
            };
            set_get_client(factory);
            set_get_labels(Box::new(|| None));
            set_get_owner(Box::new(|| None));
            set_get_owner_ns(Box::new(|| None));
            crate::set_client_name(|| "child.example.com".to_string());
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let seen: Seen = Arc::default();
            let responder = spawn_cache_child_api(&rt, handle, Arc::clone(&seen));
            // Phase 0 — voie douce du listage APIService (SCENARIO l. 562-564) :
            // `async_populate_cache` directement (CACHE jamais touché) : UN warn
            // « cannot list APIServices », discovery SANS exclusions, sans échec.
            // Le pont de `build_client` exige un worker multi-thread (le runtime
            // temporaire de `rt::block_on` est `current_thread` et le refuserait) :
            // la phase 0 se joue donc sur le worker, comme la phase 1.
            let (warn_sub, captured) = warn_capture();
            let disco = rt
                .block_on(rt.spawn(async move {
                    tracing::subscriber::with_default(warn_sub, || {
                        crate::rt::block_on(async_populate_cache())
                            .expect("le pont sert sur le worker")
                            .expect("la discovery réussit SANS exclusions malgré le listage raté")
                    })
                }))
                .unwrap();
            let warns = captured.lock().unwrap().clone();
            assert!(
                warns
                    .iter()
                    .any(|w| w.contains("E_DISCOVERY_WARN: cannot list APIServices")),
                "le warn de survie est attendu, capturés : {warns:?}"
            );
            assert!(
                disco.groups().any(|g| g.name() == "acme.io"),
                "le listage raté n'exclut RIEN : acme.io reste présent"
            );
            // Phase 1 — résolution par CACHE, AUCUN appel hors discovery/listes
            // verrouillées ci-dessous.
            run_cache_child_script_faces(&rt);
            responder.abort();
            let lines = seen.lock().unwrap().clone();
            let lists: Vec<&String> = lines
                .iter()
                .filter(|l| {
                    l.starts_with("GET /api/v1/namespaces/app/pods")
                        || l.starts_with("GET /apis/acme.io/v1/namespaces/app/pods")
                        || l.starts_with("GET /api/v1/pods")
                        || l.starts_with("GET /api/v1/nodes")
                        || l.starts_with("GET /api/v1/namespaces/app/mods")
                })
                .collect();
            assert_eq!(
                lists
                    .iter()
                    .filter(|l| l.as_str() == "GET /api/v1/namespaces/app/pods")
                    .count(),
                3,
                "PODS/Pod/pods résolvent au CŒUR (min-lexicographique cœur=\"\"), lignes : {lists:?}"
            );
            assert!(
                lists.iter().any(|l| l.as_str() == "GET /api/v1/nodes"),
                "nodes (cluster) : URL sans namespace, lignes : {lists:?}"
            );
            assert!(
                lists.iter().filter(|l| l.as_str() == "GET /api/v1/pods").count() >= 2,
                "global et ns vide = toutes namespaces (deux listes sans segment), lignes : {lists:?}"
            );
            assert!(
                lists
                    .iter()
                    .any(|l| l.as_str() == "GET /api/v1/namespaces/app/mods"),
                "« v1 » sans `/` : résolution simple cœur, lignes : {lists:?}"
            );
            assert!(
                lists
                    .iter()
                    .any(|l| l.as_str() == "GET /apis/acme.io/v1/namespaces/app/pods"),
                "groupe explicite acme.io servi, lignes : {lists:?}"
            );
            drop(rt);
            println!("{CHILD_ASSERTED}");
            return;
        }
        spawn_k8s_child(
            MARKER,
            "k8s::tests::cache_resolution_ambiguity_and_scripts_lock_in_a_fresh_process",
        );
    }

    // ── Scenario « patch et apply = SSA forcé fieldManager client_name » — faces
    // globales fraîches : valeur posée « my-app.example.com » et PANIC jamais posé
    // traversant l'engine (non convertie en erreur Rhai).
    #[test]
    fn field_manager_comes_from_client_name_and_its_absence_panics_in_a_fresh_process() {
        const MARKER: &str = "VYVIL_K8S_FM_CHILD";
        if std::env::var_os(MARKER).is_some() {
            let (generic, seen, rt, responder) = generic_over_mock(Some("app"), vec![(200, pod_body("n1"))]);
            let mut engine = Engine::new();
            k8sgeneric_rhai_register(&mut engine);
            let data = {
                let e = Engine::new();
                e.eval::<rhai::Dynamic>("#{ a: 1 }").unwrap()
            };
            // Phase A — client_name JAMAIS appelé : la panic client_name.rs
            // traverse l'engine (le script joue la méthode enregistrée) —
            // catch_unwind la capture, elle n'est PAS une erreur Rhai.
            let boom = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut scope = rhai::Scope::new();
                scope.push("h", generic.clone());
                scope.push("data", data.clone());
                let _ = engine
                    .eval_with_scope::<Dynamic>(&mut scope, r#"h.patch("n1", data)"#)
                    .expect("aucune erreur Rhai attendue : c'est la PANIC qui traverse");
            }));
            let payload = boom.expect_err("la panic du client name traverse l'engine");
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            assert!(
                msg.contains("client name not configured"),
                "la panic contractuelle de client_name.rs, obtenue : {msg}"
            );
            // Phase B — valeur posée : fieldManager exact + force + SSA content-type.
            crate::set_client_name(|| "my-app.example.com".to_string());
            let mut scope = rhai::Scope::new();
            scope.push("h", generic);
            scope.push("data", data);
            let _ = engine
                .eval_with_scope::<Dynamic>(&mut scope, r#"h.patch("n1", data)"#)
                .expect("le patch SSA passe une fois le client name posé");
            responder.abort();
            drop(rt);
            let lines = seen_lines(&seen);
            let head = lines[0].split('|').next().expect("tête");
            assert!(
                head.starts_with("PATCH ")
                    && head.contains("fieldManager=my-app.example.com")
                    && head.contains("force=true"),
                "fieldManager posé + force, obtenu : {head}"
            );
            assert!(
                lines[0].contains("application/apply-patch+yaml"),
                "SSA Apply : {}",
                lines[0]
            );
            println!("{CHILD_ASSERTED}");
            return;
        }
        spawn_k8s_child(
            MARKER,
            "k8s::tests::field_manager_comes_from_client_name_and_its_absence_panics_in_a_fresh_process",
        );
    }

    // ── Scenario « workloads — ns/name obligatoires, typo get_deamonset » : face
    // typée des quatre constructeurs — `ns` vide traité comme absent (toutes
    // namespaces), AUCUN segment `default` ; et K8sRaw en script par le renommé
    // `get_cluster_version` sur le RAW_CLIENT hydraté de mock (CLIENT/RAW_CLIENT
    // LazyLock : fils, état frais).
    /// Faux API server du fils workloads : GET d'un workload par nom (Deploy/Job/
    /// Sts/Ds selon le segment d'URL), `/version` pour le raw, 404 ailleurs.
    fn spawn_workload_child_api(
        rt: &tokio::runtime::Runtime,
        handle: tower_test::mock::Handle<http::Request<Body>, http::Response<Body>>,
        seen: Seen,
    ) -> tokio::task::JoinHandle<()> {
        rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            loop {
                let Some((req, send)) = handle.next_request().await else {
                    return;
                };
                let path = req.uri().path().to_string();
                seen.lock()
                    .unwrap()
                    .extend(std::iter::once(format!("GET {path}")));
                let kind = if path.contains("deployments") {
                    "Deployment"
                } else if path.contains("jobs") {
                    "Job"
                } else if path.contains("statefulsets") {
                    "StatefulSet"
                } else if path.contains("daemonsets") {
                    "DaemonSet"
                } else if path == "/version" {
                    send.send_response(http_json(
                        200,
                        r#"{"major":"1","minor":"31","gitVersion":"v1.31.0"}"#,
                    ));
                    continue;
                } else {
                    send.send_response(http_json(404, &status_body(404, "Not Found")));
                    continue;
                };
                let name = path.rsplit('/').next().unwrap_or("?").to_string();
                let api_version = if kind == "Job" { "batch/v1" } else { "apps/v1" };
                send.send_response(http_json(
                    200,
                    &format!(
                        r#"{{"apiVersion":"{api_version}","kind":"{kind}","metadata":{{"name":"{name}"}}}}"#
                    ),
                ));
            }
        })
    }

    #[test]
    fn workload_empty_namespace_and_raw_script_lock_in_a_fresh_process() {
        const MARKER: &str = "VYVIL_K8S_WORKLOAD_CHILD";
        if std::env::var_os(MARKER).is_some() {
            let (mock_service, handle) =
                tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
            let factory: Box<dyn Fn() -> Client + Send + Sync> = {
                let svc = mock_service.clone();
                Box::new(move || kube::Client::new(svc.clone(), "ns"))
            };
            set_get_client(factory);
            set_get_labels(Box::new(|| None));
            set_get_owner(Box::new(|| None));
            set_get_owner_ns(Box::new(|| None));
            crate::set_client_name(|| "child.example.com".to_string());
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let seen: Seen = Arc::default();
            let responder = spawn_workload_child_api(&rt, handle, Arc::clone(&seen));
            // Hydratation des LazyLock SUR le worker (le `tower::Buffer` de
            // `Client::new` se spawn à la construction, il doit vivre sur `rt`).
            rt.block_on(rt.spawn(async {
                let _a = &*CLIENT;
                let _b = &*RAW_CLIENT;
            }))
            .unwrap();
            // Face ns renseignée (contrôle) : URL namespacée.
            K8sDeploy::get_deployment("app".to_string(), "web".to_string()).expect("deploy ns app");
            // Face typée `ns` vide → TRAITÉE COMME ABSENTE (toutes namespaces,
            // aucun `default`) — l. 674-677, verrou voyageant avec l'implémentation
            // (Tasks k8s.sdd : aucun rouge d'abord possible sans seam).
            K8sDeploy::get_deployment(String::new(), "web".to_string()).expect("deploy ns vide");
            K8sJob::get_job(String::new(), "j1".to_string()).expect("job ns vide");
            K8sStatefulSet::get_sts(String::new(), "db".to_string()).expect("sts ns vide");
            K8sDaemonSet::get_deamonset(String::new(), "d".to_string()).expect("ds ns vide");
            // K8sRaw en script par le NOM RENOMMÉ `get_cluster_version` (l. 662-667).
            let mut engine = Engine::new();
            k8sraw_rhai_register(&mut engine);
            let major = engine
                .eval::<String>(r"let r = new_k8s_raw(); r.get_cluster_version().major")
                .expect("get_cluster_version en script");
            assert_eq!(major, "1", "le corps JSON seul traverse le renommé");
            responder.abort();
            drop(rt);
            let lines = seen_lines(&seen);
            for want in [
                "GET /apis/apps/v1/namespaces/app/deployments/web",
                "GET /apis/apps/v1/deployments/web",
                "GET /apis/batch/v1/jobs/j1",
                "GET /apis/apps/v1/statefulsets/db",
                "GET /apis/apps/v1/daemonsets/d",
                "GET /version",
            ] {
                assert!(
                    lines.iter().any(|l| l == want),
                    "URL attendue {want} absente, vues : {lines:?}"
                );
            }
            assert!(
                !lines
                    .iter()
                    .any(|l| l.contains("namespaces//") || l.contains("/default/")),
                "ns vide : aucun segment vide ni `default`, vues : {lines:?}"
            );
            println!("{CHILD_ASSERTED}");
            return;
        }
        spawn_k8s_child(
            MARKER,
            "k8s::tests::workload_empty_namespace_and_raw_script_lock_in_a_fresh_process",
        );
    }

    // ── Scenario « K8sRaw passe l'URL verbatim et ne rend que le corps JSON » —
    // faces d'erreur sur seam dédiée : le Status 404 porte message/raison/code dans
    // le texte ; un corps texte CASSE @serde_json (jamais rendu comme chaîne).
    #[test]
    fn raw_404_carries_the_status_text_and_a_text_body_breaks_serde() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut raw, handle) = rt.block_on(async { mocked_raw() });
        let responder = rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            let Some((_req, send)) = handle.next_request().await else {
                return;
            };
            send.send_response(http_json(404, &status_body(404, "Not Found")));
            std::future::pending::<()>().await;
        });
        let err = raw
            .rhai_get_url("/nope".to_string())
            .expect_err("le 404 rend une erreur");
        responder.abort();
        drop(rt);
        let text = err.to_string();
        assert!(
            text.contains("(404)") || text.contains("404"),
            "le texte porte le code du Status : {text}"
        );
        assert!(
            text.contains("Not Found"),
            "message/raison du Status portés : {text}"
        );
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut raw, handle) = rt.block_on(async { mocked_raw() });
        let responder = rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            let Some((_req, send)) = handle.next_request().await else {
                return;
            };
            send.send_response(
                http::Response::builder()
                    .status(200)
                    .header("Content-Type", "text/plain")
                    .body(Body::from(b"this is not json".to_vec()))
                    .unwrap(),
            );
            std::future::pending::<()>().await;
        });
        let out = raw.rhai_get_url("/text".to_string());
        responder.abort();
        drop(rt);
        match out {
            Err(e) => assert!(
                !e.to_string().contains("this is not json"),
                "le corps n'est JAMAIS rendu comme chaîne : {e}"
            ),
            Ok(v) => panic!("un corps texte ne doit pas passer la cassure serde_json : {v:?}"),
        }
    }

    // Face script du renommé `get_cluster_version` : appel réel (0 argument, GET
    // `/version` en dessous) sur moteur jouant `k8sraw_rhai_register`, K8sRaw
    // construit à la main sur mock — aucun LazyLock, aucun runtime ambiant (le
    // runtime dédié porte le `tower::Buffer`).
    #[test]
    fn raw_get_cluster_version_script_face_is_the_renamed_get_api_version() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (raw, handle) = rt.block_on(async { mocked_raw() });
        let seen: Seen = Arc::default();
        let seen2 = Arc::clone(&seen);
        let responder = rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                seen2
                    .lock()
                    .unwrap()
                    .extend(std::iter::once(format!("GET {}", req.uri().path())));
                send.send_response(http_json(
                    200,
                    r#"{"major":"1","minor":"31","gitVersion":"v1.31.0"}"#,
                ));
            }
        });
        let mut raw_engine = Engine::new();
        k8sraw_rhai_register(&mut raw_engine);
        let mut raw_scope = rhai::Scope::new();
        raw_scope.push("r", raw);
        assert_eq!(
            raw_engine
                .eval_with_scope::<String>(&mut raw_scope, r"r.get_cluster_version().major")
                .expect("le renommé est la face script de get_api_version"),
            "1"
        );
        responder.abort();
        drop(rt);
        assert_eq!(
            seen_lines(&seen),
            vec!["GET /version"],
            "le renommé joue le GET /version"
        );
    }

    // Scenario « K8sRaw passe l'URL verbatim » (face `get_url` elle-même) : la
    // relative part TALE QUELLE (méthode GET seule, chemin et query non réécrits).
    #[test]
    fn raw_get_url_passes_the_url_verbatim_on_the_wire() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut raw, handle) = rt.block_on(async { mocked_raw() });
        let seen: Seen = Arc::default();
        let seen2 = Arc::clone(&seen);
        let responder = rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            for _ in 0..2 {
                let Some((req, send)) = handle.next_request().await else {
                    return;
                };
                seen2
                    .lock()
                    .unwrap()
                    .extend(std::iter::once(format!("{} {}", req.method(), req.uri())));
                send.send_response(http_json(200, "{}"));
            }
            std::future::pending::<()>().await;
        });
        let _ = raw
            .rhai_get_url("/api/v1/namespaces/app/pods?labelSelector=app%3Dweb".to_string())
            .expect("la relative est servie");
        let _ = raw
            .rhai_get_url("http://localhost:9999/version".to_string())
            .expect("l'absolue est acceptée telle quelle");
        responder.abort();
        drop(rt);
        assert_eq!(
            seen_lines(&seen),
            vec![
                "GET /api/v1/namespaces/app/pods?labelSelector=app%3Dweb",
                // l'absolue passe VERBATIM au client tower (le mock voit l'URI
                // absolue telle quelle : rien n'est réécrit ni rejeté).
                "GET http://localhost:9999/version",
            ],
            "URL verbatim (GET seul, relatives et absolues non réécrites)"
        );
    }

    // `get_api_resources` = GET de `/apis` BRUT avec l'en-tête Discovery (les DEUX
    // versions apidiscovery v2+v2beta1), le CACHE n'est PAS consulté (handle construit
    // à la main : tout touch de CACHE paniquerait ici — `k8s context not initialized`).
    #[test]
    fn raw_get_api_resources_is_a_bare_apis_get_with_the_discovery_header() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut raw, handle) = rt.block_on(async { mocked_raw() });
        let seen: Seen = Arc::default();
        let seen2 = Arc::clone(&seen);
        let responder = rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            let Some((req, send)) = handle.next_request().await else {
                return;
            };
            let accept = req
                .headers()
                .get("Accept")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            seen2.lock().unwrap().extend(std::iter::once(format!(
                "{} {}|{}",
                req.method(),
                req.uri(),
                accept
            )));
            send.send_response(http_json(
                200,
                r#"{"kind":"APIGroupDiscoveryList","apiVersion":"apidiscovery.k8s.io/v2","items":[]}"#,
            ));
            std::future::pending::<()>().await;
        });
        let _ = raw.rhai_get_api_resources().expect("le /apis brut est servi");
        responder.abort();
        drop(rt);
        let line = &seen_lines(&seen)[0];
        assert!(
            line.starts_with("GET /apis|"),
            "GET BRUT de /apis, obtenu : {line}"
        );
        assert!(
            line.contains("apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList") && line.contains("v=v2beta1"),
            "les DEUX versions Discovery dans l'Accept, obtenu : {line}"
        );
    }

    // ── Scenario « workloads — spec/status absents UNIT » + verdict StatefulSet
    // (replicas absent compte 1, défaut Kubernetes) et `wait_available(0)` →
    // Elapsed immédiat.
    #[test]
    fn typed_workload_absent_status_is_unit_and_sts_replicas_default_counts_one() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (client, _handle) = rt.block_on(async {
            let (svc, h) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
            (kube::Client::new(svc, "ns"), h)
        });
        let job_api: Api<Job> = Api::namespaced(client.clone(), "app");
        let mut kjob = K8sJob {
            api: job_api,
            obj: serde_json::from_value(serde_json::json!({
                "apiVersion": "batch/v1", "kind": "Job", "metadata": { "name": "j1" }
            }))
            .unwrap(),
        };
        let status = kjob.get_status().expect("get_status ne rate pas sans status");
        assert!(
            status.is_unit(),
            "status absent → Dynamic::UNIT, obtenu : {status:?}"
        );
        let mut kjob2 = K8sJob {
            api: Api::namespaced(client.clone(), "app"),
            obj: serde_json::from_value(serde_json::json!({
                "apiVersion": "batch/v1", "kind": "Job", "metadata": { "name": "j2" },
                "spec": { "template": { "spec": {
                    "containers": [{ "name": "c", "image": "i" }], "restartPolicy": "Never"
                } } }
            }))
            .unwrap(),
        };
        let spec = kjob2.get_spec().expect("get_spec sert le round-trip");
        assert!(spec.is_map(), "spec présent : map rendue, obtenu : {spec:?}");
        let spec_map = spec.try_cast::<rhai::Map>().expect("map");
        assert!(spec_map.contains_key("template"));
        drop(kjob2);
        drop(rt);
        // Verdict unitaire de la condition StatefulSet (l. 682-684 : replicas
        // absent = 1, défaut Kubernetes).
        let sts = |v: serde_json::Value| {
            serde_json::from_value::<k8s_openapi::api::apps::v1::StatefulSet>(v).unwrap()
        };
        let no_spec = sts(serde_json::json!({
            "apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"db"}
        }));
        let abs = sts(serde_json::json!({
            "apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"db"},
            "spec": { "serviceName": "s" },
            "status": { "availableReplicas": 0 }
        }));
        let match2 = sts(serde_json::json!({
            "apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"db"},
            "spec": { "serviceName": "s", "replicas": 2 },
            "status": { "availableReplicas": 2 }
        }));
        assert!(!K8sStatefulSet::is_sts_available().matches_object(Some(&no_spec)));
        assert!(
            !K8sStatefulSet::is_sts_available().matches_object(Some(&abs)),
            "replicas absent compte 1 (défaut Kubernetes) ≠ available 0 : FAUX"
        );
        assert!(K8sStatefulSet::is_sts_available().matches_object(Some(&match2)));
    }

    #[test]
    fn statefulset_wait_available_zero_is_immediate_elapsed() {
        let (mock_service, handle) = tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = rt.block_on(async { kube::Client::new(mock_service, "ns") });
        // Aucune réponse jamais servie (recette `negative_timeout_is_immediate_elapsed`) :
        // le timeout 0 tranche avant toute liste, en Elapsed immédiat.
        let responder = rt.spawn(async move {
            let mut handle = std::pin::pin!(handle);
            while handle.next_request().await.is_some() {
                std::future::pending::<()>().await;
            }
        });
        let api: Api<k8s_openapi::api::apps::v1::StatefulSet> = Api::namespaced(client, "app");
        let mut sts = K8sStatefulSet {
            api,
            obj: serde_json::from_value(serde_json::json!({
                "apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"db"},
                "spec": { "serviceName": "s" },
                "status": { "availableReplicas": 0 }
            }))
            .unwrap(),
        };
        let out = sts.wait_available(0);
        responder.abort();
        drop(rt);
        let err = out.expect_err("l'objet jamais prêt à timeout 0 doit échouer");
        assert!(
            err.to_string().contains("Elapsed wait error"),
            "timeout 0 → Elapsed immédiat (replicas absent = 1 ≠ available 0), obtenu : {err}"
        );
    }

    // ── Scenario « les trois registres, surface verrouillée par macro » —
    // positifs par appel sur handle CONSTRUIT À LA MAIN (aucune LazyLock jouée),
    // négatifs par `Function not found` (le nom jamais résolu n'est jamais appelé),
    // constructeurs workload par leur panic de pont (résolution de nom prouvée :
    // on ENTRE dans la fonction avant la panique contractée). Sous
    // `current_thread`, `update_k8s_crd_cache` joue la voie douce du pont (warn,
    // CACHE et CLIENT jamais touchés — même preuve que le verrou warn existant).

    /// Sonde négative de registre : le nom n'a jamais été résolu — l'erreur rendue
    /// est « Function not found » (jamais une erreur de fond, jamais un succès).
    fn expect_function_not_found(out: crate::RhaiRes<Dynamic>, script: &str) {
        let err = out.expect_err(&format!("{script} doit être inconnu du registre"));
        assert!(
            err.to_string().contains("Function not found"),
            "Function not found attendu pour {script}, obtenu : {err}"
        );
    }

    /// Les quatre constructeurs workload sont RÉSOLOS par le registre : sous
    /// `current_thread` sans provider, ils ENTRENT dans la fonction (leur panique
    /// d'infrastructure CLIENT, première fois ou poison des sondes suivantes) —
    /// `Function not found` aurait rendu `Ok(Err)`, jamais paniqué.
    fn assert_workload_constructors_resolve(engine: &mut Engine) {
        for ctor in [
            r#"get_deployment("app","web")"#,
            r#"get_deamonset("app","d")"#,
            r#"get_statefulset("app","db")"#,
            r#"get_job("app","j1")"#,
        ] {
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| engine.eval::<Dynamic>(ctor)));
            match outcome {
                Err(_) => {}
                Ok(r) => panic!("{ctor} devait paniquer au pont sous current_thread, rendu : {r:?}"),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_three_registers_lock_the_script_surface() {
        let unresolved = K8sGeneric {
            api: None,
            ns: None,
            scope: Scope::Cluster,
            kind: String::new(),
        };
        let mut engine = Engine::new();
        k8sgeneric_rhai_register(&mut engine);
        let mut scope = rhai::Scope::new();
        scope.push("g", unresolved.clone());
        // méthodes présentes : l'usage du non-résolu répond « Unsupported method »
        // (jamais atteint pour un nom absent, qui répond « Function not found »).
        for (script, want) in [
            (r#"g.get("x")"#, "Unsupported method"),
            (r#"g.get_meta("x")"#, "Unsupported method"),
            (r#"g.get_obj("x")"#, "Unsupported method"),
            (r"g.list()", "Unsupported method"),
            (r#"g.list("app=web")"#, "Unsupported method"),
            (r"g.list_meta()", "Unsupported method"),
            (r#"g.delete("x")"#, "Unsupported method"),
            (
                r#"g.create(#{ apiVersion: "v1", kind: "ConfigMap" })"#,
                "Unsupported method",
            ),
            (
                r#"g.replace("x", #{ apiVersion: "v1", kind: "ConfigMap" })"#,
                "Unsupported method",
            ),
            (r#"g.patch("x", #{ a: 1 })"#, "Unsupported method"),
            (r#"g.apply("x", #{ a: 1 })"#, "Unsupported method"),
            (r#"k8s_resource("pods")"#, "requires a multi-thread tokio runtime"),
        ] {
            let err = engine
                .eval_with_scope::<Dynamic>(&mut scope, script)
                .expect_err(&format!("{script} doit rendre une erreur"));
            assert!(
                err.to_string().contains(want),
                "« {want} » attendu pour {script}, obtenu : {err}"
            );
        }
        assert!(
            !engine
                .eval_with_scope::<bool>(&mut scope, "g.exist()")
                .expect("exist ne rate jamais sur un non-résolu"),
            "exist non résolu : faux, présent au registre"
        );
        // `update_k8s_crd_cache` présent et branché sur l'update_cache réel : sous
        // current_thread il joue la voie douce (warn du pont), sans panic ni CACHE.
        let (sub, captured) = warn_capture();
        tracing::subscriber::with_default(sub, || {
            engine
                .eval_with_scope::<()>(&mut scope, "update_k8s_crd_cache();")
                .expect("update_k8s_crd_cache est enregistré : le script passe");
        });
        let warns = captured.lock().unwrap().clone();
        assert!(
            warns
                .iter()
                .any(|w| w.contains("E_DISCOVERY_WARN: update_k8s_crd_cache")),
            "le warn prouve la présence ET le branchement réel : {warns:?}"
        );
        // absents du registre generic seul.
        for absent in [
            "new_k8s_raw()",
            r"get_cluster_version()",
            r#"get_deployment("app","d")"#,
            r#"get_deamonset("app","d")"#,
            r#"is_condition("Ready")"#,
        ] {
            expect_function_not_found(engine.eval_with_scope::<Dynamic>(&mut scope, absent), absent);
        }
        // registre raw : seul le RENOMMÉ `get_cluster_version` est en script,
        // l'ancien nom n'existe pas (négatif sans moteur plein ; le positif par
        // appel joue `raw_get_cluster_version_script_face`, test séparé sans
        // runtime ambiant — le multi-thread dédié de `Client::new` ne se construit
        // pas sous un `current_thread`).
        let mut raw_engine = Engine::new();
        k8sraw_rhai_register(&mut raw_engine);
        // aucun alias de l'ancien nom en script
        expect_function_not_found(
            raw_engine.eval::<Dynamic>(r"get_api_version()"),
            "get_api_version",
        );
        // registre workload : les quatre constructeurs (typo `get_deamonset` incluse)
        // — sous current_thread sans provider, ils ENTRENT dans la fonction (leur
        // panique contractée de pont prouve la résolution du nom).
        set_get_client(Box::new(|| unreachable!("la fabrique ne doit jamais être jouée")));
        let mut wl_engine = Engine::new();
        k8sworkload_rhai_register(&mut wl_engine);
        assert_workload_constructors_resolve(&mut wl_engine);
        // `is_condition` JAMAIS en script
        expect_function_not_found(
            wl_engine.eval::<Dynamic>(r#"is_condition("Ready")"#),
            "is_condition",
        );
        // cumulable : generic + raw + workload sur un même moteur.
        let mut all = Engine::new();
        k8sgeneric_rhai_register(&mut all);
        k8sraw_rhai_register(&mut all);
        k8sworkload_rhai_register(&mut all);
        let mut all_scope = rhai::Scope::new();
        all_scope.push("g", unresolved);
        assert!(
            all.eval_with_scope::<Dynamic>(&mut all_scope, r"g.list()")
                .expect_err("le cumul garde le generic")
                .to_string()
                .contains("Unsupported method")
        );
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
