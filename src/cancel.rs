//! Cooperative cancellation of the crate's blocking native calls (`sleep` in `engine`,
//! `rt::block_on`) for a consumer driving a Rhai script (typically an LLM session).
//!
//! `rhai::Engine::on_progress` only gets the hand between two
//! script operations; a native call that sleeps or waits on the network does not. A
//! [`CancelToken`](crate::cancel::CancelToken) installed for the duration of an evaluation by
//! [`scope`](crate::cancel::scope) is read by those
//! native calls, which then return an error (crate-wide: [`Error::Other`] of text
//! `cancelled`) instead of waiting.
//!
//! The token is carried by the calling thread (thread-local), not by a parameter: the
//! native functions and the `block_on` callers have no signature to change, and the
//! synchronous Rhai evaluation stays on the thread that started it (including under
//! `tokio::task::block_in_place`).
//!
//! **The token is carried only for the thread that called
//! [`scope`](crate::cancel::scope)**: another thread, a
//! task spawned with `tokio::task::spawn` or `tokio::task::spawn_blocking` does not
//! inherit it. A consumer evaluating on another thread opens its own scope on that
//! thread.
//!
//! **Not cancellable**: calls that block on a child process (`shell_run`, `shell_output`,
//! `sign_image` through `cosign`) never read the token and return when the process ends.
//!
//! This module depends on neither tokio nor rhai: `Arc<AtomicBool>` and a thread-local
//! are enough. It compiles without any feature; the readers of the token are `sleep` (under
//! `rhai`) and `rt::block_on` (under `rt`), and the reading functions exist only where one
//! of them is compiled.

#[cfg(any(feature = "rhai", feature = "rt"))] use std::time::Duration;
use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

thread_local! {
    /// The token installed for this thread by the innermost open [`scope`], if any.
    /// Read through `try_with` only: during thread destruction its absence is reported,
    /// never a panic.
    static CURRENT: RefCell<Option<CancelToken>> = const { RefCell::new(None) };
}

/// Cancellation flag shared between every clone of a token and read by the crate's
/// blocking native calls on the thread [`scope`] installed it for.
///
/// Cloning is cheap and designates the **same** flag: hand a clone to the interrupting
/// party (e.g. a watchdog calling [`CancelToken::cancel`]) while the evaluating thread
/// keeps reading its own copy through the module's `current` read. Once cancelled, a
/// token stays cancelled — there is no reset.
#[derive(Clone, Debug)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    /// A fresh, not-yet-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cancel this token — and, through the shared flag, every one of its clones.
    /// Idempotent and permanent: cancelling an already-cancelled token does nothing.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }

    /// Whether this token (or any of its clones) has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard restoring the thread's previously installed token on drop — normal return
/// and unwinding alike.
struct EnterGuard {
    restore: Restore,
}

/// What the end of a [`scope`] restores on the current thread.
enum Restore {
    /// A token was installed: put back what `scope` replaced — [`None`] meaning it had
    /// installed no token before.
    Previous(Option<CancelToken>),
    /// The thread-local was unavailable at entry (thread destruction in progress):
    /// nothing was installed, so nothing is restored.
    Nothing,
}

impl EnterGuard {
    fn enter(token: &CancelToken) -> Self {
        Self {
            restore: match CURRENT.try_with(|cell| {
                let mut slot = cell.borrow_mut();
                let prev = slot.take();
                *slot = Some(token.clone());
                prev
            }) {
                Ok(prev) => Restore::Previous(prev),
                Err(_) => Restore::Nothing,
            },
        }
    }
}

impl Drop for EnterGuard {
    fn drop(&mut self) {
        if let Restore::Previous(prev) = std::mem::replace(&mut self.restore, Restore::Nothing) {
            // `try_with` again: the thread-local may have become unavailable meanwhile;
            // then there is nowhere to restore and nothing panics.
            let _ = CURRENT.try_with(move |cell| *cell.borrow_mut() = prev);
        }
    }
}

/// Install `token` for the current thread for the duration of `f` and return `f`'s value.
///
/// On exit — normal return **or** a panic out of `f` — the thread's previous token (or
/// the absence of one) is restored. Nested scopes stack: the innermost token wins while
/// it lasts, then the outer one is restored.
///
/// The token is installed for **this thread only**; threads spawned by `f` do not see it
/// (see the [module docs](self)).
pub fn scope<R>(token: &CancelToken, f: impl FnOnce() -> R) -> R {
    let _guard = EnterGuard::enter(token);
    f()
}

/// The [`CancelToken`] installed for the current thread by the innermost open [`scope`],
/// or [`None`] when no scope is open (also during thread destruction, via `try_with`).
///
/// Read by the crate's blocking native calls (`sleep`, `block_on`); cancellation is
/// never decided here — the module only carries the flag, stopping the script stays the
/// consumer's call (`rhai::Engine::on_progress`).
#[cfg(any(feature = "rhai", feature = "rt"))]
pub(crate) fn current() -> Option<CancelToken> {
    CURRENT.try_with(|cell| cell.borrow().clone()).ok().flatten()
}

/// Common wait slice of 25 ms: the bound on a native call's cancellation latency,
/// shared by `sleep` and `block_on` — each waits at most this long before re-reading
/// [`current`] and its flag.
#[cfg(any(feature = "rhai", feature = "rt"))]
pub(crate) const WAIT_SLICE: Duration = Duration::from_millis(25);

#[cfg(test)]
mod tests {
    use super::*;

    /// Le jeton courant du fil est-il (un clone de) `token`, c'est-à-dire désigne-t-il le même
    /// drapeau ?
    #[cfg(any(feature = "rhai", feature = "rt"))]
    fn installed_is(token: &CancelToken) -> bool {
        current().is_some_and(|seen| Arc::ptr_eq(&seen.flag, &token.flag))
    }

    // ── Scenario « sans portée, aucun jeton » ──
    #[test]
    #[cfg(any(feature = "rhai", feature = "rt"))]
    fn no_scope_no_token() {
        assert!(
            current().is_none(),
            "hors de toute portée `scope`, aucun jeton ne doit être rendu"
        );
    }

    // ── Scenario « la portée installe puis rétablit » ──
    #[test]
    #[cfg(any(feature = "rhai", feature = "rt"))]
    fn scope_installs_then_restores() {
        let t1 = CancelToken::new();
        let value = scope(&t1, || {
            assert!(installed_is(&t1), "dans la portée, le jeton courant est T1");
            let seen = current().expect("portée ouverte ⇒ jeton présent");
            t1.cancel();
            assert!(
                seen.is_cancelled(),
                "l'annulation de T1 est visible depuis le jeton courant"
            );
            7_u32
        });
        assert_eq!(value, 7, "`scope` rend la valeur de la fermeture");
        assert!(
            current().is_none(),
            "après le retour de `scope`, plus aucun jeton installé"
        );
    }

    // ── Scenario « portées imbriquées » ──
    #[test]
    #[cfg(any(feature = "rhai", feature = "rt"))]
    fn nested_scopes_innermost_wins_then_restores_outer() {
        let t1 = CancelToken::new();
        let t2 = CancelToken::new();
        scope(&t1, || {
            assert!(installed_is(&t1));
            scope(&t2, || assert!(installed_is(&t2), "la portée interne l'emporte"));
            assert!(
                installed_is(&t1),
                "à la sortie de la portée interne, T1 est rétabli"
            );
        });
        assert!(
            current().is_none(),
            "à la sortie de la portée externe, plus aucun jeton"
        );
    }

    // ── Scenario « la portée se rétablit sur panique » ──
    #[test]
    #[cfg(any(feature = "rhai", feature = "rt"))]
    fn scope_restores_on_panic() {
        let t1 = CancelToken::new();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scope(&t1, || panic!("boom de la fermeture"));
        }));
        assert!(
            res.is_err(),
            "la panique de la fermeture est interceptée par `catch_unwind`"
        );
        assert!(
            current().is_none(),
            "après la panique, le fil n'a plus de jeton installé"
        );
    }

    // ── Scenario « le jeton ne traverse pas les fils » ──
    #[test]
    #[cfg(any(feature = "rhai", feature = "rt"))]
    fn token_does_not_cross_threads() {
        let t1 = CancelToken::new();
        let (child_saw_token, outer_still_installed) = scope(&t1, || {
            let child = std::thread::spawn(|| current().is_some());
            let child_saw_token = child.join().expect("le fil B rend sa main");
            (child_saw_token, installed_is(&t1))
        });
        assert!(
            !child_saw_token,
            "le fil B lancé depuis la portée ne voit aucun jeton"
        );
        assert!(outer_still_installed, "le fil A garde sa portée ouverte");
    }

    // ── Scenario « les clones partagent le drapeau » ──
    #[test]
    fn clones_share_the_flag() {
        let t = CancelToken::new();
        let c = t.clone();
        assert!(!t.is_cancelled(), "un jeton neuf n'est pas annulé");
        c.cancel();
        assert!(t.is_cancelled(), "les clones désignent le MÊME drapeau");
        // Aucune réinitialisation : une fois annulé, le jeton le reste après tout autre appel.
        t.cancel();
        assert!(
            t.is_cancelled() && c.is_cancelled(),
            "une fois annulé, le jeton le reste"
        );
    }

    // ── Assertions affirmées par test (cancel.sdd Must) : Clone/Debug/Default/Send/Sync,
    // Default non annulé, tranche commune de 25 ms. ──
    #[test]
    fn token_is_send_sync_clone_debug_default() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CancelToken>();
        let t = CancelToken::new();
        assert!(!format!("{t:?}").is_empty(), "CancelToken porte Debug");
        assert!(!t.clone().is_cancelled(), "Clone, comme Default : non annulé");
        assert!(!CancelToken::default().is_cancelled(), "Default est non annulé");
    }

    // ── Tranche d'attente commune : 25 ms (borne de latence partagée par sleep et block_on) ──
    #[test]
    #[cfg(any(feature = "rhai", feature = "rt"))]
    fn wait_slice_is_25_ms() {
        assert_eq!(
            WAIT_SLICE,
            Duration::from_millis(25),
            "la tranche d'attente commune fait 25 ms (borne de latence partagée par sleep et block_on)"
        );
    }
}
