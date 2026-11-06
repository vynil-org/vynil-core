//! Cooperative cancellation of the crate's blocking native calls (`sleep` in `engine`,
//! `rt::block_on`) for a consumer driving a Rhai script (typically an LLM session).
//!
//! `rhai::Engine::on_progress` only gets the hand between two
//! script operations; a native call that sleeps or waits on the network does not. A
//! [`CancelToken`](crate::cancel::CancelToken) installed for the duration of an evaluation by
//! [`scope`](crate::cancel::scope) is read by those
//! native calls, which then return an error (crate-wide: [`Error::Cancelled`], displayed
//! `CANCEL-001 operation cancelled`) instead of waiting.
//!
//! [`CancelToken::cancel`](crate::cancel::CancelToken::cancel) wakes the waiting calls at once:
//! no polling, no time slice. The
//! waits are a waker registered by a pending future, and a condition variable for the
//! bounded blocking wait.
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
//! This module depends on neither tokio nor rhai: `std` and `core` are enough. It compiles
//! without any feature; the readers of the token are `sleep` (under `rhai`, the bounded
//! wait) and `rt::block_on` (under `rt`, the cancellation future), and each reading function
//! exists only where its reader is compiled.

#[cfg(feature = "rhai")] use std::time::{Duration, Instant};
use std::{
    cell::RefCell,
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    task::Waker,
};
#[cfg(feature = "rt")]
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

thread_local! {
    /// The token installed for this thread by the innermost open [`scope`], if any.
    /// Read through `try_with` only: during thread destruction its absence is reported,
    /// never a panic.
    static CURRENT: RefCell<Option<CancelToken>> = const { RefCell::new(None) };
}

/// State shared by every clone of a token: the flag, the wakers of the pending waits and
/// the condition variable of the bounded waits. The flag is also reachable from the lock,
/// which is what makes a wait's re-read race-free.
#[derive(Debug)]
struct Shared {
    flag: AtomicBool,
    waiters: Mutex<Waiters>,
    cond: Condvar,
}

/// The pending waits of a token. `wakers` holds one entry per registered
/// [`Cancelled`] future, under the identity that future removes itself by.
#[derive(Debug, Default)]
struct Waiters {
    wakers: Vec<(u64, Waker)>,
    /// Source of the identities above; only the cancellation futures draw from it.
    #[cfg(feature = "rt")]
    next_id: u64,
}

/// Lock the waiters, recovering a poisoned lock: the list stays usable, a panic elsewhere
/// never turns a cancellation into a panic.
fn lock(waiters: &Mutex<Waiters>) -> MutexGuard<'_, Waiters> {
    waiters.lock().unwrap_or_else(PoisonError::into_inner)
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
    shared: Arc<Shared>,
}

impl CancelToken {
    /// A fresh, not-yet-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                flag: AtomicBool::new(false),
                waiters: Mutex::new(Waiters::default()),
                cond: Condvar::new(),
            }),
        }
    }

    /// Cancel this token — and, through the shared flag, every one of its clones.
    /// Idempotent and permanent: cancelling an already-cancelled token does nothing.
    ///
    /// Wakes every pending wait of the token: the flag is raised BEFORE the waiters lock is
    /// taken, so a wait that re-reads the flag under that lock either sees it or is woken.
    /// The wakers are called outside the lock.
    pub fn cancel(&self) {
        self.shared.flag.store(true, Ordering::Release);
        let wakers = {
            let mut waiters = lock(&self.shared.waiters);
            self.shared.cond.notify_all();
            std::mem::take(&mut waiters.wakers)
        };
        for (_, waker) in wakers {
            waker.wake();
        }
    }

    /// Whether this token (or any of its clones) has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.shared.flag.load(Ordering::Acquire)
    }

    /// A future resolving as soon as this token (or any of its clones) is cancelled: at
    /// once when it already is, otherwise on the [`CancelToken::cancel`] that wakes it. No
    /// polling and no timer: the latency is the wake-up itself.
    #[cfg(feature = "rt")]
    pub(crate) fn cancelled(&self) -> Cancelled {
        Cancelled {
            token: self.clone(),
            id: None,
        }
    }

    /// Block the calling thread for at most `timeout`, returning `true` when the token is
    /// cancelled before that (`false` when the whole `timeout` elapsed without cancellation).
    /// Woken at once by [`CancelToken::cancel`]; spurious wake-ups re-read the flag and wait
    /// for the time still remaining, so the call never sleeps longer than `timeout`.
    #[cfg(feature = "rhai")]
    pub(crate) fn wait_timeout(&self, timeout: Duration) -> bool {
        let mut waiters = lock(&self.shared.waiters);
        let mut remaining = timeout;
        loop {
            // Under the lock: a `cancel` that raised the flag before this point is seen here.
            if self.is_cancelled() {
                return true;
            }
            if remaining.is_zero() {
                return false;
            }
            let started = Instant::now();
            let (guard, _) = self
                .shared
                .cond
                .wait_timeout(waiters, remaining)
                .unwrap_or_else(PoisonError::into_inner);
            waiters = guard;
            remaining = remaining.saturating_sub(started.elapsed());
        }
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Future of [`CancelToken::cancelled`]. While pending it holds an entry in the token's
/// waker list, removed on drop; `cancel` wakes and drains every entry.
#[cfg(feature = "rt")]
pub(crate) struct Cancelled {
    token: CancelToken,
    /// Identity of this future's entry in the waker list, drawn on the first pending poll.
    id: Option<u64>,
}

#[cfg(feature = "rt")]
impl Future for Cancelled {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.token.is_cancelled() {
            return Poll::Ready(());
        }
        let mut waiters = lock(&this.token.shared.waiters);
        // Re-read under the lock: no wake-up is lost between the check above and the sleep.
        if this.token.is_cancelled() {
            return Poll::Ready(());
        }
        let id = *this.id.get_or_insert_with(|| {
            let id = waiters.next_id;
            waiters.next_id = waiters.next_id.wrapping_add(1);
            id
        });
        match waiters.wakers.iter_mut().find(|(known, _)| *known == id) {
            Some((_, registered)) => {
                if !registered.will_wake(cx.waker()) {
                    registered.clone_from(cx.waker());
                }
            }
            None => waiters.wakers.push((id, cx.waker().clone())),
        }
        Poll::Pending
    }
}

#[cfg(feature = "rt")]
impl Drop for Cancelled {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            lock(&self.token.shared.waiters)
                .wakers
                .retain(|(known, _)| *known != id);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Le jeton courant du fil est-il (un clone de) `token`, c'est-à-dire désigne-t-il le même
    /// drapeau ?
    #[cfg(any(feature = "rhai", feature = "rt"))]
    fn installed_is(token: &CancelToken) -> bool {
        current().is_some_and(|seen| Arc::ptr_eq(&seen.shared, &token.shared))
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
    // Default non annulé. ──
    #[test]
    fn token_is_send_sync_clone_debug_default() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CancelToken>();
        let t = CancelToken::new();
        assert!(!format!("{t:?}").is_empty(), "CancelToken porte Debug");
        assert!(!t.clone().is_cancelled(), "Clone, comme Default : non annulé");
        assert!(!CancelToken::default().is_cancelled(), "Default est non annulé");
    }

    // ── Scenario « un verrou empoisonné ne panique pas » (annulation) ──
    #[test]
    fn poisoned_waker_lock_does_not_panic_on_cancel() {
        let token = CancelToken::new();
        poison(&token);
        token.cancel();
        assert!(
            token.is_cancelled(),
            "le drapeau est levé malgré le verrou empoisonné"
        );
    }

    /// Empoisonne le verrou des wakers par la panique d'un fil.
    fn poison(token: &CancelToken) {
        let shared = Arc::clone(&token.shared);
        let poisoner = std::thread::spawn(move || {
            let _guard = shared.waiters.lock();
            panic!("poison du verrou des wakers");
        });
        assert!(poisoner.join().is_err(), "le fil empoisonneur a paniqué");
        assert!(
            token.shared.waiters.is_poisoned(),
            "le verrou est bien empoisonné"
        );
    }

    // ── Futur d'annulation et attente bornée : chacun ne se compile que sous sa feature ──

    #[cfg(feature = "rt")]
    mod future_tests {
        use super::*;
        use std::{
            future::Future,
            pin::pin,
            sync::{PoisonError, atomic::AtomicUsize},
            task::{Context, Wake},
        };

        /// Waker témoin : compte les réveils.
        struct CountingWaker(AtomicUsize);

        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn counting_waker() -> (Arc<CountingWaker>, Waker) {
            let counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&counter));
            (counter, waker)
        }

        fn wakes(counter: &CountingWaker) -> usize {
            counter.0.load(Ordering::SeqCst)
        }

        /// Nombre de wakers actuellement enregistrés sur le jeton.
        fn registered(token: &CancelToken) -> usize {
            token
                .shared
                .waiters
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .wakers
                .len()
        }

        // ── Scenario « le futur d'annulation résout au réveil » ──
        #[test]
        fn cancelled_future_resolves_on_wake() {
            let token = CancelToken::new();
            let (counter, waker) = counting_waker();
            let mut cx = Context::from_waker(&waker);
            let mut fut = pin!(token.cancelled());
            assert!(
                fut.as_mut().poll(&mut cx).is_pending(),
                "jeton non annulé : le futur attend"
            );
            let canceller = token.clone();
            std::thread::spawn(move || canceller.cancel())
                .join()
                .expect("le fil annuleur rend sa main");
            assert!(wakes(&counter) >= 1, "le waker témoin a été réveillé");
            assert!(
                fut.as_mut().poll(&mut cx).is_ready(),
                "le futur résout à l'interrogation suivante"
            );
        }

        #[test]
        fn cancelled_future_ready_at_first_poll_when_already_cancelled() {
            let token = CancelToken::new();
            token.cancel();
            let (_counter, waker) = counting_waker();
            let mut cx = Context::from_waker(&waker);
            let mut fut = pin!(token.cancelled());
            assert!(
                fut.as_mut().poll(&mut cx).is_ready(),
                "jeton déjà annulé : résolution dès la première interrogation"
            );
        }

        // ── Scenario « plusieurs attentes sur des clones » ──
        #[test]
        fn every_waiter_on_clones_is_woken_and_dropped_one_leaves_nothing() {
            let token = CancelToken::new();
            let clone = token.clone();
            let (first_counter, first_waker) = counting_waker();
            let (second_counter, second_waker) = counting_waker();
            let mut first_cx = Context::from_waker(&first_waker);
            let mut second_cx = Context::from_waker(&second_waker);
            let mut first = pin!(token.cancelled());
            let mut second = pin!(clone.cancelled());
            assert!(first.as_mut().poll(&mut first_cx).is_pending());
            assert!(second.as_mut().poll(&mut second_cx).is_pending());
            assert_eq!(registered(&token), 2, "deux wakers enregistrés");

            token.cancel();
            assert!(wakes(&first_counter) >= 1, "le premier waker est réveillé");
            assert!(wakes(&second_counter) >= 1, "le second waker est réveillé");
            assert!(first.as_mut().poll(&mut first_cx).is_ready());
            assert!(second.as_mut().poll(&mut second_cx).is_ready());
        }

        #[test]
        fn future_dropped_before_cancel_leaves_no_waker() {
            let token = CancelToken::new();
            let (_counter, waker) = counting_waker();
            let mut cx = Context::from_waker(&waker);
            {
                let mut fut = pin!(token.cancelled());
                assert!(fut.as_mut().poll(&mut cx).is_pending());
                assert_eq!(registered(&token), 1, "le futur en attente a un waker");
            }
            assert_eq!(
                registered(&token),
                0,
                "un futur détruit avant l'annulation ne laisse aucun waker"
            );
        }

        // ── Scenario « un verrou empoisonné ne panique pas » (futur) ──
        #[test]
        fn poisoned_lock_neither_panics_nor_blocks_the_future() {
            let token = CancelToken::new();
            poison(&token);
            let (_counter, waker) = counting_waker();
            let mut cx = Context::from_waker(&waker);
            let mut fut = pin!(token.cancelled());
            assert!(
                fut.as_mut().poll(&mut cx).is_pending(),
                "un verrou empoisonné ne résout pas le futur avant l'annulation"
            );
            token.cancel();
            assert!(fut.as_mut().poll(&mut cx).is_ready());
        }
    }

    #[cfg(feature = "rhai")]
    mod wait_tests {
        use super::*;
        use std::time::{Duration, Instant};

        // ── Scenario « l'attente bornée est interrompue par l'annulation » ──
        #[test]
        fn bounded_wait_is_interrupted_by_cancel() {
            let token = CancelToken::new();
            let canceller = {
                let t = token.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    t.cancel();
                })
            };
            let start = Instant::now();
            let interrupted = token.wait_timeout(Duration::from_secs(30));
            let elapsed = start.elapsed();
            canceller.join().expect("le fil annuleur rend sa main");
            assert!(interrupted, "l'attente rend « annulé »");
            assert!(
                elapsed < Duration::from_millis(500),
                "rendu en moins de 500 ms au total, obtenu {elapsed:?}"
            );
        }

        #[test]
        fn bounded_wait_without_cancel_reports_elapsed() {
            let token = CancelToken::new();
            let start = Instant::now();
            let interrupted = token.wait_timeout(Duration::from_millis(50));
            assert!(!interrupted, "sans annulation, l'attente rend « terminé »");
            assert!(
                start.elapsed() >= Duration::from_millis(40),
                "l'attente dure au moins sa durée (marge 10 ms), obtenu {:?}",
                start.elapsed()
            );
        }

        #[test]
        fn bounded_wait_on_already_cancelled_token_returns_at_once() {
            let token = CancelToken::new();
            token.cancel();
            let start = Instant::now();
            assert!(token.wait_timeout(Duration::from_secs(30)));
            assert!(start.elapsed() < Duration::from_millis(500));
        }

        // Durée `Duration::MAX` (borne « illimitée » d'un appelant) : ni panique (addition de
        // l'instant limite débordante), ni attente infinie — l'annulation à ~100 ms la rend.
        #[test]
        fn bounded_wait_with_max_duration_neither_panics_nor_blocks() {
            let token = CancelToken::new();
            let canceller = {
                let t = token.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    t.cancel();
                })
            };
            let start = Instant::now();
            let interrupted = token.wait_timeout(Duration::MAX);
            let elapsed = start.elapsed();
            canceller.join().expect("le fil annuleur rend sa main");
            assert!(interrupted, "l'attente de Duration::MAX rend « annulé »");
            assert!(
                elapsed < Duration::from_secs(5),
                "l'attente de Duration::MAX rend à l'annulation, obtenu {elapsed:?}"
            );
        }

        // ── Scenario « aucun réveil perdu » : la course annulation/endormissement, rejouée ──
        // Une perte de réveil ferait dormir les 30 s de l'attente à chaque tour.
        #[test]
        fn no_lost_wakeup_across_a_thousand_races() {
            for round in 0..1000 {
                let token = CancelToken::new();
                let canceller = {
                    let t = token.clone();
                    std::thread::spawn(move || t.cancel())
                };
                let start = Instant::now();
                let interrupted = token.wait_timeout(Duration::from_secs(30));
                let elapsed = start.elapsed();
                canceller.join().expect("le fil annuleur rend sa main");
                assert!(interrupted, "tour {round} : l'attente rend « annulé »");
                assert!(
                    elapsed < Duration::from_secs(5),
                    "tour {round} : réveil perdu, l'attente a dormi {elapsed:?}"
                );
            }
        }

        // ── Scenario « un verrou empoisonné ne panique pas » (attente bornée) ──
        #[test]
        fn poisoned_lock_neither_panics_nor_blocks_the_bounded_wait() {
            let token = CancelToken::new();
            poison(&token);
            let start = Instant::now();
            assert!(
                !token.wait_timeout(Duration::from_millis(50)),
                "sans annulation, l'attente rend « terminé » même verrou empoisonné"
            );
            token.cancel();
            assert!(token.wait_timeout(Duration::from_secs(30)));
            assert!(start.elapsed() < Duration::from_secs(5));
        }
    }
}
