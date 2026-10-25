//! Async → sync bridge, shared by the network-facing modules (`http`, `oci`, `s3`, `k8s`),
//! which expose synchronous functions to Rhai scripts while every network call underneath
//! is `tokio`-async, and public (feature `rt`) for consumers doing the same. One bridge, one
//! strategy table (see [`crate::rt::block_on`]), no panic escaping towards the host. The module knows
//! nothing of Rhai: callers convert the error themselves.

use std::future::Future;

use tokio::{
    runtime::{Builder, Handle, RuntimeFlavor},
    task::block_in_place,
};

use crate::{Error, Result, cancel};

/// Drive `fut` to completion from a synchronous caller and return its output, without
/// ever panicking the host.
///
/// This is the bridge for native functions called from a synchronous Rhai script (MCP or
/// inference calls of a consumer, the `http`/`oci`/`s3`/`k8s` modules, …): the script
/// cannot `.await`, so the async work runs here, to completion, on the calling thread.
///
/// # Strategy
///
/// Chosen in this order, from [`Handle::try_current`]:
///
/// - a **multi-thread** tokio runtime is running on this thread: the thread is blocked with
///   [`block_in_place`] and `fut` is driven through the live [`Handle`] (the runtime's
///   worker threads keep making progress meanwhile);
/// - **no runtime** on this thread: a temporary `current_thread` runtime is built with
///   `enable_all`, `fut` is driven on it, and the runtime is dropped on return. This is a
///   *fallback*: it pays one runtime construction per call. In production, scripts run
///   inside the consumer's own runtime and this branch is not reached;
/// - a **`current_thread`** runtime is running: [`block_in_place`] would panic there, so
///   `fut` is never polled and an error is returned instead.
///
/// # Cancellation
///
/// If the calling thread carries a [`CancelToken`](crate::cancel::CancelToken) installed by
/// [`cancel::scope`], it is honoured in all three strategies, without any change to this
/// signature:
///
/// - a token already cancelled at entry refuses `fut` unpolled, before a strategy is chosen;
/// - a token cancelled while `fut` runs makes `block_on` abandon (drop) `fut`, not leave it
///   running in the background, and return the error within one 25 ms slice.
///
/// The check is a `tokio::select!` between `fut` and a periodic re-read of the flag, on the
/// same runtime (no thread, no extra task). Without a token the path is exactly the
/// token-less one, and no timer is touched.
///
/// **With a token installed, the calling runtime must have its time driver enabled**
/// (`enable_all()` or `enable_time()`): the check ticks a `tokio::time::interval`, which
/// panics on a runtime built without one. A consumer building its own runtime calls
/// `enable_all()`. The temporary runtime of the fallback always has it.
///
/// # Errors
///
/// - [`Error::Other`] `cancelled` when the token of the thread is cancelled, before or during
///   the execution, whatever the strategy;
/// - [`Error::Other`] `requires a multi-thread tokio runtime` when a `current_thread` runtime
///   is running on the calling thread (`fut` is then not executed);
/// - [`Error::Stdio`] when the temporary runtime of the fallback cannot be built (descriptor
///   exhaustion, for example).
///
/// # Trait bounds
///
/// `fut` need not be [`Send`]: it is always driven on the calling thread.
///
/// # Panics
///
/// This function adds no panic of its own. A panic raised by `fut` propagates untouched, as
/// does the panic of a token-aware call on a runtime without a time driver (see above).
pub fn block_on<F: Future>(fut: F) -> Result<F::Output> {
    // The thread's token, read once: cancelled at entry, nothing is polled —
    // whichever strategy would have run.
    let token = cancel::current();
    if token.as_ref().is_some_and(cancel::CancelToken::is_cancelled) {
        return Err(Error::Other("cancelled".to_string()));
    }
    if let Ok(handle) = Handle::try_current() {
        return match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => block_in_place(|| handle.block_on(drive(fut, token))),
            // `CurrentThread` (and any hypothetical future non-multi-thread flavor)
            // cannot host `block_in_place`: refuse without touching the future.
            RuntimeFlavor::CurrentThread | _ => {
                Err(Error::Other("requires a multi-thread tokio runtime".to_string()))
            }
        };
    }
    // No runtime on this thread: one-off `current_thread` runtime, dropped on return.
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Stdio)?;
    runtime.block_on(drive(fut, token))
}

/// Drive `fut`, racing it against the thread's cancellation token when there is
/// one: a `tokio::select!` between `fut` and a periodic re-read of the flag every
/// [`cancel::WAIT_SLICE`] (interval ticks on the *same* runtime — no thread, no
/// task). Whichever arm loses, `fut` is dropped: on cancellation the future is
/// abandoned, not left running. Without a token this is `fut.await`, the exact
/// pre-cancellation path.
async fn drive<F: Future>(fut: F, token: Option<cancel::CancelToken>) -> Result<F::Output> {
    let Some(token) = token else {
        return Ok(fut.await);
    };
    tokio::select! {
        biased;
        out = fut => Ok(out),
        () = wait_for_cancel(token) => Err(Error::Other("cancelled".to_string())),
    }
}

/// Completes once the thread's `token` reads cancelled, polled every
/// [`cancel::WAIT_SLICE`] — the bound on the cancellation latency.
async fn wait_for_cancel(token: cancel::CancelToken) {
    let mut tick = tokio::time::interval(cancel::WAIT_SLICE);
    loop {
        tick.tick().await;
        if token.is_cancelled() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::block_on;
    use crate::{Error, cancel, cancel::CancelToken};
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    // ── Scenario « multi-thread, le futur s'exécute » ──
    #[tokio::test(flavor = "multi_thread")]
    async fn multi_thread_runs_the_future() {
        let out = block_on(async { 42_i32 });
        assert_eq!(out.unwrap(), 42);
    }

    // ── Scenario « sans runtime, un runtime temporaire sert » ──
    #[test]
    fn without_runtime_a_temporary_runtime_serves() {
        let out = block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            "ok"
        });
        assert_eq!(out.unwrap(), "ok");
    }

    // ── Scenario « current_thread rend une erreur explicite » ──
    // Le futur n'est pas exécuté : verrouillé par un flag observable, pas par un
    // simple `is_err()`.
    #[tokio::test(flavor = "current_thread")]
    async fn current_thread_returns_explicit_error_and_never_runs_the_future() {
        let ran = Rc::new(RefCell::new(false));
        let ran_in_fut = Rc::clone(&ran);
        let res = block_on(async move {
            *ran_in_fut.borrow_mut() = true;
            1_i32
        });
        match res {
            Err(Error::Other(msg)) => {
                assert!(
                    msg.contains("requires a multi-thread tokio runtime"),
                    "message attendu explicite, obtenu : {msg}"
                );
            }
            other => panic!("Error::Other attendu, rendu : {other:?}"),
        }
        assert!(
            !*ran.borrow(),
            "le futur ne doit pas être exécuté sur current_thread"
        );
    }

    // ── Scenario « appel imbriqué » ──
    // Le block_on intérieur tourne dans le runtime temporaire (current_thread) du
    // block_on extérieur : il doit rendre l'erreur explicite, sans paniquer, et sans
    // exécuter son futur (flag observable).
    #[test]
    fn nested_call_from_the_temporary_runtime_returns_the_error() {
        let inner_ran = Rc::new(RefCell::new(false));
        let flag = Rc::clone(&inner_ran);
        let outer = block_on(async move {
            // contexte : runtime temporaire current_thread du block_on extérieur
            block_on(async move {
                *flag.borrow_mut() = true;
            })
        });
        let inner_res = outer.expect("l'extérieur doit s'exécuter sur le runtime temporaire");
        match inner_res {
            Err(Error::Other(msg)) => {
                assert!(
                    msg.contains("requires a multi-thread tokio runtime"),
                    "message attendu explicite, obtenu : {msg}"
                );
            }
            other => panic!("Error::Other attendu côté intérieur, rendu : {other:?}"),
        }
        assert!(
            !*inner_ran.borrow(),
            "le futur intérieur ne doit pas être exécuté"
        );
    }

    // ── Scenario « futur non Send » ──
    // Le `Rc` est vivant à travers le point d'attente : le futur du bloc async n'est
    // pas `Send`. Aucune borne `Send` n'étant exigée, cela compile et s'exécute.
    #[test]
    fn non_send_future_compiles_and_runs() {
        let data = Rc::new(String::from("rc-held-across-await"));
        let held_len = block_on(async move {
            tokio::time::sleep(std::time::Duration::ZERO).await;
            data.len() // `data` (Rc, non Send) traverse le point d'attente
        });
        assert_eq!(held_len.unwrap(), "rc-held-across-await".len());
    }

    // ── Scenario « annulation avant l'appel » ──
    // Jeton déjà annulé, portée ouverte : le futur ne doit pas être interrogé du tout
    // (drapeau observable), l'erreur est `cancelled`. Joué hors de tout runtime ; le
    // jumeau multi_thread ci-dessous couvre l'autre face.
    #[test]
    fn cancelled_token_before_call_errors_without_polling_outside_runtime() {
        let token = CancelToken::new();
        token.cancel();
        let ran = Rc::new(Cell::new(false));
        let ran_in_fut = Rc::clone(&ran);
        let res = cancel::scope(&token, move || {
            block_on(async move {
                ran_in_fut.set(true);
                7_u8
            })
        });
        match res {
            Err(Error::Other(msg)) => assert_eq!(msg, "cancelled", "texte exact attendu"),
            other => panic!("Error::Other « cancelled » attendu, rendu : {other:?}"),
        }
        assert!(
            !ran.get(),
            "le futur ne doit pas être interrogé quand le jeton est déjà annulé"
        );
    }

    // ── Scenario « annulation avant l'appel » (face multi-thread) ──
    // « le résultat est le même sous un runtime multi-thread » : le corps du test
    // n'a aucun point d'attente, la portée et l'appel restent sur le même fil.
    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_token_before_call_errors_without_polling_multithread() {
        let token = CancelToken::new();
        token.cancel();
        let ran = Rc::new(Cell::new(false));
        let ran_in_fut = Rc::clone(&ran);
        let res = cancel::scope(&token, move || {
            block_on(async move {
                ran_in_fut.set(true);
                7_u8
            })
        });
        match res {
            Err(Error::Other(msg)) => assert_eq!(msg, "cancelled", "texte exact attendu"),
            other => panic!("Error::Other « cancelled » attendu, rendu : {other:?}"),
        }
        assert!(
            !ran.get(),
            "le futur ne doit pas être interrogé quand le jeton est déjà annulé"
        );
    }

    /// Témoin de destruction : lève son drapeau à la `Drop` du futur qui le porte.
    struct DropWitness(Rc<Cell<bool>>);

    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    /// Futur qui dort 30 s en portant un témoin de destruction (abandon = `Drop` =
    /// drapeau levé ; fin normale = drapeau levé aussi, mais elle n'arrive pas ici).
    async fn thirty_second_sleeper(dropped: Rc<Cell<bool>>) {
        let _witness = DropWitness(dropped);
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }

    /// Cœur des deux faces du Scenario « annulation pendant l'attente » : tranche de
    /// 25 ms, marge CI → retour asserté sous 500 ms, jamais l'égalité à la tranche.
    fn assert_cancelled_during_wait(
        res: crate::Result<()>,
        dropped: &Rc<Cell<bool>>,
        elapsed: std::time::Duration,
    ) {
        match res {
            Err(Error::Other(msg)) => assert_eq!(msg, "cancelled", "texte exact attendu"),
            other => panic!("Error::Other « cancelled » attendu, rendu : {other:?}"),
        }
        assert!(
            dropped.get(),
            "le futur doit être détruit (abandonné), pas laissé en vie"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "retour en {elapsed:?}, moins de 500 ms attendues"
        );
    }

    fn cancel_during_wait_scenario() -> (CancelToken, Rc<Cell<bool>>, std::thread::JoinHandle<()>) {
        let token = CancelToken::new();
        let dropped = Rc::new(Cell::new(false));
        let canceller = {
            let t = token.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                t.cancel();
            })
        };
        (token, dropped, canceller)
    }

    // ── Scenario « annulation pendant l'attente » (face hors runtime : le runtime
    // temporaire current_thread doit servir la course futur/contrôle du drapeau) ──
    #[test]
    fn cancellation_during_wait_abandons_the_future_outside_runtime() {
        let (token, dropped, canceller) = cancel_during_wait_scenario();
        let fut = thirty_second_sleeper(Rc::clone(&dropped));
        let start = std::time::Instant::now();
        let res = cancel::scope(&token, move || block_on(fut));
        let elapsed = start.elapsed();
        assert_cancelled_during_wait(res, &dropped, elapsed);
        canceller.join().expect("le fil annuleur rend sa main");
    }

    // ── Scenario « annulation pendant l'attente » (face multi-thread : block_in_place
    // + Handle courant, le drapeau annulé depuis un autre fil doit être vu à la tranche) ──
    #[tokio::test(flavor = "multi_thread")]
    async fn cancellation_during_wait_abandons_the_future_multithread() {
        let (token, dropped, canceller) = cancel_during_wait_scenario();
        let fut = thirty_second_sleeper(Rc::clone(&dropped));
        let start = std::time::Instant::now();
        let res = cancel::scope(&token, move || block_on(fut));
        let elapsed = start.elapsed();
        assert_cancelled_during_wait(res, &dropped, elapsed);
        canceller.join().expect("le fil annuleur rend sa main");
    }

    // ── Scenario « annulation ignorée sans portée » ──
    // Un jeton annulé existe mais n'est installé sur aucun fil : chemin d'avant.
    #[test]
    fn cancelled_token_without_scope_is_ignored() {
        let stray = CancelToken::new();
        stray.cancel(); // jamais installé par `scope` : le fil n'a aucun jeton courant
        let out = block_on(async { 7_i32 });
        assert_eq!(out.unwrap(), 7, "sans portée, le comportement est celui d'avant");
    }

    // ── Scenario « jeton d'un autre fil » ──
    // Le jeton annulé est installé par `scope` sur le fil A ; le fil B appelle
    // `block_on` et l'ignore (le jeton est par fil, ./cancel.sdd).
    #[test]
    fn token_installed_on_another_thread_is_ignored() {
        let token = CancelToken::new();
        token.cancel();
        let (tx, rx) = std::sync::mpsc::channel();
        let holder = {
            let t = token;
            std::thread::spawn(move || {
                cancel::scope(&t, || {
                    tx.send(()).expect("le fil B attend");
                    std::thread::sleep(std::time::Duration::from_millis(50));
                });
            })
        };
        rx.recv().expect("la portée du fil A est ouverte");
        let out = block_on(async { 7_i32 });
        assert_eq!(out.unwrap(), 7, "le jeton d'un autre fil doit être ignoré");
        holder.join().expect("le fil porteur rend sa main");
    }
}
