//! Consommateur externe de `vynil_core::rt::block_on` (issue #23) : ce binaire est hors de la
//! crate et ne voit que l'API publique, compilé avec la seule feature `rt` (sans `rhai`).
//! Il joue les deux Scenario « consommateur externe » de `src/rt.sdd`.
#![cfg(feature = "rt")]

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use vynil_core::{
    Error,
    cancel::{self, CancelToken},
    rt::block_on,
};

/// Témoin de destruction : lève son drapeau quand le futur qui le porte est détruit.
struct DropWitness(Arc<AtomicBool>);

impl Drop for DropWitness {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Dort 30 s en portant un témoin : si `block_on` ne l'abandonne pas, le test dure 30 s.
async fn sleep_30s_with_witness(dropped: Arc<AtomicBool>) {
    let _witness = DropWitness(dropped);
    tokio::time::sleep(Duration::from_secs(30)).await;
}

// ── Scenario « consommateur externe, runtime multi-thread » ──
#[tokio::test(flavor = "multi_thread")]
async fn external_multi_thread_returns_the_value() {
    let out = block_on(async { 42_i32 });
    assert!(matches!(out, Ok(42)), "Ok(42) attendu, obtenu {out:?}");
}

// ── Scenario « consommateur externe, annulation » (runtime multi-thread) ──
#[tokio::test(flavor = "multi_thread")]
async fn external_cancel_multi_thread_abandons_the_future() {
    let token = CancelToken::new();
    let interrupter = token.clone();
    let dropped = Arc::new(AtomicBool::new(false));
    let witness = Arc::clone(&dropped);

    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        interrupter.cancel();
    });

    let started = Instant::now();
    let out = cancel::scope(&token, || block_on(sleep_30s_with_witness(witness)));
    let elapsed = started.elapsed();
    assert!(canceller.join().is_ok(), "le fil d'annulation doit se terminer");

    assert!(
        matches!(&out, Err(Error::Other(msg)) if msg == "cancelled"),
        "annulation attendue : Error::Other(\"cancelled\"), obtenu {out:?}"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "retour en moins de 500 ms attendu, obtenu {elapsed:?}"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "le futur doit être abandonné (témoin de destruction levé)"
    );
}

// ── Même Scenario hors de tout runtime (voie « runtime temporaire ») ──
#[test]
fn external_cancel_without_runtime_abandons_the_future() {
    let token = CancelToken::new();
    let interrupter = token.clone();
    let dropped = Arc::new(AtomicBool::new(false));
    let witness = Arc::clone(&dropped);

    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        interrupter.cancel();
    });

    let started = Instant::now();
    let out = cancel::scope(&token, || block_on(sleep_30s_with_witness(witness)));
    let elapsed = started.elapsed();
    assert!(canceller.join().is_ok(), "le fil d'annulation doit se terminer");

    assert!(
        matches!(&out, Err(Error::Other(msg)) if msg == "cancelled"),
        "annulation attendue : Error::Other(\"cancelled\"), obtenu {out:?}"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "retour en moins de 500 ms attendu, obtenu {elapsed:?}"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "le futur doit être abandonné (témoin de destruction levé)"
    );
}
