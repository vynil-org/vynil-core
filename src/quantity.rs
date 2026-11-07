//! Kubernetes `Quantity` parser (`500m`, `2Gi`, `1.5e3`…), exact integer arithmetic.
//!
//! `cpu_millis_of` and `memory_bytes_of` share one grammar and one rounding rule (away from
//! zero, as Kubernetes does); only the output unit differs. Under `rhai` together with this
//! feature, the `core` group of `crate::engine::core_rhai_register` exposes both to scripts
//! as `cpu_millis_of` and `memory_bytes_of`.

#[cfg(all(feature = "rhai", feature = "quantity"))]
use crate::engine::{Target, register_at};
#[cfg(all(feature = "rhai", feature = "quantity"))] use rhai::Dynamic;

/// Millicores of a Kubernetes CPU quantity (`"500m"` → 500, `"0.1"` → 100, `"100000n"` → 1).
///
/// Returns `None` for any input outside the grammaire, for a result that does not fit an
/// `i64`, and never panics. Results that are not whole millicores round away from zero.
#[must_use]
pub fn cpu_millis_of(q: &str) -> Option<i64> {
    to_i64(&parse(q)?, 3)
}

/// Bytes of a Kubernetes memory quantity (`"2Gi"` → 2147483648, `"1500m"` → 2).
///
/// Same grammar and rounding as [`cpu_millis_of`], output in units instead of millicores.
/// Returns `None` for an input outside the grammar or a result that does not fit an `i64`.
#[must_use]
pub fn memory_bytes_of(q: &str) -> Option<i64> {
    to_i64(&parse(q)?, 0)
}

/// A parsed quantity: the value is `±mantissa · 10^exp10 · 2^exp2`, every factor exact.
struct Parsed {
    negative: bool,
    /// Significant decimal digits of the number (integer and fraction digits together).
    mantissa: u128,
    /// Decimal exponent, `None` when the written exponent does not fit an `i64`.
    exp10: Option<i64>,
    /// Binary exponent of a `Ki`…`Ei` suffix, `0` otherwise.
    exp2: u32,
}

/// Parses the whole grammar of a Kubernetes quantity, or `None` on any deviation from it.
/// Nothing is trimmed or case-folded: a deviation stays a deviation.
fn parse(q: &str) -> Option<Parsed> {
    let (negative, body) = match q.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, q.strip_prefix('+').unwrap_or(q)),
    };
    let bytes = body.as_bytes();
    let mut mantissa: u128 = 0;
    let mut digits: usize = 0;
    let mut frac_len: i64 = 0;
    let mut seen_dot = false;
    let mut i: usize = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'.' && !seen_dot {
            seen_dot = true;
        } else if let Some(d) = char::from(b).to_digit(10) {
            mantissa = mantissa.checked_mul(10)?.checked_add(u128::from(d))?;
            digits = digits.checked_add(1)?;
            if seen_dot {
                frac_len = frac_len.checked_add(1)?;
            }
        } else {
            break;
        }
        i = i.checked_add(1)?;
    }
    if digits == 0 {
        return None;
    }
    let tail = body.get(i..)?;
    let (exp10, exp2) = if let Some(body) = exponent_body(tail) {
        // An exponent too large for an `i64` leaves `exp10` as `None`.
        (body.parse::<i64>().ok(), 0)
    } else {
        let (decimal, binary) = unit_suffix(tail)?;
        (Some(decimal), binary)
    };
    Some(Parsed {
        negative,
        mantissa,
        exp10: exp10.and_then(|e| e.checked_sub(frac_len)),
        exp2,
    })
}

/// The text after `e`/`E` when `tail` is the exponent form `e<entier signé>`, `None` when it
/// is not (a lone `E` is the exa suffix, `Ei` the binary one).
fn exponent_body(tail: &str) -> Option<&str> {
    let body = tail.strip_prefix(['e', 'E'])?;
    let digits = body.strip_prefix(['+', '-']).unwrap_or(body);
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then_some(body)
}

/// The unit suffix as `(decimal exponent, binary exponent)`: `n`…`E` multiply by a power of
/// ten, `Ki`…`Ei` by a power of two. The empty suffix is the unit itself.
fn unit_suffix(tail: &str) -> Option<(i64, u32)> {
    Some(match tail {
        "" => (0, 0),
        "n" => (-9, 0),
        "u" => (-6, 0),
        "m" => (-3, 0),
        "k" => (3, 0),
        "M" => (6, 0),
        "G" => (9, 0),
        "T" => (12, 0),
        "P" => (15, 0),
        "E" => (18, 0),
        "Ki" => (0, 10),
        "Mi" => (0, 20),
        "Gi" => (0, 30),
        "Ti" => (0, 40),
        "Pi" => (0, 50),
        "Ei" => (0, 60),
        _ => return None,
    })
}

/// Rounds `value · 10^shift` in magnitude, away from zero, to an integer `u128`. `shift` is 3
/// for millicores and 0 for units. `None` when the result does not fit a `u128`.
fn magnitude(p: &Parsed, shift: i64) -> Option<u128> {
    if p.mantissa == 0 {
        return Some(0);
    }
    let t = p.exp10?.checked_add(shift)?;
    let numerator = p.mantissa.checked_mul(2_u128.checked_pow(p.exp2)?)?;
    if t >= 0 {
        let scale = 10_u128.checked_pow(u32::try_from(t).ok()?)?;
        return numerator.checked_mul(scale);
    }
    // Known limit (écart de contrat, à trancher): with a binary suffix AND fraction digits
    // (`t < 0`), `numerator` can exceed `u128` before the division by `10^-t`, and `None` is
    // returned although the result fits an `i64`. Same for mantissas beyond `u128` (parse).
    // A divisor beyond `u128` exceeds the numerator, so the quotient is 0 and the remainder
    // is non-zero: the magnitude rounds up to 1.
    let Some(divisor) = 10_u128.checked_pow(u32::try_from(t.unsigned_abs()).unwrap_or(u32::MAX)) else {
        return Some(1);
    };
    let quotient = numerator.checked_div(divisor)?;
    if numerator.checked_rem(divisor)? == 0 {
        Some(quotient)
    } else {
        quotient.checked_add(1)
    }
}

/// Signed result of [`magnitude`] as an `i64`, `None` when it does not fit.
fn to_i64(p: &Parsed, shift: i64) -> Option<i64> {
    let mag = i128::try_from(magnitude(p, shift)?).ok()?;
    let signed = if p.negative { mag.checked_neg()? } else { mag };
    i64::try_from(signed).ok()
}

/// The two script entries, applied to their target by the `core` group (sous `rhai` + `quantity`).
#[cfg(all(feature = "rhai", feature = "quantity"))]
pub(crate) fn quantity_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "cpu_millis_of",
        &[
            "/// Millicores of a Kubernetes CPU quantity such as `\"500m\"` or `2`; `()` when unparseable or out of range.",
        ],
        &["quantity: Dynamic", "Dynamic"],
        |q: Dynamic| -> Dynamic { script_value(&q, cpu_millis_of) },
    );
    register_at(
        target,
        "memory_bytes_of",
        &[
            "/// Bytes of a Kubernetes memory quantity such as `\"2Gi\"` or `\"1500m\"`; `()` when unparseable or out of range.",
        ],
        &["quantity: Dynamic", "Dynamic"],
        |q: Dynamic| -> Dynamic { script_value(&q, memory_bytes_of) },
    );
}

/// Script-side reading of an argument: a string as is, an integer by its decimal digits, a
/// finite float by its shortest decimal representation; any other value is `()`.
#[cfg(all(feature = "rhai", feature = "quantity"))]
fn script_value(q: &Dynamic, convertir: fn(&str) -> Option<i64>) -> Dynamic {
    let text = if let Some(s) = q.clone().try_cast::<rhai::ImmutableString>() {
        s.to_string()
    } else if let Some(i) = q.clone().try_cast::<i64>() {
        i.to_string()
    } else if let Some(f) = q.clone().try_cast::<f64>() {
        if !f.is_finite() {
            return Dynamic::UNIT;
        }
        f.to_string()
    } else {
        return Dynamic::UNIT;
    };
    convertir(&text).map_or(Dynamic::UNIT, Dynamic::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "rhai")] use rhai::Engine;

    #[test]
    fn scenario_grammaire_decimale_et_binaire() {
        assert_eq!(memory_bytes_of("1Ki"), Some(1024));
        assert_eq!(memory_bytes_of("1Gi"), Some(1_073_741_824));
        assert_eq!(memory_bytes_of("1k"), Some(1000));
        assert_eq!(memory_bytes_of("1M"), Some(1_000_000));
        assert_eq!(memory_bytes_of("128974848"), Some(128_974_848));
        assert_eq!(memory_bytes_of("129e6"), Some(129_000_000));
        assert_eq!(cpu_millis_of("500m"), Some(500));
        assert_eq!(cpu_millis_of("2"), Some(2000));
        assert_eq!(cpu_millis_of("0.5"), Some(500));
        assert_eq!(cpu_millis_of("0.1"), Some(100));
        assert_eq!(cpu_millis_of(".5"), Some(500));
        assert_eq!(cpu_millis_of("1.5"), Some(1500));
    }

    #[test]
    fn scenario_sous_unites_et_arrondi() {
        assert_eq!(cpu_millis_of("100000n"), Some(1));
        assert_eq!(cpu_millis_of("1500u"), Some(2));
        assert_eq!(cpu_millis_of("1u"), Some(1));
        assert_eq!(memory_bytes_of("1500m"), Some(2));
        assert_eq!(memory_bytes_of("0.4"), Some(1));
        assert_eq!(memory_bytes_of("-0.4"), Some(-1));
    }

    #[test]
    fn scenario_hors_grammaire() {
        for entree in [
            "", " 1", "1 ", "abc", "1K", "1ki", "1mi", "1Mm", "1e", "e3", ".", "-", "1..5", "0x10",
        ] {
            assert_eq!(cpu_millis_of(entree), None, "cpu_millis_of({entree:?})");
            assert_eq!(memory_bytes_of(entree), None, "memory_bytes_of({entree:?})");
        }
    }

    #[test]
    fn scenario_debordement() {
        assert_eq!(memory_bytes_of("9Ei"), None);
        assert_eq!(memory_bytes_of("8Ei"), None);
        assert_eq!(cpu_millis_of("9223372036854775807"), None);
        assert_eq!(
            memory_bytes_of("9223372036854775807"),
            Some(9_223_372_036_854_775_807)
        );
    }

    #[cfg(all(feature = "rhai", feature = "quantity"))]
    fn engine_avec_quantity() -> Engine {
        let mut engine = Engine::new();
        crate::engine::core_rhai_register(&mut engine);
        engine
    }

    #[cfg(all(feature = "rhai", feature = "quantity"))]
    #[test]
    fn scenario_depuis_un_script() {
        let engine = engine_avec_quantity();
        let ints = [
            (r#"cpu_millis_of("500m")"#, 500_i64),
            ("cpu_millis_of(2)", 2000),
            ("cpu_millis_of(0.5)", 500),
            (r#"memory_bytes_of("1Gi")"#, 1_073_741_824),
        ];
        for (src, attendu) in ints {
            let v = engine.eval::<Dynamic>(src).unwrap();
            assert_eq!(v.clone().try_cast::<i64>(), Some(attendu), "{src}");
        }
        for src in [
            r#"cpu_millis_of("n'importe quoi")"#,
            "cpu_millis_of(true)",
            "cpu_millis_of([1])",
        ] {
            let t = engine.eval::<String>(&format!("type_of({src})")).unwrap();
            assert_eq!(t, "()", "{src}");
        }
    }

    #[cfg(all(feature = "rhai", feature = "quantity"))]
    #[test]
    fn scenario_quantity_jumeau_core_equivalent_a_lenregistreur() {
        let nu = engine_avec_quantity();
        let mut qualifie = Engine::new();
        qualifie.register_static_module("m", crate::engine::core_module().into());
        let appels = [
            (r#"cpu_millis_of("500m")"#, r#"m::cpu_millis_of("500m")"#),
            ("cpu_millis_of(2)", "m::cpu_millis_of(2)"),
            ("cpu_millis_of(0.5)", "m::cpu_millis_of(0.5)"),
            (r#"memory_bytes_of("1Gi")"#, r#"m::memory_bytes_of("1Gi")"#),
            (
                r#"cpu_millis_of("n'importe quoi")"#,
                r#"m::cpu_millis_of("n'importe quoi")"#,
            ),
        ];
        for (bare, nomme) in appels {
            let a = nu.eval::<Dynamic>(bare).unwrap().to_string();
            let b = qualifie.eval::<Dynamic>(nomme).unwrap().to_string();
            assert_eq!(a, b, "{bare} contre {nomme}");
        }
        assert_eq!(
            qualifie
                .eval::<Dynamic>(r#"m::cpu_millis_of("500m")"#)
                .unwrap()
                .try_cast::<i64>(),
            Some(500),
            "le jumeau rend la valeur, pas seulement les mêmes erreurs"
        );
    }

    #[cfg(all(feature = "rhai", feature = "quantity"))]
    #[test]
    fn scenario_enregistreur_idempotent() {
        let mut engine = Engine::new();
        crate::engine::core_rhai_register(&mut engine);
        crate::engine::core_rhai_register(&mut engine);
        let v = engine.eval::<Dynamic>(r#"memory_bytes_of("1Ki")"#).unwrap();
        assert_eq!(v.try_cast::<i64>(), Some(1024));
    }

    #[cfg(all(feature = "rhai", feature = "quantity"))]
    #[test]
    fn scenario_new_bare_cable_quantity() {
        let mut s = crate::engine::Script::new_bare(vec![]);
        assert_eq!(
            s.eval(r#"cpu_millis_of("1")"#).unwrap().try_cast::<i64>(),
            Some(1000)
        );
        assert_eq!(
            s.eval(r#"memory_bytes_of("1")"#).unwrap().try_cast::<i64>(),
            Some(1)
        );
    }

    #[cfg(all(feature = "rhai", not(feature = "quantity")))]
    #[test]
    fn scenario_new_bare_sans_quantity() {
        let mut s = crate::engine::Script::new_bare(vec![]);
        assert!(s.eval(r#"cpu_millis_of("1")"#).is_err());
        assert!(s.eval(r#"memory_bytes_of("1")"#).is_err());
    }

    #[cfg(all(feature = "metadata", feature = "rhai", feature = "quantity"))]
    #[test]
    fn scenario_fonctions_documentees_sous_metadata() {
        let mut engine = Engine::new();
        crate::engine::core_rhai_register(&mut engine);
        let signatures = engine.gen_fn_signatures(false);
        for attendue in [
            "cpu_millis_of(quantity: Dynamic) -> Dynamic",
            "memory_bytes_of(quantity: Dynamic) -> Dynamic",
        ] {
            assert!(
                signatures.iter().any(|s| s == attendue),
                "{attendue} absent de {signatures:?}"
            );
        }
    }
}
