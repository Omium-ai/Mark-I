//! `Secret<T>` — 04 §3.3, NFR-SECURITY-001.
//!
//! The type has no `Debug`, no `Display` and no `Serialize` — derived or manual — and it
//! zeroizes on drop. Two mechanisms hold that, and they check different things:
//!
//!   * the `assert_not_impl!` blocks below fail **compilation** if any of those impls ever
//!     exists, including one arriving through a blanket impl in a dependency;
//!   * `tools/ci/secret_type_gate.sh` refuses the *diff* that would add one, which is what
//!     stops the assertions themselves from being deleted in the same commit.
//!
//! The inner value leaves only through `expose_for_upstream`, and that is what lets the
//! gate treat a bare `.0` anywhere outside this file as an escape.
//!
//! **What is, and is not, held here.** In sidecar mode the customer credential is never
//! owned by this process: it arrives in a request header, the guard reads it *by reference*
//! to fingerprint and classify it, and the same header bytes go upstream untouched. So the
//! `Secret<T>` instances that exist today hold our own device-local key material. Gateway
//! mode (04 §3.3, Phase 5) is where a fetched customer credential becomes an owned value,
//! and this is the type it must land in.

use zeroize::Zeroize;

/// Owned secret material. Constructed from a value that can destroy itself; readable only
/// through the one sealed accessor.
pub struct Secret<T: Zeroize> {
    // Named, not positional: there is no `.0` to reach for in the first place.
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// The single read path out of the newtype. Named for the only reason a secret is ever
    /// legitimately observed — it is about to authenticate a request — so a call site that
    /// is doing anything else reads wrong at review time.
    pub fn expose_for_upstream(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Compile-time proof that `$ty` does **not** implement `$trait`.
///
/// If the impl exists, both `AmbiguousIfImpl` impls apply to `$ty`, the `_` in the turbofish
/// has two solutions, and inference fails — a hard compile error at this line, naming this
/// file. This is `static_assertions::assert_not_impl_any!` inlined; the crate is not a
/// declared dependency and a five-line macro does not justify becoming one.
macro_rules! assert_not_impl {
    ($ty:ty, $($trait:tt)+) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + $($trait)+> AmbiguousIfImpl<u8> for T {}
            let _ = <$ty as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

assert_not_impl!(Secret<Vec<u8>>, core::fmt::Debug);
assert_not_impl!(Secret<Vec<u8>>, core::fmt::Display);
assert_not_impl!(Secret<Vec<u8>>, serde::Serialize);
assert_not_impl!(Secret<String>, core::fmt::Debug);
assert_not_impl!(Secret<String>, core::fmt::Display);
assert_not_impl!(Secret<String>, serde::Serialize);

/// Runtime probe for whether a type implements `Debug`, used by `unit_secret_type_no_debug`
/// as the **positive control** for the assertions above.
///
/// WHY this exists: `assert_not_impl!` passes by compiling, so a refactor that broke the
/// macro into a tautology would be indistinguishable from a correct one. The probe can be
/// pointed at a type that *does* implement `Debug`, so the test can prove the detection
/// works before trusting it about `Secret`.
///
/// Autoref specialization: the `&Probe<T>` impl is only applicable when `T: Debug`, and
/// method resolution reaches it one autoref step *earlier* than the blanket `Probe<T>` impl.
pub mod probe {
    use core::marker::PhantomData;

    pub struct Probe<T: ?Sized>(pub PhantomData<T>);

    pub trait NotDebug {
        fn implements_debug(&self) -> bool {
            false
        }
    }
    impl<T: ?Sized> NotDebug for Probe<T> {}

    pub trait IsDebug {
        fn implements_debug(&self) -> bool {
            true
        }
    }
    impl<T: ?Sized + core::fmt::Debug> IsDebug for &Probe<T> {}
}

/// `true` iff `$ty` implements `Debug`.
///
/// A macro rather than a generic `fn`, and that is the whole subtlety: inside
/// `fn probe<T>() -> bool`, trait selection uses the bounds declared on `T`, not the type
/// eventually substituted — so the `IsDebug` arm can never be selected and the function
/// answers `false` for everything, including `String`. That version existed, compiled, and
/// its "negative" assertions about `Secret` were vacuous. The positive control in
/// `unit_secret_type_no_debug` is what caught it.
#[cfg(test)]
macro_rules! implements_debug {
    ($ty:ty) => {{
        #[allow(unused_imports)]
        use $crate::secret::probe::{IsDebug as _, NotDebug as _};
        let p: $crate::secret::probe::Probe<$ty> =
            $crate::secret::probe::Probe(::core::marker::PhantomData);
        (&&p).implements_debug()
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ZEROIZED: AtomicUsize = AtomicUsize::new(0);

    struct Canary;
    impl Zeroize for Canary {
        fn zeroize(&mut self) {
            ZEROIZED.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// 12 §2.7 `unit_secret_type_no_debug` (NFR-SECURITY-001).
    ///
    /// 12 specifies this as a `trybuild` compile-fail suite. `trybuild` is not a declared
    /// workspace dependency and a compile-fail harness would only prove that *a derive we
    /// wrote in a fixture* fails; the `assert_not_impl!` blocks prove the stronger thing —
    /// that no impl reaches `Secret` by any route, including a blanket impl from a
    /// dependency — and they prove it about the shipped type rather than a fixture.
    #[test]
    fn unit_secret_type_no_debug() {
        // Positive control FIRST: if the probe cannot detect Debug on a type that plainly
        // has it, the negative assertions below prove nothing and this test is decoration.
        assert!(
            implements_debug!(String),
            "probe cannot detect Debug at all"
        );
        assert!(implements_debug!(Vec<u8>));

        assert!(!implements_debug!(Secret<Vec<u8>>));
        assert!(!implements_debug!(Secret<String>));
    }

    #[test]
    fn unit_secret_zeroizes_on_drop() {
        let before = ZEROIZED.load(Ordering::SeqCst);
        drop(Secret::new(Canary));
        assert_eq!(ZEROIZED.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn unit_secret_exposes_the_value_it_was_given() {
        let s = Secret::new(b"device-guard-key".to_vec());
        assert_eq!(s.expose_for_upstream().as_slice(), b"device-guard-key");
    }
}
