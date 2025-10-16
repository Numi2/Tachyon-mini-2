//! Blog-style MaybeKind and Maybe abstractions (Always/Empty) enabling zero-cost specialization.

use core::marker::PhantomData;

/// Higher-kinded abstraction over presence of values.
pub trait MaybeKind {
    type Rebind<T>: Maybe<T, Kind = Self>;
}

/// Values are always present.
#[derive(Clone, Copy, Debug, Default)]
pub struct AlwaysKind;

/// Values are statically absent (zero-sized at runtime).
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyKind;

impl MaybeKind for AlwaysKind {
    type Rebind<T> = Always<T>;
}

impl MaybeKind for EmptyKind {
    type Rebind<T> = Empty<T>;
}

/// Concrete Maybe value when present.
#[derive(Clone, Copy, Debug)]
pub struct Always<T>(pub T);

/// Concrete Maybe value when absent (ZST), carrying only type information.
#[derive(Clone, Copy, Debug, Default)]
pub struct Empty<T>(pub PhantomData<T>);

/// Generalized Maybe interface with compile-time presence via `Kind`.
pub trait Maybe<T> {
    type Kind: MaybeKind;

    fn just<R>(f: impl FnOnce() -> R) -> <Self::Kind as MaybeKind>::Rebind<R>;

    fn with<R, E>(f: impl FnOnce() -> Result<R, E>) -> Result<<Self::Kind as MaybeKind>::Rebind<R>, E>;

    fn take(self) -> T;

    fn map<U, F>(self, f: F) -> <Self::Kind as MaybeKind>::Rebind<U>
    where
        F: FnOnce(T) -> U;

    fn view(&self) -> <Self::Kind as MaybeKind>::Rebind<&T>;

    #[inline]
    fn snag(&self) -> &T { self.view().take() }
}

impl<T> Maybe<T> for Always<T> {
    type Kind = AlwaysKind;

    #[inline]
    fn just<R>(f: impl FnOnce() -> R) -> <Self::Kind as MaybeKind>::Rebind<R> { Always(f()) }

    #[inline]
    fn with<R, E>(f: impl FnOnce() -> Result<R, E>) -> Result<<Self::Kind as MaybeKind>::Rebind<R>, E> {
        f().map(Always)
    }

    #[inline]
    fn take(self) -> T { self.0 }

    #[inline]
    fn map<U, F>(self, f: F) -> <Self::Kind as MaybeKind>::Rebind<U>
    where
        F: FnOnce(T) -> U,
    {
        Always(f(self.0))
    }

    #[inline]
    fn view(&self) -> <Self::Kind as MaybeKind>::Rebind<&T> { Always(&self.0) }
}

impl<T> Maybe<T> for Empty<T> {
    type Kind = EmptyKind;

    #[inline]
    fn just<R>(_f: impl FnOnce() -> R) -> <Self::Kind as MaybeKind>::Rebind<R> { Empty(PhantomData) }

    #[inline]
    fn with<R, E>(_f: impl FnOnce() -> Result<R, E>) -> Result<<Self::Kind as MaybeKind>::Rebind<R>, E> {
        Ok(Empty(PhantomData))
    }

    #[inline]
    fn take(self) -> T {
        // Intentionally unreachable if monomorphized away correctly.
        // Using panic avoids UB while clearly signaling misuse in debug contexts.
        panic!("attempted to take() from Empty; this should be unreachable in correct drivers")
    }

    #[inline]
    fn map<U, F>(_self, _f: F) -> <Self::Kind as MaybeKind>::Rebind<U>
    where
        F: FnOnce(T) -> U,
    {
        Empty(PhantomData)
    }

    #[inline]
    fn view(&self) -> <Self::Kind as MaybeKind>::Rebind<&T> { Empty(PhantomData) }
}


