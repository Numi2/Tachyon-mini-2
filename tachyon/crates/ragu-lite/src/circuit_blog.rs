//! Blog-style Circuit trait with input/main/output split and associated IO/Aux.

use crate::driver_blog::{Driver, Error as DriverError};
use crate::maybe_kind::{Maybe, MaybeKind};
use ff::PrimeField;

pub trait Circuit<F: PrimeField>: Sized {
    type Instance<'instance>;
    type IO<'source, D: Driver<F = F>>;
    type Witness<'witness>;
    type Aux<'witness>;

    fn input<'instance, D: Driver<F = F>>(
        &self,
        dr: &mut D,
        input: <D::MaybeKind as MaybeKind>::Rebind<Self::Instance<'instance>>,
    ) -> Result<Self::IO<'instance, D>, DriverError>;

    fn main<'witness, D: Driver<F = F>>(
        &self,
        dr: &mut D,
        witness: <D::MaybeKind as MaybeKind>::Rebind<Self::Witness<'witness>>,
    ) -> Result<(Self::IO<'witness, D>, <D::MaybeKind as MaybeKind>::Rebind<Self::Aux<'witness>>), DriverError>;

    fn output<'source, D: Driver<F = F>>(
        &self,
        dr: &mut D,
        io: Self::IO<'source, D>,
        output: &mut D::IO,
    ) -> Result<(), DriverError>;
}


