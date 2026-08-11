use super::*;

mod basic;
mod construction;
mod shipyard;
mod training_armory;
mod university;

pub(in crate::ui::city) use basic::*;
pub(in crate::ui::city) use construction::*;
pub(in crate::ui::city) use shipyard::*;
pub(in crate::ui::city) use training_armory::*;
pub(in crate::ui::city) use university::*;
