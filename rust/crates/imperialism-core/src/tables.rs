use crate::{NationId, ProductionSlot};
use std::ops::{Index, IndexMut};

pub const NATION_COUNT: usize = 23;
pub const MAJOR_NATION_COUNT: usize = 7;
pub const PENDING_ACTION_COUNT: usize = 13;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NationTable<T>([T; NATION_COUNT]);

impl<T> NationTable<T> {
    pub const fn from_array(values: [T; NATION_COUNT]) -> Self {
        Self(values)
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T: Default> Default for NationTable<T> {
    fn default() -> Self {
        Self(std::array::from_fn(|_| T::default()))
    }
}

impl<T> Index<NationId> for NationTable<T> {
    type Output = T;

    fn index(&self, nation: NationId) -> &Self::Output {
        &self.0[usize::from(nation.get())]
    }
}

impl<T> IndexMut<NationId> for NationTable<T> {
    fn index_mut(&mut self, nation: NationId) -> &mut Self::Output {
        &mut self.0[usize::from(nation.get())]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MajorNationTable<T>([T; MAJOR_NATION_COUNT]);

impl<T> MajorNationTable<T> {
    pub const fn from_array(values: [T; MAJOR_NATION_COUNT]) -> Self {
        Self(values)
    }

    pub fn from_fn(function: impl FnMut(usize) -> T) -> Self {
        Self(std::array::from_fn(function))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.0.iter()
    }
}

impl<T> Index<NationId> for MajorNationTable<T> {
    type Output = T;

    fn index(&self, nation: NationId) -> &Self::Output {
        &self.0[usize::from(nation.get())]
    }
}

impl<T> IndexMut<NationId> for MajorNationTable<T> {
    fn index_mut(&mut self, nation: NationId) -> &mut Self::Output {
        &mut self.0[usize::from(nation.get())]
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PendingActionSlot(u8);

impl PendingActionSlot {
    pub const COUNT: usize = PENDING_ACTION_COUNT;

    pub const fn new(value: u8) -> Option<Self> {
        if (value as usize) < Self::COUNT {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingActionTable<T>([T; PENDING_ACTION_COUNT]);

impl<T> PendingActionTable<T> {
    pub const fn from_array(values: [T; PENDING_ACTION_COUNT]) -> Self {
        Self(values)
    }
}

impl<T: Default> Default for PendingActionTable<T> {
    fn default() -> Self {
        Self(std::array::from_fn(|_| T::default()))
    }
}

impl<T> Index<PendingActionSlot> for PendingActionTable<T> {
    type Output = T;

    fn index(&self, slot: PendingActionSlot) -> &Self::Output {
        &self.0[slot.index()]
    }
}

impl<T> IndexMut<PendingActionSlot> for PendingActionTable<T> {
    fn index_mut(&mut self, slot: PendingActionSlot) -> &mut Self::Output {
        &mut self.0[slot.index()]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionTable<T>([T; ProductionSlot::COUNT]);

impl<T> ProductionTable<T> {
    pub const fn from_array(values: [T; ProductionSlot::COUNT]) -> Self {
        Self(values)
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn fill(&mut self, value: T)
    where
        T: Clone,
    {
        self.0.fill(value);
    }
}

impl<T: Default> Default for ProductionTable<T> {
    fn default() -> Self {
        Self(std::array::from_fn(|_| T::default()))
    }
}

impl<T> Index<ProductionSlot> for ProductionTable<T> {
    type Output = T;

    fn index(&self, slot: ProductionSlot) -> &Self::Output {
        &self.0[slot.index()]
    }
}

impl<T> IndexMut<ProductionSlot> for ProductionTable<T> {
    fn index_mut(&mut self, slot: ProductionSlot) -> &mut Self::Output {
        &mut self.0[slot.index()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_keyed_by_domain_ids() {
        let mut nations = NationTable::default();
        nations[NationId::new(6)] = 7_i16;
        assert_eq!(nations[NationId::new(6)], 7);

        let mut production = ProductionTable::default();
        let slot = ProductionSlot::new(3).unwrap();
        production[slot] = 11_i16;
        assert_eq!(production[slot], 11);

        let action = PendingActionSlot::new(7).unwrap();
        let mut pending = PendingActionTable::default();
        pending[action] = 3_i16;
        assert_eq!(pending[action], 3);
    }
}
