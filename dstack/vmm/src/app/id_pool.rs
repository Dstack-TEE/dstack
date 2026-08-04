// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt::Display;

use anyhow::bail;

macro_rules! impl_numbers {
    ($($t:ty),*) => {
        $(impl Number for $t {
            fn next(&self) -> Option<Self> {
                (*self).checked_add(1)
            }
        })*
    };
}
pub trait Number: Ord + Sized + Clone + Display {
    fn next(&self) -> Option<Self>;
}
impl_numbers!(u8, u16, u32, u64, u128);
impl_numbers!(i8, i16, i32, i64, i128);

/// A pool of ids over the half-open interval `[start, end)`.
///
/// `start >= end` is a valid but permanently empty pool.
pub struct IdPool<T: Ord = u32> {
    start: T,
    end: T,
    allocated: BTreeSet<T>,
}

impl<T: Number> IdPool<T> {
    pub fn new(start: T, end: T) -> Self {
        Self {
            start,
            end,
            allocated: BTreeSet::new(),
        }
    }

    /// Mark `id` as in use. Fails if `id` falls outside `[start, end)` or is
    /// already taken.
    ///
    /// Callers reconstructing state from ids this pool did not hand out (e.g.
    /// CIDs of processes started under an earlier configuration) should treat
    /// the out-of-range error as a warning rather than a hard failure.
    pub fn occupy(&mut self, id: T) -> anyhow::Result<()> {
        if id < self.start || id >= self.end {
            bail!("id {id} outside pool range [{}, {})", self.start, self.end);
        }
        if !self.allocated.insert(id.clone()) {
            bail!("id {id} already occupied");
        }
        Ok(())
    }

    pub fn allocate(&mut self) -> Option<T> {
        let mut id = self.start.clone();
        loop {
            if id >= self.end {
                return None;
            }
            if !self.allocated.contains(&id) {
                self.allocated.insert(id.clone());
                return Some(id);
            }
            id = id.next()?;
        }
    }

    pub fn free(&mut self, id: T) {
        self.allocated.remove(&id);
    }

    pub fn clear(&mut self) {
        self.allocated.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::IdPool;

    #[test]
    fn allocation_is_start_inclusive_and_end_exclusive() {
        let mut pool = IdPool::new(10_u8, 13);
        assert_eq!(pool.allocate(), Some(10));
        assert_eq!(pool.allocate(), Some(11));
        assert_eq!(pool.allocate(), Some(12));
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn occupied_ids_are_unique_range_bounded_and_reusable() {
        let mut pool = IdPool::new(10_u8, 13);
        assert!(pool.occupy(9).is_err());
        assert!(pool.occupy(13).is_err());
        pool.occupy(10).unwrap();
        assert!(pool.occupy(10).is_err());
        assert_eq!(pool.allocate(), Some(11));
        pool.free(10);
        assert_eq!(pool.allocate(), Some(10));
        pool.clear();
        assert_eq!(pool.allocate(), Some(10));
    }

    #[test]
    fn repeated_allocation_never_hands_out_a_duplicate() {
        let mut pool = IdPool::new(20_u8, 28);
        let mut allocated: Vec<_> = std::iter::from_fn(|| pool.allocate()).collect();
        assert_eq!(pool.allocate(), None);
        allocated.sort_unstable();
        assert_eq!(allocated, (20_u8..28).collect::<Vec<_>>());
    }

    #[test]
    fn reconstruction_from_occupied_ids_preserves_uniqueness() {
        // mirrors reload_vms(): rebuild the pool from the ids of processes
        // already running, then keep allocating from what is left.
        let mut pool = IdPool::new(20_u8, 28);
        for id in 20_u8..28 {
            pool.occupy(id).unwrap();
        }
        assert_eq!(pool.allocate(), None);
        assert!(pool.occupy(20).is_err());
        pool.free(23);
        assert_eq!(pool.allocate(), Some(23));
    }

    #[test]
    fn exhaustion_at_the_numeric_maximum_returns_none() {
        // end == T::MAX, so the last allocatable id is MAX - 1 and the walk
        // stops on the range check before `next()` can overflow.
        let mut pool = IdPool::new(u8::MAX - 1, u8::MAX);
        assert_eq!(pool.allocate(), Some(u8::MAX - 1));
        assert_eq!(pool.allocate(), None);
        assert!(pool.occupy(u8::MAX).is_err());
    }

    #[test]
    fn an_empty_range_allocates_nothing() {
        let mut pool = IdPool::new(u8::MAX, u8::MAX);
        assert_eq!(pool.allocate(), None);
        assert!(pool.occupy(u8::MAX).is_err());
    }

    #[test]
    fn out_of_range_error_names_the_id_and_the_bounds() {
        let mut pool = IdPool::new(10_u8, 13);
        let err = pool.occupy(13).unwrap_err().to_string();
        assert_eq!(err, "id 13 outside pool range [10, 13)");
    }
}
