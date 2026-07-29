// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

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
pub trait Number: Ord + Sized + Clone {
    fn next(&self) -> Option<Self>;
}
impl_numbers!(u8, u16, u32, u64, u128);
impl_numbers!(i8, i16, i32, i64, i128);

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

    pub fn occupy(&mut self, id: T) -> anyhow::Result<()> {
        if id < self.start || id >= self.end {
            bail!("id outside pool range");
        }
        if self.allocated.insert(id) {
            Ok(())
        } else {
            bail!("id already occupied")
        }
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
    fn concurrent_allocation_and_restart_reconstruction_preserve_uniqueness() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let pool = Arc::new(Mutex::new(IdPool::new(20_u8, 28)));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let pool = Arc::clone(&pool);
            workers.push(thread::spawn(move || pool.lock().unwrap().allocate().unwrap()));
        }
        let mut allocated: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        allocated.sort_unstable();
        assert_eq!(allocated, (20_u8..28).collect::<Vec<_>>());
        assert_eq!(pool.lock().unwrap().allocate(), None);

        let mut reconstructed = IdPool::new(20_u8, 28);
        for id in allocated {
            reconstructed.occupy(id).unwrap();
        }
        assert_eq!(reconstructed.allocate(), None);
        assert!(reconstructed.occupy(20).is_err());
        reconstructed.free(23);
        assert_eq!(reconstructed.allocate(), Some(23));
    }

    #[test]
    fn maximum_numeric_boundary_does_not_wrap() {
        let mut pool = IdPool::new(u8::MAX, u8::MAX);
        assert_eq!(pool.allocate(), None);
        assert!(pool.occupy(u8::MAX).is_err());
    }
}
