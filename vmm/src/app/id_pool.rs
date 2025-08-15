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
        if self.allocated.insert(id) {
            Ok(())
        } else {
            bail!("id already occupied")
        }
    }

    pub fn allocate(&mut self) -> Option<T> {
        let mut id = self.start.clone();
        while let Some(next) = id.next() {
            if next >= self.end {
                return None;
            }
            if !self.allocated.contains(&next) {
                self.allocated.insert(next.clone());
                return Some(next);
            }
            id = next;
        }
        None
    }

    pub fn free(&mut self, id: T) {
        self.allocated.remove(&id);
    }
}
