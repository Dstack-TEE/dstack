// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use std::ops::Deref;

use scale::{Decode, Input};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VecOf<I, T, const MAX_LEN: usize = 65536> {
    len: I,
    inner: Vec<T>,
}

impl<I: Default, T, const MAX_LEN: usize> Default for VecOf<I, T, MAX_LEN> {
    fn default() -> Self {
        Self {
            len: I::default(),
            inner: Vec::default(),
        }
    }
}

impl<I: Decode + Into<u32> + Copy, T: Decode, const MAX_LEN: usize> Decode
    for VecOf<I, T, MAX_LEN>
{
    fn decode<In: Input>(input: &mut In) -> Result<Self, scale::Error> {
        let decoded_len = I::decode(input)?;
        let len = decoded_len.into() as usize;
        if len > MAX_LEN {
            return Err("VecOf length exceeds upper bound".into());
        }
        let mut inner = Vec::with_capacity(len.min(1024));
        for _ in 0..len {
            inner.push(T::decode(input)?);
        }
        Ok(Self {
            len: decoded_len,
            inner,
        })
    }
}

impl<I, T, const MAX_LEN: usize> VecOf<I, T, MAX_LEN> {
    pub fn into_inner(self) -> Vec<T> {
        self.inner
    }

    pub fn length(&self) -> I
    where
        I: Clone,
    {
        self.len.clone()
    }
}

impl<I, T, const MAX_LEN: usize> Deref for VecOf<I, T, MAX_LEN> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<I, T, const MAX_LEN: usize> From<(I, Vec<T>)> for VecOf<I, T, MAX_LEN> {
    fn from((len, vec): (I, Vec<T>)) -> Self {
        Self { len, inner: vec }
    }
}

impl<I, T, const MAX_LEN: usize> AsRef<[T]> for VecOf<I, T, MAX_LEN> {
    fn as_ref(&self) -> &[T] {
        &self.inner
    }
}

impl<I, T, const MAX_LEN: usize> From<VecOf<I, T, MAX_LEN>> for Vec<T> {
    fn from(value: VecOf<I, T, MAX_LEN>) -> Self {
        value.inner
    }
}
