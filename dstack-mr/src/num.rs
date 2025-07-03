use anyhow::{Context, Result};

pub(crate) trait Num {
    fn read_le(data: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

impl Num for u16 {
    fn read_le(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        Some(u16::from_le_bytes([data[0], data[1]]))
    }
}

impl Num for u32 {
    fn read_le(data: &[u8]) -> Option<Self> {
        let bytes = data.get(0..4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }
}

pub(crate) fn read_le<T: Num>(data: &[u8], index: usize, name: &str) -> Result<T> {
    let data = &data
        .get(index..)
        .with_context(|| format!("Missing {name}"))?;
    T::read_le(data).with_context(|| format!("Invalid {name}"))
}
