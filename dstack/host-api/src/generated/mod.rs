#![allow(async_fn_in_trait)]

pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));

include!(concat!(env!("OUT_DIR"), "/host_api.rs"));
