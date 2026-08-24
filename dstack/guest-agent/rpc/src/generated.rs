#![allow(async_fn_in_trait)]

pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));

include!(concat!(env!("OUT_DIR"), "/dstack_guest.rs"));

/// The `dstack.guest.v1` package.
///
/// Kept in its own module because both packages define types with the same
/// names on purpose -- `SignRequest`, `GpuEvidenceBundle` -- and the two
/// surfaces must stay independently evolvable. A caller names the surface it
/// wants: `dstack_guest_agent_rpc::SignRequest` is the frozen unversioned one,
/// `dstack_guest_agent_rpc::v1::SignRequest` is the v1 one.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/dstack.guest.v1.rs"));
}
