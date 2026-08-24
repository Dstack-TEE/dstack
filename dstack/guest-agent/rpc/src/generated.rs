#![allow(async_fn_in_trait)]

pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));

/// The frozen v0 surface, closed at exactly what dstack v0.5.11 shipped.
///
/// Served at `/v0` and, for pre-0.6 clients, at the unversioned paths it has
/// always had. Nothing new goes here.
pub mod v0 {
    include!(concat!(env!("OUT_DIR"), "/dstack_guest.rs"));
}

/// The `dstack.guest.v1` package: the current surface.
///
/// Each version gets its own module because both packages define types with the
/// same names on purpose -- `GpuEvidenceBundle`, and the services themselves --
/// and the two surfaces must stay independently evolvable. A caller names the
/// surface it wants: `dstack_guest_agent_rpc::v0::AppInfo` is the frozen one,
/// `dstack_guest_agent_rpc::v1::InfoResponse` is the current one. Nothing is
/// re-exported at the crate root, so no import can be ambiguous about which
/// contract it speaks.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/dstack.guest.v1.rs"));
}
