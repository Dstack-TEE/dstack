#![allow(dead_code)]

// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::codecs::VecOf;

pub const TPM_ALG_ERROR: u16 = 0x0;
pub const TPM_ALG_RSA: u16 = 0x1;
pub const TPM_ALG_SHA1: u16 = 0x4;
pub const TPM_ALG_SHA256: u16 = 0xB;
pub const TPM_ALG_SHA384: u16 = 0xC;
pub const TPM_ALG_SHA512: u16 = 0xD;
pub const TPM_ALG_ECDSA: u16 = 0x18;

pub const TCG_PCCLIENT_FORMAT: u8 = 1;
pub const TCG_CANONICAL_FORMAT: u8 = 2;

// digest format: (algo id, hash value)
#[derive(Clone, Debug)]
pub struct TcgDigest {
    pub algo_id: u16,
    pub hash: Vec<u8>,
}

// traits a Tcg IMR should have
pub trait TcgIMR {
    fn max_index() -> u8;
    fn get_index(&self) -> u8;
    fn get_tcg_digest(&self, algo_id: u16) -> TcgDigest;
    fn is_valid_index(index: u8) -> Result<bool, anyhow::Error>;
    fn is_valid_algo(algo_id: u16) -> Result<bool, anyhow::Error>;
}

/***
    TCG EventType defined at
   https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub.pdf
*/
pub const EV_PREBOOT_CERT: u32 = 0x0;
pub const EV_POST_CODE: u32 = 0x1;
pub const EV_UNUSED: u32 = 0x2;
pub const EV_NO_ACTION: u32 = 0x3;
pub const EV_SEPARATOR: u32 = 0x4;
pub const EV_ACTION: u32 = 0x5;
pub const EV_EVENT_TAG: u32 = 0x6;
pub const EV_S_CRTM_CONTENTS: u32 = 0x7;
pub const EV_S_CRTM_VERSION: u32 = 0x8;
pub const EV_CPU_MICROCODE: u32 = 0x9;
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0xa;
pub const EV_TABLE_OF_DEVICES: u32 = 0xb;
pub const EV_COMPACT_HASH: u32 = 0xc;
pub const EV_IPL: u32 = 0xd;
pub const EV_IPL_PARTITION_DATA: u32 = 0xe;
pub const EV_NONHOST_CODE: u32 = 0xf;
pub const EV_NONHOST_CONFIG: u32 = 0x10;
pub const EV_NONHOST_INFO: u32 = 0x11;
pub const EV_OMIT_BOOT_DEVICE_EVENTS: u32 = 0x12;
pub const EV_POST_CODE2: u32 = 0x13;

pub const EV_EFI_EVENT_BASE: u32 = 0x80000000;
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = EV_EFI_EVENT_BASE + 0x1;
pub const EV_EFI_VARIABLE_BOOT: u32 = EV_EFI_EVENT_BASE + 0x2;
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = EV_EFI_EVENT_BASE + 0x3;
pub const EV_EFI_BOOT_SERVICES_DRIVER: u32 = EV_EFI_EVENT_BASE + 0x4;
pub const EV_EFI_RUNTIME_SERVICES_DRIVER: u32 = EV_EFI_EVENT_BASE + 0x5;
pub const EV_EFI_GPT_EVENT: u32 = EV_EFI_EVENT_BASE + 0x6;
pub const EV_EFI_ACTION: u32 = EV_EFI_EVENT_BASE + 0x7;
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB: u32 = EV_EFI_EVENT_BASE + 0x8;
pub const EV_EFI_HANDOFF_TABLES: u32 = EV_EFI_EVENT_BASE + 0x9;
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB2: u32 = EV_EFI_EVENT_BASE + 0xa;
pub const EV_EFI_HANDOFF_TABLES2: u32 = EV_EFI_EVENT_BASE + 0xb;
pub const EV_EFI_VARIABLE_BOOT2: u32 = EV_EFI_EVENT_BASE + 0xc;
pub const EV_EFI_GPT_EVENT2: u32 = EV_EFI_EVENT_BASE + 0xd;
pub const EV_EFI_HCRTM_EVENT: u32 = EV_EFI_EVENT_BASE + 0x10;
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = EV_EFI_EVENT_BASE + 0xe0;
pub const EV_EFI_SPDM_FIRMWARE_BLOB: u32 = EV_EFI_EVENT_BASE + 0xe1;
pub const EV_EFI_SPDM_FIRMWARE_CONFIG: u32 = EV_EFI_EVENT_BASE + 0xe2;
pub const EV_EFI_SPDM_DEVICE_POLICY: u32 = EV_EFI_EVENT_BASE + 0xe3;
pub const EV_EFI_SPDM_DEVICE_AUTHORITY: u32 = EV_EFI_EVENT_BASE + 0xe4;

pub const IMA_MEASUREMENT_EVENT: u32 = 0x14;

/***
    TCG IMR Event struct defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf.
    Definition:
    typedef struct tdTCG_PCR_EVENT2{
        UINT32 pcrIndex;
        UINT32 eventType;
        TPML_DIGEST_VALUES digests;
        UINT32 eventSize;
        BYTE event[eventSize];
    } TCG_PCR_EVENT2;
*/
#[derive(Clone)]
pub struct TcgImrEvent {
    pub imr_index: u32,
    pub event_type: u32,
    pub digests: Vec<TcgDigest>,
    pub event_size: u32,
    pub event: Vec<u8>,
}

impl std::fmt::Debug for TcgImrEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcgImrEvent")
            .field("imr_index", &self.imr_index)
            .field("event_type", &self.event_type)
            .field(
                "digests",
                &self
                    .digests
                    .iter()
                    .map(|d| hex::encode(&d.hash))
                    .collect::<Vec<String>>(),
            )
            .field("event", &hex::encode(&self.event))
            .finish()
    }
}

/***
    TCG TCG_PCClientPCREvent defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf.
    Definition:
    typedef tdTCG_PCClientPCREvent {
        UINT32 pcrIndex;
        UINT32 eventType;
        BYTE digest[20];
        UINT32 eventDataSize;
        BYTE event[eventDataSize]; //This is actually a TCG_EfiSpecIDEventStruct
    } TCG_PCClientPCREvent;
*/
#[derive(Clone)]
pub struct TcgPcClientImrEvent {
    pub imr_index: u32,
    pub event_type: u32,
    pub digest: [u8; 20],
    pub event_size: u32,
    pub event: Vec<u8>,
}

/***
    TCG TCG_EfiSpecIDEventStruct defined at
    https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf.
    Definition:
    typedef struct tdTCG_EfiSpecIdEventStruct {
        BYTE[16] signature;
        UINT32 platformClass;
        UINT8 specVersionMinor;
        UINT8 specVersionMajor;
        UINT8 specErrata;
        UINT8 uintnSize;
        UINT32 numberOfAlgorithms;
        TCG_EfiSpecIdEventAlgorithmSize[numberOfAlgorithms] digestSizes;
        UINT8 vendorInfoSize;
        BYTE[VendorInfoSize] vendorInfo;
    } TCG_EfiSpecIDEventStruct;
*/
#[derive(Clone, scale::Decode, Debug)]
pub struct TcgEfiSpecIdEvent {
    pub signature: [u8; 16],
    pub platform_class: u32,
    pub spec_version_minor: u8,
    pub spec_version_major: u8,
    pub spec_errata: u8,
    pub uintn_ize: u8,
    pub digest_sizes: VecOf<u32, TcgEfiSpecIdEventAlgorithmSize>,
    pub vendor_info: VecOf<u8, u8>,
}

impl Default for TcgEfiSpecIdEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl TcgEfiSpecIdEvent {
    pub fn new() -> TcgEfiSpecIdEvent {
        TcgEfiSpecIdEvent {
            signature: [0; 16],
            platform_class: 0,
            spec_version_minor: 0,
            spec_version_major: 0,
            spec_errata: 0,
            uintn_ize: 0,
            digest_sizes: Default::default(),
            vendor_info: Default::default(),
        }
    }
}

/***
    TCG TCG_EfiSpecIdEventAlgorithmSize defined at
    https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf.
    Definiton:
    typedef struct tdTCG_EfiSpecIdEventAlgorithmSize {
        UINT16 algorithmId;
        UINT16 digestSize;
    } TCG_EfiSpecIdEventAlgorithmSize;
*/
#[derive(Clone, scale::Decode, Debug)]
pub struct TcgEfiSpecIdEventAlgorithmSize {
    pub algo_id: u16,
    pub digest_size: u16,
}
