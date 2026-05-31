// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! TPM 2.0 constants and command codes

/// TPM 2.0 Command Codes (TPM_CC)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TpmCc {
    NvDefineSpace = 0x0000012A,
    NvUndefineSpace = 0x00000122,
    NvRead = 0x0000014E,
    NvWrite = 0x00000137,
    NvReadPublic = 0x00000169,
    PcrRead = 0x0000017E,
    PcrExtend = 0x00000182,
    GetRandom = 0x0000017B,
    CreatePrimary = 0x00000131,
    Create = 0x00000153,
    Load = 0x00000157,
    Unseal = 0x0000015E,
    Quote = 0x00000158,
    StartAuthSession = 0x00000176,
    PolicyPcr = 0x0000017F,
    PolicyGetDigest = 0x00000189,
    FlushContext = 0x00000165,
    EvictControl = 0x00000120,
    ReadPublic = 0x00000173,
    GetCapability = 0x0000017A,
}

impl TpmCc {
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

/// TPM 2.0 Response Codes (TPM_RC)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TpmRc {
    Success = 0x00000000,
    // Format 0 errors
    Initialize = 0x00000100,
    Failure = 0x00000101,
    // Format 1 errors (parameter errors)
    Value = 0x00000184,
    Handle = 0x0000008B,
    // NV errors
    NvDefined = 0x0000014C,
    NvNotDefined = 0x0000014B,
    NvLocked = 0x00000148,
    NvRange = 0x00000146,
    // Auth errors
    AuthFail = 0x0000098E,
    PolicyFail = 0x0000099D,
    // PCR errors
    Locality = 0x00000107,
}

impl TpmRc {
    pub fn from_u32(code: u32) -> Self {
        match code {
            0x00000000 => TpmRc::Success,
            0x00000100 => TpmRc::Initialize,
            0x00000101 => TpmRc::Failure,
            0x00000184 => TpmRc::Value,
            0x0000008B => TpmRc::Handle,
            0x0000014C => TpmRc::NvDefined,
            0x0000014B => TpmRc::NvNotDefined,
            0x00000148 => TpmRc::NvLocked,
            0x00000146 => TpmRc::NvRange,
            0x0000098E => TpmRc::AuthFail,
            0x0000099D => TpmRc::PolicyFail,
            0x00000107 => TpmRc::Locality,
            _ => TpmRc::Failure, // Unknown error
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, TpmRc::Success)
    }
}

/// TPM 2.0 Algorithm IDs (TPM_ALG_ID)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TpmAlgId {
    Null = 0x0010,
    Sha1 = 0x0004,
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
    Rsa = 0x0001,
    Ecc = 0x0023,
    Aes = 0x0006,
    Cfb = 0x0043,
    RsaSsa = 0x0014,
    RsaPss = 0x0016,
    EcDsa = 0x0018,
    KeyedHash = 0x0008,
    SymCipher = 0x0025,
}

impl TpmAlgId {
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0010 => Some(TpmAlgId::Null),
            0x0004 => Some(TpmAlgId::Sha1),
            0x000B => Some(TpmAlgId::Sha256),
            0x000C => Some(TpmAlgId::Sha384),
            0x000D => Some(TpmAlgId::Sha512),
            0x0001 => Some(TpmAlgId::Rsa),
            0x0023 => Some(TpmAlgId::Ecc),
            0x0006 => Some(TpmAlgId::Aes),
            0x0043 => Some(TpmAlgId::Cfb),
            0x0014 => Some(TpmAlgId::RsaSsa),
            0x0016 => Some(TpmAlgId::RsaPss),
            0x0018 => Some(TpmAlgId::EcDsa),
            0x0008 => Some(TpmAlgId::KeyedHash),
            0x0025 => Some(TpmAlgId::SymCipher),
            _ => None,
        }
    }

    pub fn digest_size(self) -> usize {
        match self {
            TpmAlgId::Sha1 => 20,
            TpmAlgId::Sha256 => 32,
            TpmAlgId::Sha384 => 48,
            TpmAlgId::Sha512 => 64,
            _ => 0,
        }
    }
}

/// TPM 2.0 Handle Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TpmHt {
    Pcr = 0x00,
    NvIndex = 0x01,
    HmacSession = 0x02,
    PolicySession = 0x03,
    Permanent = 0x40,
    Transient = 0x80,
    Persistent = 0x81,
}

/// TPM 2.0 Permanent Handles
pub mod tpm_rh {
    pub const OWNER: u32 = 0x40000001;
    pub const NULL: u32 = 0x40000007;
    pub const ENDORSEMENT: u32 = 0x4000000B;
    pub const PLATFORM: u32 = 0x4000000C;
    pub const PW: u32 = 0x40000009; // Password authorization
}

/// TPM 2.0 Session Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TpmSe {
    Hmac = 0x00,
    Policy = 0x01,
    Trial = 0x03,
}

/// TPM 2.0 Startup Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TpmSu {
    Clear = 0x0000,
    State = 0x0001,
}

/// TPM 2.0 Capability Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TpmCap {
    Handles = 0x00000001,
    Commands = 0x00000002,
    PpCommands = 0x00000003,
    AuditCommands = 0x00000004,
    Pcrs = 0x00000005,
    TpmProperties = 0x00000006,
    PcrProperties = 0x00000007,
    EccCurves = 0x00000008,
    AuthPolicies = 0x00000009,
}

/// TPM 2.0 Object Attributes
#[derive(Debug, Clone, Copy, Default)]
pub struct TpmaObject(pub u32);

impl TpmaObject {
    pub const FIXED_TPM: u32 = 1 << 1;
    pub const ST_CLEAR: u32 = 1 << 2;
    pub const FIXED_PARENT: u32 = 1 << 4;
    pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    pub const USER_WITH_AUTH: u32 = 1 << 6;
    pub const ADMIN_WITH_POLICY: u32 = 1 << 7;
    pub const NO_DA: u32 = 1 << 10;
    pub const ENCRYPTED_DUPLICATION: u32 = 1 << 11;
    pub const RESTRICTED: u32 = 1 << 16;
    pub const DECRYPT: u32 = 1 << 17;
    pub const SIGN_ENCRYPT: u32 = 1 << 18;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with_fixed_tpm(mut self) -> Self {
        self.0 |= Self::FIXED_TPM;
        self
    }

    pub fn with_fixed_parent(mut self) -> Self {
        self.0 |= Self::FIXED_PARENT;
        self
    }

    pub fn with_sensitive_data_origin(mut self) -> Self {
        self.0 |= Self::SENSITIVE_DATA_ORIGIN;
        self
    }

    pub fn with_user_with_auth(mut self) -> Self {
        self.0 |= Self::USER_WITH_AUTH;
        self
    }

    pub fn with_admin_with_policy(mut self) -> Self {
        self.0 |= Self::ADMIN_WITH_POLICY;
        self
    }

    pub fn with_restricted(mut self) -> Self {
        self.0 |= Self::RESTRICTED;
        self
    }

    pub fn with_decrypt(mut self) -> Self {
        self.0 |= Self::DECRYPT;
        self
    }

    pub fn with_sign_encrypt(mut self) -> Self {
        self.0 |= Self::SIGN_ENCRYPT;
        self
    }
}

/// TPM 2.0 NV Attributes
#[derive(Debug, Clone, Copy, Default)]
pub struct TpmaNv(pub u32);

impl TpmaNv {
    pub const PP_WRITE: u32 = 1 << 0;
    pub const OWNER_WRITE: u32 = 1 << 1;
    pub const AUTH_WRITE: u32 = 1 << 2;
    pub const POLICY_WRITE: u32 = 1 << 3;
    pub const PP_READ: u32 = 1 << 16;
    pub const OWNER_READ: u32 = 1 << 17;
    pub const AUTH_READ: u32 = 1 << 18;
    pub const POLICY_READ: u32 = 1 << 19;
    pub const NO_DA: u32 = 1 << 25;
    pub const ORDERLY: u32 = 1 << 26;
    pub const CLEAR_STCLEAR: u32 = 1 << 27;
    pub const READ_LOCKED: u32 = 1 << 28;
    pub const WRITTEN: u32 = 1 << 29;
    pub const PLATFORM_CREATE: u32 = 1 << 30;
    pub const READ_STCLEAR: u32 = 1 << 31;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with_owner_write(mut self) -> Self {
        self.0 |= Self::OWNER_WRITE;
        self
    }

    pub fn with_owner_read(mut self) -> Self {
        self.0 |= Self::OWNER_READ;
        self
    }

    pub fn with_auth_write(mut self) -> Self {
        self.0 |= Self::AUTH_WRITE;
        self
    }

    pub fn with_auth_read(mut self) -> Self {
        self.0 |= Self::AUTH_READ;
        self
    }
}

/// TPM 2.0 Session Attributes
#[derive(Debug, Clone, Copy, Default)]
pub struct TpmaSa(pub u8);

impl TpmaSa {
    pub const CONTINUE_SESSION: u8 = 1 << 0;
    pub const AUDIT_EXCLUSIVE: u8 = 1 << 1;
    pub const AUDIT_RESET: u8 = 1 << 2;
    pub const DECRYPT: u8 = 1 << 5;
    pub const ENCRYPT: u8 = 1 << 6;
    pub const AUDIT: u8 = 1 << 7;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with_continue_session(mut self) -> Self {
        self.0 |= Self::CONTINUE_SESSION;
        self
    }
}

/// TPM command header tag
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TpmSt {
    NoSessions = 0x8001,
    Sessions = 0x8002,
    RspCommand = 0x00C4,
}

impl TpmSt {
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x8001 => Some(TpmSt::NoSessions),
            0x8002 => Some(TpmSt::Sessions),
            0x00C4 => Some(TpmSt::RspCommand),
            _ => None,
        }
    }
}

/// ECC Curve IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TpmEccCurve {
    None = 0x0000,
    NistP256 = 0x0003,
    NistP384 = 0x0004,
    NistP521 = 0x0005,
}

impl TpmEccCurve {
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// RSA Key Bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RsaKeyBits {
    Rsa1024 = 1024,
    Rsa2048 = 2048,
    Rsa3072 = 3072,
    Rsa4096 = 4096,
}

impl RsaKeyBits {
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}
