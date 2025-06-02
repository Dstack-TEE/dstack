use parcelona::parser_combinators::{Msg, PErr};
use parcelona::u8::*;
use tracing::trace;

pub fn extract_sni(b: &[u8]) -> Option<&[u8]> {
    extract_sni_inner(b).ok().map(|r| r.1)
}

fn extract_sni_inner(b: &[u8]) -> Result<(usize, &[u8]), PErr<u8>> {
    const HANDSHAKE_TYPE_CLIENT_HELLO: usize = 1;
    const EXTENSION_TYPE_SNI: usize = 0;
    const NAME_TYPE_HOST_NAME: usize = 0;

    let origin_len = b.len();
    if origin_len < 10 {
        return Err(PErr::new(b));
    }

    let b = &b[5..];
    // Handshake message type.
    let (b, c) = take_len_be_u8(b)?;
    if c != HANDSHAKE_TYPE_CLIENT_HELLO {
        let err = PErr::new(b).user_msg_push(Msg::Str("HANDSHAKE_TYPE_CLIENT_HELLO error"));
        return Err(err);
    }

    // Handshake message length.
    let (b, c) = take_len_be_u24(b)?;
    trace!("1. message len {:?}", c);

    // ProtocolVersion (2 bytes) & random (32 bytes).
    let (b, _) = take_record(b, 34)?;

    // Session ID (u8-length vec), cipher suites (u16-length vec), compression methods (u8-length vec).
    let (b, _) = take_record_be_u8(b)?;
    let (b, _) = take_record_be_u16(b)?;
    let (b, _) = take_record_be_u8(b)?;

    // Extensions length.
    let (mut b, mut c) = take_len_be_u16(b)?;
    let mut ext_type: usize;
    let mut ext_leng: usize;
    trace!("3. Extensions length {:?}", c);
    loop {
        // Extension type & length.
        (b, ext_type) = take_len_be_u16(b)?;
        (b, ext_leng) = take_len_be_u16(b)?;

        trace!("4. Ext type (0) {:?} len {:?}", ext_type, ext_leng);
        if ext_type != EXTENSION_TYPE_SNI {
            if ext_leng > 0 {
                (b, _) = take_record(b, ext_leng)?;
            }
            continue;
        }
        // ServerNameList length.
        (b, c) = take_len_be_u16(b)?;
        trace!("5. ServerNameListmessag len {:?}", c);
        // ServerNameList.
        let mut sni: &[u8];
        let mut name_type: usize;
        let mut name_leng: usize;
        loop {
            // NameType & length.
            (b, name_type) = take_len_be_u8(b)?;
            (b, name_leng) = take_len_be_u16(b)?;
            (b, sni) = take_record(b, name_leng)?;
            if name_type != NAME_TYPE_HOST_NAME {
                continue;
            }
            let sni_point: usize = origin_len - b.len();
            trace!(
                "[sni] {:?} sni {:?}",
                sni_point,
                String::from_utf8_lossy(sni)
            );
            return Ok((sni_point, sni));
        }
    }
}
