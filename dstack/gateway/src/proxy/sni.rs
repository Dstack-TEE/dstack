// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use parcelona::parser_combinators::{Msg, PErr};
use parcelona::u8::*;
use tracing::trace;

pub fn extract_sni(b: &[u8]) -> Option<&[u8]> {
    extract_sni_inner(b).ok().map(|r| r.1)
}

/// Read a `u8`-length-prefixed record.
///
/// `parcelona::take_record_be_u8` cannot be used here: its guard is
/// `b.len() < b[0]`, but it then splits `&b[1..]` -- one byte shorter -- at
/// `b[0]`, so a record whose declared length equals the number of bytes
/// *including* the length byte slips past the check and panics inside
/// `split_at_revers`. With `panic = "abort"` that is the whole gateway, so this
/// composes the two correctly-guarded primitives instead. `take_record_be_u16`
/// is already written this way upstream and needs no replacement.
///
/// Reachable from the public TLS port: a 53-byte ClientHello prefix whose
/// session-id length byte is the count of bytes after it plus one is enough.
fn take_record_u8_len(b: &[u8]) -> Result<(&[u8], &[u8]), PErr<'_, u8>> {
    let (b, len) = take_len_be_u8(b)?;
    take_record(b, len)
}

fn extract_sni_inner(b: &[u8]) -> Result<(usize, &[u8]), PErr<'_, u8>> {
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
    let (b, _) = take_record_u8_len(b)?;
    let (b, _) = take_record_be_u16(b)?;
    let (b, _) = take_record_u8_len(b)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello carrying one `host_name` SNI entry.
    fn client_hello(server_name: &[u8]) -> Vec<u8> {
        let mut sni_ext = vec![0x00]; // NameType: host_name
        sni_ext.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(server_name);

        let mut server_name_list = (sni_ext.len() as u16).to_be_bytes().to_vec();
        server_name_list.extend_from_slice(&sni_ext);

        let mut extensions = vec![0x00, 0x00]; // ExtensionType: server_name
        extensions.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name_list);

        let mut body = vec![0x03, 0x03]; // legacy_version
        body.extend_from_slice(&[0x41; 32]); // random
        body.push(0x00); // session_id: empty
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        body.extend_from_slice(&[0x01, 0x00]); // compression_methods: null
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![0x01]; // client_hello
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // u24 length
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01]; // handshake record, TLS 1.0 framing
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_the_server_name_from_a_client_hello() {
        let hello = client_hello(b"app.example.com");
        assert_eq!(extract_sni(&hello), Some(&b"app.example.com"[..]));
    }

    #[test]
    fn a_truncated_client_hello_yields_no_name_rather_than_a_wrong_one() {
        let hello = client_hello(b"app.example.com");
        for len in 0..hello.len() {
            assert_eq!(extract_sni(&hello[..len]), None, "prefix of {len} bytes");
        }
    }

    /// A `u8`-length-prefixed record may declare a length that covers its own
    /// length byte. `parcelona::take_record_be_u8` admits exactly that case and
    /// then indexes past the end of the slice; the process builds with
    /// `panic = "abort"`, so on the public TLS port one short write ends every
    /// connection the gateway is currently relaying, not just this one.
    #[test]
    fn a_session_id_length_covering_its_own_length_byte_does_not_abort() {
        // 5 record header + 1 handshake type + 3 handshake length + 34
        // version/random puts the session-id length byte at offset 43.
        const SESSION_ID_LEN_OFFSET: usize = 43;
        fn over_declaring_hello(total: usize) -> Vec<u8> {
            let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x00];
            hello.push(0x01);
            hello.extend_from_slice(&[0x00, 0x00, 0x00]);
            hello.extend_from_slice(&[0x00; 34]);
            assert_eq!(hello.len(), SESSION_ID_LEN_OFFSET);
            // Declares one byte more than actually follows it.
            hello.push((total - SESSION_ID_LEN_OFFSET) as u8);
            hello.resize(total, 0);
            hello
        }

        // The minimal reproducer: 53 bytes, session-id length 10, nine to go.
        assert_eq!(extract_sni(&over_declaring_hello(53)), None);
        for total in SESSION_ID_LEN_OFFSET + 2..=SESSION_ID_LEN_OFFSET + 255 {
            // Returning at all is the property; an all-zero tail is a
            // well-formed empty extension list for some of these lengths.
            let _ = extract_sni(&over_declaring_hello(total));
        }
    }

    /// The same shape one level down, where the compression-methods length is
    /// the field that over-declares.
    #[test]
    fn a_compression_methods_length_covering_its_own_length_byte_does_not_abort() {
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x00];
        hello.push(0x01);
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);
        hello.extend_from_slice(&[0x00; 34]);
        hello.push(0x00); // session_id: empty
        hello.extend_from_slice(&[0x00, 0x00]); // cipher_suites: empty
        hello.push(0x04); // compression_methods: declares 4, three bytes follow
        hello.extend_from_slice(&[0x00; 3]);
        assert_eq!(extract_sni(&hello), None);
    }

    /// Every byte of a valid ClientHello, walked through every value, must
    /// leave the extractor returning rather than aborting. Deterministic, so a
    /// failure is reproducible from the printed offset and value alone.
    #[test]
    fn no_single_byte_mutation_of_a_client_hello_aborts_the_extractor() {
        let hello = client_hello(b"app.example.com");
        for offset in 0..hello.len() {
            for value in [0x00u8, 0x01, 0x7f, 0x80, 0xfe, 0xff] {
                let mut mutated = hello.clone();
                mutated[offset] = value;
                // The result is uninteresting; not aborting is the property.
                let _ = extract_sni(&mutated);
            }
            // Truncating after a mutated length byte is the other half of it.
            for value in [0x00u8, 0xff] {
                let mut mutated = hello[..offset].to_vec();
                mutated.push(value);
                let _ = extract_sni(&mutated);
            }
        }
    }
}
