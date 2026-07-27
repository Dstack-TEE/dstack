use std::{io, pin::Pin, task};

use rustls::internal::msgs::codec::Codec;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::AsyncReadReady;

enum State {
    ReadHeader { header_buf: [u8; 5], offset: usize },
    ReadPayload { msg_size: usize, offset: usize },
    // we encountered EOF while reading, or saw an invalid header and we're just
    // passing reads through without doing any sort of processing now.
    Passthrough,
}

/// This is a wrapper that reads TLS message headers so it knows when to start
/// doing empty reads at the message boundary when "draining" a rustls
/// connection before setting up kTLS for it.
///
/// The short explanation is: rustls might have buffered one or more
/// ApplicationData messages (the last one might even be partial) by the time
/// "connect" / "accept" returns.
///
/// We not only need to pop messages rustls has already deframed (that's done in
/// a drain function elsewhere), but also let rustls finish reading and
/// deframing any partial message it may have already buffered.
///
/// Because this wrapper is trying very hard not to do any error handling, if it
/// encounters anything that doesn't look like a TLS header (unknown type,
/// nonsensical size, unexpected EOF), it'll quite easily fall back to a
/// "passthrough" mode with no internal buffering, letting rustls take care
/// reporting any errors.
pub struct CorkStream<IO> {
    pub io: IO,
    // if true, causes empty reads at the message boudnary
    pub corked: bool,
    state: State,
}

impl<IO> CorkStream<IO> {
    pub fn new(io: IO) -> Self {
        Self {
            io,
            corked: false,
            state: State::ReadHeader {
                header_buf: Default::default(),
                offset: 0,
            },
        }
    }
}

impl<IO> AsyncRead for CorkStream<IO>
where
    IO: AsyncRead,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        let this = unsafe { self.get_unchecked_mut() };
        let mut io = unsafe { Pin::new_unchecked(&mut this.io) };

        let state = &mut this.state;

        loop {
            match state {
                State::ReadHeader { header_buf, offset } => {
                    if *offset == 0 && this.corked {
                        tracing::trace!(
                            "corked, returning empty read (but waking to prevent stalls)"
                        );
                        cx.waker().wake_by_ref();
                        return task::Poll::Ready(Ok(()));
                    }

                    let left = header_buf.len() - *offset;
                    tracing::trace!("reading header, {left}/{} bytes left", header_buf.len());

                    {
                        let mut rest = ReadBuf::new(&mut header_buf[*offset..]);
                        tracing::trace!("reading header: doing i/o");
                        futures_util::ready!(io.as_mut().poll_read(cx, &mut rest)?);
                        tracing::trace!("reading header: io was ready");
                        *offset += rest.filled().len();
                        if rest.filled().is_empty() {
                            // that's an unexpected EOF for sure, but let's have
                            // rustls deal with the error reporting shall we?
                            tracing::trace!(
                                "unexpected EOF: header cut short after {} bytes",
                                *offset
                            );
                            buf.put_slice(&header_buf[..*offset]);
                            *state = State::Passthrough;

                            return task::Poll::Ready(Ok(()));
                        }
                        tracing::trace!("read {} bytes off of header", rest.filled().len());
                    }

                    if *offset == 5 {
                        // TODO: handle cases where buffer has less than 5 bytes
                        // remaining. I (fasterthanlime) bet this never happens in
                        // practice since the rustls deframer uses `copy_within` to
                        // get rid of the part of the buffer it's already decoded.
                        assert!(buf.remaining() >= 5, "you found an edge case in ktls!");
                        buf.put_slice(&header_buf[..]);

                        match decode_header(*header_buf) {
                            Some((typ, version, len)) => {
                                tracing::trace!(
                                    "read header: typ={typ:?}, version={version:?}, len={len}"
                                );
                                *state = State::ReadPayload {
                                    msg_size: len as usize,
                                    offset: 0,
                                };
                            }
                            None => {
                                // we encountered an invalid header, let's bail out
                                tracing::warn!("encountered invalid header, bailing out");
                                *state = State::Passthrough;
                            }
                        }

                        return task::Poll::Ready(Ok(()));
                    } else {
                        // keep trying
                    }
                }
                State::ReadPayload { msg_size, offset } => {
                    let rest = *msg_size - *offset;

                    let just_read = {
                        let mut rest = buf.take(rest);
                        futures_util::ready!(io.as_mut().poll_read(cx, &mut rest)?);

                        tracing::trace!("read {} bytes off of payload", rest.filled().len());
                        *offset += rest.filled().len();

                        if *offset == *msg_size {
                            tracing::trace!("read full payload (all {} bytes)", *offset);
                            *state = State::ReadHeader {
                                header_buf: Default::default(),
                                offset: 0,
                            };
                        }

                        rest.filled().len()
                    };

                    let new_filled = buf.filled().len() + just_read;
                    buf.set_filled(new_filled);

                    return task::Poll::Ready(Ok(()));
                }
                State::Passthrough => {
                    // we encountered EOF while reading, or saw an invalid header and we're just
                    // passing reads through without doing any sort of processing now.
                    return io.poll_read(cx, buf);
                }
            }
        }
    }
}

impl<IO> AsyncReadReady for CorkStream<IO>
where
    IO: AsyncReadReady,
{
    fn poll_read_ready(&self, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.io.poll_read_ready(cx)
    }
}

impl<IO> AsyncWrite for CorkStream<IO>
where
    IO: AsyncWrite,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        let io = unsafe { self.map_unchecked_mut(|s| &mut s.io) };
        io.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        let io = unsafe { self.map_unchecked_mut(|s| &mut s.io) };
        io.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        let io = unsafe { self.map_unchecked_mut(|s| &mut s.io) };
        io.poll_shutdown(cx)
    }
}

fn decode_header(b: [u8; 5]) -> Option<(rustls::ContentType, rustls::ProtocolVersion, u16)> {
    let typ = rustls::ContentType::read_bytes(&b[0..1]).ok()?;
    let version = rustls::ProtocolVersion::read_bytes(&b[1..3]).ok()?;
    // this is dumb but it looks less scary than `.try_into().unwrap()`:
    let len: u16 = u16::from_be_bytes([b[3], b[4]]);
    Some((typ, version, len))
}
