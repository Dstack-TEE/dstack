use nix::{
    errno::Errno,
    sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrIn, TlsGetRecordType},
};
use num_enum::FromPrimitive;
use std::{
    io::{self, IoSliceMut},
    os::unix::prelude::AsRawFd,
    pin::Pin,
    task,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::AsyncReadReady;

// A wrapper around `IO` that sends a `close_notify` when shut down or dropped.
pin_project_lite::pin_project! {
    pub struct KtlsStream<IO>
    where
        IO: AsRawFd
    {
        #[pin]
        inner: IO,
        write_closed: bool,
        read_closed: bool,
        drained: Option<(usize, Vec<u8>)>,
    }
}

impl<IO> KtlsStream<IO>
where
    IO: AsRawFd,
{
    pub fn new(inner: IO, drained: Option<Vec<u8>>) -> Self {
        Self {
            inner,
            write_closed: false,
            read_closed: false,
            drained: drained.map(|drained| (0, drained)),
        }
    }

    /// Return the drained data + the original I/O
    pub fn into_raw(self) -> (Option<Vec<u8>>, IO) {
        (self.drained.map(|(_, drained)| drained), self.inner)
    }

    /// Returns a reference to the original I/O
    pub fn get_ref(&self) -> &IO {
        &self.inner
    }

    /// Returns a mut reference to the original I/O
    pub fn get_mut(&mut self) -> &mut IO {
        &mut self.inner
    }
}

#[derive(Debug, PartialEq, Clone, Copy, num_enum::FromPrimitive)]
#[repr(u8)]
enum TlsAlertLevel {
    Warning = 1,
    Fatal = 2,
    #[num_enum(catch_all)]
    Other(u8),
}

#[derive(Debug, PartialEq, Clone, Copy, num_enum::FromPrimitive)]
#[repr(u8)]
enum TlsAlertDescription {
    CloseNotify = 0,
    #[num_enum(catch_all)]
    Other(u8),
}

impl<IO> AsyncRead for KtlsStream<IO>
where
    IO: AsRawFd + AsyncRead + AsyncReadReady,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        tracing::trace!(buf.remaining = %buf.remaining(), "KtlsStream::poll_read");

        if self.read_closed {
            return task::Poll::Ready(Ok(()));
        }

        if buf.remaining() == 0 {
            return task::Poll::Ready(Ok(()));
        }

        let mut this = self.project();

        if let Some((drain_index, drained)) = this.drained.as_mut() {
            let drained = &drained[*drain_index..];
            let len = std::cmp::min(buf.remaining(), drained.len());

            tracing::trace!(%len, "KtlsStream::poll_read, can take from drain");
            buf.put_slice(&drained[..len]);

            *drain_index += len;
            if *drain_index >= drained.len() {
                tracing::trace!("KtlsStream::poll_read, done draining");
                *this.drained = None;
            }
            cx.waker().wake_by_ref();

            tracing::trace!("KtlsStream::poll_read, returning after drain");
            return task::Poll::Ready(Ok(()));
        }

        let read_res = this.inner.as_mut().poll_read(cx, buf);
        if let task::Poll::Ready(Err(e)) = &read_res {
            // 5 is a generic "input/output error", it happens when
            // using poll_read on a kTLS socket that just received
            // a control message
            if let Some(5) = e.raw_os_error() {
                // could be a control message, let's check
                let fd = this.inner.as_raw_fd();

                // XXX: recvmsg wants a `&mut Vec<u8>` so it's able to resize it
                // I guess? Or so there's a clear separation between uninitialized
                // and initialized? We could probably get read of that heap alloc, idk.

                // let mut cmsgspace =
                //     [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<u8>() as _) as _ }];
                let mut cmsgspace = Vec::with_capacity(unsafe {
                    libc::CMSG_SPACE(std::mem::size_of::<u8>() as _) as _
                });

                let mut iov = [IoSliceMut::new(buf.initialize_unfilled())];
                let flags = MsgFlags::empty();

                let r = recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsgspace), flags);
                let r = match r {
                    Ok(r) => r,
                    Err(Errno::EAGAIN) => {
                        unreachable!("expected a control message, got EAGAIN")
                    }
                    Err(e) => {
                        // ok I guess it really failed then
                        tracing::trace!(?e, "recvmsg failed");
                        return Err(e.into()).into();
                    }
                };
                let cmsg = r
                    .cmsgs()?
                    .next()
                    .expect("we should've received exactly one control message");

                let record_type = match cmsg {
                    ControlMessageOwned::TlsGetRecordType(t) => t,
                    _ => panic!("unexpected cmsg type: {cmsg:#?}"),
                };

                match record_type {
                    TlsGetRecordType::ChangeCipherSpec => {
                        panic!("change_cipher_spec isn't supported by the ktls crate")
                    }
                    TlsGetRecordType::Alert => {
                        // the alert level and description are in iovs
                        let iov = r.iovs().next().expect("expected data in iovs");

                        let (level, description) = match iov {
                            [] => {
                                // we have an early return case for that
                                unreachable!();
                            }
                            &[level] => {
                                // https://github.com/facebookincubator/fizz/blob/fff6d9d49d3c554ab66b58822d1e1fe93e8d80f2/fizz/experimental/ktls/AsyncKTLSSocket.cpp#L144
                                //
                                // Since all alerts (even warning-level alerts)
                                // signal the abort of a TLS session, we do not
                                // need to worry about additional application
                                // data.
                                //
                                // If we only have half the alert (because the
                                // user passed a buffer of size 1), just assume
                                // it's a close_notify
                                (
                                    TlsAlertLevel::from_primitive(level),
                                    TlsAlertDescription::CloseNotify,
                                )
                            }
                            &[level, description] => (
                                TlsAlertLevel::from_primitive(level),
                                TlsAlertDescription::from_primitive(description),
                            ),
                            _ => {
                                unreachable!(
                                    "TLS alerts are exactly 2 bytes, your kTLS is misbehaving"
                                );
                            }
                        };

                        match (level, description) {
                            // https://datatracker.ietf.org/doc/html/rfc5246#section-7.2
                            // alerts we should handle are ones with fatal level or a
                            // close_notify
                            (_, TlsAlertDescription::CloseNotify) | (TlsAlertLevel::Fatal, _) => {
                                tracing::trace!(?level, ?description, "got TLS alert");
                                *this.read_closed = true;
                                *this.write_closed = true;
                                if let Err(e) =
                                    crate::ffi::send_close_notify(this.inner.as_raw_fd())
                                {
                                    return Err(e).into();
                                }
                                // the file descriptor will be closed when the stream is dropped,
                                // we already protect against writes-after-close_notify through
                                // the write_closed flag
                                return task::Poll::Ready(Ok(()));
                            }
                            _ => {
                                // we got something we probably can't handle
                            }
                        }
                        return task::Poll::Ready(Ok(()));
                    }
                    TlsGetRecordType::Handshake => {
                        // TODO: this is where we receive TLS 1.3 resumption tickets,
                        // should those be stored anywhere? I'm not even sure what
                        // format they have at this point
                        tracing::trace!(
                            "ignoring handshake message (probably a resumption ticket)"
                        );
                    }
                    TlsGetRecordType::ApplicationData => {
                        unreachable!("received TLS application in recvmsg, this is supposed to happen in the poll_read codepath")
                    }
                    TlsGetRecordType::Unknown(t) => {
                        // just ignore the record?
                        tracing::trace!("received record_type {t:#?}");
                    }
                    _ => {
                        tracing::trace!("received unsupported record type");
                    }
                };

                // FIXME: this is hacky, but can we do better?
                // after we handled (..ignored) the control message, we don't
                // know whether the socket is still ready to be read or not.
                //
                // we could try looping (tricky code structure), but we can't,
                // for example, just call `poll_read`, which might fail not
                // not with EAGAIN/EWOULDBLOCK, but because _another_ control
                // message is available.
                cx.waker().wake_by_ref();
                return task::Poll::Pending;
            }
        }

        read_res
    }
}

impl<IO> AsyncWrite for KtlsStream<IO>
where
    IO: AsRawFd + AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        if self.write_closed {
            return task::Poll::Ready(Ok(0));
        }

        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        let this = self.project();

        if !*this.write_closed {
            // they didn't hang up on us, we're nicely being asked to shut down,
            // let's send a close_notify (and not wait for them to send it back)
            *this.write_closed = true;
            if let Err(e) = crate::ffi::send_close_notify(this.inner.as_raw_fd()) {
                return Err(e).into();
            }
        }

        // this ends up closing the inner file descriptor no matter what
        this.inner.poll_shutdown(cx)
    }
}

impl<IO> AsRawFd for KtlsStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.inner.as_raw_fd()
    }
}
