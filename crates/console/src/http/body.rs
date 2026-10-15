//! A bounded JSON request body decoded into a protocol type (Zig's `http.parse`).
//!
//! The caller owns the body buffer and chooses its size per route (SID 0007 bounds every
//! body at 1 MiB; most routes need far less). The listener refuses a declared length larger
//! than the buffer before `100 Continue`. The buffer is wiped after decoding, because bodies
//! carry passwords, codes and secrets.

use sibuna_console_protocol::codec::{self, Decode};
use sibuna_crypto::ct;
use sibuna_serve::Context;

use super::reply::RouteError;

/// The largest body any route reads.
pub const MAX_BODY: usize = 1024 * 1024;

/// Reads the body into `buffer` and decodes it as `T`. The request must declare
/// `Content-Type: application/json` exactly, as in Zig. The bytes of `buffer` that held the
/// body are zeroed before this returns.
///
/// Fails with [`RouteError::BadRequest`] for another content type, a body larger than
/// `buffer`, or a document `T` does not decode (unknown keys and out-of-range values are
/// refused), and with [`RouteError::Serve`] when the connection fails.
pub fn read_json<T: Decode>(
    context: &mut Context<'_>,
    buffer: &mut [u8],
) -> Result<T, RouteError> {
    match context.header(b"Content-Type")? {
        Some(b"application/json") => {}
        _ => return Err(RouteError::BadRequest),
    }
    let length = context.body(buffer)?.len();
    let body = buffer.get_mut(..length).ok_or(RouteError::BadRequest)?;
    let decoded = codec::from_json::<T>(body);
    ct::zeroize(body);
    decoded.map_err(|_| RouteError::BadRequest)
}
