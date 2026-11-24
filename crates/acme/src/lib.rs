//! An ACME client (RFC 8555) that performs no network I/O (SID 0021).
//!
//! The crate turns the responses of a certificate authority into the next request. The
//! caller owns the sockets and the clock.
//!
//! ```text
//!   caller                         sibuna-acme
//!   ------                         -----------
//!   Order::begin ----------------> Action::Send(request)
//!   send it, read the response
//!   order.advance(response) -----> Action::Send | Present | Wait | Done | Failed
//!   publish the challenge answer
//!   order.presented() -----------> Action::Send(request)
//!   sleep
//!   order.resume() --------------> Action::Send(request)
//! ```
//!
//! [`obtain`] runs this loop with three closures, for a caller that may block.
//!
//! The other modules are the pieces an order needs: a P-256 key pair ([`KeyPair`]), the
//! JSON Web Signature ([`jws`]), the certificate request ([`csr`]), reading and writing
//! certificates ([`x509`]), the renewal time and the retry delay ([`schedule`]), and the
//! files of the certificate store ([`store`]).

mod der;
mod error;
mod key;
mod order;
mod time;

pub mod csr;
pub mod jws;
pub mod local;
pub mod pem;
pub mod schedule;
pub mod store;
pub mod x509;

pub use error::Error;
pub use key::{KeyPair, random_serial};
pub use order::{
    Account, Action, Challenge, ChallengeKind, Issued, Method, Order, OrderOptions, Request,
    Response, obtain,
};
pub use time::format_rfc3339;
