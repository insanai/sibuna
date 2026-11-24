//! The HTTP client towards the certificate authority: one connection per request, with a
//! limit on the time to connect, on the whole exchange and on the size of the response.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{self, HeaderMap};
use hyper::{Method as HttpMethod, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use sibuna_acme::{Error, Method, Request, Response};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// The longest wait for a TCP connection and a TLS handshake.
const CONNECT: Duration = Duration::from_secs(10);
/// The longest wait for one request and its response.
const EXCHANGE: Duration = Duration::from_secs(30);
/// The largest response body, the bound of the order machine.
const MAX_BODY: usize = 128 * 1024;
/// The longest header value we keep.
const MAX_HEADER: usize = 2048;

/// Sends the requests of an order.
pub(super) struct Client {
    tls: TlsConnector,
}

fn unreachable(url: &str, what: impl std::fmt::Display) -> Error {
    Error::unreachable(format!("{url}: {what}."))
}

/// A header value as text, when it is short and printable.
fn text(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    (value.len() <= MAX_HEADER).then(|| value.to_owned())
}

impl Client {
    /// Loads the trust roots: the PEM file `ca_file`, or the system store. Fails with
    /// `ACME002` when no root can be loaded.
    pub fn load(ca_file: Option<&str>) -> Result<Self, Error> {
        let trust = match ca_file {
            Some(path) => sibuna_tls::Trust::from_ca_file(path),
            None => sibuna_tls::Trust::default(),
        };
        let connector = sibuna_tls::Connector::load(&trust).map_err(|error| {
            let source = ca_file.unwrap_or("the system trust store");
            Error::unreachable(format!(
                "The trust roots in {source} could not be loaded: {error}."
            ))
        })?;
        Ok(Self { tls: TlsConnector::from(connector.client_config()) })
    }

    /// Sends one request and reads the response, within 30 seconds.
    pub async fn send(&self, request: &Request) -> Result<Response, Error> {
        let url = request.url.as_str();
        match timeout(EXCHANGE, self.exchange(request)).await {
            Ok(result) => result,
            Err(_) => Err(unreachable(url, "the authority did not answer within 30 seconds")),
        }
    }

    async fn exchange(&self, request: &Request) -> Result<Response, Error> {
        let url = request.url.as_str();
        let uri: Uri = url.parse().map_err(|_| unreachable(url, "the URL is malformed"))?;
        let host = uri.host().ok_or_else(|| unreachable(url, "the URL has no host"))?;
        let secure = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
        let connect = TcpStream::connect((host.trim_matches(['[', ']']), port));
        let tcp = match timeout(CONNECT, connect).await {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(error)) => return Err(unreachable(url, error)),
            Err(_) => return Err(unreachable(url, "no connection within 10 seconds")),
        };
        let _ = tcp.set_nodelay(true);
        if !secure {
            return self.converse(TokioIo::new(tcp), request, &uri).await;
        }
        let name = ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
            .map_err(|_| unreachable(url, "the host is no server name"))?;
        match timeout(CONNECT, self.tls.connect(name, tcp)).await {
            Ok(Ok(tls)) => self.converse(TokioIo::new(tls), request, &uri).await,
            Ok(Err(error)) => Err(unreachable(url, format!("the TLS handshake failed: {error}"))),
            Err(_) => Err(unreachable(url, "no TLS handshake within 10 seconds")),
        }
    }

    /// Speaks HTTP/1.1 on an open connection.
    async fn converse<I>(&self, io: I, request: &Request, uri: &Uri) -> Result<Response, Error>
    where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let url = request.url.as_str();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|error| unreachable(url, error))?;
        let connection = tokio::spawn(connection);
        let method = match request.method {
            Method::Get => HttpMethod::GET,
            Method::Head => HttpMethod::HEAD,
            Method::Post => HttpMethod::POST,
        };
        let target = uri.path_and_query().map_or("/", |target| target.as_str());
        let authority = uri.authority().map_or("", |authority| authority.as_str());
        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(target)
            .header(header::HOST, authority)
            .header(header::USER_AGENT, concat!("sibuna/", env!("CARGO_PKG_VERSION")))
            .header(header::CONNECTION, "close");
        if request.method == Method::Post {
            builder = builder.header(header::CONTENT_TYPE, "application/jose+json");
        }
        let outgoing = builder
            .body(Full::new(Bytes::from(request.body.clone())))
            .map_err(|error| unreachable(url, error))?;
        let answer = sender.send_request(outgoing).await.map_err(|e| unreachable(url, e))?;
        let (head, body) = answer.into_parts();
        let body = Limited::new(body, MAX_BODY)
            .collect()
            .await
            .map_err(|error| {
                Error::unexpected(format!("{url}: the response is unusable: {error}."))
            })?
            .to_bytes();
        connection.abort();
        Ok(Response {
            status: head.status.as_u16(),
            location: text(&head.headers, header::LOCATION),
            nonce: text(&head.headers, header::HeaderName::from_static("replay-nonce")),
            retry_after: text(&head.headers, header::RETRY_AFTER)
                .and_then(|seconds| seconds.trim().parse().ok()),
            body: body.to_vec(),
        })
    }
}
