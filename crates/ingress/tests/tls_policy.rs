//! The TLS policy of a listener: the version floor and client certificates.
#![allow(clippy::unwrap_used)]

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sibuna_ingress::{Handler, Identity, Ingress, Limits};
use sibuna_lb::{Config, Edge, TlsOptions, TlsVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn server_file(name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join("../tls/tests/data").join(name).to_str().unwrap().to_owned()
}

fn client_file(name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join("tests/data").join(name).to_str().unwrap().to_owned()
}

/// A client configuration for the given TLS versions, with or without a certificate.
fn client(
    versions: &[&'static rustls::SupportedProtocolVersion],
    certified: bool,
) -> rustls::ClientConfig {
    let mut trust = rustls::RootCertStore::empty();
    trust.add(CertificateDer::from_pem_file(server_file("ca.pem")).unwrap()).unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_root_certificates(trust);
    let mut config = if certified {
        let chain = vec![CertificateDer::from_pem_file(client_file("client.pem")).unwrap()];
        let key = PrivateKeyDer::from_pem_file(client_file("client.key")).unwrap();
        builder.with_client_auth_cert(chain, key).unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Whether a client with `config` gets a request through the listener to the firewall.
async fn reaches(vip: SocketAddr, config: rustls::ClientConfig, handoffs: &AtomicUsize) -> bool {
    let before = handoffs.load(Ordering::SeqCst);
    let tcp = tokio::net::TcpStream::connect(vip).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let Ok(mut tls) = connector.connect("localhost".try_into().unwrap(), tcp).await else {
        return false;
    };
    // A refused certificate shows on the first exchange under TLS 1.3.
    let _ = tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    let mut byte = [0; 1];
    let _ = tokio::time::timeout(Duration::from_millis(300), tls.read(&mut byte)).await;
    handoffs.load(Ordering::SeqCst) > before
}

/// Runs `check` against a listener with the given policy.
fn with_listener<F>(policy: TlsOptions, check: fn(SocketAddr, Arc<AtomicUsize>) -> F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let topology = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],
        "default_backend":"pool"}}}},"backends":{{"pool":{{"mode":"http",
        "servers":[{{"name":"origin","addr":"127.0.0.1:8080"}}]}}}}}}"#
    );
    let mut edge = Edge::bind(Config::parse(topology.as_bytes()).unwrap()).unwrap();
    let tls = TlsOptions {
        cert_file: Some(server_file("localhost.pem")),
        key_file: Some(server_file("localhost.key")),
        ..policy
    };
    let handoffs = Arc::new(AtomicUsize::new(0));
    let counted = handoffs.clone();
    let handler: Handler = Arc::new(move |_, _, _, _| {
        counted.fetch_add(1, Ordering::SeqCst);
    });
    let identity = Identity::load(&tls).unwrap();
    let identities = [(vip, identity)].into();
    let ingress =
        Ingress::start(identities, edge.flow_budget(), handler, None, Limits::default()).unwrap();
    let runner = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(8), check(vip, handoffs)).await.unwrap();
        });
    });
    while !runner.is_finished() {
        edge.step().unwrap();
        for (bind, stream, permit) in edge.accepted_http() {
            ingress.accept(bind, stream, permit);
        }
    }
    runner.join().unwrap();
}

const BOTH: &[&rustls::SupportedProtocolVersion] = rustls::ALL_VERSIONS;
const OLD: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

#[test]
fn a_required_client_certificate_admits_only_clients_that_present_one() {
    let policy =
        TlsOptions { client_ca: Some(client_file("client-ca.pem")), ..TlsOptions::default() };
    with_listener(policy, |vip, handoffs| async move {
        assert!(reaches(vip, client(BOTH, true), &handoffs).await);
        assert!(!reaches(vip, client(BOTH, false), &handoffs).await);
        assert!(reaches(vip, client(OLD, true), &handoffs).await);
        assert!(!reaches(vip, client(OLD, false), &handoffs).await);
    });
}

#[test]
fn an_optional_client_certificate_admits_both() {
    let policy = TlsOptions {
        client_ca: Some(client_file("client-ca.pem")),
        client_optional: true,
        ..TlsOptions::default()
    };
    with_listener(policy, |vip, handoffs| async move {
        assert!(reaches(vip, client(BOTH, true), &handoffs).await);
        assert!(reaches(vip, client(BOTH, false), &handoffs).await);
    });
}

#[test]
fn a_version_floor_of_tls13_refuses_tls12() {
    let policy = TlsOptions { min_version: TlsVersion::V13, ..TlsOptions::default() };
    with_listener(policy, |vip, handoffs| async move {
        assert!(reaches(vip, client(BOTH, false), &handoffs).await);
        assert!(!reaches(vip, client(OLD, false), &handoffs).await);
    });
}

#[test]
fn the_default_policy_accepts_tls12_and_needs_no_client_certificate() {
    with_listener(TlsOptions::default(), |vip, handoffs| async move {
        assert!(reaches(vip, client(OLD, false), &handoffs).await);
    });
}

#[test]
fn a_client_ca_file_without_a_certificate_is_refused_at_load() {
    let tls = TlsOptions {
        cert_file: Some(server_file("localhost.pem")),
        key_file: Some(server_file("localhost.key")),
        client_ca: Some(server_file("localhost.key")),
        ..TlsOptions::default()
    };
    let error = Identity::load(&tls).err().unwrap().to_string();
    assert!(error.contains("localhost.key"), "{error}");
}
