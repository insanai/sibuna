//! Join the reviewed HTTP firewall, the edge request scheduler and optional TLS transports.

use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, atomic::Ordering};
use std::thread::JoinHandle;

use sibuna_core::{Config, Metrics};
use sibuna_lb::{Edge, FlowPermit, HttpOptions, TlsOptions};
use sibuna_policy::{Engine, loader::Diagnostic};

use crate::connection::Ingress;
use crate::recipe::Recipe;
use crate::server::{Hooks, Options, Server, admit, start_reaper};
use crate::slot::EngineSlot;

/// The policy of `http.surface: "off"`.
const ALLOW_ALL: &[u8] = br#"{"rules":[{"name":"load-balancer","path":"/*","action":"ALLOW"}]}"#;

pub(super) struct Prepared {
    options: HttpOptions,
    seed: Option<sibuna_challenge::Seed>,
    engine: Engine,
    binds: BTreeMap<SocketAddr, Arc<TlsOptions>>,
    #[cfg(feature = "https")]
    identities: BTreeMap<SocketAddr, sibuna_ingress::Identity>,
}

impl Prepared {
    pub fn load(topology: &sibuna_lb::Config) -> io::Result<Option<Self>> {
        let Some(options) = topology.http().cloned() else { return Ok(None) };
        let seed = options.secret_file.as_deref().map(crate::cli::read_seed).transpose()?;
        let config = firewall_config(&options);
        let bytes = match options.policy_file.as_deref() {
            Some(path) => {
                let bytes = crate::cli::read_bounded(path, 256 * 1024 + 1)?;
                if bytes.len() > 256 * 1024 {
                    return Err(io::Error::other("HTTP policy exceeds 256 KiB"));
                }
                Some(bytes)
            }
            // A pure load balancer admits every well-formed request.
            None if !options.firewall => Some(ALLOW_ALL.to_vec()),
            None => None,
        };
        let engine = Recipe::new(&config, bytes)
            .base_engine(&mut Diagnostic::default())
            .map_err(io::Error::other)?;
        let binds = topology.tls();
        #[cfg(not(feature = "https"))]
        if !binds.is_empty() {
            return Err(io::Error::other("TLS termination requires the https feature"));
        }
        #[cfg(feature = "https")]
        let identities = binds
            .iter()
            .map(|(addr, tls)| {
                Ok((*addr, sibuna_ingress::Identity::load(tls).map_err(io::Error::other)?))
            })
            .collect::<io::Result<_>>()?;
        Ok(Some(Self {
            options,
            seed,
            engine,
            binds,
            #[cfg(feature = "https")]
            identities,
        }))
    }
}

/// The firewall configuration of an edge topology. Fields without an edge option keep
/// the daemon's defaults.
fn firewall_config(options: &HttpOptions) -> Config {
    Config {
        waf: options.shield,
        secret_file: options.secret_file.clone(),
        rate_limit: options.rate_limit.unwrap_or(u32::MAX),
        rate_window_seconds: options.rate_window_seconds,
        max_connections: options.max_connections,
        max_connections_per_ip: options.max_connections_per_ip,
        idle_timeout_seconds: options.idle_timeout_seconds,
        websocket_idle_timeout_seconds: options.websocket_idle_timeout_seconds,
        ..Config::default()
    }
}

pub(super) struct Http {
    server: Arc<Server>,
    reaper: Option<JoinHandle<()>>,
    options: HttpOptions,
    binds: BTreeMap<SocketAddr, Arc<TlsOptions>>,
    #[cfg(feature = "https")]
    ingress: Option<sibuna_ingress::Ingress>,
}

impl Http {
    pub fn start(prepared: Prepared, edge: &Edge, secret: Option<&str>) -> io::Result<Self> {
        let mut config = firewall_config(&prepared.options);
        let seed = if let Some(seed) = prepared.seed {
            config.secret_seed = Some(*seed.as_bytes());
            seed
        } else {
            crate::cli::resolve_secret(&mut config, secret)
                .map_err(|()| io::Error::other("cannot load HTTP challenge seed"))?
        };
        let mut server = Server::new(Options {
            config,
            seed,
            slot: Arc::new(EngineSlot::new(prepared.engine)),
            metrics: Arc::new(Metrics::default()),
            hooks: Hooks::default(),
        });
        server.edge_routes = Some(edge.http_routes());
        server.unlimited = prepared.options.rate_limit.is_none();
        let server = Arc::new(server);
        #[cfg(feature = "https")]
        let ingress = if prepared.identities.is_empty() {
            None
        } else {
            let web = server.clone();
            let handler = Arc::new(move |stream, peer, vip| {
                launch(&web, stream, Ingress { peer, vip, secure: true }, None);
            });
            let limits = sibuna_ingress::Limits {
                exchanges: prepared.options.max_connections as usize,
                idle: std::time::Duration::from_secs(u64::from(
                    prepared.options.idle_timeout_seconds.max(60),
                )),
            };
            Some(sibuna_ingress::Ingress::start(
                prepared.identities,
                edge.flow_budget(),
                handler,
                limits,
            )?)
        };
        let reaper = start_reaper(&server)?;
        Ok(Self {
            server,
            reaper,
            options: prepared.options,
            binds: prepared.binds,
            #[cfg(feature = "https")]
            ingress,
        })
    }

    pub fn drain(&self) {
        #[cfg(feature = "https")]
        if let Some(ingress) = &self.ingress {
            ingress.drain();
        }
    }

    pub fn compatible(&self, next: &Prepared) -> bool {
        self.options == next.options
            && self.binds == next.binds
            && next.seed.as_ref().is_none_or(|seed| {
                self.server.config.secret_seed.as_ref() == Some(seed.as_bytes())
            })
    }
    pub fn reload(&mut self, prepared: Prepared) {
        #[cfg(feature = "https")]
        if let Some(ingress) = &mut self.ingress {
            ingress.reload(prepared.identities);
        }
        self.server.slot.publish(prepared.engine);
    }

    pub fn accept(&self, bind: SocketAddr, stream: TcpStream, permit: FlowPermit) {
        #[cfg(feature = "https")]
        if self.binds.contains_key(&bind)
            && let Some(ingress) = &self.ingress
        {
            ingress.accept(bind, stream, permit);
            return;
        }
        let _ = bind;
        let (Ok(peer), Ok(vip)) = (stream.peer_addr(), stream.local_addr()) else { return };
        launch(&self.server, stream, Ingress { peer, vip, secure: false }, Some(permit));
    }
}

fn launch(server: &Arc<Server>, stream: TcpStream, ingress: Ingress, permit: Option<FlowPermit>) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let server_ref = server.clone();
    let task = server.tasks.launch(move || {
        let _permit = permit;
        if server_ref.is_stopping() {
            return;
        }
        let Some(admission) = admit(&server_ref, &stream, ingress.peer.ip()) else { return };
        sibuna_net::connect::set_no_delay(&stream);
        crate::connection::serve_from(&server_ref, &stream, admission, Some(ingress));
    });
    if task.is_err() {
        server.metrics.overloaded.bump();
    }
}

impl Drop for Http {
    fn drop(&mut self) {
        self.server.stopping.store(true, Ordering::Release);
        #[cfg(feature = "https")]
        drop(self.ingress.take());
        self.server.idle.shutdown();
        self.server.pool.shutdown();
        self.server.tasks.join();
        if let Some(reaper) = self.reaper.take() {
            let _ = reaper.join();
        }
        self.server.pool.drain();
    }
}
