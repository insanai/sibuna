//! Edge-mode startup, reload at batch boundaries and bounded shutdown.

mod http;

use std::fs::File;
use std::io::{self, Read};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sibuna_lb::{Config, Edge};

use crate::signals::{self, Shutdown};

pub(crate) fn command(args: &[String]) -> Option<ExitCode> {
    let path = match args {
        [option, path] if option == "--config-file" => path,
        [check, option, path] if check == "check" && option == "-f" => path,
        _ => return None,
    };
    let result = load(path).and_then(|config| {
        if args[0] == "check" { Ok(()) } else { serve(path.to_owned(), config) }
    });
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "EDGE001: {path}: {error}\nHint: check the edge configuration and listener binds."
            );
            ExitCode::FAILURE
        }
    })
}

struct Revision {
    config: Config,
    http: Option<http::Prepared>,
}

fn load(path: &str) -> io::Result<Revision> {
    let config = topology(path)?;
    let http = http::Prepared::load(&config)?;
    Ok(Revision { config, http })
}
fn topology(path: &str) -> io::Result<Config> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(Config::DOCUMENT_LIMITS.max_input_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if std::path::Path::new(path).extension().is_some_and(|ext| ext == "jlv") {
        #[cfg(feature = "jlv")]
        return sibuna_jlv::parse(path, &bytes);
        #[cfg(not(feature = "jlv"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this build needs the jlv feature for .jlv files",
        ));
    }
    Config::parse(&bytes)
}

fn serve(path: String, revision: Revision) -> io::Result<()> {
    let shutdown = Shutdown::new();
    let pending = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pending);
    signals::install_edge(Arc::clone(&shutdown), move || match load(&path) {
        Ok(next) => *slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(next),
        Err(error) => eprintln!("EDGE002: keeping current routes: {error}"),
    })
    .map_err(io::Error::other)?;
    let Revision { config, http } = revision;
    let mesh = config.mesh().map(start_mesh).transpose()?;
    let mut current = sibuna_lb::Regime::Standalone;
    let mut edge = Edge::bind(config)?;
    let mut http = http.map(|p| http::Http::start(p, &edge)).transpose()?;
    eprintln!("Sibuna edge listeners ready");
    while !shutdown.is_requested() {
        let next = pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(next) = next {
            match reload(&mut edge, http.as_mut(), next) {
                Ok(()) => eprintln!("Sibuna edge routes reloaded"),
                Err(error) => eprintln!("EDGE002: keeping current routes: {error}"),
            }
        }
        if let Some(mesh) = &mesh {
            let regime = mesh.regime();
            if current != regime {
                edge.set_regime(regime);
                eprintln!("Sibuna edge routing regime: {regime:?}");
                current = regime;
            }
        }
        step(&mut edge, http.as_ref())?;
    }
    drop(mesh);
    edge.drain();
    if let Some(http) = &http {
        http.drain();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while edge.active() > 0 && Instant::now() < deadline {
        step(&mut edge, http.as_ref())?;
    }
    eprintln!("Sibuna edge stopped: {} forced closes, {} drops", edge.active(), edge.dropped());
    Ok(())
}

fn step(edge: &mut Edge, http: Option<&http::Http>) -> io::Result<()> {
    edge.step()?;
    if let Some(http) = http {
        for (bind, stream, permit) in edge.accepted_http() {
            http.accept(bind, stream, permit);
        }
    }
    Ok(())
}

fn reload(edge: &mut Edge, http: Option<&mut http::Http>, revision: Revision) -> io::Result<()> {
    match (http, revision.http) {
        (None, None) => edge.reload(revision.config),
        (Some(http), Some(prepared)) if http.compatible(&prepared) => {
            edge.reload(revision.config)?;
            http.reload(prepared);
            Ok(())
        }
        _ => Err(io::Error::other(
            "changing HTTP firewall settings or TLS listeners requires a restart",
        )),
    }
}

fn start_mesh(spec: &sibuna_lb::MeshConfig) -> io::Result<sibuna_lb::Mesh> {
    let mut key = [0; 32];
    let mut file = File::open(&spec.key_file)?;
    file.read_exact(&mut key)?;
    if file.read(&mut [0])? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "mesh key must be 32 bytes"));
    }
    let mut boot = [0; 16];
    crate::random::fill(&mut boot)?;
    sibuna_lb::Mesh::start(spec, &key, boot)
}
