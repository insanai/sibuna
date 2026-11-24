//! Edge-mode startup, reload at batch boundaries and bounded shutdown.

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

fn load(path: &str) -> io::Result<Config> {
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

fn serve(path: String, config: Config) -> io::Result<()> {
    let shutdown = Shutdown::new();
    let pending = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pending);
    signals::install_edge(Arc::clone(&shutdown), move || match load(&path) {
        Ok(next) => *slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(next),
        Err(error) => eprintln!("EDGE002: keeping current routes: {error}"),
    })
    .map_err(io::Error::other)?;
    let mesh = config.mesh().map(start_mesh).transpose()?;
    let mut current = sibuna_lb::Regime::Standalone;
    let mut edge = Edge::bind(config)?;
    eprintln!("Sibuna edge listeners ready");
    while !shutdown.is_requested() {
        let next = pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(next) = next {
            match edge.reload(next) {
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
        edge.step()?;
    }
    edge.drain();
    let deadline = Instant::now() + Duration::from_secs(5);
    while edge.active() > 0 && Instant::now() < deadline {
        edge.step()?;
    }
    eprintln!("Sibuna edge stopped: {} forced closes, {} drops", edge.active(), edge.dropped());
    Ok(())
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
