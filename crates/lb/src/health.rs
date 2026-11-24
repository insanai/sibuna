//! Off-path TCP and HTTP health checks. Each lane owns its probe timers and counters.
//! Routing reads a single atomic status. A server starts in service, as in HAProxy, and
//! leaves after `fall` consecutive failures. A reload keeps the status of every address.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sibuna_json::ObjectReader;

use crate::config::{Config, duration, field, invalid, number, required};

/// What a probe sends after connecting.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// A completed TCP connect is a pass.
    Tcp,
    /// `GET path` must answer with a status in `lowest..=highest`.
    Http { path: String, host: String, lowest: u16, highest: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Spec {
    kind: Kind,
    timeout: Duration,
    interval: Duration,
    rise: usize,
    fall: usize,
}

impl Spec {
    pub fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let kind = match required(&mut r, "kind")?.as_str() {
            "tcp" => Kind::Tcp,
            "http" => {
                let path = field(r.take_str("path"))?.unwrap_or("/").to_owned();
                let host = field(r.take_str("host"))?.unwrap_or("").to_owned();
                let token = |text: &str| text.bytes().all(|b| b.is_ascii_graphic());
                if !path.starts_with('/') || !token(&path) || !token(&host) {
                    return Err(invalid(format!(
                        "{}: expected an absolute path and a plain host",
                        r.path()
                    )));
                }
                // HAProxy's default: any 2xx or 3xx answer passes.
                let (lowest, highest) = match field(r.take_u64("expect_status"))? {
                    None => (200, 399),
                    Some(code) if (100..=599).contains(&code) => (code as u16, code as u16),
                    Some(_) => return Err(invalid(r.field_path("expect_status"))),
                };
                Kind::Http { path, host, lowest, highest }
            }
            _ => return Err(invalid("health_check.kind must be tcp or http")),
        };
        let time = |r: &mut ObjectReader<'_, '_>, field_name, default| {
            field(r.take_str(field_name))?.map_or(Ok(default), |s| {
                duration(s).ok_or_else(|| invalid(r.field_path(field_name)))
            })
        };
        let timeout = time(&mut r, "timeout", Duration::from_millis(500))?;
        let interval = time(&mut r, "interval", Duration::from_secs(2))?;
        if timeout > Duration::from_secs(10) || interval < Duration::from_millis(100) {
            return Err(invalid("health probes require timeout <= 10s and interval >= 100ms"));
        }
        let rise = number(&mut r, "rise", 2, 255)?;
        let fall = number(&mut r, "fall", 3, 255)?;
        field(r.finish())?;
        Ok(Self { kind, timeout, interval, rise, fall })
    }

    pub fn is_http(&self) -> bool {
        matches!(self.kind, Kind::Http { .. })
    }

    /// Runs one probe against `addr` within the timeout.
    fn passes(&self, addr: SocketAddr) -> bool {
        let deadline = Instant::now() + self.timeout;
        let Ok(mut stream) = TcpStream::connect_timeout(&addr, self.timeout) else {
            return false;
        };
        let Kind::Http { path, host, lowest, highest } = &self.kind else { return true };
        let host = if host.is_empty() { addr.to_string() } else { host.clone() };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sibuna-health\r\n\
             Connection: close\r\n\r\n"
        );
        let left = |deadline: Instant| {
            deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero())
        };
        if stream.set_write_timeout(left(deadline)).is_err()
            || stream.write_all(request.as_bytes()).is_err()
        {
            return false;
        }
        // "HTTP/1.1 200" is twelve bytes. A slow origin may deliver them in pieces.
        let mut head = [0u8; 12];
        let mut filled = 0;
        while filled < head.len() {
            let Some(left) = left(deadline) else { return false };
            if stream.set_read_timeout(Some(left)).is_err() {
                return false;
            }
            match stream.read(&mut head[filled..]) {
                Ok(0) | Err(_) => return false,
                Ok(n) => filled += n,
            }
        }
        let status = std::str::from_utf8(&head[9..]).ok().and_then(|s| s.parse::<u16>().ok());
        head.starts_with(b"HTTP/1.") && status.is_some_and(|s| (*lowest..=*highest).contains(&s))
    }
}

type Schedule = Vec<((SocketAddr, Spec), Arc<AtomicBool>)>;
type Published = Arc<Mutex<Option<Arc<Schedule>>>>;

#[derive(Default)]
pub(crate) struct Checks {
    lanes: Vec<Published>,
    current: BTreeMap<(SocketAddr, Spec), Arc<AtomicBool>>,
}

impl Checks {
    pub fn configure(&mut self, config: &mut Config) -> io::Result<()> {
        let mut next: BTreeMap<(SocketAddr, Spec), Arc<AtomicBool>> = BTreeMap::new();
        for pool in config.pools.values_mut() {
            let Some(spec) = &pool.health else { continue };
            for server in &mut pool.servers {
                // An HTTP probe enters through the pool's protocol adapter, like a request.
                let key = (server.via.unwrap_or(server.addr), spec.clone());
                let status = next.entry(key.clone()).or_insert_with(|| self.inherit(&key));
                server.healthy = Some(Arc::clone(status));
            }
        }
        self.publish(next)
    }

    /// Starts the probe of a server added at run time and returns its status, which
    /// begins in service. An address that is already probed keeps its status.
    pub fn watch(&mut self, addr: SocketAddr, spec: &Spec) -> io::Result<Arc<AtomicBool>> {
        let key = (addr, spec.clone());
        let status = self.inherit(&key);
        let mut next = self.current.clone();
        next.insert(key, Arc::clone(&status));
        self.publish(next)?;
        Ok(status)
    }

    /// Stops the probes that `used` no longer names, after a server was removed.
    pub fn retain(&mut self, used: impl Fn(SocketAddr, &Spec) -> bool) {
        let mut next = self.current.clone();
        next.retain(|(addr, spec), _| used(*addr, spec));
        if next.len() != self.current.len() {
            // The lanes exist, because a probe was running. Publishing cannot fail then.
            let _ = self.publish(next);
        }
    }

    /// Makes `next` the probed set: starts the lanes on first use and deals the jobs.
    fn publish(&mut self, next: BTreeMap<(SocketAddr, Spec), Arc<AtomicBool>>) -> io::Result<()> {
        if !next.is_empty() && self.lanes.is_empty() {
            let mut lanes = Self::default();
            for _ in 0..4 {
                let lane = Arc::new(Mutex::new(Some(Arc::new(Vec::new()))));
                let slot = Arc::clone(&lane);
                std::thread::Builder::new()
                    .name("edge-health".into())
                    .spawn(move || probe(slot))?;
                lanes.lanes.push(lane);
            }
            self.lanes = std::mem::take(&mut lanes.lanes);
        }
        for (index, lane) in self.lanes.iter().enumerate() {
            let jobs = next
                .iter()
                .skip(index)
                .step_by(4)
                .map(|(key, status)| (key.clone(), Arc::clone(status)))
                .collect();
            *lane.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(jobs));
        }
        self.current = next;
        Ok(())
    }
}

impl Checks {
    /// The status a probe starts with: its own from the serving revision, else the last
    /// status of the same address under another specification, else in service.
    fn inherit(&self, key: &(SocketAddr, Spec)) -> Arc<AtomicBool> {
        if let Some(status) = self.current.get(key) {
            return Arc::clone(status);
        }
        let known = self.current.iter().find(|((addr, _), _)| *addr == key.0);
        let up = known.is_none_or(|(_, status)| status.load(Ordering::Relaxed));
        Arc::new(AtomicBool::new(up))
    }
}

impl Drop for Checks {
    fn drop(&mut self) {
        for lane in &self.lanes {
            *lane.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }
    }
}

struct Probe {
    next: Option<Instant>,
    passes: usize,
    failures: usize,
}

fn probe(lane: Published) {
    let mut states: BTreeMap<(SocketAddr, Spec), Probe> = BTreeMap::new();
    let mut previous = Arc::<Schedule>::default();
    loop {
        let Some(jobs) = lane.lock().unwrap_or_else(PoisonError::into_inner).clone() else {
            break;
        };
        if !Arc::ptr_eq(&previous, &jobs) {
            states.retain(|key, _| jobs.iter().any(|(job, _)| job == key));
            previous = Arc::clone(&jobs);
        }
        for (key, healthy) in jobs.iter() {
            let (addr, spec) = key;
            let state = states.entry(key.clone()).or_insert_with(|| {
                // Continue from the published status, so one result cannot flip it.
                let up = healthy.load(Ordering::Relaxed);
                Probe {
                    next: None,
                    passes: if up { spec.rise } else { 0 },
                    failures: if up { 0 } else { spec.fall },
                }
            });
            if state.next.is_some_and(|next| next > Instant::now()) {
                continue;
            }
            // Stop using a retired schedule even if every origin takes the full timeout.
            if lane
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .is_none_or(|latest| !Arc::ptr_eq(latest, &jobs))
            {
                break;
            }
            if spec.passes(*addr) {
                state.passes = (state.passes + 1).min(spec.rise);
                state.failures = 0;
                if state.passes == spec.rise {
                    healthy.store(true, Ordering::Relaxed);
                }
            } else {
                state.failures = (state.failures + 1).min(spec.fall);
                state.passes = 0;
                if state.failures == spec.fall {
                    healthy.store(false, Ordering::Relaxed);
                }
            }
            state.next = Some(Instant::now() + spec.interval);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
