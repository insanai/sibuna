//! Off-path TCP health checks. Each lane owns its probe timers and counters.
//! Routing reads a single atomic status. A reload retains the status of an unchanged probe.

use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sibuna_json::ObjectReader;

use crate::config::{Config, duration, field, invalid, number, required};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Spec {
    timeout: Duration,
    interval: Duration,
    rise: usize,
    fall: usize,
}

impl Spec {
    pub fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        if required(&mut r, "kind")? != "tcp" {
            return Err(invalid("health_check.kind must be tcp"));
        }
        let time = |r: &mut ObjectReader<'_, '_>, field_name, default| {
            field(r.take_str(field_name))?.map_or(Ok(default), |s| {
                duration(s).ok_or_else(|| invalid(r.field_path(field_name)))
            })
        };
        let timeout = time(&mut r, "timeout", Duration::from_millis(500))?;
        let interval = time(&mut r, "interval", Duration::from_secs(2))?;
        if timeout > Duration::from_secs(2) || interval < Duration::from_millis(100) {
            return Err(invalid("health probes require timeout <= 2s and interval >= 100ms"));
        }
        let rise = number(&mut r, "rise", 2, 255)?;
        let fall = number(&mut r, "fall", 3, 255)?;
        field(r.finish())?;
        Ok(Self { timeout, interval, rise, fall })
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
        let mut next = BTreeMap::new();
        for pool in config.pools.values_mut() {
            if let Some(spec) = pool.health {
                for server in &mut pool.servers {
                    let key = (server.addr, spec);
                    let status = next
                        .entry(key)
                        .or_insert_with(|| self.current.get(&key).cloned().unwrap_or_default());
                    server.healthy = Some(Arc::clone(status));
                }
            }
        }
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
                .map(|(key, status)| (*key, Arc::clone(status)))
                .collect();
            *lane.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(jobs));
        }
        self.current = next;
        Ok(())
    }
}

impl Drop for Checks {
    fn drop(&mut self) {
        for lane in &self.lanes {
            *lane.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }
    }
}

#[derive(Default)]
struct Probe {
    next: Option<Instant>,
    passes: usize,
    failures: usize,
}

fn probe(lane: Published) {
    let mut states = BTreeMap::new();
    let mut previous = Arc::<Schedule>::default();
    loop {
        let Some(jobs) = lane.lock().unwrap_or_else(PoisonError::into_inner).clone() else {
            break;
        };
        if !Arc::ptr_eq(&previous, &jobs) {
            states.clear();
            previous = Arc::clone(&jobs);
        }
        for &((addr, spec), ref healthy) in jobs.iter() {
            let state: &mut Probe = states.entry((addr, spec)).or_default();
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
            if TcpStream::connect_timeout(&addr, spec.timeout).is_ok() {
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
