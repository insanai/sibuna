//! The invariant catalogue of SID 0013: one test per invariant, each on SQLite and, when
//! `SIBUNA_TEST_DATABASE_URL` is set, on PostgreSQL. A subsystem adds its tests as a module
//! of its own below.

#[path = "../common/mod.rs"]
mod common;

mod access;
mod accounts;
mod audit;
mod deliveries;
mod events;
mod feed;
mod geoip;
mod ja4;
mod kiosk;
mod leases;
mod nodes;
mod notifications;
mod observations;
mod pages;
mod policy;
mod race;
mod rankings;
mod reputation;
mod retention;
mod revision;
mod rule_hits;
mod security;
mod settings;
mod sidecars;
mod tokens;
