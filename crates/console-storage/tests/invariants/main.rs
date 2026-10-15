//! The invariant catalogue of SID 0013: one test per invariant, each on SQLite and, when
//! `SIBUNA_TEST_DATABASE_URL` is set, on PostgreSQL. A subsystem adds its tests as a module
//! of its own below.

#[path = "../common/mod.rs"]
mod common;

mod access;
mod accounts;
mod audit;
mod kiosk;
mod race;
mod revision;
mod tokens;
