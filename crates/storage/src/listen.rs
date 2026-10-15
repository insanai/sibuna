//! The PostgreSQL `LISTEN sibuna_policy` session that makes a node tick as soon as another
//! node changes the policy. Polling remains the guarantee; a lost session only delays a
//! node until its next poll.

use std::sync::Arc;

use crate::database::Database;
use crate::worker::Shared;

/// The channel the revision triggers notify.
pub const POLICY_CHANNEL: &str = "sibuna_policy";

/// Starts the listener task on the current runtime when `db` is PostgreSQL; returns its
/// handle so shutdown can stop it before closing the pool.
pub(crate) fn start(db: &Database, shared: Arc<Shared>) -> Option<tokio::task::JoinHandle<()>> {
    match db {
        #[cfg(feature = "postgres")]
        Database::Postgres(pool) => Some(tokio::spawn(postgres::listen(pool.clone(), shared))),
        #[allow(unreachable_patterns)]
        _ => {
            drop(shared);
            None
        }
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use std::sync::Arc;
    use std::time::Duration;

    use std::sync::atomic::Ordering;

    use sqlx::PgPool;
    use sqlx::postgres::PgListener;

    use super::POLICY_CHANNEL;
    use crate::storage::MAX_BACKOFF;
    use crate::worker::Shared;

    const FIRST_RETRY: Duration = Duration::from_millis(100);

    /// Asks the storage thread for a tick now.
    fn request_tick(shared: &Shared) {
        shared.policy_notified.store(true, Ordering::Relaxed);
        shared.wake.notify_one();
    }

    /// Keeps a listening session open, reconnecting with backoff, until the pool closes.
    pub(super) async fn listen(pool: PgPool, shared: Arc<Shared>) {
        let mut delay = FIRST_RETRY;
        loop {
            if let Err(sqlx::Error::PoolClosed) = session(&pool, &shared, &mut delay).await {
                return;
            }
            // Notifications sent while the session was down are lost: tick to catch up.
            request_tick(&shared);
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2).min(MAX_BACKOFF);
        }
    }

    async fn session(
        pool: &PgPool,
        shared: &Shared,
        delay: &mut Duration,
    ) -> Result<(), sqlx::Error> {
        let mut listener = PgListener::connect_with(pool).await?;
        listener.listen(POLICY_CHANNEL).await?;
        *delay = FIRST_RETRY;
        loop {
            // `None` means the connection was lost and is being re-established; whatever
            // was missed meanwhile is caught up by a tick.
            let _notification = listener.try_recv().await?;
            request_tick(shared);
        }
    }
}
