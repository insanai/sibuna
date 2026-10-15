//! S38: a policy workflow commits only at the expected revision and leaves it at exactly
//! the expected revision plus one, however often the core triggers moved it meanwhile.

use sibuna_console_storage::{ConsoleStorageError, revision};
use sibuna_storage::Sql;

use crate::common::{for_each_backend, scalar};

const INSERT_RULE: Sql = Sql::both(
    "INSERT INTO policies (id, name, action, created_at, updated_at) \
     VALUES ($1, $1, 'deny', 0, 0)",
);
const REVISION: &str = "SELECT revision FROM policy_revision WHERE id = 1";

#[test]
fn workflow_revision_is_expected_plus_one() {
    for_each_backend("revision_advance", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let start = u64::try_from(scalar(&mut tx, REVISION).await).expect("revision");
        assert!(matches!(
            revision::lock(&mut tx, start + 1).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let lock = revision::lock(&mut tx, start).await.expect("lock");
        assert_eq!(lock.expected(), start);
        for id in ["a", "b", "c"] {
            tx.execute(INSERT_RULE, &[id.into()]).await.expect("rule");
        }
        assert!(scalar(&mut tx, REVISION).await > i64::try_from(start + 1).expect("revision"));
        assert_eq!(revision::advance(&mut tx, lock).await.expect("advance"), start + 1);
        assert_eq!(scalar(&mut tx, REVISION).await, i64::try_from(start + 1).expect("revision"));
        assert_eq!(revision::increment(&mut tx).await.expect("increment"), start + 2);
        tx.commit().await.expect("commit");
    });
}
