#define _POSIX_C_SOURCE 200809L

/* C ABI smoke test: exercises every exported function against a scratch
 * directory passed as argv[1]. Exits non-zero on the first failure. */

#include "zaxonlite.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#include <io.h>
#include <process.h>
#define close _close
#define getpid _getpid
#define open _open
#define unlink _unlink
#define write _write
#else
#include <unistd.h>
#endif

static int restrict_file_permissions(int fd, const char *path) {
#ifdef _WIN32
    (void)fd;
    return _chmod(path, _S_IREAD | _S_IWRITE);
#else
    (void)path;
    return fchmod(fd, S_IRUSR | S_IWUSR);
#endif
}

static int failures = 0;

#define CHECK(name, condition)                                                \
    do {                                                                      \
        if (condition) {                                                      \
            printf("ok   %s\n", name);                                        \
        } else {                                                              \
            printf("FAIL %s\n", name);                                        \
            failures++;                                                       \
        }                                                                     \
        fflush(stdout);                                                       \
    } while (0)

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: capi_smoke <data-dir>\n");
        return 2;
    }
    /* The pid alone is not unique across CI runs: fresh runners assign
     * near-identical pids and the cache preserves old data directories,
     * which the journal then faithfully replays. */
    char dir[1024];
    snprintf(dir, sizeof dir, "%s-%d-%ld", argv[1], (int)getpid(),
             (long)time(NULL));

    CHECK("version string", strcmp(zaxonlite_version(), "0.7.0") == 0);

    zaxonlite *db = NULL;
    CHECK("open", zaxonlite_open(dir, &db) == 0 && db != NULL);
    if (db == NULL) return 1;

    /* A second open of the same directory must report unavailable. */
    zaxonlite *locked = NULL;
    CHECK("locking", zaxonlite_open(dir, &locked) == 4 && locked == NULL);

    int64_t changes = -1;
    CHECK("create table",
          zaxonlite_exec(db, "create table c(a integer primary key, b text)",
                         &changes) == 0);
    CHECK("insert",
          zaxonlite_exec(db, "insert into c(b) values ('x'), ('y')",
                         &changes) == 0 &&
              changes == 2);

    const char prepared_text[] = "prepared";
    zaxonlite_value prepared_values[] = {
        {.type = ZAXONLITE_TEXT,
         .bytes = prepared_text,
         .length = strlen(prepared_text)}};
    CHECK("prepared insert",
          zaxonlite_exec_prepared(db, "insert into c(b) values (?1)",
                                  prepared_values, 1, &changes) == 0 &&
              changes == 1);

    zaxonlite_transaction *transaction = NULL;
    CHECK("transaction begin",
          zaxonlite_transaction_begin(db, &transaction) == 0 &&
              transaction != NULL);
    zaxonlite_value tx_one[] = {
        {.type = ZAXONLITE_TEXT, .bytes = "tx-one", .length = 6}};
    zaxonlite_value tx_two[] = {
        {.type = ZAXONLITE_TEXT, .bytes = "tx-two", .length = 6}};
    CHECK("transaction first statement",
          zaxonlite_transaction_exec(transaction,
                                     "insert into c(b) values (?1)", tx_one,
                                     1) == 0);
    CHECK("transaction second statement",
          zaxonlite_transaction_exec(transaction,
                                     "insert into c(b) values (?1)", tx_two,
                                     1) == 0);
    CHECK("transaction commit",
          zaxonlite_transaction_commit(transaction, &changes) == 0 &&
              changes == 2);
    zaxonlite_transaction_close(transaction);

    zaxonlite_value query_value[] = {
        {.type = ZAXONLITE_TEXT, .bytes = "prepared", .length = 8}};
    char *prepared_json = NULL;
    CHECK("prepared query",
          zaxonlite_query_prepared_json(
              db, "select count(*) from c where b = ?1", query_value, 1,
              &prepared_json) == 0 &&
              prepared_json != NULL && strstr(prepared_json, "[[\"1\"]]") != NULL);
    zaxonlite_free(prepared_json);
    CHECK("sql error surfaces",
          zaxonlite_exec(db, "insert into missing values (1)", &changes) == 1 &&
              strstr(zaxonlite_last_error(db), "no such table") != NULL);

    char *json = NULL;
    CHECK("query json",
          zaxonlite_query_json(db, "select * from c order by a", &json) == 0 &&
              json != NULL &&
              strcmp(json, "{\"columns\":[\"a\",\"b\"],"
                           "\"rows\":[[\"1\",\"x\"],[\"2\",\"y\"],"
                           "[\"3\",\"prepared\"],[\"4\",\"tx-one\"],"
                           "[\"5\",\"tx-two\"]]}") == 0);
    zaxonlite_free(json);
    CHECK("write via query is misuse",
          zaxonlite_query_json(db, "delete from c", &json) == 2);

    /* Typed results preserve all five storage classes. */
    CHECK("typed fixture table",
          zaxonlite_exec(db,
                         "create table typed(i integer, r real, t text, "
                         "b blob, n integer)",
                         &changes) == 0);
    CHECK("typed fixture row",
          zaxonlite_exec(db,
                         "insert into typed values (7, 1.5, 'text', "
                         "X'00ff', NULL)",
                         &changes) == 0 &&
              changes == 1);
    zaxonlite_result *typed = NULL;
    CHECK("typed query",
          zaxonlite_query_prepared_result(db, "select * from typed", NULL, 0,
                                          &typed) == 0 &&
              typed != NULL);
    if (typed != NULL) {
        CHECK("typed column count",
              zaxonlite_result_column_count(typed) == 5);
        CHECK("typed row count", zaxonlite_result_row_count(typed) == 1);
        CHECK("typed column name",
              strcmp(zaxonlite_result_column_name(typed, 1), "r") == 0);
        CHECK("typed column name bounds",
              zaxonlite_result_column_name(typed, 5) == NULL);
        zaxonlite_value cell;
        CHECK("typed integer",
              zaxonlite_result_value(typed, 0, 0, &cell) == 0 &&
                  cell.type == ZAXONLITE_INTEGER && cell.integer == 7);
        CHECK("typed real",
              zaxonlite_result_value(typed, 0, 1, &cell) == 0 &&
                  cell.type == ZAXONLITE_REAL && cell.real == 1.5);
        CHECK("typed text",
              zaxonlite_result_value(typed, 0, 2, &cell) == 0 &&
                  cell.type == ZAXONLITE_TEXT && cell.length == 4 &&
                  memcmp(cell.bytes, "text", 4) == 0);
        CHECK("typed blob",
              zaxonlite_result_value(typed, 0, 3, &cell) == 0 &&
                  cell.type == ZAXONLITE_BLOB && cell.length == 2 &&
                  memcmp(cell.bytes, "\x00\xff", 2) == 0);
        CHECK("typed null",
              zaxonlite_result_value(typed, 0, 4, &cell) == 0 &&
                  cell.type == ZAXONLITE_NULL);
        CHECK("typed value bounds",
              zaxonlite_result_value(typed, 1, 0, &cell) == 2 &&
                  zaxonlite_result_value(typed, 0, 5, &cell) == 2);
        zaxonlite_result_close(typed);
    }

    /* A zero-row typed query still reports column metadata. */
    zaxonlite_result *empty = NULL;
    CHECK("typed empty query",
          zaxonlite_query_prepared_result(db,
                                          "select i from typed where i = -1",
                                          NULL, 0, &empty) == 0 &&
              empty != NULL && zaxonlite_result_row_count(empty) == 0 &&
              zaxonlite_result_column_count(empty) == 1);
    zaxonlite_result_close(empty);
    zaxonlite_result_close(NULL);

    /* Structured write results: rowid and RETURNING rows. */
    zaxonlite_exec_result write_result;
    zaxonlite_result *returning = NULL;
    zaxonlite_value returning_text[] = {
        {.type = ZAXONLITE_TEXT, .bytes = "returned", .length = 8}};
    CHECK("exec result with returning",
          zaxonlite_exec_prepared_result(
              db, "insert into c(b) values (?1) returning a, b",
              returning_text, 1, &write_result, &returning) == 0 &&
              write_result.changes == 1 &&
              write_result.has_last_insert_rowid && returning != NULL);
    if (returning != NULL) {
        zaxonlite_value cell;
        CHECK("returning row",
              zaxonlite_result_row_count(returning) == 1 &&
                  zaxonlite_result_value(returning, 0, 0, &cell) == 0 &&
                  cell.type == ZAXONLITE_INTEGER &&
                  cell.integer == write_result.last_insert_rowid);
        CHECK("returning text cell",
              zaxonlite_result_value(returning, 0, 1, &cell) == 0 &&
                  cell.type == ZAXONLITE_TEXT && cell.length == 8 &&
                  memcmp(cell.bytes, "returned", 8) == 0);
        zaxonlite_result_close(returning);
    }
    CHECK("update sets no rowid",
          zaxonlite_exec_prepared_result(
              db, "update typed set i = i + 1", NULL, 0, &write_result,
              NULL) == 0 &&
              !write_result.has_last_insert_rowid);

    /* Stable error categories: constraint violations classify as 1. */
    CHECK("unique fixture",
          zaxonlite_exec(db,
                         "create table uniq(v text unique); "
                         "insert into uniq values ('one')",
                         &changes) == 0);
    CHECK("constraint category",
          zaxonlite_exec(db, "insert into uniq values ('one')", &changes) ==
                  1 &&
              zaxonlite_last_error_category(db) == 1);

    /* Statement description: shape without execution. */
    zaxonlite_statement_info info;
    CHECK("describe read",
          zaxonlite_statement_describe(db, "select i from typed where i = ?1",
                                       &info) == 0 &&
              info.read_only && info.parameter_count == 1 &&
              info.column_count == 1 && !info.has_tail);
    CHECK("describe write with tail",
          zaxonlite_statement_describe(
              db, "insert into c(b) values ('x'); select 1", &info) == 0 &&
              !info.read_only && info.has_tail);
    CHECK("describe trailing semicolon is no tail",
          zaxonlite_statement_describe(db, "select 1;", &info) == 0 &&
              !info.has_tail);

    /* Typed search: lexical-only through the validated planner. */
    CHECK("search fixture",
          zaxonlite_exec(db,
                         "create virtual table docs using fts5(body); "
                         "insert into docs(body) values "
                         "('paxos replicates sqlite'), ('unrelated text')",
                         &changes) == 0);
    zaxonlite_search_options search_options = {
        .fts_table = "docs",
        .text = "paxos",
        .text_length = 5,
        .k = 5,
        .fusion = ZAXONLITE_SEARCH_RRF,
        .text_weight = 1.0,
        .vector_weight = 1.0,
    };
    zaxonlite_result *found = NULL;
    CHECK("typed search",
          zaxonlite_search(db, &search_options, &found) == 0 &&
              found != NULL && zaxonlite_result_row_count(found) == 1);
    zaxonlite_result_close(found);
    zaxonlite_search_options bad_search = search_options;
    bad_search.fts_table = "docs; drop table c";
    CHECK("search identifier validation",
          zaxonlite_search(db, &bad_search, &found) == 2 &&
              zaxonlite_last_error_category(db) == 10);

    uint64_t session = 0;
    CHECK("session open", zaxonlite_session_open(db, &session) == 0 && session > 0);
    bool replayed = true;
    CHECK("idempotent exec",
          zaxonlite_exec_idempotent(db, session, 1,
                                    "insert into c(b) values ('z')", &changes,
                                    &replayed) == 0 &&
              changes == 1 && !replayed);
    CHECK("idempotent replay",
          zaxonlite_exec_idempotent(db, session, 1,
                                    "insert into c(b) values ('z')", &changes,
                                    &replayed) == 0 &&
              changes == 1 && replayed);
    CHECK("sequence gap",
          zaxonlite_exec_idempotent(db, session, 5,
                                    "insert into c(b) values ('g')", &changes,
                                    &replayed) == 1);

    /* Gate C live transaction: read-your-writes, RETURNING, savepoints. */
    CHECK("live begin", zaxonlite_live_begin(db) == 0 &&
                            zaxonlite_live_active(db));
    zaxonlite_exec_result live_result;
    zaxonlite_result *live_returning = NULL;
    zaxonlite_value live_text[] = {
        {.type = ZAXONLITE_TEXT, .bytes = "live", .length = 4}};
    CHECK("live insert returning",
          zaxonlite_live_exec(db, "insert into c(b) values (?1) returning a",
                              live_text, 1, &live_result,
                              &live_returning) == 0 &&
              live_result.changes == 1 &&
              live_result.has_last_insert_rowid && live_returning != NULL);
    zaxonlite_result_close(live_returning);
    zaxonlite_result *live_read = NULL;
    CHECK("live read-your-writes",
          zaxonlite_live_exec(db, "select count(*) from c where b = 'live'",
                              NULL, 0, &live_result, &live_read) == 0 &&
              live_read != NULL);
    if (live_read != NULL) {
        zaxonlite_value live_cell;
        CHECK("live uncommitted row visible",
              zaxonlite_result_value(live_read, 0, 0, &live_cell) == 0 &&
                  live_cell.integer == 1);
        zaxonlite_result_close(live_read);
    }
    CHECK("live savepoint", zaxonlite_live_savepoint(db, 1) == 0);
    CHECK("live discarded insert",
          zaxonlite_live_exec(db, "insert into c(b) values ('discard')", NULL,
                              0, &live_result, NULL) == 0);
    CHECK("live rollback to savepoint",
          zaxonlite_live_rollback_to_savepoint(db, 1) == 0 &&
              zaxonlite_live_release_savepoint(db, 1) == 0);
    CHECK("one-shot write refused during live transaction",
          zaxonlite_exec(db, "insert into c(b) values ('blocked')",
                         &changes) != 0);
    int64_t live_changes = 0;
    CHECK("live commit",
          zaxonlite_live_commit(db, &live_changes) == 0 &&
              !zaxonlite_live_active(db));
    char *live_json = NULL;
    CHECK("live commit visible",
          zaxonlite_query_json(db, "select count(*) from c where b = 'live'",
                               &live_json) == 0 &&
              live_json != NULL && strstr(live_json, "[[\"1\"]]") != NULL);
    zaxonlite_free(live_json);
    CHECK("live rollback publishes nothing",
          zaxonlite_live_begin(db) == 0 &&
              zaxonlite_live_exec(db, "insert into c(b) values ('gone')",
                                  NULL, 0, &live_result, NULL) == 0 &&
              zaxonlite_live_rollback(db) == 0);
    char *gone_json = NULL;
    CHECK("live rolled-back row absent",
          zaxonlite_query_json(db, "select count(*) from c where b = 'gone'",
                               &gone_json) == 0 &&
              gone_json != NULL && strstr(gone_json, "[[\"0\"]]") != NULL);
    zaxonlite_free(gone_json);
    CHECK("live misuse outside transaction",
          zaxonlite_live_commit(db, &live_changes) == 2 &&
              zaxonlite_live_rollback(db) == 2);

    CHECK("anchor", zaxonlite_state_anchor(db) == 0);
    CHECK("integrity", zaxonlite_integrity_check(db) == 0);

    int64_t expired = -1;
    CHECK("expire sessions",
          zaxonlite_expire_sessions(db, 1000, &expired) == 0 && expired == 0);

    char backup_path[1024];
    snprintf(backup_path, sizeof backup_path, "%s.backup.db", dir);
    CHECK("backup", zaxonlite_backup(db, backup_path) == 0);

    zaxonlite_close(db);

    /* Reopen: state survives, the session replays. */
    CHECK("reopen", zaxonlite_open(dir, &db) == 0 && db != NULL);
    CHECK("replay after reopen",
          zaxonlite_exec_idempotent(db, session, 1,
                                    "insert into c(b) values ('z')", &changes,
                                    &replayed) == 0 &&
              replayed);
    zaxonlite_close(db);

    /* The transport-owning facade is a separate C surface. */
    char cluster_dir[1024];
    char gateway_dir[1024];
    char cluster_address[64];
    char gateway_address[64];
    snprintf(cluster_dir, sizeof cluster_dir, "%s.cluster", dir);
    snprintf(gateway_dir, sizeof gateway_dir, "%s.gateway", dir);
    const int cluster_port = 30000 + ((int)getpid() % 20000);
    snprintf(cluster_address, sizeof cluster_address, "127.0.0.1:%d",
             cluster_port);
    snprintf(gateway_address, sizeof gateway_address, "127.0.0.1:%d",
             cluster_port + 1);
    zaxonlite_member cluster_members[] = {
        {.id = 1,
         .address = cluster_address,
         .role = ZAXONLITE_DATA_VOTER},
        {.id = 99, .address = gateway_address, .role = ZAXONLITE_GATEWAY},
    };
    zaxonlite_cluster_options cluster_options = {
        .directory = cluster_dir,
        .node_id = 1,
        .members = cluster_members,
        .member_count = 2,
        .cluster_id = "c-api-smoke",
        .startup_timeout_ms = 5000,
        .allow_insecure_test_tcp = true,
    };
    zaxonlite_cluster *cluster = NULL;
    CHECK("cluster facade open",
          zaxonlite_cluster_open(&cluster_options, &cluster) == 0 &&
              cluster != NULL);
    if (cluster != NULL) {
        char cluster_failure[128];
        CHECK("cluster facade healthy state",
              zaxonlite_cluster_state(cluster, cluster_failure,
                                      sizeof cluster_failure) == 0 &&
                  cluster_failure[0] == '\0');
        CHECK("cluster facade exec",
              zaxonlite_cluster_exec(
                  cluster, "create table facade(value text)", &changes) == 0);
        CHECK("cluster facade insert",
              zaxonlite_cluster_exec(
                  cluster, "insert into facade values ('paxos')", &changes) == 0);
        char *cluster_json = NULL;
        CHECK("cluster facade query",
              zaxonlite_cluster_query_json(
                  cluster, "select value from facade", &cluster_json) == 0 &&
                  cluster_json != NULL && strstr(cluster_json, "paxos") != NULL);
        zaxonlite_free(cluster_json);
        char *status_json = NULL;
        CHECK("cluster facade generic RPC",
              zaxonlite_cluster_call_json(cluster, "{\"op\":\"status\"}",
                                          false, &status_json) == 0 &&
                  status_json != NULL &&
                  strstr(status_json, "data-voter") != NULL);
        zaxonlite_free(status_json);

        /* Typed-v1 client RPC: tagged params in, tagged cells out. */
        char *typed_json = NULL;
        CHECK("cluster typed-v1 query",
              zaxonlite_cluster_call_json(
                  cluster,
                  "{\"op\":\"query\",\"sql\":\"select 2+2 as v\","
                  "\"format\":\"typed-v1\"}",
                  false, &typed_json) == 0 &&
                  typed_json != NULL &&
                  strstr(typed_json, "\"t\":\"i\",\"i\":4") != NULL);
        zaxonlite_free(typed_json);
        char *typed_exec_json = NULL;
        CHECK("cluster typed-v1 exec with params",
              zaxonlite_cluster_call_json(
                  cluster,
                  "{\"op\":\"exec\",\"sql\":\"insert into facade values (?1)\","
                  "\"format\":\"typed-v1\","
                  "\"params\":[{\"t\":\"text\",\"v\":\"typed\"}]}",
                  true, &typed_exec_json) == 0 &&
                  typed_exec_json != NULL &&
                  strstr(typed_exec_json, "\"changes\":1") != NULL);
        zaxonlite_free(typed_exec_json);

        zaxonlite_member gateway_members[] = {
            {.id = 99,
             .address = gateway_address,
             .role = ZAXONLITE_GATEWAY},
            {.id = 1,
             .address = cluster_address,
             .role = ZAXONLITE_DATA_VOTER},
        };
        zaxonlite_cluster_options gateway_options = {
            .directory = gateway_dir,
            .node_id = 99,
            .members = gateway_members,
            .member_count = 2,
            .cluster_id = "c-api-smoke",
            .startup_timeout_ms = 5000,
            .allow_insecure_test_tcp = true,
        };
        zaxonlite_cluster *gateway = NULL;
        CHECK("gateway C facade open",
              zaxonlite_cluster_open(&gateway_options, &gateway) == 0 &&
                  gateway != NULL);
        if (gateway != NULL) {
            char *gateway_json = NULL;
            CHECK("gateway C facade query",
                  zaxonlite_cluster_query_json(
                      gateway, "select value from facade", &gateway_json) == 0 &&
                      gateway_json != NULL &&
                      strstr(gateway_json, "paxos") != NULL);
            zaxonlite_free(gateway_json);
            zaxonlite_cluster_close(gateway);
        }
        zaxonlite_cluster_close(cluster);
    }

#ifndef _WIN32
    /* v2 options: single-node Unix-domain service. */
    char unix_dir[1024];
    char unix_socket[1024];
    char unix_address[1100];
    snprintf(unix_dir, sizeof unix_dir, "%s.unix", dir);
    snprintf(unix_socket, sizeof unix_socket, "/tmp/zx-smoke-%d.sock",
             (int)getpid());
    snprintf(unix_address, sizeof unix_address, "unix:%s", unix_socket);
    zaxonlite_member unix_members[] = {
        {.id = 1, .address = unix_address, .role = ZAXONLITE_DATA_VOTER}};
    zaxonlite_cluster_options_v2 unix_options = {
        .struct_size = sizeof(zaxonlite_cluster_options_v2),
        .directory = unix_dir,
        .node_id = 1,
        .members = unix_members,
        .member_count = 1,
        .cluster_id = "c-api-smoke-unix",
        .startup_timeout_ms = 5000,
    };
    zaxonlite_cluster *unix_cluster = NULL;
    CHECK("unix v2 open",
          zaxonlite_cluster_open_v2(&unix_options, &unix_cluster) == 0 &&
              unix_cluster != NULL);
    if (unix_cluster != NULL) {
        CHECK("unix socket exists", access(unix_socket, F_OK) == 0);
        CHECK("unix exec",
              zaxonlite_cluster_exec(unix_cluster,
                                     "create table u(value text)",
                                     &changes) == 0);
        char *unix_json = NULL;
        CHECK("unix query",
              zaxonlite_cluster_query_json(unix_cluster, "select 42",
                                           &unix_json) == 0 &&
                  unix_json != NULL && strstr(unix_json, "42") != NULL);
        zaxonlite_free(unix_json);
        zaxonlite_cluster_close(unix_cluster);
        CHECK("unix socket removed on close",
              access(unix_socket, F_OK) != 0);
    }

    /* v2 validation: unix service refuses a multi-member registry, and
     * development PSK refuses a non-loopback member. */
    zaxonlite_member bad_unix_members[] = {
        {.id = 1, .address = unix_address, .role = ZAXONLITE_DATA_VOTER},
        {.id = 2, .address = "127.0.0.1:39999", .role = ZAXONLITE_DATA_VOTER}};
    zaxonlite_cluster_options_v2 bad_unix = unix_options;
    bad_unix.directory = unix_dir;
    bad_unix.members = bad_unix_members;
    bad_unix.member_count = 2;
    zaxonlite_cluster *rejected = NULL;
    CHECK("unix multi-member rejected",
          zaxonlite_cluster_open_v2(&bad_unix, &rejected) == 2 &&
              rejected == NULL);
    const char psk_secret[] = "cluster-test-secret-32-bytes-minimum";
    zaxonlite_member nonloop_members[] = {
        {.id = 1, .address = "10.0.0.1:39999", .role = ZAXONLITE_DATA_VOTER}};
    zaxonlite_cluster_options_v2 bad_psk = {
        .struct_size = sizeof(zaxonlite_cluster_options_v2),
        .directory = unix_dir,
        .node_id = 1,
        .members = nonloop_members,
        .member_count = 1,
        .auth_secret = psk_secret,
        .auth_secret_length = sizeof psk_secret - 1,
        .startup_timeout_ms = 5000,
        .allow_psk_only_loopback = true,
    };
    CHECK("dev psk non-loopback rejected",
          zaxonlite_cluster_open_v2(&bad_psk, &rejected) == 2 &&
              rejected == NULL);
    zaxonlite_cluster_options_v2 wrong_size = unix_options;
    wrong_size.struct_size = sizeof(zaxonlite_cluster_options_v2) - 8;
    CHECK("v2 struct size checked",
          zaxonlite_cluster_open_v2(&wrong_size, &rejected) == 2 &&
              rejected == NULL);
#endif

    /* External-client remote pool (ZDS 0010 Gate B): a dev-PSK loopback
     * server and zaxonlite_remote_* sharing one auth provider file. */
    char psk_path[1024];
    snprintf(psk_path, sizeof psk_path, "%s.psk", dir);
    int psk_fd = open(psk_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    CHECK("remote psk file created", psk_fd >= 0);
    if (psk_fd >= 0) {
        const char psk_bytes[] =
            "remote-smoke-secret-0123456789abcdef0123456789abcdef";
        CHECK("remote psk file written",
              restrict_file_permissions(psk_fd, psk_path) == 0 &&
                  write(psk_fd, psk_bytes, sizeof psk_bytes - 1) ==
                      (int)(sizeof psk_bytes - 1));
        close(psk_fd);

        char remote_dir[1024];
        char remote_address[64];
        snprintf(remote_dir, sizeof remote_dir, "%s.remote", dir);
        const int remote_port = 30000 + (((int)getpid() + 7) % 20000);
        snprintf(remote_address, sizeof remote_address, "127.0.0.1:%d",
                 remote_port);
        zaxonlite_member remote_members[] = {
            {.id = 1, .address = remote_address, .role = ZAXONLITE_DATA_VOTER}};
        zaxonlite_cluster_options_v2 remote_server_options = {
            .struct_size = sizeof(zaxonlite_cluster_options_v2),
            .directory = remote_dir,
            .node_id = 1,
            .members = remote_members,
            .member_count = 1,
            .cluster_id = "c-api-smoke-remote",
            .auth_file_path = psk_path,
            .startup_timeout_ms = 5000,
            .allow_psk_only_loopback = true,
        };
        zaxonlite_cluster *remote_server = NULL;
        CHECK("remote psk server open",
              zaxonlite_cluster_open_v2(&remote_server_options,
                                        &remote_server) == 0 &&
                  remote_server != NULL);
        if (remote_server != NULL) {
            const char *remote_seeds[] = {remote_address};
            zaxonlite_remote_options remote_options = {
                .seeds = remote_seeds,
                .seed_count = 1,
                .auth_file_path = psk_path,
                .allow_psk_only_loopback = true,
            };
            zaxonlite_remote *remote = NULL;
            CHECK("remote open",
                  zaxonlite_remote_open(&remote_options, &remote) == 0 &&
                      remote != NULL);
            if (remote != NULL) {
                zaxonlite_value cell;
                zaxonlite_result *sum = NULL;
                CHECK("remote typed query",
                      zaxonlite_remote_query(remote, "select 1+1 as v", NULL,
                                             0, 2, 0, &sum) == 0 &&
                          sum != NULL);
                if (sum != NULL) {
                    CHECK("remote typed sum",
                          zaxonlite_result_row_count(sum) == 1 &&
                              zaxonlite_result_value(sum, 0, 0, &cell) == 0 &&
                              cell.type == ZAXONLITE_INTEGER &&
                              cell.integer == 2);
                    zaxonlite_result_close(sum);
                }

                zaxonlite_exec_result remote_write;
                CHECK("remote create table",
                      zaxonlite_remote_exec(remote, "create table r(v text)",
                                            NULL, 0, &remote_write) == 0);
                zaxonlite_value remote_text[] = {
                    {.type = ZAXONLITE_TEXT, .bytes = "remote", .length = 6}};
                CHECK("remote insert with text param",
                      zaxonlite_remote_exec(remote,
                                            "insert into r(v) values (?1)",
                                            remote_text, 1,
                                            &remote_write) == 0 &&
                          remote_write.changes == 1 &&
                          !remote_write.replayed);
                /* An identical second exec must execute, not replay: the
                 * write lane advanced its session sequence. A fresh
                 * (non-replayed) session write reports the last insert
                 * rowid when the statement observably set one; only a
                 * replay retains just the change count (the session
                 * table does not persist the rowid yet). */
                CHECK("remote sequence advance",
                      zaxonlite_remote_exec(remote,
                                            "insert into r(v) values (?1)",
                                            remote_text, 1,
                                            &remote_write) == 0 &&
                          remote_write.changes == 1 &&
                          !remote_write.replayed &&
                          remote_write.has_last_insert_rowid &&
                          remote_write.last_insert_rowid == 2);

                zaxonlite_result *linearizable = NULL;
                CHECK("remote linearizable read",
                      zaxonlite_remote_query(remote, "select count(*) from r",
                                             NULL, 0, 2, 0,
                                             &linearizable) == 0 &&
                          linearizable != NULL);
                if (linearizable != NULL) {
                    CHECK("remote linearizable count",
                          zaxonlite_result_value(linearizable, 0, 0, &cell) ==
                                  0 &&
                              cell.type == ZAXONLITE_INTEGER &&
                              cell.integer == 2);
                    zaxonlite_result_close(linearizable);
                }
                zaxonlite_result *any_level = NULL;
                CHECK("remote any-level read",
                      zaxonlite_remote_query(remote,
                                             "select v from r order by rowid",
                                             NULL, 0, 0, 0,
                                             &any_level) == 0 &&
                          any_level != NULL &&
                          zaxonlite_result_row_count(any_level) == 2);
                zaxonlite_result_close(any_level);

                /* Atomic remote executemany: one typed-v1 batch, one
                 * replicated transaction, one session sequence. */
                CHECK("remote batch table",
                      zaxonlite_remote_exec(remote,
                                            "create table rb(v text unique)",
                                            NULL, 0, &remote_write) == 0);
                zaxonlite_value batch_rows[] = {
                    {.type = ZAXONLITE_TEXT, .bytes = "ba", .length = 2},
                    {.type = ZAXONLITE_TEXT, .bytes = "bb", .length = 2},
                    {.type = ZAXONLITE_TEXT, .bytes = "bc", .length = 2}};
                CHECK("remote batch insert",
                      zaxonlite_remote_exec_batch(
                          remote, "insert into rb(v) values (?1)", batch_rows,
                          1, 3, &remote_write) == 0 &&
                          remote_write.changes == 3 &&
                          !remote_write.replayed);
                zaxonlite_result *batch_count = NULL;
                CHECK("remote batch count",
                      zaxonlite_remote_query(remote, "select count(*) from rb",
                                             NULL, 0, 2, 0,
                                             &batch_count) == 0 &&
                          batch_count != NULL);
                if (batch_count != NULL) {
                    CHECK("remote batch rows visible",
                          zaxonlite_result_value(batch_count, 0, 0, &cell) ==
                                  0 &&
                              cell.type == ZAXONLITE_INTEGER &&
                              cell.integer == 3);
                    zaxonlite_result_close(batch_count);
                }
                /* One good row plus one duplicate: the batch is atomic,
                 * so the whole transaction fails and the good row is
                 * not applied either. */
                zaxonlite_value dup_rows[] = {
                    {.type = ZAXONLITE_TEXT, .bytes = "bd", .length = 2},
                    {.type = ZAXONLITE_TEXT, .bytes = "ba", .length = 2}};
                CHECK("remote batch duplicate fails",
                      zaxonlite_remote_exec_batch(
                          remote, "insert into rb(v) values (?1)", dup_rows,
                          1, 2, &remote_write) == 1);
                zaxonlite_result *after_dup = NULL;
                CHECK("remote batch failure query",
                      zaxonlite_remote_query(remote, "select count(*) from rb",
                                             NULL, 0, 2, 0, &after_dup) == 0 &&
                          after_dup != NULL);
                if (after_dup != NULL) {
                    CHECK("remote batch rolled back atomically",
                          zaxonlite_result_value(after_dup, 0, 0, &cell) == 0 &&
                              cell.type == ZAXONLITE_INTEGER &&
                              cell.integer == 3);
                    zaxonlite_result_close(after_dup);
                }

                CHECK("remote search table",
                      zaxonlite_remote_exec(
                          remote,
                          "create virtual table docs using fts5(body)",
                          NULL, 0, &remote_write) == 0);
                zaxonlite_value search_text[] = {
                    {.type = ZAXONLITE_TEXT,
                     .bytes = "paxos replicates sqlite",
                     .length = 23}};
                CHECK("remote search corpus",
                      zaxonlite_remote_exec(
                          remote, "insert into docs(body) values (?1)",
                          search_text, 1, &remote_write) == 0);
                zaxonlite_search_options remote_search_options = {
                    .fts_table = "docs",
                    .text = "paxos",
                    .text_length = 5,
                    .k = 5,
                    .fusion = ZAXONLITE_SEARCH_RRF,
                    .text_weight = 1.0,
                    .vector_weight = 1.0,
                };
                zaxonlite_result *search_result = NULL;
                CHECK("remote typed search",
                      zaxonlite_remote_search(
                          remote, &remote_search_options, 2, 0,
                          &search_result) == 0 &&
                          search_result != NULL &&
                          zaxonlite_result_row_count(search_result) == 1);
                zaxonlite_result_close(search_result);

                char *remote_status = NULL;
                CHECK("remote status json",
                      zaxonlite_remote_status_json(remote, &remote_status) ==
                              0 &&
                          remote_status != NULL &&
                          strstr(remote_status, "typed_v1") != NULL);
                zaxonlite_free(remote_status);
                zaxonlite_remote_close(remote);
            }
            zaxonlite_cluster_close(remote_server);
        }

        /* Open-time probe: opening against a dead loopback port must
         * fail with a nonzero code instead of succeeding lazily. */
        char dead_address[64];
        snprintf(dead_address, sizeof dead_address, "127.0.0.1:%d",
                 remote_port + 2);
        const char *dead_seeds[] = {dead_address};
        zaxonlite_remote_options dead_options = {
            .seeds = dead_seeds,
            .seed_count = 1,
            .auth_file_path = psk_path,
            .allow_psk_only_loopback = true,
            .connect_timeout_ms = 500,
        };
        zaxonlite_remote *dead_remote = NULL;
        CHECK("remote open probes a dead port",
              zaxonlite_remote_open(&dead_options, &dead_remote) != 0 &&
                  dead_remote == NULL);

        unlink(psk_path);
    }

    /* Negative: a seedless remote configuration is misuse. */
    zaxonlite_remote_options no_seed_options = {0};
    zaxonlite_remote *no_remote = NULL;
    CHECK("remote zero seeds rejected",
          zaxonlite_remote_open(&no_seed_options, &no_remote) == 2 &&
              no_remote == NULL);

    /* Negative: duplicate seed addresses are rejected before any
     * endpoint is parsed or dialed (1..=36 UNIQUE seeds). */
    const char *dup_seeds[] = {"127.0.0.1:7001", "127.0.0.1:7001"};
    zaxonlite_remote_options dup_seed_options = {
        .seeds = dup_seeds,
        .seed_count = 2,
    };
    CHECK("remote duplicate seeds rejected",
          zaxonlite_remote_open(&dup_seed_options, &no_remote) == 2 &&
              no_remote == NULL);

    /* Negative: two registry members sharing one address are misuse,
     * reported before any thread or file is touched. */
    char dup_dir[1024];
    snprintf(dup_dir, sizeof dup_dir, "%s.dup", dir);
    zaxonlite_member dup_members[] = {
        {.id = 1, .address = "127.0.0.1:39997", .role = ZAXONLITE_DATA_VOTER},
        {.id = 2, .address = "127.0.0.1:39997", .role = ZAXONLITE_DATA_VOTER}};
    zaxonlite_cluster_options dup_member_options = {
        .directory = dup_dir,
        .node_id = 1,
        .members = dup_members,
        .member_count = 2,
        .allow_insecure_test_tcp = true,
    };
    zaxonlite_cluster *dup_cluster = NULL;
    CHECK("duplicate member endpoint rejected",
          zaxonlite_cluster_open(&dup_member_options, &dup_cluster) == 2 &&
              dup_cluster == NULL);

    if (failures == 0) {
        printf("capi smoke: all checks passed\n");
        return 0;
    }
    printf("capi smoke: %d failure(s)\n", failures);
    return 1;
}
