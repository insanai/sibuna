/*
 * zaxonlite: an embeddable SQLite service replicated by Multi-Paxos.
 *
 * One handle owns one node data directory (journal, payload store,
 * snapshots, and the materialized SQLite image). Handles are independent;
 * use each handle from one thread at a time, or under your own lock.
 *
 * Return codes:
 *   0  ok
 *   1  SQL or session error (see zaxonlite_last_error)
 *   2  misuse (null argument, write statement on the read path)
 *   3  integrity failure
 *   4  unavailable (directory locked, corrupt state, or I/O failure)
 *
 * Boundary contract (every function follows these rules):
 *   - NULL is accepted only where a parameter is documented optional. A
 *     non-zero length always requires a non-null pointer, and a null
 *     pointer always requires a zero length.
 *   - Declared counts and lengths are validated against product limits
 *     before any memory is read, sliced, or allocated from them
 *     (member lists, bound-value counts, value byte lengths, secrets).
 *   - Input buffers are borrowed only for the duration of the call.
 *     Output buffers name their release function (zaxonlite_free);
 *     opaque handles name their close/destroy function.
 *   - Every fallible function sets its output handles, pointers, and
 *     scalar out-parameters to a safe empty value (NULL/0/false) before
 *     doing any other work, on success and on every error path.
 *   - Error strings from zaxonlite_last_error are bounded, owned by the
 *     handle, and valid until the next call on that handle.
 */

#ifndef ZAXONLITE_H
#define ZAXONLITE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void zaxonlite;
typedef void zaxonlite_transaction;
typedef void zaxonlite_cluster;
typedef void zaxonlite_result;

typedef enum zaxonlite_node_role {
    ZAXONLITE_DATA_VOTER = 0,
    ZAXONLITE_WITNESS = 1,
    ZAXONLITE_STANDBY = 2,
    ZAXONLITE_READ_REPLICA = 3,
    ZAXONLITE_GATEWAY = 4
} zaxonlite_node_role;

typedef struct zaxonlite_member {
    uint32_t id;
    const char *address;
    zaxonlite_node_role role;
} zaxonlite_member;

typedef struct zaxonlite_cluster_options {
    const char *directory;
    uint32_t node_id;
    const zaxonlite_member *members;
    size_t member_count;
    const char *cluster_id;
    const void *auth_secret;
    size_t auth_secret_length;
    /* All three TLS paths are required together for production TCP. */
    const char *tls_cert_path;
    const char *tls_key_path;
    const char *tls_ca_path;
    uint64_t startup_timeout_ms;
    /* Tests only: requires the library's failpoint-gated transport path. */
    bool allow_insecure_test_tcp;
} zaxonlite_cluster_options;

typedef enum zaxonlite_value_type {
    ZAXONLITE_NULL = 0,
    ZAXONLITE_INTEGER = 1,
    ZAXONLITE_REAL = 2,
    ZAXONLITE_TEXT = 3,
    ZAXONLITE_BLOB = 4
} zaxonlite_value_type;

/* TEXT and BLOB borrow `bytes` for the duration of the call. */
typedef struct zaxonlite_value {
    zaxonlite_value_type type;
    int64_t integer;
    double real;
    const void *bytes;
    size_t length;
} zaxonlite_value;

/* Library version string, for example "0.7.0". */
const char *zaxonlite_version(void);

/* Opens (or creates) a node data directory. */
int zaxonlite_open(const char *directory, zaxonlite **out_handle);

/* Closes the node and releases the handle. */
void zaxonlite_close(zaxonlite *handle);

/*
 * Opens a transport-owning cluster member. The registry may contain any
 * number of learners; at most nine entries may be voting roles. Addresses
 * use host:port syntax and all pointed-to data is copied before return.
 */
int zaxonlite_cluster_open(const zaxonlite_cluster_options *options,
                           zaxonlite_cluster **out_handle);

/*
 * Versioned cluster options. The v1 struct has no size member, so its
 * layout is frozen; set struct_size = sizeof(zaxonlite_cluster_options_v2)
 * before calling zaxonlite_cluster_open_v2. Additions over v1:
 *   - auth_file_path: PSK provider file, loaded with the native regular-
 *     file, symlink, permission, and size checks; mutually exclusive with
 *     the raw auth_secret buffer.
 *   - allow_psk_only_loopback: development-only PSK TCP; requires a
 *     secret, forbids TLS, and every member address must be numeric
 *     loopback (127.0.0.1 or ::1).
 *   - a single member whose address is "unix:<absolute path>" serves one
 *     local node over an owner-only Unix-domain socket (POSIX only; the
 *     registry must contain exactly that member and it may not be a
 *     gateway). Unix service composes with neither TLS nor the PSK flag.
 */
typedef struct zaxonlite_cluster_options_v2 {
    size_t struct_size;
    const char *directory;
    uint32_t node_id;
    const zaxonlite_member *members;
    size_t member_count;
    const char *cluster_id;
    const void *auth_secret;
    size_t auth_secret_length;
    const char *auth_file_path;
    const char *tls_cert_path;
    const char *tls_key_path;
    const char *tls_ca_path;
    uint64_t startup_timeout_ms;
    bool allow_insecure_test_tcp;
    bool allow_psk_only_loopback;
} zaxonlite_cluster_options_v2;

int zaxonlite_cluster_open_v2(const zaxonlite_cluster_options_v2 *options,
                              zaxonlite_cluster **out_handle);
void zaxonlite_cluster_close(zaxonlite_cluster *handle);
/* Local member lifecycle: 0 healthy, 1 stopping, 2 stopped, 4 failed.
 * On failure, out_failure receives the first error name when space permits.
 * A null handle, or null out_failure with nonzero out_len, returns misuse. */
int zaxonlite_cluster_state(zaxonlite_cluster *handle, char *out_failure,
                            size_t out_len);
int zaxonlite_cluster_exec(zaxonlite_cluster *handle, const char *sql,
                           int64_t *changes_out);
int zaxonlite_cluster_query_json(zaxonlite_cluster *handle, const char *sql,
                                 char **json_out);
int zaxonlite_cluster_call_json(zaxonlite_cluster *handle,
                                const char *request_json,
                                bool require_leader, char **json_out);
const char *zaxonlite_cluster_last_error(zaxonlite_cluster *handle);

/* Executes one replicated write transaction (any SQL statement batch). */
int zaxonlite_exec(zaxonlite *handle, const char *sql, int64_t *changes_out);

/* Executes one prepared statement as a replicated transaction. */
int zaxonlite_exec_prepared(zaxonlite *handle, const char *sql,
                            const zaxonlite_value *values, size_t value_count,
                            int64_t *changes_out);

/*
 * Structured write result. last_insert_rowid is present only when the
 * statement observably updated SQLite's last insert rowid (INSERT or
 * REPLACE); replayed reports idempotent-session replay.
 */
typedef struct zaxonlite_exec_result {
    int64_t changes;
    int64_t last_insert_rowid;
    bool has_last_insert_rowid;
    bool replayed;
} zaxonlite_exec_result;

/*
 * Executes one prepared statement as a replicated transaction and reports
 * the structured result. When the statement has a RETURNING clause its
 * typed rows are stored in *out_returning (release with
 * zaxonlite_result_close); pass NULL to discard them. The rows complete
 * before the write is acknowledged.
 */
int zaxonlite_exec_prepared_result(zaxonlite *handle, const char *sql,
                                   const zaxonlite_value *values,
                                   size_t value_count,
                                   zaxonlite_exec_result *exec_out,
                                   zaxonlite_result **out_returning);

/*
 * Runs a read-only prepared query and returns an opaque materialized
 * typed result. The result owns copied column names and cell bytes;
 * zaxonlite_result_value borrows text/blob bytes until the result is
 * closed. Integer and real values preserve SQLite's runtime storage
 * class, and zero-length text or blob is distinct from NULL.
 */
int zaxonlite_query_prepared_result(zaxonlite *handle, const char *sql,
                                    const zaxonlite_value *values,
                                    size_t value_count,
                                    zaxonlite_result **out_result);

/* All count and index operations below are bounds-checked. */
size_t zaxonlite_result_column_count(const zaxonlite_result *result);
size_t zaxonlite_result_row_count(const zaxonlite_result *result);
const char *zaxonlite_result_column_name(const zaxonlite_result *result,
                                         size_t column);
int zaxonlite_result_value(const zaxonlite_result *result, size_t row,
                           size_t column, zaxonlite_value *out_value);
/* Releases a typed result. Accepts NULL. */
void zaxonlite_result_close(zaxonlite_result *result);

typedef enum zaxonlite_search_fusion {
    ZAXONLITE_SEARCH_RRF = 0,
    ZAXONLITE_SEARCH_DBSF = 1
} zaxonlite_search_fusion;

/*
 * Typed search request (ZDS 0009). Optional strings use null pointers.
 * `text` uses pointer plus explicit length so an FTS query is not
 * constrained by C-string termination; `embedding` is raw little-endian
 * float32 bytes. Identifier, weight, embedding-shape, and candidate-cap
 * validation happen in the native planner, never in the host.
 */
typedef struct zaxonlite_search_options {
    const char *fts_table;
    const char *vec_table;
    const void *text;
    size_t text_length;
    const void *embedding;
    size_t embedding_length;
    uint32_t k;
    uint32_t candidate_count;
    bool has_candidate_count;
    zaxonlite_search_fusion fusion;
    double text_weight;
    double vector_weight;
    const char *metadata_table;
    const char *metadata_id_column;
    const char *const *metadata_columns;
    size_t metadata_column_count;
} zaxonlite_search_options;

int zaxonlite_search(zaxonlite *handle,
                     const zaxonlite_search_options *options,
                     zaxonlite_result **out_result);

/*
 * Prepares (without executing) the first statement of `sql` and reports
 * its parameter count, result-column count, read-only classification, and
 * whether a trailing statement follows. Hosts use it to reject
 * multi-statement input without parsing SQL.
 */
typedef struct zaxonlite_statement_info {
    uint32_t parameter_count;
    uint32_t column_count;
    bool read_only;
    bool has_tail;
} zaxonlite_statement_info;

int zaxonlite_statement_describe(zaxonlite *handle, const char *sql,
                                 zaxonlite_statement_info *out_info);

/*
 * Copies the NUL-terminated name of one bound parameter (1-based index,
 * ":name"/"@name"/"$name" spelling included) into buffer, or an empty
 * string for a positional parameter. SQLite resolves the names; the host
 * never rewrites SQL.
 */
int zaxonlite_statement_parameter_name(zaxonlite *handle, const char *sql,
                                       uint32_t index, char *buffer,
                                       size_t buffer_len);

/*
 * Stable category of the most recent error on this handle. Values are
 * ABI: 0 none, 1 constraint, 2 busy, 3 interrupt, 4 misuse, 5 storage,
 * 6 integrity, 7 availability, 8 session, 9 other SQL, 10 validation.
 * Drives host exception mapping; the message remains diagnostic only.
 */
int zaxonlite_last_error_category(zaxonlite *handle);

/*
 * Gate C live transactions (ZDS 0010): a caller-held SQLite transaction
 * on the writer connection of a single-member local handle. Statements
 * inside it observe earlier uncommitted writes; nothing is replicated
 * until zaxonlite_live_commit, which captures exactly one WAL transition
 * and acknowledges only after the decided slot is applied. Rollback
 * publishes nothing. While a live transaction is open, one-shot writes,
 * snapshots, and membership operations on the handle are refused.
 * Multi-member handles refuse zaxonlite_live_begin.
 */
int zaxonlite_live_begin(zaxonlite *handle);
int zaxonlite_live_exec(zaxonlite *handle, const char *sql,
                        const zaxonlite_value *values, size_t value_count,
                        zaxonlite_exec_result *exec_out,
                        zaxonlite_result **out_returning);
/* Savepoints are host-managed and named by ordinal (zx_sp_<index>). */
int zaxonlite_live_savepoint(zaxonlite *handle, uint32_t index);
int zaxonlite_live_release_savepoint(zaxonlite *handle, uint32_t index);
int zaxonlite_live_rollback_to_savepoint(zaxonlite *handle, uint32_t index);
int zaxonlite_live_commit(zaxonlite *handle, int64_t *changes_out);
int zaxonlite_live_rollback(zaxonlite *handle);
bool zaxonlite_live_active(zaxonlite *handle);

/*
 * Explicit transactions collect copied statements across calls, then execute
 * and replicate them atomically at commit. A transaction is single-use.
 */
int zaxonlite_transaction_begin(zaxonlite *handle,
                                zaxonlite_transaction **out_transaction);
int zaxonlite_transaction_exec(zaxonlite_transaction *transaction,
                               const char *sql,
                               const zaxonlite_value *values,
                               size_t value_count);
int zaxonlite_transaction_commit(zaxonlite_transaction *transaction,
                                 int64_t *changes_out);
void zaxonlite_transaction_close(zaxonlite_transaction *transaction);

/* Opens a replicated client session for idempotent retry. */
int zaxonlite_session_open(zaxonlite *handle, uint64_t *session_out);

/*
 * Executes `sequence` for `session` exactly once. Retrying the last
 * sequence sets *replayed_out and returns the recorded change count;
 * gaps and expired sequences fail with code 1 without executing SQL.
 */
int zaxonlite_exec_idempotent(zaxonlite *handle, uint64_t session,
                              uint64_t sequence, const char *sql,
                              int64_t *changes_out, bool *replayed_out);

/*
 * Runs a read-only query; on success *json_out receives one JSON object
 * {"columns":[...],"rows":[[...]]} to be released with zaxonlite_free.
 */
int zaxonlite_query_json(zaxonlite *handle, const char *sql, char **json_out);

int zaxonlite_query_prepared_json(zaxonlite *handle, const char *sql,
                                  const zaxonlite_value *values,
                                  size_t value_count, char **json_out);

/* Releases a buffer returned by zaxonlite_query_json. */
void zaxonlite_free(char *pointer);

/* Publishes a durable state anchor for fast recovery (ZDS 0011). */
int zaxonlite_state_anchor(zaxonlite *handle);

/* Streams a consistent logical backup to `path`. */
int zaxonlite_backup(zaxonlite *handle, const char *path);

/* Verifies the image, descriptor chain, and payload availability. */
int zaxonlite_integrity_check(zaxonlite *handle);

/* Deletes sessions idle for more than `retain` recent session writes. */
int zaxonlite_expire_sessions(zaxonlite *handle, uint64_t retain,
                              int64_t *expired_out);

/* The most recent error message for this handle. */
const char *zaxonlite_last_error(zaxonlite *handle);

/*
 * External client (ZDS 0010): a pooled remote connection to an existing
 * cluster. Opens no data directory and no listener; every request is
 * typed-v1 client RPC over the seed endpoints. A remote handle may be
 * used from multiple threads: reads run on a bounded pool of
 * independent connections and writes serialize on one write lane.
 */
typedef void zaxonlite_remote;

/*
 * Remote client options. Zero-initialize, then set:
 *   - seeds/seed_count: 1..36 addresses, "host:port" or "unix:<path>".
 *     A unix seed must be the only seed (one socket path names exactly
 *     one server).
 *   - tls_ca_path, tls_cert_path, tls_key_path: mutual TLS identity;
 *     all three together or none. Production TCP requires them.
 *   - auth_file_path: PSK provider file, loaded with the native
 *     regular-file, symlink, permission, and minimum-length checks.
 *   - allow_psk_only_loopback: development-only PSK TCP; requires
 *     auth_file_path, forbids TLS, and every seed must be a numeric
 *     loopback literal (127.0.0.1 or ::1).
 *   - pool_size: connection slots, clamped to 1..64; 0 selects
 *     min(32, max(4, 2 * seed_count)).
 *   - connect_timeout_ms: bounds each slot's first status probe;
 *     0 selects 5000.
 *   - operation_timeout_ms: bounds one write's retry window;
 *     0 selects 10000.
 *   - expected_database_id: with has_expected_database_id, the
 *     big-endian bytes of the cluster's 32-hex-digit database identity.
 *     The open-time probe otherwise pins whatever identity it sees;
 *     either way every slot's first probe must observe the pinned
 *     identity or fail with return code 3 (category 6).
 *   - write_admission_timeout_ms: bounds how long a write may wait for
 *     admission to the ordered write lane; 0 means unbounded. A write
 *     that misses the bound fails with return code 4 and category 2
 *     (busy): the admission timeout means the write never left the
 *     process, so it may be retried plainly.
 *
 * Comment history: write_admission_timeout_ms was appended before the
 * first release of this struct (it carries no size/version member, so
 * its layout freezes at release).
 */
typedef struct zaxonlite_remote_options {
    const char *const *seeds;
    size_t seed_count;
    const char *tls_ca_path;
    const char *tls_cert_path;
    const char *tls_key_path;
    const char *auth_file_path;
    bool allow_psk_only_loopback;
    size_t pool_size;
    uint64_t connect_timeout_ms;
    uint64_t operation_timeout_ms;
    bool has_expected_database_id;
    uint8_t expected_database_id[16];
    uint64_t write_admission_timeout_ms;
} zaxonlite_remote_options;

/*
 * Validates configuration, then probes one seed before returning:
 * opening succeeds only when at least one seed authenticates, reports
 * the expected database identity, and answers a client RPC (bounded by
 * connect_timeout_ms). The remaining pool slots dial lazily.
 */
int zaxonlite_remote_open(const zaxonlite_remote_options *options,
                          zaxonlite_remote **out_remote);

/*
 * Closes the pool and releases the handle. Calls racing the close fail
 * with return code 2; close waits until every in-flight call on the
 * pool has finished before any memory is released. An unresolved
 * pending write is abandoned locally and never re-executed. Accepts
 * NULL.
 */
void zaxonlite_remote_close(zaxonlite_remote *remote);

/*
 * Executes one prepared statement through the ordered write lane:
 * first-in-first-out admission, one replicated session, monotonically
 * increasing sequences, and same-session/same-sequence retry across
 * leader changes and ambiguous connection loss. If admission misses
 * write_admission_timeout_ms the call fails with return code 4 and
 * category 2 (busy); nothing was sent, so a plain retry is safe. If
 * the operation deadline expires with the fate still unknown, the
 * exact request is retained and this call (and every later write)
 * fails with return code 4 and the message "write pending: call
 * zaxonlite_remote_resolve_pending" until the pending write is
 * resolved. Remote RETURNING stays unsupported. A fresh (non-replayed)
 * write reports last_insert_rowid when the statement observably set
 * one; a REPLAYED session result retains only the change count, so
 * exec_out->has_last_insert_rowid stays false on replay (the session
 * table does not persist the rowid yet).
 */
int zaxonlite_remote_exec(zaxonlite_remote *remote, const char *sql,
                          const zaxonlite_value *values, size_t value_count,
                          zaxonlite_exec_result *exec_out);

/*
 * Atomic remote executemany: executes one prepared statement once per
 * row as ONE typed-v1 batch, ONE replicated transaction, and ONE
 * session sequence. `values` is a flat array of row_count rows of
 * per_row_count values each (every row binds the same statement
 * shape); row_count is bounded by the 1024-statement transaction
 * limit. exec_out->changes reports the whole batch's total, and any
 * per-row failure (a constraint violation on any row) rolls the entire
 * batch back on the server: either every row is applied or none is.
 * Admission, session, pending-write, and replay semantics match
 * zaxonlite_remote_exec.
 */
int zaxonlite_remote_exec_batch(zaxonlite_remote *remote, const char *sql,
                                const zaxonlite_value *values,
                                size_t per_row_count, size_t row_count,
                                zaxonlite_exec_result *exec_out);

/*
 * Runs one read-only typed query. `level` is 0 any, 1 leader,
 * 2 linearizable; `any` distributes over the read slots while the
 * leader levels follow the authenticated leader. `freshness_ms` 0 means
 * unset and is only meaningful with level 0. The result uses the same
 * opaque typed representation as local queries: read it with the
 * zaxonlite_result_* accessors and release it with
 * zaxonlite_result_close.
 */
int zaxonlite_remote_query(zaxonlite_remote *remote, const char *sql,
                           const zaxonlite_value *values, size_t value_count,
                           int level, uint64_t freshness_ms,
                           zaxonlite_result **out_result);

/*
 * Runs the typed ZDS 0009 search operation through the remote pool.
 * Identifier, candidate, weight, and embedding validation stays in the
 * server's native planner. Consistency, freshness, scheduling, and result
 * ownership match zaxonlite_remote_query.
 */
int zaxonlite_remote_search(zaxonlite_remote *remote,
                            const zaxonlite_search_options *options,
                            int level, uint64_t freshness_ms,
                            zaxonlite_result **out_result);

/*
 * Retries the retained pending write with its original session and
 * sequence until the server reports a definitive outcome: success, an
 * idempotent replay, or a definitive rejection (which proves the
 * statement never committed and never will). Fails with the
 * write-pending error while the fate stays unknown, and with code 2
 * when no write is pending.
 */
int zaxonlite_remote_resolve_pending(zaxonlite_remote *remote,
                                     zaxonlite_exec_result *exec_out);

/*
 * Raw status JSON from any healthy identity-checked member, for host
 * diagnostics. Release with zaxonlite_free.
 */
int zaxonlite_remote_status_json(zaxonlite_remote *remote, char **json_out);

/* The most recent error message for this remote handle. */
const char *zaxonlite_remote_last_error(zaxonlite_remote *remote);

/*
 * Stable category of the most recent error on this remote handle; the
 * values match zaxonlite_last_error_category.
 */
int zaxonlite_remote_last_error_category(zaxonlite_remote *remote);

#ifdef __cplusplus
}
#endif

#endif /* ZAXONLITE_H */
