/* Test adapter for the exact pinned libinjection sources, never linked into Sibuna. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "libinjection_sqli.h"
#include "libinjection.h"
#include "libinjection_html5.h"

struct crs_oracle_token {
    size_t position;
    size_t length;
    unsigned char count;
    unsigned char kind;
    unsigned char open;
    unsigned char close;
    unsigned char value[32];
};

struct crs_oracle_stats {
    size_t tokens;
    size_t dash_comment;
    size_t hash;
    size_t folds;
};

static void save_token(struct crs_oracle_token *out, const stoken_t *token)
{
    out->position = token->pos;
    out->length = token->len;
    out->count = (unsigned char)token->count;
    out->kind = (unsigned char)token->type;
    out->open = (unsigned char)token->str_open;
    out->close = (unsigned char)token->str_close;
    memcpy(out->value, token->val, 32);
}

static void save_stats(struct crs_oracle_stats *out, const struct libinjection_sqli_state *state)
{
    out->tokens = state->stats_tokens;
    out->dash_comment = state->stats_comment_ddx;
    out->hash = state->stats_comment_hash;
    out->folds = state->stats_folds;
}

size_t crs_oracle_tokens(const unsigned char *input, size_t length, int flags,
                        struct crs_oracle_token *output, size_t capacity,
                        struct crs_oracle_stats *stats)
{
    struct libinjection_sqli_state state;
    size_t count = 0;
    libinjection_sqli_init(&state, (const char *)input, length, flags);
    while (libinjection_sqli_tokenize(&state)) {
        const stoken_t *token = state.current;
        if (count == capacity) return SIZE_MAX;
        save_token(&output[count], token);
        count += 1;
    }
    save_stats(stats, &state);
    return count;
}

size_t crs_oracle_fingerprint(const unsigned char *input, size_t length, int flags,
                            struct crs_oracle_token *output, struct crs_oracle_stats *stats,
                            unsigned char *signature)
{
    struct libinjection_sqli_state state;
    size_t index;
    size_t count;
    libinjection_sqli_init(&state, (const char *)input, length, flags);
    libinjection_sqli_fingerprint(&state, flags);
    count = strlen(state.fingerprint);
    for (index = 0; index < count; index++) save_token(&output[index], &state.tokenvec[index]);
    save_stats(stats, &state);
    memcpy(signature, state.fingerprint, 8);
    return count;
}

int crs_oracle_detect(const unsigned char *input, size_t length, unsigned char *fingerprint)
{
    memset(fingerprint, 0, 8);
    return libinjection_sqli((const char *)input, length, (char *)fingerprint);
}

struct crs_oracle_html_token {
    size_t position;
    size_t length;
    unsigned char kind;
};

size_t crs_oracle_html(const unsigned char *input, size_t length, int flags,
                      struct crs_oracle_html_token *output, size_t capacity)
{
    h5_state_t state;
    size_t count = 0;
    libinjection_h5_init(&state, (const char *)input, length, flags);
    while (libinjection_h5_next(&state)) {
        if (count == capacity) return SIZE_MAX;
        output[count].position = (size_t)(state.token_start - (const char *)input);
        output[count].length = state.token_len;
        output[count].kind = (unsigned char)state.token_type;
        count += 1;
    }
    return count;
}
