/* Test adapter for the exact pinned libinjection sources, never linked into Sibuna. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "libinjection_sqli.h"

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
};

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
        output[count].position = token->pos;
        output[count].length = token->len;
        output[count].count = (unsigned char)token->count;
        output[count].kind = (unsigned char)token->type;
        output[count].open = (unsigned char)token->str_open;
        output[count].close = (unsigned char)token->str_close;
        memcpy(output[count].value, token->val, 32);
        count += 1;
    }
    stats->tokens = state.stats_tokens;
    stats->dash_comment = state.stats_comment_ddx;
    stats->hash = state.stats_comment_hash;
    return count;
}
