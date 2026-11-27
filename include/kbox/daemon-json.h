/* SPDX-License-Identifier: MIT */
/* daemon-json.h - the daemon's RPC request parser.
 *
 * Every op arrives as one line of JSON; these are the accessors the op handlers
 * use. They are separated from daemon.c so the unit suite can link them.
 */
#ifndef KBOX_DAEMON_JSON_H
#define KBOX_DAEMON_JSON_H

#include <stddef.h>

const char *kbox_json_skip_ws(const char *p);
const char *kbox_json_parse_string(const char *p, char *out, size_t cap);
const char *kbox_json_find_field(const char *json, const char *key);

int kbox_json_get_str(const char *json, const char *key, char *out, size_t cap);
int kbox_json_get_int(const char *json, const char *key, long *out);
int kbox_json_get_bool(const char *json, const char *key, int def);

/* Parses a JSON array of strings into out[0..], returning the count. Each entry
 * is allocated to its own length: an argv entry is not bounded by a page, and a
 * fixed cap here silently truncates the command the guest then runs. */
int kbox_json_get_str_array(const char *json,
                            const char *key,
                            char **out,
                            int max_items);

/* Escapes s into dst[pos..], returning the new length: the reply path needs
 * the same understanding of what needs escaping as the request path. */
size_t kbox_json_escape_append(char *dst,
                               size_t cap,
                               size_t pos,
                               const char *s);

#endif /* KBOX_DAEMON_JSON_H */
