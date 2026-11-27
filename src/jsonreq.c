/* SPDX-License-Identifier: MIT */
/* jsonreq.c - the daemon RPC request parser.
 *
 * Kept out of daemon.c so it can be unit-tested: daemon.c pulls in LKL and
 * cannot link into the unit suite, which is how a fixed-size buffer here went
 * unnoticed until a >4 KiB argv reached a real workload.
 */

#include "kbox/daemon-json.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *kbox_json_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    return p;
}

const char *kbox_json_parse_string(const char *p, char *out, size_t cap)
{
    if (*p != '"')
        return NULL;
    p++;
    size_t pos = 0;
    while (*p && *p != '"') {
        unsigned char c = (unsigned char) *p++;
        if (c == '\\') {
            unsigned char esc = (unsigned char) *p;
            if (!esc)
                return NULL;
            p++;
            switch (esc) {
            case '"':
            case '\\':
            case '/':
                c = esc;
                break;
            case 'n':
                c = '\n';
                break;
            case 'r':
                c = '\r';
                break;
            case 't':
                c = '\t';
                break;
            case 'u': {
                unsigned int code = 0;
                for (int i = 0; i < 4 && p[i]; i++) {
                    char h = p[i];
                    code <<= 4;
                    if (h >= '0' && h <= '9')
                        code |= (unsigned int) (h - '0');
                    else if (h >= 'a' && h <= 'f')
                        code |= (unsigned int) (h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F')
                        code |= (unsigned int) (h - 'A' + 10);
                }
                if (strlen(p) >= 4)
                    p += 4;
                c = (unsigned char) (code & 0xff);
                break;
            }
            default:
                c = esc;
                break;
            }
        }
        if (out && pos + 1 < cap)
            out[pos++] = (char) c;
    }
    if (*p != '"')
        return NULL;
    if (out && cap > 0)
        out[pos] = '\0';
    return p + 1;
}

static const char *kbox_json_skip_value(const char *p)
{
    p = kbox_json_skip_ws(p);
    if (*p == '"')
        return kbox_json_parse_string(p, NULL, 0);
    if (*p == '{' || *p == '[') {
        char open = *p;
        char close_ch = (open == '{') ? '}' : ']';
        int depth = 1;
        p++;
        while (*p && depth > 0) {
            if (*p == '"') {
                p = kbox_json_parse_string(p, NULL, 0);
                if (!p)
                    return NULL;
                continue;
            }
            if (*p == open)
                depth++;
            else if (*p == close_ch)
                depth--;
            p++;
        }
        return depth == 0 ? p : NULL;
    }
    while (*p && *p != ',' && *p != '}' && *p != ']' &&
           !isspace((unsigned char) *p))
        p++;
    return p;
}

const char *kbox_json_find_field(const char *json, const char *key)
{
    const char *p = kbox_json_skip_ws(json);
    if (*p != '{')
        return NULL;
    p = kbox_json_skip_ws(p + 1);

    char kbuf[128];
    while (*p && *p != '}') {
        if (*p == ',') {
            p = kbox_json_skip_ws(p + 1);
            continue;
        }
        const char *next = kbox_json_parse_string(p, kbuf, sizeof(kbuf));
        if (!next)
            return NULL;
        p = kbox_json_skip_ws(next);
        if (*p != ':')
            return NULL;
        p = kbox_json_skip_ws(p + 1);
        if (strcmp(kbuf, key) == 0)
            return p;
        p = kbox_json_skip_value(p);
        if (!p)
            return NULL;
        p = kbox_json_skip_ws(p);
    }
    return NULL;
}

int kbox_json_get_str(const char *json, const char *key, char *out, size_t cap)
{
    const char *v = kbox_json_find_field(json, key);
    if (!v || *v != '"')
        return -1;
    return kbox_json_parse_string(v, out, cap) ? 0 : -1;
}

int kbox_json_get_int(const char *json, const char *key, long *out)
{
    const char *v = kbox_json_find_field(json, key);
    if (!v)
        return -1;
    char *endp = NULL;
    errno = 0;
    long val = strtol(v, &endp, 10);
    if (errno || endp == v)
        return -1;
    *out = val;
    return 0;
}

int kbox_json_get_bool(const char *json, const char *key, int def)
{
    const char *v = kbox_json_find_field(json, key);
    if (!v)
        return def;
    if (strncmp(v, "true", 4) == 0)
        return 1;
    if (strncmp(v, "false", 5) == 0)
        return 0;
    return def;
}

int kbox_json_get_str_array(const char *json,
                            const char *key,
                            char **out,
                            int max_items)
{
    const char *v = kbox_json_find_field(json, key);
    if (!v || *v != '[')
        return 0;
    const char *p = kbox_json_skip_ws(v + 1);
    int count = 0;

    while (*p && *p != ']' && count < max_items) {
        if (*p == ',') {
            p = kbox_json_skip_ws(p + 1);
            continue;
        }
        /* Size the buffer to the literal rather than a fixed page: an argv
         * entry is not bounded by 4096 and a short cap silently truncates it.
         */
        const char *q = p;
        size_t need = 0;
        if (*q == '"') {
            q++;
            while (*q && *q != '"') {
                if (*q == '\\' && q[1])
                    q++;
                q++;
                need++;
            }
        }
        char *tmp = malloc(need + 1);
        if (!tmp)
            break;
        const char *next = kbox_json_parse_string(p, tmp, need + 1);
        if (!next) {
            free(tmp);
            break;
        }
        out[count] = tmp;
        if (out[count])
            count++;
        else
            free(tmp);
        p = kbox_json_skip_ws(next);
    }
    return count;
}

static size_t json_escape_append(char *dst,
                                 size_t cap,
                                 size_t pos,
                                 const char *s)
{
    for (const unsigned char *p = (const unsigned char *) s; *p; p++) {
        if (pos + 8 >= cap)
            break;
        if (*p == '"' || *p == '\\') {
            dst[pos++] = '\\';
            dst[pos++] = (char) *p;
        } else if (*p == '\n') {
            dst[pos++] = '\\';
            dst[pos++] = 'n';
        } else if (*p == '\r') {
            dst[pos++] = '\\';
            dst[pos++] = 'r';
        } else if (*p == '\t') {
            dst[pos++] = '\\';
            dst[pos++] = 't';
        } else if (*p < 0x20) {
            int n = snprintf(dst + pos, cap - pos, "\\u%04x", *p);
            if (n > 0)
                pos += (size_t) n;
        } else {
            dst[pos++] = (char) *p;
        }
    }
    if (pos < cap)
        dst[pos] = '\0';
    return pos;
}

size_t kbox_json_escape_append(char *dst, size_t cap, size_t pos, const char *s)
{
    for (const unsigned char *p = (const unsigned char *) s; *p; p++) {
        if (pos + 8 >= cap)
            break;
        if (*p == '"' || *p == '\\') {
            dst[pos++] = '\\';
            dst[pos++] = (char) *p;
        } else if (*p == '\n') {
            dst[pos++] = '\\';
            dst[pos++] = 'n';
        } else if (*p == '\r') {
            dst[pos++] = '\\';
            dst[pos++] = 'r';
        } else if (*p == '\t') {
            dst[pos++] = '\\';
            dst[pos++] = 't';
        } else if (*p < 0x20) {
            int n = snprintf(dst + pos, cap - pos, "\\u%04x", *p);
            if (n > 0)
                pos += (size_t) n;
        } else {
            dst[pos++] = (char) *p;
        }
    }
    if (pos < cap)
        dst[pos] = '\0';
    return pos;
}
