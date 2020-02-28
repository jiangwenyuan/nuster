/*
 * include/nuster/nuster.h
 * This file defines everything related to nuster.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef _NUSTER_H
#define _NUSTER_H

#define NUSTER_VERSION    "5.0.0.21-dev1"
#define NUSTER_COPYRIGHT                                                     \
    "2017-present, Jiang Wenyuan, <koubunen AT gmail DOT com >"

#include <common/chunk.h>
#include <types/applet.h>
#include <import/xxhash.h>

#include <nuster/cache.h>
#include <nuster/nosql.h>

struct nst_proxy {
    struct nst_rule2 *rule;
    struct nst_key2  *key;

    int               rule_cnt;
    int               key_cnt;
};

struct nuster {
    struct nst_cache *cache;
    struct nst_nosql *nosql;

    struct {
        struct applet cache_engine;
        struct applet cache_manager;
        struct applet cache_stats;
        struct applet nosql_engine;
        struct applet cache_disk_engine;
    } applet;

    struct nst_proxy **proxy;
};

extern struct nuster nuster;


void nuster_init();

/* parser */
const char *nst_parse_size(const char *text, uint64_t *ret);
const char *nst_parse_time(const char *text, int len, unsigned *ret);
int nuster_parse_global_cache(const char *file, int linenum, char **args);
int nuster_parse_global_nosql(const char *file, int linenum, char **args);

static inline void nuster_housekeeping() {
    nst_cache_housekeeping();
    nst_nosql_housekeeping();
}

static inline int nuster_check_applet(struct stream *s, struct channel *req,
        struct proxy *px) {

    return (nst_nosql_check_applet(s, req, px) ||
            nst_cache_manager(s, req, px) ||
            nst_cache_stats(s, req, px));
}

int nst_test_rule(struct nst_rule *rule, struct stream *s, int res);

static inline uint64_t nst_hash(const char *buf, size_t len) {
    return XXH64(buf, len, 0);
}

struct buffer *nst_key_init(struct nst_memory *memory);
int nst_key_advance(struct nst_memory *memory, struct buffer *key, int step);
int nst_key_append(struct nst_memory *memory, struct buffer *key, char *str,
        int len);

int nst_ci_send(struct channel *chn, int len);

#endif /* _NUSTER_H */
