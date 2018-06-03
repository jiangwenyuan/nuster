/*
 * include/nuster/nuster.h
 * This file defines everything related to nuster.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _NUSTER_H
#define _NUSTER_H

#define NUSTER_VERSION     HAPROXY_VERSION".1"
#define NUSTER_COPYRIGHT  "2017-2018, Jiang Wenyuan, <koubunen AT gmail DOT com >"

#include <nuster/cache.h>
#include <nuster/nosql.h>

#include <common/chunk.h>
#include <types/applet.h>

struct nuster {
    struct nst_cache *cache;
    struct nst_nosql *nosql;
    struct {
        struct applet cache_engine;
        struct applet cache_manager;
        struct applet cache_stats;
        struct applet nosql_engine;
    } applet;
};

extern struct nuster nuster;

extern const char *nuster_http_msgs[NUSTER_HTTP_SIZE];
extern struct chunk nuster_http_msg_chunks[NUSTER_HTTP_SIZE];

void nuster_init();
void nuster_response(struct stream *s, struct chunk *msg);

/* parser */
const char *nuster_parse_size(const char *text, uint64_t *ret);
const char *nuster_parse_time(const char *text, int len, unsigned *ret);
int nuster_parse_global_cache(const char *file, int linenum, char **args, int kwm);
int nuster_parse_global_nosql(const char *file, int linenum, char **args, int kwm);

static inline void nuster_housekeeping() {
    nst_cache_housekeeping();
    nst_nosql_housekeeping();
}

static inline int nuster_check_applet (struct stream *s, struct channel *req, struct proxy *px) {
    return (nst_nosql_check_applet(s, req, px) ||
            nst_cache_manager(s, req, px) ||
            nst_cache_stats(s, req, px));
}

int nuster_test_rule(struct nuster_rule *rule, struct stream *s, int res);

#endif /* _NUSTER_H */
