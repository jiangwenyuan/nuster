/*
 * include/types/cache.h
 * This file defines everything related to cache.
 *
 * Copyright (C) 2017, [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
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

#ifndef _PROTO_CACHE_H
#define _PROTO_CACHE_H

#include <common/config.h>

#include <types/proxy.h>
#include <types/filters.h>
#include <types/cache.h>

/* dict */
int cache_dict_init();
struct cache_entry *cache_dict_get(uint64_t hash, const char *key);
struct cache_entry *cache_dict_set(uint64_t hash, char *key);
void cache_dict_rehash();
void cache_dict_cleanup();


/* engine */
void cache_debug(const char *fmt, ...);
void cache_init();
void cache_housekeeping();
int cache_full();
char *cache_build_key(struct cache_key **pck, struct stream *s, struct http_msg *msg);
uint64_t cache_hash_key(const char *key);
void cache_create(struct cache_ctx *ctx, char *key, uint64_t hash);
int cache_update(struct cache_ctx *ctx, struct http_msg *msg, long msg_len);
void cache_finish(struct cache_ctx *ctx);
void cache_abort(struct cache_ctx *ctx);
struct cache_data *cache_exists(const char *key, uint64_t hash);
struct cache_data *cache_data_new();
void cache_hit(struct stream *s, struct stream_interface *si,
                struct channel *req, struct channel *res, struct cache_data *data);
struct cache_rule_stash *cache_stash_rule(struct cache_ctx *ctx,
                struct cache_rule *rule, char *key, uint64_t hash);
int cache_test_rule(struct cache_rule *rule, struct stream *s, int res);


/* parser */
int cache_parse_filter(char **args, int *cur_arg, struct proxy *px,
                struct flt_conf *fconf, char **err, void *private);
int cache_parse_rule(char **args, int section, struct proxy *proxy,
                struct proxy *defpx, const char *file, int line, char **err);
const char *cache_parse_size(const char *text, uint64_t *ret);

/* get current timestamp in seconds */
static inline uint64_t _get_current_timestamp() {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return tv.tv_sec;
}

#endif /* _PROTO_CACHE_H */
