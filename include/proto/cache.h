/*
 * include/types/cache.h
 * This file defines everything related to cache.
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

#ifndef _PROTO_CACHE_H
#define _PROTO_CACHE_H

#include <common/config.h>

#include <types/global.h>
#include <types/proxy.h>
#include <types/filters.h>
#include <types/cache.h>

/* dict */
int cache_dict_init();
struct cache_entry *cache_dict_get(const char *key, uint64_t hash);
struct cache_entry *cache_dict_set(const char *key, uint64_t hash, struct cache_ctx *ctx);
void cache_dict_rehash();
void cache_dict_cleanup();


/* engine */
void cache_debug(const char *fmt, ...);
void cache_init();
void cache_housekeeping();
void cache_prebuild_key(struct cache_ctx *ctx, struct stream *s, struct http_msg *msg);
char *cache_build_key(struct cache_ctx *ctx, struct cache_key **pck, struct stream *s,
        struct http_msg *msg);
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
int cache_purge(struct stream *s, struct channel *req, struct proxy *px);
int cache_manager(struct stream *s, struct channel *req, struct proxy *px);


/* parser */
int cache_parse_filter(char **args, int *cur_arg, struct proxy *px,
        struct flt_conf *fconf, char **err, void *private);
int cache_parse_rule(char **args, int section, struct proxy *proxy,
        struct proxy *defpx, const char *file, int line, char **err);
const char *cache_parse_size(const char *text, uint64_t *ret);
const char *cache_parse_time(const char *text, int len, unsigned *ret);

/* get current timestamp in seconds */
static inline uint64_t _get_current_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

/* get current timestamp in milliseconds */
static inline uint64_t get_current_timestamp() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* memory */
#define bit_set(bit, i) (bit |= 1 << i)
#define bit_clear(bit, i) (bit &= ~(1 << i))
#define bit_used(bit, i) (((bit) >> (i)) & 1)
#define bit_unused(bit, i) ((((bit) >> (i)) & 1) == 0)
static inline void _nuster_memory_block_set_type(struct nuster_memory_ctrl *block, uint8_t type) {
    *(uint8_t *)(&block->info) = type;
}
static inline void _nuster_memory_block_set_inited(struct nuster_memory_ctrl *block) {
    bit_set(block->info, 9);
}
static inline int _nuster_memory_block_is_inited(struct nuster_memory_ctrl *block) {
    return bit_used(block->info, 9);
}
static inline void _nuster_memory_block_set_bitmap(struct nuster_memory_ctrl *block) {
    bit_set(block->info, 10);
}
static inline void _nuster_memory_block_set_full(struct nuster_memory_ctrl *block) {
    bit_set(block->info, 11);
}
static inline int _nuster_memory_block_is_full(struct nuster_memory_ctrl *block) {
    return bit_used(block->info, 11);
}
static inline void _nuster_memory_block_clear_full(struct nuster_memory_ctrl *block) {
    bit_clear(block->info, 11);
}

struct nuster_memory *nuster_memory_create(char *name, uint64_t size, uint32_t block_size, uint32_t chunk_size);
void *nuster_memory_alloc(struct nuster_memory *memory, int size);
void nuster_memory_free(struct nuster_memory *memory, void *p);

/* cache memory */
static inline void *cache_memory_alloc(struct pool_head *pool, int size) {
    if(global.cache.share) {
        return nuster_memory_alloc(global.cache.memory, size);
    } else {
        return pool_alloc2(pool);
    }
}
static inline void cache_memory_free(struct pool_head *pool, void *p) {
    if(global.cache.share) {
        return nuster_memory_free(global.cache.memory, p);
    } else {
        return pool_free2(pool, p);
    }
}

/* stats */
void cache_stats_update_used_mem(int i);
int cache_stats_init();
int cache_stats_full();


/* lock, borrowed from shctx.c */
#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
#include <pthread.h>
#else
#ifdef USE_SYSCALL_FUTEX
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#endif
#endif

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED

static inline int _nuster_shctx_init(pthread_mutex_t *mutex) {
    if(global.cache.share) {
        pthread_mutexattr_t attr;
        if(pthread_mutexattr_init(&attr)) {
            return 0;
        }
        if(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
            return 0;
        }
        if(pthread_mutex_init(mutex, &attr)) {
            return 0;
        }
    }
    return 1;
}

#define nuster_shctx_init(shctx)   _nuster_shctx_init(&(shctx)->mutex)
#define nuster_shctx_lock(shctx)   if (global.cache.share) pthread_mutex_lock(&(shctx)->mutex)
#define nuster_shctx_unlock(shctx) if (global.cache.share) pthread_mutex_unlock(&(shctx)->mutex)

#else

#ifdef USE_SYSCALL_FUTEX
static inline void _shctx_wait4lock(unsigned int *count, unsigned int *uaddr, int value) {
    syscall(SYS_futex, uaddr, FUTEX_WAIT, value, NULL, 0, 0);
}

static inline void _shctx_awakelocker(unsigned int *uaddr) {
    syscall(SYS_futex, uaddr, FUTEX_WAKE, 1, NULL, 0, 0);
}

#else /* internal spin lock */

#if defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)
static inline void relax() {
    __asm volatile("rep;nop\n" ::: "memory");
}
#else /* if no x86_64 or i586 arch: use less optimized but generic asm */
static inline void relax() {
    __asm volatile("" ::: "memory");
}
#endif

static inline void _shctx_wait4lock(unsigned int *count, unsigned int *uaddr, int value) {
    int i;

    for (i = 0; i < *count; i++) {
        relax();
        relax();
    }
    *count = *count << 1;
}

#define _shctx_awakelocker(a)

#endif

#if defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)
static inline unsigned int xchg(unsigned int *ptr, unsigned int x) {
    __asm volatile("lock xchgl %0,%1"
            : "=r" (x), "+m" (*ptr)
            : "0" (x)
            : "memory");
    return x;
}

static inline unsigned int cmpxchg(unsigned int *ptr, unsigned int old, unsigned int new) {
    unsigned int ret;

    __asm volatile("lock cmpxchgl %2,%1"
            : "=a" (ret), "+m" (*ptr)
            : "r" (new), "0" (old)
            : "memory");
    return ret;
}

static inline unsigned char atomic_dec(unsigned int *ptr) {
    unsigned char ret;
    __asm volatile("lock decl %0\n"
            "setne %1\n"
            : "+m" (*ptr), "=qm" (ret)
            :
            : "memory");
    return ret;
}

#else /* if no x86_64 or i586 arch: use less optimized gcc >= 4.1 built-ins */
static inline unsigned int xchg(unsigned int *ptr, unsigned int x) {
    return __sync_lock_test_and_set(ptr, x);
}

static inline unsigned int cmpxchg(unsigned int *ptr, unsigned int old, unsigned int new) {
    return __sync_val_compare_and_swap(ptr, old, new);
}

static inline unsigned char atomic_dec(unsigned int *ptr) {
    return __sync_sub_and_fetch(ptr, 1) ? 1 : 0;
}

#endif

static inline void _shctx_lock(unsigned int *waiters) {
    unsigned int x;
    unsigned int count = 4;

    x = cmpxchg(waiters, 0, 1);
    if (x) {
        if (x != 2)
            x = xchg(waiters, 2);

        while (x) {
            _shctx_wait4lock(&count, waiters, 2);
            x = xchg(waiters, 2);
        }
    }
}

static inline void _shctx_unlock(unsigned int *waiters) {
    if (atomic_dec(waiters)) {
        *waiters = 0;
        _shctx_awakelocker(waiters);
    }
}

static inline int _nuster_shctx_init(unsigned int *waiters) {
    *waiters = 0;
    return 1;
}
#define nuster_shctx_init(shctx)   _nuster_shctx_init(&(shctx)->waiters)
#define nuster_shctx_lock(shctx)   if (global.cache.share) _shctx_lock(&(shctx)->waiters)
#define nuster_shctx_unlock(shctx) if (global.cache.share) _shctx_unlock(&(shctx)->waiters)

#endif

#endif /* _PROTO_CACHE_H */
