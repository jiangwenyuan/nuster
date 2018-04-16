/*
 * include/nuster/common.h
 * This file defines everything related to nuster common.
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

#ifndef _NUSTER_COMMON_H
#define _NUSTER_COMMON_H

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
#include <pthread.h>
#else
#ifdef USE_SYSCALL_FUTEX
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#endif
#endif

enum {
    NUSTER_HTTP_200 = 0,
    NUSTER_HTTP_400,
    NUSTER_HTTP_404,
    NUSTER_HTTP_500,
    NUSTER_HTTP_SIZE
};

enum nuster_rule_key_type {
    NST_CACHE_KEY_METHOD = 1,                /* method:    GET, POST... */
    NST_CACHE_KEY_SCHEME,                    /* scheme:    http, https */
    NST_CACHE_KEY_HOST,                      /* host:      Host header   */
    NST_CACHE_KEY_URI,                       /* uri:       first slash to end of the url */
    NST_CACHE_KEY_PATH,                      /* path:      first slach to question mark */
    NST_CACHE_KEY_DELIMITER,                 /* delimiter: '?' or '' */
    NST_CACHE_KEY_QUERY,                     /* query:     question mark to end of the url, or empty */
    NST_CACHE_KEY_PARAM,                     /* param:     query key/value pair */
    NST_CACHE_KEY_HEADER,                    /* header */
    NST_CACHE_KEY_COOKIE,                    /* cookie */
    NST_CACHE_KEY_BODY,                      /* body   */
};

struct nuster_str {
    char *data;
    int   len;
};

/* get current timestamp in milliseconds */
static inline uint64_t get_current_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void nuster_debug(const char *fmt, ...);

#endif /* _NUSTER_COMMON_H */
