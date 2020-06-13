/*
 * include/nuster/shctx.h
 * This file defines everything related to nuster shctx.
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

#ifndef _NUSTER_SHCTX_H
#define _NUSTER_SHCTX_H

#include <nuster/common.h>

/* lock, borrowed from shctx.c */

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED

static inline int
_nst_shctx_init(pthread_mutex_t *mutex) {
    pthread_mutexattr_t  attr;

    if(pthread_mutexattr_init(&attr)) {
        return NST_ERR;
    }

    if(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
        return NST_ERR;
    }

    if(pthread_mutex_init(mutex, &attr)) {
        return NST_ERR;
    }

    return NST_OK;
}

#define nst_shctx_init(shctx)   _nst_shctx_init(&(shctx)->mutex)
#define nst_shctx_lock(shctx)   pthread_mutex_lock(&(shctx)->mutex)
#define nst_shctx_unlock(shctx) pthread_mutex_unlock(&(shctx)->mutex)

#else

#ifdef USE_SYSCALL_FUTEX
static inline void
_shctx_wait4lock(unsigned int *count, unsigned int *uaddr, int value) {

    syscall(SYS_futex, uaddr, FUTEX_WAIT, value, NULL, 0, 0);
}

static inline void
_shctx_awakelocker(unsigned int *uaddr) {
    syscall(SYS_futex, uaddr, FUTEX_WAKE, 1, NULL, 0, 0);
}

#else /* internal spin lock */

#if defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)
static inline void
relax() {
    __asm volatile("rep;nop\n" ::: "memory");
}
#else /* if no x86_64 or i586 arch: use less optimized but generic asm */
static inline void
relax() {
    __asm volatile("" ::: "memory");
}
#endif

static inline void
_shctx_wait4lock(unsigned int *count, unsigned int *uaddr, int value) {

    int  i;

    for(i = 0; i < *count; i++) {
        relax();
        relax();

        if(*uaddr != value) {
            return;
        }
    }

   *count = (unsigned char)((*count << 1) + 1);
}

#define _shctx_awakelocker(a)

#endif

#if defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)
static inline unsigned int
xchg(unsigned int *ptr, unsigned int x) {
    __asm volatile("lock xchgl %0,%1"
            : "=r" (x), "+m" (*ptr)
            : "0" (x)
            : "memory");

    return x;
}

static inline unsigned int
cmpxchg(unsigned int *ptr, unsigned int old, unsigned int new) {

    unsigned int  ret;

    __asm volatile("lock cmpxchgl %2,%1"
            : "=a" (ret), "+m" (*ptr)
            : "r" (new), "0" (old)
            : "memory");

    return ret;
}

static inline unsigned char
atomic_dec(unsigned int *ptr) {
    unsigned char  ret;

    __asm volatile("lock decl %0\n"
            "setne %1\n"
            : "+m" (*ptr), "=qm" (ret)
            :
            : "memory");

    return ret;
}

#else /* if no x86_64 or i586 arch: use less optimized gcc >= 4.1 built-ins */
static inline unsigned int
xchg(unsigned int *ptr, unsigned int x) {
    return __sync_lock_test_and_set(ptr, x);
}

static inline unsigned int
cmpxchg(unsigned int *ptr, unsigned int old, unsigned int new) {

    return __sync_val_compare_and_swap(ptr, old, new);
}

static inline unsigned char
atomic_dec(unsigned int *ptr) {
    return __sync_sub_and_fetch(ptr, 1) ? 1 : 0;
}

#endif

static inline void
_shctx_lock(unsigned int *waiters) {
    unsigned int  x;
    unsigned int  count = 3;

    x = cmpxchg(waiters, 0, 1);

    if (x) {

        if (x != 2) {
            x = xchg(waiters, 2);
        }

        while (x) {
            _shctx_wait4lock(&count, waiters, 2);
            x = xchg(waiters, 2);
        }

    }

}

static inline void
_shctx_unlock(unsigned int *waiters) {

    if (atomic_dec(waiters)) {
        *waiters = 0;
        _shctx_awakelocker(waiters);
    }

}

static inline int
_nst_shctx_init(unsigned int *waiters) {
    *waiters = 0;

    return NST_OK;
}
#define nst_shctx_init(shctx)   _nst_shctx_init(&(shctx)->waiters)
#define nst_shctx_lock(shctx)   _shctx_lock(&(shctx)->waiters)
#define nst_shctx_unlock(shctx) _shctx_unlock(&(shctx)->waiters)

#endif

#endif /* _NUSTER_SHCTX_H */
