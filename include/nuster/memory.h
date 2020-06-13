/*
 * include/nuster/memory.h
 * This file defines everything related to nuster memory.
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

#ifndef _NUSTER_MEMORY_H
#define _NUSTER_MEMORY_H

#include <nuster/common.h>


/*
 * A nst_memory_object contains a complete http response data
 * All nst_memory_object are stored in a circular singly linked list
 */
typedef struct nst_memory_item {
    struct nst_memory_item      *next;

    uint32_t                     info;
    char                         data[0];
} nst_memory_item_t;

typedef struct nst_memory_object {
    struct nst_memory_object    *next;

    int                          clients;
    int                          invalid;

    nst_memory_item_t           *item;
} nst_memory_obj_t;

typedef struct nst_memory {
    nst_shmem_t                 *shmem;

    nst_memory_obj_t            *head;
    nst_memory_obj_t            *tail;

    uint64_t                     count;
    uint64_t                     invalid;

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t              mutex;
#else
    unsigned int                 waiters;
#endif
} nst_memory_t;


int nst_memory_init(nst_memory_t *mem, nst_shmem_t *shmem);
void nst_memory_cleanup(nst_memory_t *mem);
static inline void
nst_memory_incr_invalid(nst_memory_t *mem) {
    nst_shctx_lock(mem);
    mem->invalid++;
    nst_shctx_unlock(mem);
}


static inline nst_memory_item_t *
nst_memory_alloc_item(nst_memory_t *mem, uint32_t size) {
    return nst_shmem_alloc(mem->shmem, sizeof(nst_memory_item_t) + size);
}

nst_memory_obj_t *nst_memory_obj_create(nst_memory_t *mem);

int nst_memory_obj_append(nst_memory_t *mem, nst_memory_obj_t *obj, nst_memory_item_t **tail,
        const char *buf, uint32_t len, uint32_t info);

static inline int
nst_memory_obj_finish(nst_memory_t *mem, nst_memory_obj_t *obj) {
    obj->invalid = 0;

    return NST_OK;
}

static inline void
nst_memory_obj_abort(nst_memory_t *mem, nst_memory_obj_t *obj) {

    if(obj) {
        obj->invalid = 1;
    }

    nst_memory_incr_invalid(mem);
}

static inline int
nst_memory_obj_invalid(nst_memory_obj_t *obj) {

    if(obj->invalid) {

        if(!obj->clients) {
            return NST_OK;
        }
    }

    return NST_ERR;
}

static inline void
nst_memory_obj_attach(nst_memory_t *mem, nst_memory_obj_t *obj) {
    nst_shctx_lock(mem);
    obj->clients++;
    nst_shctx_unlock(mem);
}

static inline void
nst_memory_obj_detach(nst_memory_t *mem, nst_memory_obj_t *obj) {
    nst_shctx_lock(mem);
    obj->clients--;
    nst_shctx_unlock(mem);
}


#endif /* _NUSTER_MEMORY_H */
