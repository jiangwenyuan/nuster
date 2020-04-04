/*
 * include/nuster/ring.h
 * This file defines everything related to nuster ring.
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

#ifndef _NUSTER_RING_H
#define _NUSTER_RING_H

#include <nuster/common.h>

typedef struct nst_data_element {
    struct nst_data_element  *next;

    int                       info;
    char                      data[0];
} nst_data_element_t;

/*
 * A nst_data contains a complete http response data,
 * and is pointed by nst_entry->data.
 * All nst_data are stored in a circular singly linked list
 */
typedef struct nst_data {
    struct nst_data     *next;

    int                  clients;
    int                  invalid;

    nst_data_element_t  *element;
} nst_data_t;




/*
 * A nst_ring_data contains a complete http response data,
 * and is pointed by nst_entry->data.
 * All nst_ring_data are stored in a circular singly linked list
 */
typedef struct nst_ring_element {
    struct nst_ring_element     *next;

    int                          info;
    char                         data[0];
} nst_ring_element_t;

typedef struct nst_ring_data {
    struct nst_ring_data        *next;

    int                          clients;
    int                          invalid;

    nst_ring_element_t          *element;
} nst_ring_data_t;

typedef struct nst_ring {
    nst_memory_t                *memory;

    nst_ring_data_t             *head;
    nst_ring_data_t             *tail;

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t             mutex;
#else
    unsigned int                waiters;
#endif
} nst_ring_t;


static inline int
nst_ring_data_invalid(nst_ring_data_t *data) {

    if(data->invalid) {

        if(!data->clients) {
            return NST_OK;
        }
    }

    return NST_ERR;
}

int nst_ring_init(nst_ring_t *ring, nst_memory_t *memory);

#endif /* _NUSTER_RING_H */
