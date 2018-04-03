/*
 * include/nuster/memory.h
 * This file defines everything related to nuster memory.
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

#ifndef _NUSTER_MEMORY_H
#define _NUSTER_MEMORY_H

#include <nuster/common.h>

#define NUSTER_MEMORY_BLOCK_MIN_SIZE      4096ULL
#define NUSTER_MEMORY_BLOCK_MIN_SHIFT     12
#define NUSTER_MEMORY_CHUNK_MIN_SIZE      8ULL
#define NUSTER_MEMORY_CHUNK_MIN_SHIFT     3
#define NUSTER_MEMORY_BLOCK_MAX_SIZE      1024 * 1024 * 2
#define NUSTER_MEMORY_BLOCK_MAX_SHIFT     21
#define NUSTER_MEMORY_INFO_BITMAP_BITS    32


/* start                                 alignment                   stop
 * |                                     |   |                       |
 * |_______|_0_|_...._|_M_|_0_|_..._|_N__|_*_|__0__|__...__|__N__|_*_|
 *         |              |                  |             |     |
 *         chunk        block              begin         end   <bitmap>
 *
 *
 */

/*
 * info: | bitmap: 32 | reserved: 24 | 1 | full: 1 | bitmap: 1 | inited: 1 | type: 4 |
 * info: | bitmap: 32 | reserved: 16 | 5 | full: 1 | bitmap: 1 | inited: 1 | type: 8 |
 * bitmap: points to bitmap area, doesn't change once set
 * chunk size[n]: 1<<(NUSTER_MEMORY_CHUNK_MIN_SHIFT + n)
 */
struct nuster_memory_ctrl {
    uint64_t                   info;
    uint8_t                   *bitmap;

    struct nuster_memory_ctrl *prev;
    struct nuster_memory_ctrl *next;
};

struct nuster_memory {
    uint8_t                    *start;
    uint8_t                    *stop;
    uint8_t                    *bitmap;
    char                        name[16];
#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t             mutex;
#else
    unsigned int                waiters;
#endif

    uint32_t                    block_size;  /* max memory can be allocated */
    uint32_t                    chunk_size;  /* min memory can be allocated */
    int                         chunk_shift;
    int                         block_shift;

    int                         chunks;
    int                         blocks;
    struct nuster_memory_ctrl **chunk;
    struct nuster_memory_ctrl  *block;
    struct nuster_memory_ctrl  *empty;
    struct nuster_memory_ctrl  *full;

    struct {
        uint8_t                *begin;
        uint8_t                *free;
        uint8_t                *end;
    } data;
};

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

#endif /* _NUSTER_MEMORY_H */
