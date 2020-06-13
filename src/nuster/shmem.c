/*
 * nuster shmem functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/mman.h>

#include <haproxy/tools.h>

#include <nuster/shctx.h>
#include <nuster/shmem.h>

nst_shmem_t *
nst_shmem_create(char *name, uint64_t size, uint32_t block_size, uint32_t chunk_size) {
    uint8_t      *p;
    nst_shmem_t  *shmem;
    uint64_t      n;
    uint8_t      *begin, *end;
    uint32_t      bitmap_size;

    if(block_size < NST_SHMEM_BLOCK_MIN_SIZE) {
        block_size = NST_SHMEM_BLOCK_MIN_SIZE;
    }

    if(block_size > NST_SHMEM_BLOCK_MAX_SIZE) {
        fprintf(stderr, "tune.bufsize exceeds the maximum %d.\n", NST_SHMEM_BLOCK_MAX_SIZE);

        return NULL;
    }

    if(chunk_size < NST_SHMEM_CHUNK_MIN_SIZE) {
        chunk_size = NST_SHMEM_CHUNK_MIN_SIZE;
    }

    /* set block_size to minimal number that
     * 1: > block_size
     * 2: = (2**n) * NST_SHMEM_BLOCK_MIN_SIZE
     */
    for(n = NST_SHMEM_BLOCK_MIN_SHIFT; n <= NST_SHMEM_BLOCK_MAX_SHIFT; n++) {

        if(1UL << n >= block_size) {
            block_size = 1UL << n;

            break;
        }
    }

    /*
     * set chunk_size to minimal number that
     * 1, > chunk_size , 2, = n * NST_SHMEM_CHUNK_MIN_SIZE
     */
    chunk_size = ((chunk_size + NST_SHMEM_CHUNK_MIN_SIZE - 1)
            / NST_SHMEM_CHUNK_MIN_SIZE) << NST_SHMEM_CHUNK_MIN_SHIFT;

    if(chunk_size > block_size) {
        fprintf(stderr, "chunk_size cannot be greater than block_size.\n");

        return NULL;
    }

    size = (size + block_size - 1) / block_size * block_size;

    /* create shared memory */
    p = (uint8_t *) mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);

    if(p == MAP_FAILED) {
        fprintf(stderr, "Out of memory when initialization.\n");

        return NULL;
    }

    shmem = (nst_shmem_t *)p;

    /* init header */
    if(name) {
        strlcpy2(shmem->name, name, sizeof(shmem->name));
    }

    shmem->start      = p;
    shmem->stop       = p + size;
    shmem->block_size = block_size;
    shmem->chunk_size = chunk_size;
    shmem->size       = size;
    shmem->used       = 0;

    p += sizeof(nst_shmem_t);

    /* calculate */
    for(n = NST_SHMEM_CHUNK_MIN_SHIFT; (1ULL << n) < chunk_size; n++) { }

    shmem->chunk_shift = n;

    for(n = NST_SHMEM_BLOCK_MIN_SHIFT; (1ULL << n) < block_size; n++) { }

    shmem->block_shift = n;
    shmem->chunks      = n - shmem->chunk_shift + 1;
    shmem->chunk       = (nst_shmem_ctrl_t **)p;

    p += shmem->chunks * sizeof(nst_shmem_ctrl_t *);

    shmem->block = (nst_shmem_ctrl_t *)p;
    shmem->empty = NULL;
    shmem->full  = NULL;

    bitmap_size = block_size / chunk_size / 8;

    /* set data begin */
    n = (shmem->stop - p) / (sizeof(nst_shmem_ctrl_t) + block_size + bitmap_size);

    begin = (uint8_t *) (((uintptr_t)(p)
                + n * sizeof(nst_shmem_ctrl_t) + n * bitmap_size
                + ((uintptr_t) NST_SHMEM_BLOCK_MIN_SIZE - 1))
            & ~((uintptr_t) NST_SHMEM_BLOCK_MIN_SIZE - 1));

    end = begin + block_size * n;

    if(shmem->stop < end) {
        n--;
        begin = (uint8_t *) (((uintptr_t)(p) + n * sizeof(nst_shmem_ctrl_t)
                    + n * bitmap_size + ((uintptr_t) NST_SHMEM_BLOCK_MIN_SIZE - 1))
                & ~((uintptr_t) NST_SHMEM_BLOCK_MIN_SIZE - 1));
    }

    shmem->blocks     = n;
    shmem->bitmap     = (uint8_t *)(shmem->block + n);
    shmem->data.begin = begin;
    shmem->data.free  = begin;
    shmem->data.end   = begin + block_size * (n - 1);

    n = sizeof(nst_shmem_t) + sizeof(nst_shmem_ctrl_t *) * shmem->chunks
        + sizeof(nst_shmem_ctrl_t) * n;

    if(shmem->blocks == 0 || shmem->data.end + block_size > shmem->stop) {
        return NULL;
    }

    /* initialize chunk */
    for(n = 0; n < shmem->chunks; n++) {
        shmem->chunk[n] = NULL;
    }

    /* initialize block */
    for(n = 0; n < shmem->blocks; n++) {
        shmem->block[n].info   = 0;
        shmem->block[n].bitmap = shmem->bitmap + n * bitmap_size;
        shmem->block[n].prev   = NULL;
        shmem->block[n].next   = NULL;
    }

    return shmem;
}

void *
_nst_shmem_block_alloc(nst_shmem_t *shmem, nst_shmem_ctrl_t *block, int chunk_idx) {

    int  chunk_size = 1<<(shmem->chunk_shift + chunk_idx);
    int  block_idx  = block - shmem->block;
    int  bits_need  = shmem->block_size / chunk_size;
    int  bits_idx   = 0;
    int  i          = 0;
    int  unset      = 1;
    int  full       = 1;

    shmem->used += chunk_size;

    /* use info, should not use anymore */
    if(chunk_size * NST_SHMEM_INFO_BITMAP_BITS >= shmem->block_size) {
        uint32_t  mask =  ~0U >> (NST_SHMEM_INFO_BITMAP_BITS - bits_need);
        uint32_t  *v   = (uint32_t *)(&block->info) + 1;
        uint32_t  t    = *v;

        /* get bits_idx */
        bits_idx = __builtin_ffs(~t) - 1;
        /* set rightmost 0 to 1 */
        *v  |= *v + 1;
        full = (mask == *v);
    }
    /* use bitmap */
    else {
        uint64_t  *begin;

        begin = (uint64_t *)block->bitmap;
        i     = 0;
        unset = 1;

        for(i = 0; i < bits_need / 64; i++) {
            uint64_t  *v = begin + i;

            if(*v == ~0ULL && unset) {
                bits_idx += 64;

                continue;
            }

            if(unset) {
                uint64_t  t = *v;

                bits_idx += __builtin_ffsll(~t) - 1;
                *v       |= *v + 1;
                unset     = 0;
            }

            if(*v != ~0ULL) {
                full = 0;

                break;
            }
        }
    }

    /* yes */
    if(full) {
        _nst_shmem_block_set_full(block);
        /* remove from chunk list */
        shmem->chunk[chunk_idx] = block->next;

        if(block->next) {
            block->next->prev = NULL;
        }

        /* add to full list */
        if(shmem->full) {
            block->next       = shmem->full;
            shmem->full->prev = block;
        } else {
            block->next = NULL;
        }

        block->prev = NULL;
        shmem->full = block;
    }

    return (void *)(shmem->data.begin + 1ULL * shmem->block_size * block_idx
            + chunk_size * bits_idx);
}

void
_nst_shmem_block_init(nst_shmem_t * shmem, nst_shmem_ctrl_t *block, int chunk_idx) {
    nst_shmem_ctrl_t  *chunk;

    chunk       = shmem->chunk[chunk_idx];
    block->info = 0;

    _nst_shmem_block_set_type(block, chunk_idx);
    _nst_shmem_block_set_inited(block);

    memset(block->bitmap, 0, shmem->block_size / shmem->chunk_size / 8);

    block->prev = NULL;
    block->next = NULL;

    /* add to chunk list */
    if(chunk) {
        block->next = chunk;
        chunk->prev = block;
    }

    shmem->chunk[chunk_idx] = block;
}

void *
nst_shmem_alloc_locked(nst_shmem_t *shmem, int size) {
    nst_shmem_ctrl_t  *chunk, *block;
    int                 i, chunk_idx = 0;

    if(!size || size > shmem->block_size) {
        return NULL;
    }

    for(i = (size - 1) >> (shmem->chunk_shift - 1); i >>= 1; chunk_idx++) {}

    chunk = shmem->chunk[chunk_idx];

    /* check chunk list */
    if(chunk) {
        block = chunk;
    }
    /* check empty list */
    else if(shmem->empty) {
        /* remove from empty list */
        block        = shmem->empty;
        shmem->empty = block->next;

        if(shmem->empty) {
            shmem->empty->prev = NULL;
        }

        _nst_shmem_block_init(shmem, block, chunk_idx);
    }
    /* require new block from unused */
    else if(shmem->data.free <= shmem->data.end) {
        int  block_idx = (shmem->data.free - shmem->data.begin) / shmem->block_size;

        shmem->data.free += shmem->block_size;
        block             = &shmem->block[block_idx];

        if(_nst_shmem_block_is_inited(block)) {
            return NULL;
        } else {
            _nst_shmem_block_init(shmem, block, chunk_idx);
        }
    }
    else {
        return NULL;
    }

    return _nst_shmem_block_alloc(shmem, block, chunk_idx);
}

void *
nst_shmem_alloc(nst_shmem_t *shmem, int size) {
    void  *p;

    nst_shctx_lock(shmem);
    p = nst_shmem_alloc_locked(shmem, size);
    nst_shctx_unlock(shmem);

    return p;
}

void
nst_shmem_free_locked(nst_shmem_t *shmem, void *p) {
    nst_shmem_ctrl_t  *chunk, *block;
    uint8_t             chunk_idx;
    int                 block_idx, chunk_size, bits, bits_idx, empty, full;

    if((uint8_t *)p < shmem->data.begin || (uint8_t *)p >= shmem->data.free) {
        return;
    }

    block_idx  = ((uint8_t *)p - shmem->data.begin) / shmem->block_size;
    block      = &shmem->block[block_idx];
    chunk_idx  = block->info & 0xFF;
    chunk      = shmem->chunk[chunk_idx];
    chunk_size = 1<<(shmem->chunk_shift + chunk_idx);
    bits       = shmem->block_size / chunk_size;

    bits_idx = ((uint8_t *)p - (shmem->data.begin + 1ULL * block_idx * shmem->block_size))
        / chunk_size;

    shmem->used -= chunk_size;

    empty = 0;
    full  = _nst_shmem_block_is_full(block);

    _nst_shmem_block_clear_full(block);

    /* info used */
    if(chunk_size * NST_SHMEM_INFO_BITMAP_BITS >= shmem->block_size) {
        block->info &= ~(1ULL << (bits_idx + 32));

        if(!(block->info & 0xFFFFFFFF00000000ULL)) {
            empty = 1;
        }
    }
    /* bitmap used */
    else {
        int  i;

        *((uint64_t *)block->bitmap + bits_idx / 64 ) &= ~(1ULL<<(bits_idx % 64));

        for(i = 0; i < bits / 64; i++) {

            if(*((uint64_t *)block->bitmap + i) == 0) {
                empty += 64;
            }
        }

        if(empty == bits) {
            empty = 1;
        } else {
            empty = 0;
        }
    }

    /*
     * 1. if the block previously was full
     *  a. if chunk_id is LAST, move the block from full list to empty list
     *  b. else move the block from full list to chunk[chunk_idx]
     * 2. else if the block became empty after free
     *  a. if chunk_id is LAST, move the block from full list to empty list
     *  b. else move the block from chunk[chunk_idx] to empty list
     * 3. else do nothing
     *
     * 1. if chunk_id is LAST(full && empty)
     *  a. move the block from full list to empty list
     * 2. else
     *  a. if previously full, move the block from full list to chunk[chunk_idx]
     *  b. else if empty after free, move the block
     *     from chunk[chunk_idx] to empty list
     *  c. else do nothing
     */
    /* remove from full list and add to chunk list */
    if(full && empty) {

        /* remove from full list */
        if(block->prev) {
            block->prev->next = block->next;
        } else {
            shmem->full = block->next;
        }

        if(block->next) {
            block->next->prev = block->prev;
        }

        /* add to empty list */
        block->prev  = NULL;
        block->next  = shmem->empty;
        shmem->empty = block;

        if(block->next) {
            block->next->prev = block;
        }
    } else {

        if(full) {

            /* remove from full list */
            if(block->prev) {
                block->prev->next = block->next;
            } else {
                shmem->full = block->next;
            }

            if(block->next) {
                block->next->prev = block->prev;
            }

            /* add to chunk list */
            block->prev             = NULL;
            block->next             = chunk;
            shmem->chunk[chunk_idx] = block;

            if(block->next) {
                block->next->prev = block;
            }
        } else if(empty) {

            /* remove from chunk list */
            if(block->prev) {
                block->prev->next = block->next;
            } else {
                shmem->chunk[chunk_idx] = block->next;
            }

            if(block->next) {
                block->next->prev = block->prev;
            }

            /* add to empty list */
            block->prev  = NULL;
            block->next  = shmem->empty;
            shmem->empty = block;

            if(block->next) {
                block->next->prev = block;
            }
        }
    }
}

void
nst_shmem_free(nst_shmem_t *shmem, void *p) {

    if(p == NULL) {
        return;
    }

    nst_shctx_lock(shmem);
    nst_shmem_free_locked(shmem, p);
    nst_shctx_unlock(shmem);
}

