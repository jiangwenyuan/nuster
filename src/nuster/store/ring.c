/*
 * nuster ring functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <nuster/nuster.h>

int
nst_ring_init(nst_ring_t *ring, nst_memory_t *memory) {

    ring->memory  = memory;
    ring->head    = NULL;
    ring->tail    = NULL;
    ring->count   = 0;
    ring->invalid = 0;

    return nst_shctx_init(ring);
}

/*
 * create a new nst_ring_data and insert it to nst_ring list
 */
nst_ring_data_t *
nst_ring_alloc_data(nst_ring_t *ring) {
    nst_ring_data_t  *data = nst_memory_alloc(ring->memory, sizeof(*data));

    if(data) {
        memset(data, 0, sizeof(*data));

        nst_shctx_lock(ring);

        if(ring->head == NULL) {
            ring->head = data;
            ring->tail = data;
            data->next = data;
        } else {

            if(ring->head == ring->tail) {
                ring->head->next = data;
                data->next       = ring->head;
                ring->tail       = data;
            } else {
                data->next       = ring->head;
                ring->tail->next = data;
                ring->tail       = data;
            }
        }

        ring->count++;

        nst_shctx_unlock(ring);
    }

    return data;
}

/*
 * free invalid nst_ring_data
 */
void
nst_ring_cleanup(nst_ring_t *ring) {
    nst_ring_data_t  *data = NULL;
    nst_ring_item_t  *item = NULL;
    nst_ring_item_t  *tmp;

    nst_shctx_lock(ring);

    if(ring->head) {

        if(ring->head == ring->tail) {

            if(nst_ring_data_invalid(ring->head) == NST_OK) {
                data       = ring->head;
                ring->head = NULL;
                ring->tail = NULL;
            }

        } else {

            if(nst_ring_data_invalid(ring->head) == NST_OK) {
                data             = ring->head;
                ring->tail->next = ring->head->next;
                ring->head       = ring->head->next;
            } else {
                ring->tail = ring->head;
                ring->head = ring->head->next;
            }

        }

    }

    if(data) {
        item = data->item;

        while(item) {
            tmp  = item;
            item = item->next;

            nst_memory_free(ring->memory, tmp);
        }

        nst_memory_free(ring->memory, data);

        ring->count--;
        ring->invalid--;
    }

    nst_shctx_unlock(ring);
}

int
nst_ring_store_add(nst_ring_t *ring, nst_ring_data_t *data, nst_ring_item_t **tail,
        const char *buf, uint32_t len, uint32_t info) {

    nst_ring_item_t  *item;

    if(data->invalid) {
        return NST_ERR;
    }

    item = nst_ring_alloc_item(ring, len);

    if(!item) {
        data->invalid = 1;

        nst_ring_incr_invalid(ring);

        return NST_ERR;
    }

    memcpy(item->data, buf, len);

    item->info = info;
    item->next = NULL;

    if(*tail) {
        (*tail)->next = item;
    } else {
        data->item = item;
    }

    *tail = item;

    return NST_OK;
}

void
nst_ring_store_sync(nst_core_t *core) {
    nst_dict_entry_t   *entry;
    nst_disk_data_t     data = { .file = NULL };
    nst_ring_item_t    *item;
    nst_http_txn_t      txn;
    hpx_htx_blk_type_t  type;
    uint64_t            ttl_extend, start;
    uint32_t            blksz, info;
    int                 ret;


    if(!core->root.len || !core->store.disk.loaded) {
        return;
    }

    if(!core->dict.used) {
        return;
    }

    start = get_current_timestamp();

    nst_shctx_lock(&core->dict);

    entry = core->dict.entry[core->dict.sync_idx];

    while(entry) {

        if(nst_dict_entry_valid(entry)
                && nst_store_disk_sync(entry->prop.store)
                && entry->store.disk.file == NULL) {

            ttl_extend  = entry->prop.ttl;

            txn.req.host          = entry->host;
            txn.req.path          = entry->path;
            txn.res.etag          = entry->etag;
            txn.res.last_modified = entry->last_modified;
            txn.res.header_len    = 0;
            txn.res.payload_len   = 0;

            ttl_extend = ttl_extend << 32;
            *( uint8_t *)(&ttl_extend)      = entry->prop.extend[0];
            *((uint8_t *)(&ttl_extend) + 1) = entry->prop.extend[1];
            *((uint8_t *)(&ttl_extend) + 2) = entry->prop.extend[2];
            *((uint8_t *)(&ttl_extend) + 3) = entry->prop.extend[3];

            ret = nst_disk_store_init(&core->store.disk, &data, &entry->key, &txn,
                    entry->prop.etag, entry->prop.last_modified, ttl_extend);

            if(ret != NST_OK) {
                goto next;
            }

            entry->store.disk.file = data.file;

            item = entry->store.ring.data->item;

            while(item) {
                info  = item->info;
                type  = (info >> 28);
                blksz = ((type == HTX_BLK_HDR || type == HTX_BLK_TLR)
                        ? (info & 0xff) + ((info >> 8) & 0xfffff)
                        : info & 0xfffffff);

                if(type == HTX_BLK_RES_SL || type == HTX_BLK_HDR || type == HTX_BLK_EOH) {
                    txn.res.header_len += 4 + blksz;
                }

                if(type == HTX_BLK_DATA) {
                    txn.res.payload_len += blksz;
                }

                if(type != HTX_BLK_DATA) {
                    ret = nst_disk_store_add(&core->store.disk, &data, (char *)&info, 4);

                    if(ret != NST_OK) {
                        goto next;
                    }

                }

                ret = nst_disk_store_add(&core->store.disk, &data, item->data, blksz);

                if(ret != NST_OK) {
                    goto next;
                }

                item = item->next;
            }

            nst_disk_store_end(&core->store.disk, &data, &entry->key, &txn, entry->expire);
        }
next:

        entry = entry->next;

        if(get_current_timestamp() - start >= 10) {
            break;
        }
    }

    if(entry == NULL) {
        core->dict.sync_idx++;
    }

    /* if we have checked the whole dict */
    if(core->dict.sync_idx == core->dict.size) {
        core->dict.sync_idx = 0;
    }

    nst_shctx_unlock(&core->dict);
}

