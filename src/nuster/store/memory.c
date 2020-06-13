/*
 * nuster store memory functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/htx-t.h>

#include <nuster/nuster.h>

int
nst_memory_init(nst_memory_t *mem, nst_shmem_t *shmem) {

    mem->shmem   = shmem;
    mem->head    = NULL;
    mem->tail    = NULL;
    mem->count   = 0;
    mem->invalid = 0;

    return nst_shctx_init(mem);
}

/*
 * free invalid nst_memory_object
 */
void
nst_memory_cleanup(nst_memory_t *mem) {
    nst_memory_obj_t   *obj  = NULL;
    nst_memory_item_t  *item = NULL;
    nst_memory_item_t  *tmp;

    nst_shctx_lock(mem);

    if(mem->head) {

        if(mem->head == mem->tail) {

            if(nst_memory_obj_invalid(mem->head) == NST_OK) {
                obj       = mem->head;
                mem->head = NULL;
                mem->tail = NULL;
            }

        } else {

            if(nst_memory_obj_invalid(mem->head) == NST_OK) {
                obj             = mem->head;
                mem->tail->next = mem->head->next;
                mem->head       = mem->head->next;
            } else {
                mem->tail = mem->head;
                mem->head = mem->head->next;
            }

        }

    }

    if(obj) {
        item = obj->item;

        while(item) {
            tmp  = item;
            item = item->next;

            nst_shmem_free(mem->shmem, tmp);
        }

        nst_shmem_free(mem->shmem, obj);

        mem->count--;
        mem->invalid--;
    }

    nst_shctx_unlock(mem);
}

/*
 * create a new nst_memory_object and insert it to nst_memory list
 */
nst_memory_obj_t *
nst_memory_obj_create(nst_memory_t *mem) {
    nst_memory_obj_t  *obj = nst_shmem_alloc(mem->shmem, sizeof(*obj));

    if(obj) {
        memset(obj, 0, sizeof(*obj));

        nst_shctx_lock(mem);

        if(mem->head == NULL) {
            mem->head = obj;
            mem->tail = obj;
            obj->next    = obj;
        } else {

            if(mem->head == mem->tail) {
                mem->head->next = obj;
                obj->next       = mem->head;
                mem->tail       = obj;
            } else {
                obj->next       = mem->head;
                mem->tail->next = obj;
                mem->tail       = obj;
            }
        }

        mem->count++;

        nst_shctx_unlock(mem);
    }

    return obj;
}

int
nst_memory_obj_append(nst_memory_t *mem, nst_memory_obj_t *obj, nst_memory_item_t **tail,
        const char *buf, uint32_t len, uint32_t info) {

    nst_memory_item_t  *item;

    if(obj->invalid) {
        return NST_ERR;
    }

    item = nst_memory_alloc_item(mem, len);

    if(!item) {
        obj->invalid = 1;

        nst_memory_incr_invalid(mem);

        return NST_ERR;
    }

    memcpy(item->data, buf, len);

    item->info = info;
    item->next = NULL;

    if(*tail) {
        (*tail)->next = item;
    } else {
        obj->item = item;
    }

    *tail = item;

    return NST_OK;
}

void
nst_store_memory_sync_disk(nst_core_t *core) {
    nst_dict_entry_t   *entry;
    nst_disk_obj_t      data = { .file = NULL };
    nst_memory_item_t  *item;
    nst_http_txn_t      txn;
    hpx_htx_blk_type_t  type;
    uint64_t            start;
    uint32_t            blksz, info;
    int                 ret;


    if(!core->root.len || !core->store.disk.loaded) {
        return;
    }

    if(!core->dict.used) {
        return;
    }

    start = nst_time_now_ms();

    nst_shctx_lock(&core->dict);

    entry = core->dict.entry[core->dict.sync_idx];

    while(entry) {

        if(nst_dict_entry_valid(entry)
                && nst_store_disk_sync(entry->prop.store)
                && entry->store.disk.file == NULL) {

            txn.req.host          = entry->host;
            txn.req.path          = entry->path;
            txn.res.etag          = entry->etag;
            txn.res.last_modified = entry->last_modified;
            txn.res.header_len    = 0;
            txn.res.payload_len   = 0;

            ret = nst_disk_obj_create(&core->store.disk, &data, &entry->key, &txn, &entry->prop);

            if(ret != NST_OK) {
                goto next;
            }

            entry->store.disk.file = data.file;

            item = entry->store.memory.obj->item;

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
                    ret = nst_disk_obj_append(&core->store.disk, &data, (char *)&info, 4);

                    if(ret != NST_OK) {
                        goto next;
                    }

                }

                ret = nst_disk_obj_append(&core->store.disk, &data, item->data, blksz);

                if(ret != NST_OK) {
                    goto next;
                }

                item = item->next;
            }

            nst_disk_obj_finish(&core->store.disk, &data, &entry->key, &txn, entry->expire);
        }
next:

        entry = entry->next;

        if(nst_time_now_ms() - start >= 10) {
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

