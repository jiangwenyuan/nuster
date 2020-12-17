/*
 * nuster dict functions.
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
nst_dict_init(nst_dict_t *dict, nst_store_t *store, nst_shmem_t *shmem, uint64_t dict_size) {

    int  block_size = shmem->block_size;
    int  entry_size = sizeof(nst_dict_entry_t *);
    int  size       = (block_size + dict_size - 1) / block_size * block_size;
    int  i;

    dict->shmem = shmem;
    dict->size  = size / entry_size;
    dict->used  = 0;
    dict->entry = nst_shmem_alloc(shmem, block_size);
    dict->store = store;

    if(!dict->entry) {
        return NST_ERR;
    }

    for(i = 1; i < size / block_size; i++) {

        if(!nst_shmem_alloc(shmem, block_size)) {
            return NST_ERR;
        }
    }

    for(i = 0; i < dict->size; i++) {
        dict->entry[i] = NULL;
    }

    return nst_shctx_init(dict);
}

/*
 * Check entry validity, free the entry if its invalid,
 */
void
nst_dict_cleanup(nst_dict_t *dict) {
    nst_dict_entry_t  *entry;
    nst_dict_entry_t  *prev;
    uint64_t           start;

    if(!dict->used) {
        return;
    }

    start = nst_time_now_ms();

    nst_shctx_lock(dict);

    entry = dict->entry[dict->cleanup_idx];
    prev  = entry;

    while(entry) {

        if(nst_dict_entry_invalid(entry)) {
            nst_dict_entry_t  *tmp = entry;

            if(entry->store.memory.obj) {
                entry->store.memory.obj->invalid = 1;
                entry->store.memory.obj          = NULL;

                nst_memory_incr_invalid(&dict->store->memory);
            }

            if(entry->store.disk.file) {
                nst_shmem_free(dict->shmem, entry->store.disk.file);
                entry->store.disk.file = NULL;
            }

            if(prev == entry) {
                dict->entry[dict->cleanup_idx] = entry->next;
                prev = entry->next;
            } else {
                prev->next = entry->next;
            }

            entry = entry->next;

            nst_shmem_free(dict->shmem, tmp->buf.area);
            nst_shmem_free(dict->shmem, tmp->key.data);
            nst_shmem_free(dict->shmem, tmp);

            dict->used--;
        } else {
            prev  = entry;
            entry = entry->next;
        }

        if(nst_time_now_ms() - start >= 10) {
            break;
        }
    }

    if(entry == NULL) {
        dict->cleanup_idx++;
    }

    /* if we have checked the whole dict */
    if(dict->cleanup_idx == dict->size) {
        dict->cleanup_idx = 0;
    }

    nst_shctx_unlock(dict);
}

nst_dict_entry_t *
nst_dict_set(nst_dict_t *dict, nst_key_t *key, nst_http_txn_t *txn, nst_rule_prop_t *prop) {
    nst_dict_entry_t  *entry = NULL;
    int                idx;

    entry = nst_shmem_alloc(dict->shmem, sizeof(*entry));

    if(!entry) {
        goto err;
    }

    memset(entry, 0, sizeof(*entry));

    idx = key->hash % dict->size;

    /* prepend entry to dict->entry[idx] */
    entry->next      = dict->entry[idx];
    dict->entry[idx] = entry;
    dict->used++;

    /* init entry */
    entry->state = NST_DICT_ENTRY_STATE_INIT;

    /* set key */
    entry->key.size = key->size;
    entry->key.hash = key->hash;
    entry->key.data = nst_shmem_alloc(dict->shmem, key->size);

    if(!entry->key.data) {
        goto err;
    }

    memcpy(entry->key.data, key->data, key->size);
    memcpy(entry->key.uuid, key->uuid, 20);

    /* set buf */
    entry->buf.size = txn->req.host.len + txn->req.path.len + txn->res.etag.len
        + txn->res.last_modified.len + prop->pid.len + prop->rid.len;

    entry->buf.data = 0;
    entry->buf.area = nst_shmem_alloc(dict->shmem, entry->buf.size);

    if(!entry->buf.area) {
        goto err;
    }

    entry->host = ist2(entry->buf.area + entry->buf.data, txn->req.host.len);
    chunk_istcat(&entry->buf, txn->req.host);

    entry->path = ist2(entry->buf.area + entry->buf.data, txn->req.path.len);
    chunk_istcat(&entry->buf, txn->req.path);

    entry->etag = ist2(entry->buf.area + entry->buf.data, txn->res.etag.len);
    chunk_istcat(&entry->buf, txn->res.etag);

    entry->last_modified = ist2(entry->buf.area + entry->buf.data, txn->res.last_modified.len);
    chunk_istcat(&entry->buf, txn->res.last_modified);

    entry->prop.pid = ist2(entry->buf.area + entry->buf.data, prop->pid.len);
    chunk_istcat(&entry->buf, prop->pid);

    entry->prop.rid = ist2(entry->buf.area + entry->buf.data, prop->rid.len);
    chunk_istcat(&entry->buf, prop->rid);

    entry->prop.ttl           = txn->res.ttl;

    entry->prop.extend[0]     = prop->extend[0];
    entry->prop.extend[1]     = prop->extend[1];
    entry->prop.extend[2]     = prop->extend[2];
    entry->prop.extend[3]     = prop->extend[3];
    entry->prop.etag          = prop->etag;
    entry->prop.last_modified = prop->last_modified;
    entry->prop.wait          = prop->wait;
    entry->prop.stale         = prop->stale;
    entry->prop.inactive      = prop->inactive;
    entry->prop.store         = prop->store;
    entry->expire             = 0;
    entry->atime              = nst_time_now_ms();

    return entry;

err:

    if(entry) {
        entry->state = NST_DICT_ENTRY_STATE_INVALID;
    }

    return NULL;
}

/*
 * return NULL if invalid;
 * return entry if init and valid
 */
nst_dict_entry_t *
nst_dict_get(nst_dict_t *dict, nst_key_t *key) {
    nst_dict_entry_t  *entry = NULL;
    uint64_t           max;
    int                idx, expired;

    if(dict->used == 0) {
        return NULL;
    }

    idx   = key->hash % dict->size;
    entry = dict->entry[idx];

    while(entry) {

        if(entry->key.hash == key->hash && entry->key.size == key->size
                && !memcmp(entry->key.uuid, key->uuid, NST_KEY_UUID_LEN)
                && !memcmp(entry->key.data, key->data, key->size)) {

            if(entry->state == NST_DICT_ENTRY_STATE_INVALID) {
                return NULL;
            }

            if(entry->state == NST_DICT_ENTRY_STATE_INIT
                    || entry->state == NST_DICT_ENTRY_STATE_UPDATE) {

                return entry;
            }

            if(entry->state == NST_DICT_ENTRY_STATE_STALE) {

                if(nst_dict_entry_stale_valid(entry)) {
                    return entry;
                } else {
                    return NULL;
                }
            }

            /*
             * check extend
             */
            expired = nst_dict_entry_expired(entry);

            max = 1000 * entry->expire + 1000 * entry->prop.ttl * entry->prop.extend[3] / 100;

            entry->atime = nst_time_now_ms();

            if(expired && entry->prop.extend[0] != 0xFF && entry->atime <= max
                    && entry->access[3] > entry->access[2]
                    && entry->access[2] > entry->access[1]) {

                entry->expire    += entry->prop.ttl;

                entry->access[0] += entry->access[1];
                entry->access[0] += entry->access[2];
                entry->access[0] += entry->access[3];
                entry->access[1]  = 0;
                entry->access[2]  = 0;
                entry->access[3]  = 0;
                entry->extended  += 1;

                if(entry->store.disk.file) {
                    nst_disk_update_expire(entry->store.disk.file, entry->expire);
                }

                expired = 0;
            }

            /*
             * check stale
             */
            if(expired && entry->prop.stale >= 0) {
                entry->state = NST_DICT_ENTRY_STATE_REFRESH;

                expired = 0;
            }

            /* check expire
             * change state only, leave the free stuff to cleanup
             * */
            if(expired) {
                entry->state     = NST_DICT_ENTRY_STATE_INVALID;
                entry->expire    = 0;
                entry->access[0] = 0;
                entry->access[1] = 0;
                entry->access[2] = 0;
                entry->access[3] = 0;
                entry->extended  = 0;

                if(entry->store.memory.obj) {
                    entry->store.memory.obj->invalid = 1;
                    entry->store.memory.obj          = NULL;

                    nst_memory_incr_invalid(&dict->store->memory);
                }

                return NULL;
            }

            return entry;
        }

        entry = entry->next;
    }

    return NULL;
}

int
nst_dict_set_from_disk(nst_dict_t *dict, hpx_buffer_t *buf, nst_key_t *key, nst_http_txn_t *txn,
        nst_rule_prop_t *prop, char *file, uint64_t expire) {

    nst_dict_entry_t  *entry = NULL;
    int                idx;

    idx = key->hash % dict->size;

    entry = dict->entry[idx];

    while(entry) {

        if(entry->key.hash == key->hash && entry->key.size == key->size
                && !memcmp(entry->key.uuid, key->uuid, NST_KEY_UUID_LEN)
                && !memcmp(entry->key.data, key->data, key->size)) {

            break;
        }

        entry = entry->next;
    }

    if(entry) {
        nst_shmem_free(dict->shmem, key->data);
        nst_shmem_free(dict->shmem, buf->area);

        return NST_OK;
    }

    entry = nst_shmem_alloc(dict->shmem, sizeof(*entry));

    if(!entry) {
        return NST_ERR;
    }

    memset(entry, 0, sizeof(*entry));

    /* prepend entry to dict->entry[idx] */
    entry->next      = dict->entry[idx];
    dict->entry[idx] = entry;
    dict->used++;

    /* init entry */
    if(expire == 0 || expire * 1000 > nst_time_now_ms()) {
        entry->state = NST_DICT_ENTRY_STATE_VALID;
    } else {
        entry->state = NST_DICT_ENTRY_STATE_STALE;
    }

    entry->key    = *key;
    entry->expire = expire;
    entry->atime  = nst_time_now_ms();

    entry->store.disk.file = nst_shmem_alloc(dict->shmem, strlen(file));

    if(!entry->store.disk.file) {
        nst_shmem_free(dict->shmem, entry);

        return NST_ERR;
    }

    memcpy(entry->store.disk.file, file, strlen(file));

    entry->header_len         = txn->res.header_len;
    entry->payload_len        = txn->res.payload_len;
    entry->buf                = *buf;
    entry->host               = txn->req.host;
    entry->path               = txn->req.path;
    entry->etag               = txn->res.etag;
    entry->last_modified      = txn->res.last_modified;
    entry->prop.pid           = prop->pid;
    entry->prop.rid           = prop->rid;
    entry->prop.ttl           = prop->ttl;
    entry->prop.extend[0]     = prop->extend[0];
    entry->prop.extend[1]     = prop->extend[1];
    entry->prop.extend[2]     = prop->extend[2];
    entry->prop.extend[3]     = prop->extend[3];
    entry->prop.etag          = prop->etag;
    entry->prop.last_modified = prop->last_modified;
    entry->prop.stale         = prop->stale;
    entry->prop.inactive      = prop->inactive;

    return NST_OK;
}

void
nst_dict_record_access(nst_dict_entry_t *entry) {

    if(entry->expire == 0 || entry->prop.extend[0] == 0xFF) {
        entry->access[0]++;
    } else {
        uint64_t  stime, diff;
        float     pct;
        uint32_t  ttl = entry->prop.ttl;

        stime = entry->ctime + ttl * entry->extended * 1000;
        diff  = entry->atime - stime;
        pct   = diff / 1000.0 / ttl * 100;

        if(pct < 100 - entry->prop.extend[0] - entry->prop.extend[1] - entry->prop.extend[2]) {
            entry->access[0]++;
        } else if(pct < 100 - entry->prop.extend[1] - entry->prop.extend[2]) {
            entry->access[1]++;
        } else if(pct < 100 - entry->prop.extend[2]) {
            entry->access[2]++;
        } else {
            entry->access[3]++;
        }
    }

}
