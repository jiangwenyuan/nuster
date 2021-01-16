/*
 * nuster cache engine functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/stream_interface.h>

#include <nuster/nuster.h>

static void
_nst_cache_memory_handler(hpx_appctx_t *appctx) {
    hpx_htx_t               *req_htx, *res_htx;
    hpx_stream_interface_t  *si    = appctx->owner;
    hpx_channel_t           *req   = si_oc(si);
    hpx_channel_t           *res   = si_ic(si);
    nst_memory_item_t       *item  = NULL;
    int                      total = 0;

    res_htx = htxbuf(&res->buf);
    total   = res_htx->data;

    if(unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
        goto out;
    }

    /* Check if the input buffer is avalaible. */
    if(!b_size(&res->buf)) {
        si_rx_room_blk(si);

        goto out;
    }

    if(res->flags & (CF_SHUTW|CF_SHUTR|CF_SHUTW_NOW)) {
        appctx->ctx.nuster.store.memory.item = NULL;
    }

    if(appctx->ctx.nuster.store.memory.item) {
        item = appctx->ctx.nuster.store.memory.item;

        while(item) {

            if(nst_http_memory_item_to_htx(item, res_htx) != NST_OK) {
                si_rx_room_blk(si);

                goto out;
            }

            item = item->next;

        }

    } else {

        if(!htx_add_endof(res_htx, HTX_BLK_EOM)) {
            si_rx_room_blk(si);

            goto out;
        }

        if(!(res->flags & CF_SHUTR) ) {
            res->flags |= CF_READ_NULL;
            si_shutr(si);
        }

        /* eat the whole request */
        if(co_data(req)) {
            req_htx = htx_from_buf(&req->buf);
            co_htx_skip(req, req_htx, co_data(req));
            htx_to_buf(req_htx, &req->buf);
        }
    }

out:
    appctx->ctx.nuster.store.memory.item = item;
    total = res_htx->data - total;

    if(total) {
        channel_add_input(res, total);
    }

    htx_to_buf(res_htx, &res->buf);
}

/*
 * The cache disk applet acts like the backend to send cached http data
 */
static void
_nst_cache_disk_handler(hpx_appctx_t *appctx) {
    hpx_stream_interface_t  *si  = appctx->owner;
    hpx_channel_t           *req = si_oc(si);
    hpx_channel_t           *res = si_ic(si);
    hpx_buffer_t            *buf;
    hpx_htx_t               *req_htx, *res_htx;
    hpx_htx_blk_type_t       type;
    hpx_htx_blk_t           *blk;
    char                    *p, *ptr;
    uint64_t                 offset, payload_len;
    uint32_t                 blksz, sz, info;
    int                      total, ret, max, fd, header_len;

    header_len  = appctx->ctx.nuster.store.disk.header_len;
    payload_len = appctx->ctx.nuster.store.disk.payload_len;
    offset      = appctx->ctx.nuster.store.disk.offset;
    fd          = appctx->ctx.nuster.store.disk.fd;
    res_htx     = htxbuf(&res->buf);
    total       = res_htx->data;

    if(unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
        goto out;
    }

    /* Check if the input buffer is avalaible. */
    if(res->buf.size == 0) {
        si_rx_room_blk(si);

        goto out;
    }

    /* check that the output is not closed */
    if(res->flags & (CF_SHUTW|CF_SHUTR|CF_SHUTW_NOW)) {
        appctx->st1 = NST_DISK_APPLET_DONE;
    }

    switch(appctx->st1) {
        case NST_DISK_APPLET_HEADER:
            buf = get_trash_chunk();
            p   = buf->area;

            ret = pread(fd, p, header_len, offset);

            if(ret != header_len) {
                appctx->st1 = NST_DISK_APPLET_ERROR;

                break;
            }

            while(header_len != 0) {
                info  = *(uint32_t *)p;
                type  = (info >> 28);
                blksz = (info & 0xff) + ((info >> 8) & 0xfffff);
                blk   = htx_add_blk(res_htx, type, blksz);

                if(!blk) {
                    appctx->st1 = NST_DISK_APPLET_ERROR;

                    break;
                }

                blk->info = info;

                ptr = htx_get_blk_ptr(res_htx, blk);
                sz  = htx_get_blksz(blk);
                p  += 4;
                memcpy(ptr, p, sz);
                p  += sz;

                header_len -= 4 + sz;
            }

            appctx->st1 = NST_DISK_APPLET_PAYLOAD;
            offset += ret;

            appctx->ctx.nuster.store.disk.offset = offset;

            /* fall through */
        case NST_DISK_APPLET_PAYLOAD:
            buf = get_trash_chunk();
            p   = buf->area;
            max = htx_get_max_blksz(res_htx, channel_htx_recv_max(res, res_htx));

            if(max <= 0) {
                goto out;
            }

            if(appctx->ctx.nuster.store.disk.payload_len == 0) {
                appctx->st1 = NST_DISK_APPLET_EOP;
            } else {

                if(max < payload_len) {
                    ret = pread(fd, p, max, offset);
                } else {
                    ret = pread(fd, p, payload_len, offset);
                }

                if(ret <= 0) {
                    appctx->st1 = NST_DISK_APPLET_ERROR;

                    break;
                }

                appctx->ctx.nuster.store.disk.payload_len -= ret;

                type  = HTX_BLK_DATA;
                info  = (type << 28) + ret;
                blksz = info & 0xfffffff;
                blk   = htx_add_blk(res_htx, type, blksz);

                if(!blk) {
                    appctx->st1 = NST_DISK_APPLET_ERROR;

                    break;
                }

                blk->info = info;

                ptr = htx_get_blk_ptr(res_htx, blk);
                sz  = htx_get_blksz(blk);
                memcpy(ptr, p, sz);

                offset += ret;
                appctx->ctx.nuster.store.disk.offset = offset;

                if(appctx->ctx.nuster.store.disk.payload_len == 0) {
                    appctx->st1 = NST_DISK_APPLET_EOP;
                } else {
                    si_rx_room_blk(si);

                    break;
                }
            }

            /* fall through */
        case NST_DISK_APPLET_EOP:
            buf = get_trash_chunk();
            p   = buf->area;
            max = htx_get_max_blksz(res_htx, channel_htx_recv_max(res, res_htx));

            ret = pread(fd, p, max, offset);

            if(ret < 0) {
                appctx->st1 = NST_DISK_APPLET_ERROR;

                break;
            }

            if(ret > 0) {
                max = ret;

                while(max != 0) {
                    info  = *(uint32_t *)p;
                    type  = (info >> 28);
                    blksz = (info & 0xff) + ((info >> 8) & 0xfffff);
                    blk   = htx_add_blk(res_htx, type, blksz);

                    if(!blk) {
                        appctx->st1 = NST_DISK_APPLET_ERROR;

                        break;
                    }

                    blk->info = info;

                    ptr = htx_get_blk_ptr(res_htx, blk);
                    sz  = htx_get_blksz(blk);
                    p  += 4;
                    memcpy(ptr, p, sz);
                    p  += sz;

                    max -= 4 + sz;
                }

                offset += ret;

                appctx->ctx.nuster.store.disk.offset = offset;

                break;
            }

            appctx->st1 = NST_DISK_APPLET_END;

            close(fd);

            /* fall through */
        case NST_DISK_APPLET_END:

            if(!htx_add_endof(res_htx, HTX_BLK_EOM)) {
                si_rx_room_blk(si);

                goto out;
            }

            appctx->st1 = NST_DISK_APPLET_DONE;

            /* fall through */
        case NST_DISK_APPLET_DONE:

            if(!(res->flags & CF_SHUTR) ) {
                res->flags |= CF_READ_NULL;
                si_shutr(si);
            }

            if(co_data(req)) {
                req_htx = htx_from_buf(&req->buf);
                co_htx_skip(req, req_htx, co_data(req));
                htx_to_buf(req_htx, &req->buf);
            }

            break;
        case NST_DISK_APPLET_ERROR:
            si_shutr(si);
            res->flags |= CF_READ_NULL;
            close(fd);

            return;
    }

out:
    total = res_htx->data - total;

    if(total) {
        channel_add_input(res, total);
    }

    htx_to_buf(res_htx, &res->buf);
}

/*
 * The cache applet acts like the backend to send cached http data
 */
static void
nst_cache_handler(hpx_appctx_t *appctx) {

    if(appctx->st0 == NST_CTX_STATE_HIT_MEMORY) {
        _nst_cache_memory_handler(appctx);
    } else {
        _nst_cache_disk_handler(appctx);
    }
}

void
nst_cache_housekeeping() {
    nst_dict_t   *dict  = &nuster.cache->dict;
    nst_store_t  *store = &nuster.cache->store;
    uint64_t      start;

#ifndef USE_THREAD
    uint64_t      begin = nst_time_now_ms();
#endif

    if(global.nuster.cache.status == NST_STATUS_ON && master == 1) {
        int  dict_cleaner = global.nuster.cache.dict_cleaner;
        int  data_cleaner = global.nuster.cache.data_cleaner;
        int  disk_cleaner = global.nuster.cache.disk_cleaner;
        int  disk_saver   = global.nuster.cache.disk_saver;
        int  ms           = 10;
        int  ratio        = 1;

#ifndef USE_THREAD
        int  disk_loader  = global.nuster.cache.disk_loader;
#endif

        start = nst_time_now_ms();

        while(dict_cleaner--) {
            nst_dict_cleanup(dict);

            if(nst_time_now_ms() - start >= ms) {
                break;
            }
        }

        start = nst_time_now_ms();

        if(data_cleaner > store->memory.count) {
            data_cleaner = store->memory.count;
        }

        if(store->memory.count) {
            ratio = store->memory.invalid * 10 / store->memory.count;
        }

        if(ratio >= 2) {
            data_cleaner = store->memory.count;

            ms = ms * ratio ;
            ms = ms >= 100 ? 100 : ms;
        }

        while(data_cleaner--) {
            nst_memory_cleanup(&store->memory);

            if(nst_time_now_ms() - start >= ms) {
                break;
            }
        }

        start = nst_time_now_ms();
        ms    = 10;

        while(store->disk.loaded && disk_saver--) {
            nst_store_memory_sync_disk(nuster.cache);

            if(nst_time_now_ms() - start >= ms) {
                break;
            }
        }

        start = nst_time_now_ms();

        while(store->disk.loaded && disk_cleaner--) {
            nst_disk_cleanup(nuster.cache);

            if(nst_time_now_ms() - start >= ms) {
                break;
            }
        }

#ifndef USE_THREAD
        while(!store->disk.loaded && disk_loader--) {
            nst_disk_load(nuster.cache);

            if(nst_time_now_ms() - begin >= 500) {
                break;
            }
        }
#endif

    }
}

void
nst_cache_init() {
    hpx_ist_t     root;
    nst_shmem_t  *shmem;
    uint64_t      dict_size, data_size, size;
    int           clean_temp;

    root       = global.nuster.cache.root;
    dict_size  = global.nuster.cache.dict_size;
    data_size  = global.nuster.cache.data_size;
    size       = dict_size + data_size;
    clean_temp = global.nuster.cache.clean_temp;

    nuster.applet.cache.fct = nst_cache_handler;

    if(global.nuster.cache.status == NST_STATUS_ON) {

        shmem = nst_shmem_create("cache.shm", size, global.tune.bufsize, NST_DEFAULT_CHUNK_SIZE);

        if(!shmem) {
            ha_alert("Failed to create nuster cache memory zone.\n");
            exit(1);
        }

        global.nuster.cache.shmem = shmem;

        if(nst_shctx_init(shmem) != NST_OK) {
            ha_alert("Failed to init nuster cache memory.\n");
            exit(1);
        }

        nuster.cache = nst_shmem_alloc(shmem, sizeof(nst_core_t));

        if(!nuster.cache) {
            ha_alert("Failed to init nuster cache core.\n");
            exit(1);
        }

        memset(nuster.cache, 0, sizeof(*nuster.cache));

        nuster.cache->shmem = shmem;
        nuster.cache->root  = root;

        if(nst_store_init(&nuster.cache->store, root, shmem, clean_temp, nuster.cache) != NST_OK) {
            ha_alert("Failed to init nuster cache store.\n");
            exit(1);
        }

        if(nst_dict_init(&nuster.cache->dict, &nuster.cache->store, shmem, dict_size) != NST_OK) {
            ha_alert("Failed to init nuster cache dict.\n");
            exit(1);
        }


    }
}

void
nst_cache_create(hpx_http_msg_t *msg, nst_ctx_t *ctx) {
    hpx_htx_blk_type_t  type;
    hpx_htx_blk_t      *blk;
    hpx_htx_t          *htx;
    nst_dict_entry_t   *entry;
    nst_memory_t       *mem;
    nst_dict_t         *dict;
    nst_disk_t         *disk;
    uint32_t            sz;
    int                 idx;

    dict = &nuster.cache->dict;
    mem  = &nuster.cache->store.memory;
    disk = &nuster.cache->store.disk;
    htx  = htxbuf(&msg->chn->buf);

    if(ctx->state == NST_CTX_STATE_CREATE) {
        nst_shctx_lock(dict);

        entry = nst_dict_get(dict, ctx->key);

        if(entry) {
            ctx->state = NST_CTX_STATE_BYPASS;
        }

        if(ctx->state == NST_CTX_STATE_CREATE) {
            entry = nst_dict_set(dict, ctx->key, &ctx->txn, &ctx->rule->prop);

            if(entry) {
                ctx->state = NST_CTX_STATE_CREATE;
                ctx->entry = entry;
            } else {
                ctx->state = NST_CTX_STATE_BYPASS;
            }
        }

        nst_shctx_unlock(dict);
    }

    /* init store data */

    if(ctx->state == NST_CTX_STATE_CREATE || ctx->state == NST_CTX_STATE_UPDATE) {

        if(nst_store_memory_on(ctx->rule->prop.store)) {
            ctx->store.memory.obj = nst_memory_obj_create(mem);
        }

        if(nst_store_disk_on(ctx->rule->prop.store)) {
            nst_disk_obj_create(disk, &ctx->store.disk.obj, ctx->key, &ctx->txn, &ctx->rule->prop);
        }
    }

    /* add header */

    if(ctx->state == NST_CTX_STATE_CREATE || ctx->state == NST_CTX_STATE_UPDATE) {

        ctx->txn.res.header_len  = 0;
        ctx->txn.res.payload_len = 0;

        for(idx = htx_get_first(htx); idx != -1; idx = htx_get_next(htx, idx)) {
            blk  = htx_get_blk(htx, idx);
            sz   = htx_get_blksz(blk);
            type = htx_get_blk_type(blk);

            if(type == HTX_BLK_UNUSED) {
                continue;
            }

            ctx->txn.res.header_len += 4 + sz;

            if(nst_store_memory_on(ctx->rule->prop.store) && ctx->store.memory.obj) {
                nst_memory_obj_t    *obj  = ctx->store.memory.obj;
                nst_memory_item_t  **item = &ctx->store.memory.item;
                char                *ptr  = htx_get_blk_ptr(htx, blk);
                int                  ret;

                ret = nst_memory_obj_append(mem, obj, item, ptr, sz, blk->info);

                if(ret == NST_ERR) {
                    ctx->store.memory.obj = NULL;
                }
            }

            if(nst_store_disk_on(ctx->rule->prop.store) && ctx->store.disk.obj.file) {
                nst_disk_obj_append(disk, &ctx->store.disk.obj, (char *)&blk->info, 4);
                nst_disk_obj_append(disk, &ctx->store.disk.obj, htx_get_blk_ptr(htx, blk), sz);
            }

            if(type == HTX_BLK_EOH) {
                break;
            }
        }
    }

err:
    return;
}

/*
 * Add partial http data to nst_memory_object
 */
int
nst_cache_append(hpx_http_msg_t *msg, nst_ctx_t *ctx, unsigned int offset, unsigned int len) {
    hpx_htx_blk_type_t  type;
    hpx_htx_ret_t       htxret;
    hpx_htx_blk_t      *blk;
    hpx_htx_t          *htx;
    nst_memory_t       *mem;
    nst_disk_t         *disk;
    unsigned int        forward = 0;

    mem    = &nuster.cache->store.memory;
    disk   = &nuster.cache->store.disk;
    htx    = htxbuf(&msg->chn->buf);
    htxret = htx_find_offset(htx, offset);
    blk    = htxret.blk;
    offset = htxret.ret;

    for(; blk && len; blk = htx_get_next_blk(htx, blk)) {
        hpx_ist_t  data;
        uint32_t   info;

        type = htx_get_blk_type(blk);

        if(type == HTX_BLK_DATA) {
            data = htx_get_blk_value(htx, blk);
            data.ptr += offset;
            data.len -= offset;

            if(data.len > len) {
                data.len = len;
            }

            info = (type << 28) + data.len;

            ctx->txn.res.payload_len += data.len;

            forward += data.len;
            len     -= data.len;

            if(nst_store_memory_on(ctx->rule->prop.store) && ctx->store.memory.obj) {
                nst_memory_obj_t    *obj  = ctx->store.memory.obj;
                nst_memory_item_t  **item = &ctx->store.memory.item;
                int                  ret;

                ret = nst_memory_obj_append(mem, obj, item, data.ptr, data.len, info);

                if(ret == NST_ERR) {
                    ctx->store.memory.obj = NULL;
                }
            }

            if(nst_store_disk_on(ctx->rule->prop.store) && ctx->store.disk.obj.file) {
                nst_disk_obj_append(disk, &ctx->store.disk.obj, data.ptr, data.len);
            }
        }

        if(type == HTX_BLK_TLR || type == HTX_BLK_EOT) {
            uint32_t  sz = htx_get_blksz(blk);

            forward += sz;
            len     -= sz;

            if(nst_store_memory_on(ctx->rule->prop.store) && ctx->store.memory.obj) {
                nst_memory_obj_t    *obj  = ctx->store.memory.obj;
                nst_memory_item_t  **item = &ctx->store.memory.item;
                char                *ptr  = htx_get_blk_ptr(htx, blk);
                int                  ret;

                ret = nst_memory_obj_append(mem, obj, item, ptr, sz, blk->info);

                if(ret == NST_ERR) {
                    ctx->store.memory.obj = NULL;
                }
            }

            if(nst_store_disk_on(ctx->rule->prop.store) && ctx->store.disk.obj.file) {
                nst_disk_obj_append(disk, &ctx->store.disk.obj, (char *)&blk->info, 4);
                nst_disk_obj_append(disk, &ctx->store.disk.obj, htx_get_blk_ptr(htx, blk), sz);
            }
        }

        if(type == HTX_BLK_EOM) {
            uint32_t  sz = htx_get_blksz(blk);

            forward += sz;
            len     -= sz;
        }

        offset = 0;

    }

    return forward;
}

/*
 * cache done
 */
int
nst_cache_finish(nst_ctx_t *ctx) {
    nst_dict_t        *dict  = &nuster.cache->dict;
    nst_disk_t        *disk  = &nuster.cache->store.disk;
    nst_dict_entry_t  *entry = ctx->entry;

    ctx->state = NST_CTX_STATE_DONE;

    entry->ctime = nst_time_now_ms();

    if(entry->prop.ttl == 0) {
        entry->expire = 0;
    } else {
        entry->expire = entry->ctime / 1000 + entry->prop.ttl;
    }

    entry->header_len  = ctx->txn.res.header_len;
    entry->payload_len = ctx->txn.res.payload_len;

    if(nst_store_memory_on(ctx->rule->prop.store) && ctx->store.memory.obj) {
        nst_shctx_lock(dict);

        if(entry && entry->state != NST_DICT_ENTRY_STATE_INVALID && entry->store.memory.obj) {
            entry->store.memory.obj->invalid = 1;

            nst_memory_incr_invalid(&nuster.cache->store.memory);
        }

        entry->state = NST_DICT_ENTRY_STATE_VALID;
        entry->store.memory.obj = ctx->store.memory.obj;

        nst_shctx_unlock(dict);
    }

    if(nst_store_disk_on(ctx->rule->prop.store) && ctx->store.disk.obj.file) {
        nst_disk_obj_t  *obj  = &ctx->store.disk.obj;

        if(nst_disk_obj_finish(disk, obj, ctx->key, &ctx->txn, entry->expire) == NST_OK) {
            entry->state = NST_DICT_ENTRY_STATE_VALID;
            entry->store.disk.file = ctx->store.disk.obj.file;
        }
    }

    if(entry->state != NST_DICT_ENTRY_STATE_VALID) {
        entry->state = NST_DICT_ENTRY_STATE_INVALID;

        return NST_ERR;
    }

    return NST_OK;
}

/*
 * Check if valid cache exists
 */
int
nst_cache_exists(nst_ctx_t *ctx) {
    nst_dict_entry_t  *entry = NULL;
    nst_dict_t        *dict  = &nuster.cache->dict;
    nst_disk_t        *disk  = &nuster.cache->store.disk;
    int                ret;

    ret = NST_CTX_STATE_INIT;

    if(!ctx->key) {
        return ret;
    }

    if(!nst_key_memory_checked(ctx->key)) {
        nst_key_memory_set_checked(ctx->key);

        nst_shctx_lock(dict);

        entry = nst_dict_get(dict, ctx->key);

        if(entry) {

            if(entry->state == NST_DICT_ENTRY_STATE_VALID
                    || entry->state == NST_DICT_ENTRY_STATE_UPDATE
                    || entry->state == NST_DICT_ENTRY_STATE_STALE) {

                if(entry->store.memory.obj) {
                    ret = NST_CTX_STATE_HIT_MEMORY;

                    ctx->store.memory.obj = entry->store.memory.obj;
                } else if(entry->store.disk.file) {
                    ret = NST_CTX_STATE_HIT_DISK;

                    ctx->store.disk.obj.file = entry->store.disk.file;
                }

                ctx->txn.res.header_len    = entry->header_len;
                ctx->txn.res.payload_len   = entry->payload_len;
                ctx->txn.res.etag          = entry->etag;
                ctx->txn.res.last_modified = entry->last_modified;
                ctx->prop                  = &entry->prop;

                nst_dict_record_access(entry);
            }

            if(entry->state == NST_DICT_ENTRY_STATE_INIT) {
                ret = NST_CTX_STATE_WAIT;

                ctx->prop = &entry->prop;
            }

            if(entry->state == NST_DICT_ENTRY_STATE_REFRESH) {
                ret = NST_CTX_STATE_UPDATE;

                entry->state = NST_DICT_ENTRY_STATE_UPDATE;
                ctx->entry   = entry;
                ctx->prop    = &entry->prop;
            }

        }

        nst_shctx_unlock(dict);
    }

    if(ret == NST_CTX_STATE_INIT) {

        if(!nst_store_disk_off(ctx->rule->prop.store)) {

            if(!disk->loaded || global.nuster.cache.always_check_disk) {
                ret = NST_CTX_STATE_CHECK_DISK;
            }
        }
    }


    if(ret == NST_CTX_STATE_HIT_MEMORY) {
        return ret;
    }

    if(ret == NST_CTX_STATE_HIT_DISK) {

        if(!nst_key_disk_checked(ctx->key)) {
            nst_key_disk_set_checked(ctx->key);

            if(ctx->store.disk.obj.file) {

                if(nst_disk_obj_valid(&ctx->store.disk.obj, ctx->key) != NST_OK) {

                    ret = NST_CTX_STATE_INIT;

                    if(entry->state == NST_DICT_ENTRY_STATE_VALID) {
                        entry->state = NST_DICT_ENTRY_STATE_INVALID;
                    }
                } else {

                    if(entry->state == NST_DICT_ENTRY_STATE_VALID) {

                        if(nst_disk_meta_check_expire(ctx->store.disk.obj.meta) != NST_OK) {
                            ret = NST_CTX_STATE_INIT;

                            entry->state = NST_DICT_ENTRY_STATE_INVALID;
                        }
                    }

                    if(entry->state == NST_DICT_ENTRY_STATE_UPDATE) {
                        ret = NST_CTX_STATE_HIT_DISK;
                    }

                    if(entry->state == NST_DICT_ENTRY_STATE_STALE) {
                        ret = NST_CTX_STATE_HIT_DISK;
                    }
                }
            } else {
                ret = NST_CTX_STATE_INIT;
            }
        }
    }

    if(ret == NST_CTX_STATE_CHECK_DISK) {

        if(!nst_key_disk_checked(ctx->key)) {
            nst_disk_obj_t  *obj = &ctx->store.disk.obj;

            nst_key_disk_set_checked(ctx->key);

            if(nst_disk_obj_exists(disk, obj, ctx->key) == NST_OK) {
                char *meta      = ctx->store.disk.obj.meta;
                int  stale_prop = nst_disk_meta_get_stale(meta);
                int  stale      = nst_disk_meta_check_stale(meta) != NST_OK;
                int  expired    = nst_disk_meta_check_expire(meta) != NST_OK;

                if(stale_prop == 0 || (stale_prop > 0 && stale) || (stale_prop < 0 && expired)) {
                    ret = NST_CTX_STATE_INIT;
                } else {
                    ctx->prop = (nst_rule_prop_t *)(ctx->buf->area + ctx->buf->data);
                    ctx->buf->data += sizeof(nst_rule_prop_t);

                    ctx->prop->etag = nst_disk_meta_get_etag_prop(meta);

                    if(ctx->prop->etag == NST_STATUS_ON) {
                        ctx->txn.res.etag.ptr = ctx->buf->area + ctx->buf->data;
                        ctx->txn.res.etag.len = nst_disk_meta_get_etag_len(meta);

                        nst_disk_read_etag(obj, ctx->txn.res.etag);

                        ctx->buf->data += ctx->txn.res.etag.len;
                    }

                    ctx->prop->last_modified = nst_disk_meta_get_last_modified_prop(meta);

                    if(ctx->prop->last_modified == NST_STATUS_ON) {
                        ctx->txn.res.last_modified.ptr = ctx->buf->area + ctx->buf->data;
                        ctx->txn.res.last_modified.len = nst_disk_meta_get_last_modified_len(meta);

                        nst_disk_read_last_modified(obj, ctx->txn.res.last_modified);

                        ctx->buf->data += ctx->txn.res.last_modified.len;
                    }

                    ret = NST_CTX_STATE_HIT_DISK;
                }
            } else {
                ret = NST_CTX_STATE_INIT;
            }
        } else {
            ret = NST_CTX_STATE_INIT;
        }
    }

    return ret;
}

void
nst_cache_abort(nst_ctx_t *ctx) {
    nst_dict_entry_t   *entry = ctx->entry;

    if(entry->state == NST_DICT_ENTRY_STATE_INIT || entry->state == NST_DICT_ENTRY_STATE_UPDATE) {

        if(ctx->store.memory.obj) {
            nst_memory_obj_abort(&nuster.cache->store.memory, ctx->store.memory.obj);
        }

        if(ctx->store.disk.obj.file) {
            nst_disk_obj_abort(&nuster.cache->store.disk, &ctx->store.disk.obj);
        }
    }

    if(entry->state == NST_DICT_ENTRY_STATE_INIT) {
        entry->state = NST_DICT_ENTRY_STATE_INVALID;
    }

    if(entry->state == NST_DICT_ENTRY_STATE_UPDATE) {
        entry->state = NST_DICT_ENTRY_STATE_STALE;
    }
}

/*
 * -1: error
 *  0: not found
 *  1: ok
 */
int
nst_cache_delete(nst_key_t *key) {
    nst_dict_t        *dict  = &nuster.cache->dict;
    nst_dict_entry_t  *entry = NULL;
    int                ret   = 1;

    nst_shctx_lock(dict);

    entry = nst_dict_get(dict, key);

    if(entry) {

        if(entry->state == NST_DICT_ENTRY_STATE_VALID
                || entry->state == NST_DICT_ENTRY_STATE_UPDATE
                || entry->state == NST_DICT_ENTRY_STATE_STALE) {

            entry->state  = NST_DICT_ENTRY_STATE_INVALID;
            entry->expire = 0;

            if(entry->store.memory.obj) {
                entry->store.memory.obj->invalid = 1;
                entry->store.memory.obj          = NULL;

                nst_memory_incr_invalid(&nuster.cache->store.memory);
            }

            if(entry->store.disk.file) {
                nst_disk_file_remove(entry->store.disk.file);
                nst_shmem_free(nuster.cache->shmem, entry->store.disk.file);
                entry->store.disk.file = NULL;
            }

            ret = 1;

        }
    } else {
        ret = 0;
    }

    nst_shctx_unlock(dict);

    if(!nuster.cache->store.disk.loaded && global.nuster.cache.root.len){
        nst_disk_obj_t  disk;
        hpx_buffer_t    *buf = get_trash_chunk();

        disk.file = buf->area;

        ret = nst_disk_purge_by_key(&disk, key, global.nuster.cache.root);

    }

    return ret;
}

/*
 * Create cache applet to handle the request
 */
void
nst_cache_hit(hpx_stream_t *s, hpx_stream_interface_t *si, hpx_channel_t *req, hpx_channel_t *res,
        nst_ctx_t *ctx) {

    hpx_appctx_t  *appctx = NULL;

    /*
     * set backend to nuster.applet.cache
     */
    s->target = &nuster.applet.cache.obj_type;

    if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
        /* return to regular process on error */
        s->target = NULL;
    } else {
        appctx = si_appctx(si);
        memset(&appctx->ctx.nuster.store, 0, sizeof(appctx->ctx.nuster.store));

        appctx->st0 = ctx->state;

        if(ctx->state == NST_CTX_STATE_HIT_MEMORY) {
            nst_memory_obj_attach(&nuster.cache->store.memory, ctx->store.memory.obj);
            appctx->ctx.nuster.store.memory.obj  = ctx->store.memory.obj;
            appctx->ctx.nuster.store.memory.item = ctx->store.memory.obj->item;
        } else {
            char  *meta = ctx->store.disk.obj.meta;

            appctx->ctx.nuster.store.disk.fd          = ctx->store.disk.obj.fd;
            appctx->ctx.nuster.store.disk.offset      = nst_disk_pos_header(&ctx->store.disk.obj);
            appctx->ctx.nuster.store.disk.header_len  = nst_disk_meta_get_header_len(meta);
            appctx->ctx.nuster.store.disk.payload_len = nst_disk_meta_get_payload_len(meta);
        }

        appctx->st1 = NST_DISK_APPLET_HEADER;

        req->analysers  &= ~AN_REQ_FLT_HTTP_HDRS;
        req->analysers  &= ~AN_REQ_FLT_XFER_DATA;
        req->analysers  |= AN_REQ_FLT_END;

        req->analyse_exp = TICK_ETERNITY;

        res->flags |= CF_NEVER_WAIT;
    }
}

