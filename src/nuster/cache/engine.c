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

#include <proto/log.h>
#include <proto/http_ana.h>
#include <proto/raw_sock.h>
#include <proto/stream_interface.h>
#include <proto/acl.h>
#include <proto/proxy.h>
#include <proto/http_htx.h>
#include <common/htx.h>

#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#include <types/ssl_sock.h>
#endif

#include <nuster/nuster.h>

static void _nst_cache_memory_handler(struct appctx *appctx) {
    struct stream_interface *si = appctx->owner;
    struct channel *req = si_oc(si);
    struct channel *res = si_ic(si);

    struct htx *req_htx, *res_htx;
    struct nst_data_element *element = NULL;
    int total = 0;

    res_htx = htxbuf(&res->buf);
    total = res_htx->data;

    if(unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
        appctx->ctx.nuster.cache.data->clients--;

        goto out;
    }

    /* Check if the input buffer is avalaible. */
    if(!b_size(&res->buf)) {
        si_rx_room_blk(si);

        goto out;
    }

    if(res->flags & (CF_SHUTW|CF_SHUTR|CF_SHUTW_NOW)) {
        appctx->ctx.nuster.cache.element = NULL;
    }

    if(appctx->ctx.nuster.cache.element) {
        element = appctx->ctx.nuster.cache.element;

        while(element) {
            if(nst_http_data_element_to_htx(element, res_htx) != NST_OK) {
                si_rx_room_blk(si);

                goto out;
            }

            element = element->next;

        }

    } else {

        if(!htx_add_endof(res_htx, HTX_BLK_EOM)) {
            si_rx_room_blk(si);

            goto out;
        }

        appctx->ctx.nuster.cache.data->clients--;

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
    appctx->ctx.nuster.cache.element = element;
    total = res_htx->data - total;
    channel_add_input(res, total);
    htx_to_buf(res_htx, &res->buf);
}

/*
 * The cache disk applet acts like the backend to send cached http data
 */
static void _nst_cache_disk_handler(struct appctx *appctx) {
    struct stream_interface *si = appctx->owner;

    struct channel *req = si_oc(si);
    struct channel *res = si_ic(si);
    struct htx *req_htx, *res_htx;
    int total = 0;
    int ret;
    int max;

    int fd = appctx->ctx.nuster.cache.fd;
    int header_len = appctx->ctx.nuster.cache.header_len;
    uint64_t offset = appctx->ctx.nuster.cache.offset;

    res_htx = htxbuf(&res->buf);
    total = res_htx->data;

    if(unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
        goto out;
    }

    /* Check if the input buffer is avalaible. */
    if(res->buf.size == 0) {
        si_rx_room_blk(si);

        goto out;
    }

    /* check that the output is not closed */
    if(res->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
        appctx->st1 = NST_PERSIST_APPLET_DONE;
    }

    switch(appctx->st1) {
        case NST_PERSIST_APPLET_HEADER:
            {
                char *p = trash.area;
                ret = pread(fd, p, header_len, offset);

                if(ret != header_len) {
                    appctx->st1 = NST_PERSIST_APPLET_ERROR;

                    break;
                }

                while(header_len != 0) {
                    struct htx_blk *blk;
                    char *ptr;
                    uint32_t blksz, sz, info;
                    enum htx_blk_type type;

                    info = *(uint32_t *)p;
                    type = (info >> 28);
                    blksz = (info & 0xff) + ((info >> 8) & 0xfffff);

                    blk = htx_add_blk(res_htx, type, blksz);

                    if(!blk) {
                        appctx->st1 = NST_PERSIST_APPLET_ERROR;

                        break;
                    }

                    blk->info = info;
                    ptr = htx_get_blk_ptr(res_htx, blk);
                    sz = htx_get_blksz(blk);
                    p += 4;
                    memcpy(ptr, p, sz);
                    p += sz;

                    header_len -= 4 + sz;
                }

                appctx->st1 = NST_PERSIST_APPLET_PAYLOAD;
                offset += ret;
                appctx->ctx.nuster.cache.offset = offset;
            }

        case NST_PERSIST_APPLET_PAYLOAD:
            max = htx_get_max_blksz(res_htx, channel_htx_recv_max(res, res_htx));
            ret = pread(fd, trash.area, max, offset);

            if(ret == -1) {
                appctx->st1 = NST_PERSIST_APPLET_ERROR;

                break;
            }

            if(ret > 0) {
                struct htx_blk *blk;
                char *ptr;
                uint32_t blksz, sz, info;
                enum htx_blk_type type;

                type = HTX_BLK_DATA;
                info = (type << 28) + ret;
                blksz = info & 0xfffffff;

                blk = htx_add_blk(res_htx, type, blksz);

                if(!blk) {
                    appctx->st1 = NST_PERSIST_APPLET_ERROR;

                    break;
                }

                blk->info = info;
                ptr = htx_get_blk_ptr(res_htx, blk);
                sz = htx_get_blksz(blk);
                memcpy(ptr, trash.area, sz);

                appctx->ctx.nuster.cache.offset += ret;

                break;
            }

            close(fd);

            appctx->st1 = NST_PERSIST_APPLET_EOM;

        case NST_PERSIST_APPLET_EOM:

            if(!htx_add_endof(res_htx, HTX_BLK_EOM)) {
                si_rx_room_blk(si);

                goto out;
            }

            appctx->st1 = NST_PERSIST_APPLET_DONE;
        case NST_PERSIST_APPLET_DONE:

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
        case NST_PERSIST_APPLET_ERROR:
            si_shutr(si);
            res->flags |= CF_READ_NULL;
            close(fd);

            return;
    }

out:
    total = res_htx->data - total;
    channel_add_input(res, total);
    htx_to_buf(res_htx, &res->buf);
}

/*
 * The cache applet acts like the backend to send cached http data
 */
static void nst_cache_handler(struct appctx *appctx) {
    if(appctx->st0 == NST_CACHE_CTX_STATE_HIT_MEMORY) {
        _nst_cache_memory_handler(appctx);
    } else {
        _nst_cache_disk_handler(appctx);
    }
}

/*
 * create a new nst_cache_data and insert it to cache->data list
 */
struct nst_cache_data *nst_cache_data_new() {

    struct nst_cache_data *data = nst_cache_memory_alloc(sizeof(*data));

    nst_shctx_lock(nuster.cache);

    if(data) {
        memset(data, 0, sizeof(*data));

        if(nuster.cache->data_head == NULL) {
            nuster.cache->data_head = data;
            nuster.cache->data_tail = data;
            data->next              = data;
        } else {

            if(nuster.cache->data_head == nuster.cache->data_tail) {
                nuster.cache->data_head->next = data;
                data->next                    = nuster.cache->data_head;
                nuster.cache->data_tail       = data;
            } else {
                data->next                    = nuster.cache->data_head;
                nuster.cache->data_tail->next = data;
                nuster.cache->data_tail       = data;
            }
        }
    }

    nst_shctx_unlock(nuster.cache);

    return data;
}

static int _nst_cache_data_invalid(struct nst_cache_data *data) {

    if(data->invalid) {

        if(!data->clients) {
            return 1;
        }

    }

    return 0;
}

/*
 * free invalid nst_cache_data
 */
static void _nst_cache_data_cleanup() {
    struct nst_cache_data *data = NULL;

    if(nuster.cache->data_head) {

        if(nuster.cache->data_head == nuster.cache->data_tail) {

            if(_nst_cache_data_invalid(nuster.cache->data_head)) {
                data                    = nuster.cache->data_head;
                nuster.cache->data_head = NULL;
                nuster.cache->data_tail = NULL;
            }

        } else {

            if(_nst_cache_data_invalid(nuster.cache->data_head)) {
                data                          = nuster.cache->data_head;
                nuster.cache->data_tail->next = nuster.cache->data_head->next;
                nuster.cache->data_head       = nuster.cache->data_head->next;
            } else {
                nuster.cache->data_tail = nuster.cache->data_head;
                nuster.cache->data_head = nuster.cache->data_head->next;
            }

        }

    }

    if(data) {
        struct nst_data_element *element = data->element;

        while(element) {
            struct nst_data_element *tmp = element;
            element                      = element->next;

            nst_cache_memory_free(tmp);
        }

        nst_cache_memory_free(data);
    }
}

void nst_cache_housekeeping() {

    if(global.nuster.cache.status == NST_STATUS_ON && master == 1) {

        int dict_cleaner = global.nuster.cache.dict_cleaner;
        int data_cleaner = global.nuster.cache.data_cleaner;
        int disk_cleaner = global.nuster.cache.disk_cleaner;
        int disk_loader  = global.nuster.cache.disk_loader;
        int disk_saver   = global.nuster.cache.disk_saver;

        while(dict_cleaner--) {
            nst_shctx_lock(&nuster.cache->dict[0]);
            nst_cache_dict_cleanup();
            nst_shctx_unlock(&nuster.cache->dict[0]);
        }

        while(data_cleaner--) {
            nst_shctx_lock(nuster.cache);
            _nst_cache_data_cleanup();
            nst_shctx_unlock(nuster.cache);
        }

        while(disk_cleaner--) {
            nst_cache_persist_cleanup();
        }

        while(disk_loader--) {
            nst_cache_persist_load();
        }

        while(disk_saver--) {
            nst_shctx_lock(&nuster.cache->dict[0]);
            nst_cache_persist_async();
            nst_shctx_unlock(&nuster.cache->dict[0]);
        }

    }
}

void nst_cache_init() {

    nuster.applet.cache.fct = nst_cache_handler;

    if(global.nuster.cache.status == NST_STATUS_ON) {

        if(global.nuster.cache.root.len) {

            if(nst_persist_mkdir(global.nuster.cache.root.ptr) == NST_ERR) {
                ha_alert("Create `%s` failed\n", global.nuster.cache.root.ptr);

                exit(1);
            }
        }

        global.nuster.cache.memory = nst_memory_create("cache.shm", global.nuster.cache.dict_size
                + global.nuster.cache.data_size, global.tune.bufsize, NST_CACHE_DEFAULT_CHUNK_SIZE);

        if(!global.nuster.cache.memory) {
            goto shm_err;
        }

        if(nst_shctx_init(global.nuster.cache.memory) != NST_OK) {
            goto shm_err;
        }

        nuster.cache = nst_cache_memory_alloc(sizeof(struct nst_cache));

        if(!nuster.cache) {
            goto err;
        }

        memset(nuster.cache, 0, sizeof(*nuster.cache));

        if(global.nuster.cache.root.len) {
            int len = nst_persist_path_file_len(global.nuster.cache.root) + 1;

            nuster.cache->disk.file = nst_cache_memory_alloc(len);

            if(!nuster.cache->disk.file) {
                goto err;
            }
        }

        if(nst_shctx_init(nuster.cache) != NST_OK) {
            goto shm_err;
        }

        if(nst_cache_dict_init() != NST_OK) {
            goto err;
        }

        ha_notice("[nuster][cache] on, data_size=%"PRIu64"\n", global.nuster.cache.data_size);

    }

    return;

err:
    ha_alert("Out of memory when initializing cache.\n");
    exit(1);

shm_err:
    ha_alert("Error when initializing cache.\n");
    exit(1);
}

static void _nst_cache_record_access(struct nst_cache_entry *entry) {
    if(entry->expire == 0 || entry->extend[0] == 0xFF) {
        entry->access[0]++;
    } else {
        uint64_t stime, diff;
        uint32_t ttl = entry->ttl;
        float pct;

        stime = entry->ctime + ttl * entry->extended * 1000;
        diff = entry->atime - stime;

        pct = diff / 1000.0 / ttl * 100;

        if(pct < 100 - entry->extend[0] - entry->extend[1] - entry->extend[2]) {
            entry->access[0]++;
        } else if(pct < 100 - entry->extend[1] - entry->extend[2]) {
            entry->access[1]++;
        } else if(pct < 100 - entry->extend[2]) {
            entry->access[2]++;
        } else {
            entry->access[3]++;
        }
    }

}

/*
 * Check if valid cache exists
 */
int nst_cache_exists(struct nst_cache_ctx *ctx) {
    struct nst_cache_entry *entry = NULL;
    int ret = NST_CACHE_CTX_STATE_INIT;

    int idx = ctx->rule->key->idx;
    struct nst_key *key = &(ctx->keys[idx]);

    if(!key) {
        return ret;
    }

    nst_shctx_lock(&nuster.cache->dict[0]);
    entry = nst_cache_dict_get(key);

    if(entry) {

        /*
         * before disk, entry is set to valid after response is cached to memory
         * now we can save cache to both memory and disk, and we can also save
         * cache to disk only.
         * To keep from big changes, we still use valid to indicate the cache is
         * in memory, and use another *file to indicate the disk persistence.
         * So if valid, return memory cache
         * if invalid and file is set, return disk cache
         * if entry is null, check disk and return cache if exists
         * Since valid only indicates whether or not cached is in memory, the
         * state is set to invalid even if the cache is successfully saved to
         * disk in disk_only mode
         */
        if(entry->state == NST_CACHE_ENTRY_STATE_VALID) {
            ctx->data = entry->data;
            ctx->data->clients++;

            ctx->txn.res.etag  = entry->etag;

            ctx->txn.res.last_modified = entry->last_modified;

            _nst_cache_record_access(entry);

            ret = NST_CACHE_CTX_STATE_HIT_MEMORY;
        }

        if(entry->state == NST_CACHE_ENTRY_STATE_INVALID && entry->file) {
            ctx->disk.file = entry->file;
            ret = NST_CACHE_CTX_STATE_CHECK_PERSIST;
        }
    } else {
        if(ctx->rule->disk != NST_DISK_OFF) {
            ctx->disk.file = NULL;

            if(nuster.cache->disk.loaded) {
                ret = NST_CACHE_CTX_STATE_INIT;
            } else {
                ret = NST_CACHE_CTX_STATE_CHECK_PERSIST;
            }
        }
    }

    nst_shctx_unlock(&nuster.cache->dict[0]);

    if(ret == NST_CACHE_CTX_STATE_CHECK_PERSIST) {

        if(ctx->disk.file) {

            if(nst_persist_valid(&ctx->disk, key) == NST_OK) {
                _nst_cache_record_access(entry);
                ret = NST_CACHE_CTX_STATE_HIT_DISK;
            } else {
                ret = NST_CACHE_CTX_STATE_INIT;
            }
        } else {
            ctx->disk.file = nst_cache_memory_alloc(
                    nst_persist_path_file_len(global.nuster.cache.root) + 1);

            if(!ctx->disk.file) {
                ret = NST_CACHE_CTX_STATE_INIT;
            } else {

                if(nst_persist_exists(global.nuster.cache.root, &ctx->disk, key) == NST_OK) {
                    ret = NST_CACHE_CTX_STATE_HIT_DISK;
                } else {
                    nst_cache_memory_free(ctx->disk.file);
                    ret = NST_CACHE_CTX_STATE_INIT;
                }
            }
        }
    }

    return ret;
}

void nst_cache_create(struct http_msg *msg, struct nst_cache_ctx *ctx) {
    struct nst_cache_entry *entry = NULL;

    int idx = ctx->rule->key->idx;
    struct nst_key *key = &(ctx->keys[idx]);
    struct buffer buf = { .area = NULL };

    nst_shctx_lock(&nuster.cache->dict[0]);
    entry = nst_cache_dict_get(key);

    if(entry) {

        if(entry->state == NST_CACHE_ENTRY_STATE_CREATING) {
            ctx->state = NST_CACHE_CTX_STATE_WAIT;
        } else if(entry->state == NST_CACHE_ENTRY_STATE_VALID) {
            ctx->state = NST_CACHE_CTX_STATE_HIT_MEMORY;
        } else if(entry->state == NST_CACHE_ENTRY_STATE_EXPIRED
                || entry->state == NST_CACHE_ENTRY_STATE_INVALID) {

            entry->state = NST_CACHE_ENTRY_STATE_CREATING;

            if(ctx->rule->disk != NST_DISK_ONLY) {
                entry->data = nst_cache_data_new();

                buf.size = ctx->txn.buf->data;
                buf.data = ctx->txn.buf->data;
                buf.area = nst_cache_memory_alloc(buf.size);

                if(!entry->data || !buf.area) {
                    entry->state = NST_CACHE_ENTRY_STATE_INVALID;
                    ctx->state   = NST_CACHE_CTX_STATE_BYPASS;
                } else {
                    ctx->state   = NST_CACHE_CTX_STATE_CREATE;
                    ctx->entry   = entry;

                    memcpy(buf.area, ctx->txn.buf->area, buf.data);

                    entry->buf = buf;

                    entry->host.ptr = buf.area + (ctx->txn.req.host.ptr - ctx->txn.buf->area);
                    entry->host.len = ctx->txn.req.host.len;

                    entry->path.ptr = buf.area + (ctx->txn.req.path.ptr - ctx->txn.buf->area);
                    entry->path.len = ctx->txn.req.path.len;

                    entry->etag.ptr = buf.area + (ctx->txn.res.etag.ptr - ctx->txn.buf->area);
                    entry->etag.len = ctx->txn.res.etag.len;

                    entry->last_modified.ptr = buf.area
                        + (ctx->txn.res.last_modified.ptr - ctx->txn.buf->area);

                    entry->last_modified.len = ctx->txn.res.last_modified.len;

                    ctx->data    = entry->data;
                    ctx->element = entry->data->element;
                }
            } else {
                ctx->state = NST_CACHE_CTX_STATE_CREATE;
                ctx->entry = entry;
            }

        } else {
            ctx->state = NST_CACHE_CTX_STATE_BYPASS;
        }
    } else {
        entry = nst_cache_dict_set(ctx);

        if(entry) {
            ctx->state = NST_CACHE_CTX_STATE_CREATE;
            ctx->entry = entry;
            ctx->data  = entry->data;

            if(ctx->data) {
                ctx->element = entry->data->element;
            }
        } else {
            ctx->state = NST_CACHE_CTX_STATE_BYPASS;
        }
    }

    nst_shctx_unlock(&nuster.cache->dict[0]);

    if(ctx->state == NST_CACHE_CTX_STATE_CREATE) {
        int pos;
        struct htx *htx = htxbuf(&msg->chn->buf);
        ctx->txn.res.header_len = 0;

        for(pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
            struct htx_blk *blk = htx_get_blk(htx, pos);
            uint32_t        sz  = htx_get_blksz(blk);
            enum htx_blk_type type = htx_get_blk_type(blk);

            struct nst_data_element *element = NULL;

            if(ctx->rule->disk != NST_DISK_ONLY)  {
                element = nst_cache_memory_alloc(sizeof(struct nst_data_element) + sz);

                if(!element) {
                    goto err;
                }

                memcpy(element->data, htx_get_blk_ptr(htx, blk), sz);

                element->info = blk->info;
                element->next = NULL;

                if(ctx->element) {
                    ctx->element->next = element;
                } else {
                    ctx->data->element = element;
                }

                ctx->element = element;
            }

            ctx->txn.res.header_len += 4 + sz;

            if(type == HTX_BLK_EOH) {
                break;
            }

        }
    }

    if(ctx->state == NST_CACHE_CTX_STATE_CREATE
            && (ctx->rule->disk == NST_DISK_SYNC || ctx->rule->disk == NST_DISK_ONLY)) {

        uint64_t ttl_extend = ctx->rule->ttl;
        int pos;
        struct htx *htx;

        ctx->disk.file = nst_cache_memory_alloc(
                nst_persist_path_file_len(global.nuster.cache.root) + 1);

        if(!ctx->disk.file) {
            return;
        }

        if(nst_persist_init(global.nuster.cache.root, ctx->disk.file, key->hash) != NST_OK) {
            return;
        }

        ctx->disk.fd = nst_persist_create(ctx->disk.file);

        ttl_extend = ttl_extend << 32;
        *( uint8_t *)(&ttl_extend)      = ctx->rule->extend[0];
        *((uint8_t *)(&ttl_extend) + 1) = ctx->rule->extend[1];
        *((uint8_t *)(&ttl_extend) + 2) = ctx->rule->extend[2];
        *((uint8_t *)(&ttl_extend) + 3) = ctx->rule->extend[3];

        nst_persist_meta_init(ctx->disk.meta, (char)ctx->rule->disk, key->hash, 0,
                ctx->txn.res.header_len, 0, ctx->entry->key.size, ctx->entry->host.len,
                ctx->entry->path.len, ctx->entry->etag.len, ctx->entry->last_modified.len,
                ttl_extend);

        nst_persist_write_key(&ctx->disk, &ctx->entry->key);
        nst_persist_write_host(&ctx->disk, ctx->entry->host);
        nst_persist_write_path(&ctx->disk, ctx->entry->path);
        nst_persist_write_etag(&ctx->disk, ctx->entry->etag);
        nst_persist_write_last_modified(&ctx->disk, ctx->entry->last_modified);

        htx = htxbuf(&msg->chn->buf);

        for(pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
            struct htx_blk *blk = htx_get_blk(htx, pos);
            uint32_t        sz  = htx_get_blksz(blk);
            enum htx_blk_type type = htx_get_blk_type(blk);

            nst_persist_write(&ctx->disk, (char *)&blk->info, 4);
            nst_persist_write(&ctx->disk, htx_get_blk_ptr(htx, blk), sz);

            if(type == HTX_BLK_EOH) {
                break;
            }
        }
    }

err:
    return;
}

/*
 * Add partial http data to nst_cache_data
 */
int nst_cache_update(struct http_msg *msg, struct nst_cache_ctx *ctx, unsigned int offset,
        unsigned int len) {

    int pos;
    struct htx *htx = htxbuf(&msg->chn->buf);

    for(pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
        struct htx_blk *blk = htx_get_blk(htx, pos);
        uint32_t        sz  = htx_get_blksz(blk);
        enum htx_blk_type type = htx_get_blk_type(blk);
        struct nst_data_element *element;

        if(type != HTX_BLK_DATA) {
            continue;
        }

        if(ctx->rule->disk == NST_DISK_ONLY)  {
            nst_persist_write(&ctx->disk, htx_get_blk_ptr(htx, blk), sz);
        } else {
            element = nst_cache_memory_alloc(sizeof(*element) + sz);

            if(!element) {
                goto err;
            }

            memcpy(element->data, htx_get_blk_ptr(htx, blk), sz);

            element->info = blk->info;
            element->next = NULL;

            if(ctx->element) {
                ctx->element->next = element;
            } else {
                ctx->data->element = element;
            }

            ctx->element = element;

            if(ctx->rule->disk == NST_DISK_SYNC) {
                nst_persist_write(&ctx->disk, htx_get_blk_ptr(htx, blk), sz);
            }

        }

        ctx->txn.res.payload_len += sz;
    }

    return NST_OK;

err:

    return NST_ERR;
}

/*
 * cache done
 */
void nst_cache_finish(struct nst_cache_ctx *ctx) {
    ctx->state = NST_CACHE_CTX_STATE_DONE;

    if(ctx->rule->disk == NST_DISK_ONLY) {
        ctx->entry->state = NST_CACHE_ENTRY_STATE_INVALID;
    } else {
        ctx->entry->state = NST_CACHE_ENTRY_STATE_VALID;
    }

    ctx->entry->ctime = get_current_timestamp();

    if(ctx->rule->ttl == 0) {
        ctx->entry->expire = 0;
    } else {
        ctx->entry->expire = ctx->entry->ctime / 1000 + ctx->rule->ttl;
    }

    if(ctx->rule->disk == NST_DISK_SYNC || ctx->rule->disk == NST_DISK_ONLY) {

        nst_persist_meta_set_expire(ctx->disk.meta, ctx->entry->expire);

        nst_persist_meta_set_payload_len(ctx->disk.meta, ctx->txn.res.payload_len);

        nst_persist_write_meta(&ctx->disk);

        ctx->entry->file = ctx->disk.file;
    }
}

void nst_cache_abort(struct nst_cache_ctx *ctx) {
    ctx->entry->state = NST_CACHE_ENTRY_STATE_INVALID;
}

/*
 * -1: error
 *  0: not found
 *  1: ok
 */
int nst_cache_delete(struct nst_key *key) {
    struct nst_cache_entry *entry = NULL;
    int ret;

    nst_shctx_lock(&nuster.cache->dict[0]);
    entry = nst_cache_dict_get(key);

    if(entry) {

        if(entry->state == NST_CACHE_ENTRY_STATE_VALID) {
            entry->state         = NST_CACHE_ENTRY_STATE_EXPIRED;
            entry->data->invalid = 1;
            entry->data          = NULL;
            entry->expire        = 0;

            ret = 1;
        }

        if(entry->file) {
            ret = nst_persist_purge_by_path(entry->file);
        }
    } else {
        ret = 0;
    }

    nst_shctx_unlock(&nuster.cache->dict[0]);

    if(!nuster.cache->disk.loaded && global.nuster.cache.root.len){
        struct persist disk;

        disk.file = nst_cache_memory_alloc(nst_persist_path_file_len(global.nuster.cache.root) + 1);

        if(!disk.file) {
            ret = -1;
        } else {
            ret = nst_persist_purge_by_key(global.nuster.cache.root, &disk, key);
        }

        nst_cache_memory_free(disk.file);
    }

    return ret;
}

/*
 * Create cache applet to handle the request
 */
void nst_cache_hit(struct stream *s, struct stream_interface *si, struct channel *req,
        struct channel *res, struct nst_cache_ctx *ctx) {

    struct appctx *appctx = NULL;

    /*
     * set backend to nuster.applet.cache
     */
    s->target = &nuster.applet.cache.obj_type;

    if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
        /* return to regular process on error */
        ctx->data->clients--;
        s->target = NULL;
    } else {
        appctx = si_appctx(si);
        memset(&appctx->ctx.nuster.cache, 0, sizeof(appctx->ctx.nuster.cache));

        appctx->st0 = ctx->state;

        if(ctx->state == NST_CACHE_CTX_STATE_HIT_MEMORY) {
            appctx->ctx.nuster.cache.data    = ctx->data;
            appctx->ctx.nuster.cache.element = ctx->data->element;
        } else {

            appctx->ctx.nuster.cache.fd = ctx->disk.fd;
            appctx->ctx.nuster.cache.offset = nst_persist_get_header_pos(ctx->disk.meta);
            appctx->ctx.nuster.cache.header_len = nst_persist_meta_get_header_len(ctx->disk.meta);
        }

        appctx->st1 = NST_PERSIST_APPLET_HEADER;

        req->analysers &= ~AN_REQ_FLT_HTTP_HDRS;
        req->analysers &= ~AN_REQ_FLT_XFER_DATA;

        req->analysers |= AN_REQ_FLT_END;
        req->analyse_exp = TICK_ETERNITY;

        res->flags |= CF_NEVER_WAIT;
    }
}

void nst_cache_persist_async() {
    struct nst_cache_entry *entry;

    if(!global.nuster.cache.root.len || !nuster.cache->disk.loaded) {
        return;
    }

    if(!nuster.cache->dict[0].used) {
        return;
    }

    entry = nuster.cache->dict[0].entry[nuster.cache->persist_idx];

    while(entry) {

        if(!nst_cache_entry_invalid(entry) && entry->rule->disk == NST_DISK_ASYNC
                && entry->file == NULL) {

            struct nst_data_element *element = entry->data->element;
            struct persist disk;
            uint64_t ttl_extend  = entry->ttl;
            uint64_t header_len  = 0;
            uint64_t payload_len = 0;

            entry->file = nst_cache_memory_alloc(
                    nst_persist_path_file_len(global.nuster.cache.root) + 1);

            if(!entry->file) {
                return;
            }

            if(nst_persist_init(global.nuster.cache.root, entry->file, entry->key.hash) != NST_OK) {
                return;
            }

            disk.fd = nst_persist_create(entry->file);

            ttl_extend = ttl_extend << 32;
            *( uint8_t *)(&ttl_extend)      = entry->extend[0];
            *((uint8_t *)(&ttl_extend) + 1) = entry->extend[1];
            *((uint8_t *)(&ttl_extend) + 2) = entry->extend[2];
            *((uint8_t *)(&ttl_extend) + 3) = entry->extend[3];

            nst_persist_meta_init(disk.meta, (char)entry->rule->disk, entry->key.hash,
                    entry->expire, 0, 0, entry->key.size, entry->host.len, entry->path.len,
                    entry->etag.len, entry->last_modified.len, ttl_extend);

            nst_persist_write_key(&disk,  &entry->key);
            nst_persist_write_host(&disk, entry->host);
            nst_persist_write_path(&disk, entry->path);
            nst_persist_write_etag(&disk, entry->etag);
            nst_persist_write_last_modified(&disk, entry->last_modified);

            while(element) {
                uint32_t blksz, info;
                enum htx_blk_type type;

                info = element->info;
                type = (info >> 28);
                blksz = ((type == HTX_BLK_HDR || type == HTX_BLK_TLR)
                        ? (info & 0xff) + ((info >> 8) & 0xfffff)
                        : info & 0xfffffff);

                if(type != HTX_BLK_DATA) {
                    nst_persist_write(&disk, (char *)&info, 4);
                    header_len += 4 + blksz;
                }

                nst_persist_write(&disk, element->data, blksz);

                payload_len += blksz;

                element = element->next;
            }

            nst_persist_meta_set_header_len(disk.meta, header_len);
            nst_persist_meta_set_payload_len(disk.meta, payload_len);

            nst_persist_write_meta(&disk);

            close(disk.fd);
        }

        entry = entry->next;

    }

    nuster.cache->persist_idx++;

    /* if we have checked the whole dict */
    if(nuster.cache->persist_idx == nuster.cache->dict[0].size) {
        nuster.cache->persist_idx = 0;
    }

}

void nst_cache_persist_load() {

    if(global.nuster.cache.root.len && !nuster.cache->disk.loaded) {
        struct ist root;
        char *file;
        char meta[NST_PERSIST_META_SIZE];
        int fd;
        DIR *dir2;
        struct dirent *de2;
        struct nst_key key = { .data = NULL };
        struct buffer buf = { .area = NULL };
        struct ist host;
        struct ist path;

        fd = -1;
        dir2 = NULL;

        root = global.nuster.cache.root;
        file = nuster.cache->disk.file;

        if(nuster.cache->disk.dir) {
            struct dirent *de = nst_persist_dir_next(nuster.cache->disk.dir);

            if(de) {

                if(strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {

                    return;
                }

                memcpy(file + nst_persist_path_base_len(root), "/", 1);
                memcpy(file + nst_persist_path_base_len(root) + 1, de->d_name, strlen(de->d_name));

                dir2 = opendir(file);

                if(!dir2) {
                    return;
                }

                while((de2 = readdir(dir2)) != NULL) {

                    if(strcmp(de2->d_name, ".") == 0 || strcmp(de2->d_name, "..") == 0) {
                        continue;
                    }

                    memcpy(file + nst_persist_path_hash_len(root), "/", 1);
                    memcpy(file + nst_persist_path_hash_len(root) + 1, de2->d_name,
                            strlen(de2->d_name));

                    fd = nst_persist_open(file);

                    if(fd == -1) {
                        closedir(dir2);

                        return;
                    }

                    if(nst_persist_get_meta(fd, meta) != NST_OK) {
                        goto err;
                    }

                    key.size = nst_persist_meta_get_key_len(meta);
                    key.data = nst_cache_memory_alloc(key.size);

                    if(!key.data) {
                        goto err;
                    }

                    if(nst_persist_get_key(fd, meta, &key) != NST_OK) {
                        goto err;
                    }

                    host.len = nst_persist_meta_get_host_len(meta);
                    path.len = nst_persist_meta_get_path_len(meta);

                    buf.size = host.len + path.len;
                    buf.data = 0;
                    buf.area = nst_cache_memory_alloc(buf.size);

                    if(!buf.area) {
                        goto err;
                    }

                    host.ptr = buf.area + buf.data;

                    if(nst_persist_get_host(fd, meta, host) != NST_OK) {
                        goto err;
                    }

                    path.ptr = buf.area + buf.data;

                    if(nst_persist_get_path(fd, meta, path) != NST_OK) {
                        goto err;
                    }

                    if(nst_cache_dict_set_from_disk(buf, host, path, key, file, meta) != NST_OK) {
                        goto err;
                    }

                    close(fd);
                }

                closedir(dir2);
            } else {
                nuster.cache->disk.idx++;
                closedir(nuster.cache->disk.dir);
                nuster.cache->disk.dir = NULL;
            }
        } else {
            nuster.cache->disk.dir = nst_persist_opendir_by_idx(
                    global.nuster.cache.root, file, nuster.cache->disk.idx);

            if(!nuster.cache->disk.dir) {
                nuster.cache->disk.idx++;
            }
        }

        if(nuster.cache->disk.idx == 16 * 16) {
            nuster.cache->disk.loaded = 1;
            nuster.cache->disk.idx    = 0;
        }

        return;

err:

        if(file) {
            unlink(file);
        }

        if(fd) {
            close(fd);
        }

        if(dir2) {
            closedir(dir2);
        }

        nst_cache_memory_free(key.data);
        nst_cache_memory_free(buf.area);

    }
}

void nst_cache_persist_cleanup() {

    if(global.nuster.cache.root.len && nuster.cache->disk.loaded) {
        char *file = nuster.cache->disk.file;

        if(nuster.cache->disk.dir) {
            struct dirent *de = nst_persist_dir_next(nuster.cache->disk.dir);

            if(de) {
                nst_persist_cleanup(global.nuster.cache.root, file, de);
            } else {
                nuster.cache->disk.idx++;
                closedir(nuster.cache->disk.dir);
                nuster.cache->disk.dir = NULL;
            }
        } else {
            nuster.cache->disk.dir = nst_persist_opendir_by_idx(
                    global.nuster.cache.root, file, nuster.cache->disk.idx);

            if(!nuster.cache->disk.dir) {
                nuster.cache->disk.idx++;
            }
        }

        if(nuster.cache->disk.idx == 16 * 16) {
            nuster.cache->disk.idx = 0;
        }

    }
}

void nst_cache_build_etag(struct stream *s, struct http_msg *msg, struct nst_cache_ctx *ctx) {

    struct htx *htx;

    struct http_hdr_ctx hdr = { .blk = NULL };

    ctx->txn.res.etag.ptr = ctx->txn.buf->area + ctx->txn.buf->data;
    ctx->txn.res.etag.len = 0;

    htx = htxbuf(&s->res.buf);

    if(http_find_header(htx, ist("ETag"), &hdr, 1)) {
        ctx->txn.res.etag.len = hdr.value.len;

        chunk_istcat(ctx->txn.buf, hdr.value);
    } else {
        uint64_t t = get_current_timestamp();

        sprintf(ctx->txn.res.etag.ptr, "\"%08x\"", XXH32(&t, 8, 0));
        ctx->txn.res.etag.len = 10;
        b_add(ctx->txn.buf, ctx->txn.res.etag.len);

        if(ctx->rule->etag == NST_STATUS_ON) {
            http_add_header(htx, ist("Etag"), ctx->txn.res.etag);
        }
    }
}

void
nst_cache_build_last_modified(struct stream *s, struct http_msg *msg, struct nst_cache_ctx *ctx) {

    struct htx *htx;

    struct http_hdr_ctx hdr = { .blk = NULL };

    int len  = sizeof("Mon, 01 JAN 1970 00:00:00 GMT") - 1;

    htx = htxbuf(&s->res.buf);

    ctx->txn.res.last_modified.ptr = ctx->txn.buf->area + ctx->txn.buf->data;
    ctx->txn.res.last_modified.len = len;

    if(http_find_header(htx, ist("Last-Modified"), &hdr, 1)) {

        if(hdr.value.len == len) {
            chunk_istcat(ctx->txn.buf, hdr.value);
        }

    } else {
        char mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
            "Nov", "Dec" };

        char day[7][4]  = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

        struct tm *tm;
        time_t now;
        time(&now);
        tm = gmtime(&now);

        sprintf(ctx->txn.res.last_modified.ptr, "%s, %02d %s %04d %02d:%02d:%02d GMT",
                day[tm->tm_wday], tm->tm_mday, mon[tm->tm_mon],
                1900 + tm->tm_year, tm->tm_hour, tm->tm_min, tm->tm_sec);
        b_add(ctx->txn.buf, ctx->txn.res.last_modified.len);

        if(ctx->rule->last_modified == NST_STATUS_ON) {
            http_add_header(htx, ist("Last-Modified"), ctx->txn.res.last_modified);
        }
    }
}

