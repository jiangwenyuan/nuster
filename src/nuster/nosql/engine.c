/*
 * nuster nosql engine functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <inttypes.h>

#include <types/global.h>
#include <types/stream.h>
#include <types/channel.h>
#include <types/proxy.h>

#include <proto/stream_interface.h>
#include <proto/http_ana.h>
#include <proto/acl.h>
#include <proto/log.h>
#include <proto/proxy.h>
#include <proto/http_htx.h>
#include <common/htx.h>

#include <nuster/nuster.h>

static void
nst_nosql_handler(hpx_appctx_t *appctx) {
    hpx_stream_interface_t  *si      = appctx->owner;
    hpx_stream_t            *s       = si_strm(si);
    hpx_channel_t           *req     = si_oc(si);
    hpx_channel_t           *res     = si_ic(si);
    nst_ring_item_t         *item    = NULL;
    int                      total   = 0;
    hpx_htx_t               *req_htx, *res_htx;
    int                      ret, max, fd, header_len;
    uint64_t                 offset;

    res_htx = htx_from_buf(&res->buf);

    if(unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
        appctx->ctx.nuster.nosql.store.ring.data->clients--;

        return;
    }

    /* Check if the input buffer is avalaible. */
    if(!b_size(&res->buf)) {
        si_rx_room_blk(si);

        return;
    }

    /* check that the output is not closed */
    if(res->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
        appctx->st0 = NST_CTX_STATE_DONE;
    }

    switch(appctx->st0) {
        case NST_NOSQL_APPCTX_STATE_CREATE:

            if(co_data(req)) {
                req_htx = htx_from_buf(&req->buf);
                co_htx_skip(req, req_htx, co_data(req));
                htx_to_buf(req_htx, &req->buf);
            }

            task_wakeup(s->task, TASK_WOKEN_OTHER);

            break;
        case NST_NOSQL_APPCTX_STATE_HIT_MEMORY:

            if(appctx->ctx.nuster.nosql.store.ring.item) {
                item = appctx->ctx.nuster.nosql.store.ring.item;

                while(item) {

                    if(nst_http_ring_item_to_htx(item, res_htx) != NST_OK) {
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
            appctx->ctx.nuster.nosql.store.ring.item = item;
            total = res_htx->data - total;
            channel_add_input(res, total);
            htx_to_buf(res_htx, &res->buf);

            break;
        case NST_NOSQL_APPCTX_STATE_HIT_DISK:
            {
                max        = b_room(&res->buf) - global.tune.maxrewrite;
                header_len = appctx->ctx.nuster.nosql.header_len;
                offset     = appctx->ctx.nuster.nosql.offset;
                fd         = appctx->ctx.nuster.nosql.fd;

                switch(appctx->st1) {
                    case NST_DISK_APPLET_HEADER:
                        {
                            char  *p = trash.area;

                            ret = pread(fd, p, header_len, offset);

                            if(ret != header_len) {
                                appctx->st1 = NST_DISK_APPLET_ERROR;

                                break;
                            }

                            while(header_len != 0) {
                                hpx_htx_blk_type_t  type;
                                hpx_htx_blk_t      *blk;
                                char               *ptr;
                                uint32_t            blksz, sz, info;

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
                            appctx->ctx.nuster.nosql.offset += ret;
                        }

                        break;
                    case NST_DISK_APPLET_PAYLOAD:
                        max = htx_get_max_blksz(res_htx, channel_htx_recv_max(res, res_htx));

                        ret = pread(fd, trash.area, max, offset);

                        if(ret == -1) {
                            appctx->st1 = NST_DISK_APPLET_ERROR;

                            break;
                        }

                        if(ret > 0) {
                            hpx_htx_blk_type_t  type;
                            hpx_htx_blk_t      *blk;
                            char               *ptr;
                            uint32_t            blksz, sz, info;

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
                            memcpy(ptr, trash.area, sz);

                            appctx->ctx.nuster.nosql.offset += ret;

                            break;
                        }

                        close(fd);

                        appctx->st1 = NST_DISK_APPLET_EOM;
                    case NST_DISK_APPLET_EOM:

                        if(!htx_add_endof(res_htx, HTX_BLK_EOM)) {
                            si_rx_room_blk(si);

                            goto end;
                        }

                        appctx->st1 = NST_DISK_APPLET_DONE;
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

                        break;
                }
            }

end:
            total = res_htx->data - total;
            channel_add_input(res, total);
            htx_to_buf(res_htx, &res->buf);
            task_wakeup(s->task, TASK_WOKEN_OTHER);

            break;
        case NST_NOSQL_APPCTX_STATE_ERROR:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_http_reply(s, NST_HTTP_500);

            break;
        case NST_NOSQL_APPCTX_STATE_NOT_ALLOWED:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_http_reply(s, NST_HTTP_405);

            break;
        case NST_NOSQL_APPCTX_STATE_NOT_FOUND:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_http_reply(s, NST_HTTP_404);

            break;
        case NST_NOSQL_APPCTX_STATE_EMPTY:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_http_reply(s, NST_HTTP_400);

            break;
        case NST_NOSQL_APPCTX_STATE_FULL:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_http_reply(s, NST_HTTP_507);

            break;
        case NST_NOSQL_APPCTX_STATE_END:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_http_reply(s, NST_HTTP_200);

            break;
        case NST_NOSQL_APPCTX_STATE_WAIT:
            break;
        case NST_NOSQL_APPCTX_STATE_DONE:

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

            break;
        default:
            co_skip(si_oc(si), co_data(si_oc(si)));

            break;
    }

    return;
}

void
nst_nosql_housekeeping() {

    if(global.nuster.nosql.status == NST_STATUS_ON && master == 1) {

        int  dict_cleaner = global.nuster.nosql.dict_cleaner;
        int  data_cleaner = global.nuster.nosql.data_cleaner;
        int  disk_cleaner = global.nuster.nosql.disk_cleaner;
        int  disk_loader  = global.nuster.nosql.disk_loader;
        int  disk_saver   = global.nuster.nosql.disk_saver;

        while(dict_cleaner--) {
            nst_shctx_lock(&nuster.nosql->dict);
            nst_dict_cleanup(&nuster.nosql->dict);
            nst_shctx_unlock(&nuster.nosql->dict);
        }

        while(data_cleaner--) {
            nst_shctx_lock(&nuster.nosql->store.ring);
            nst_ring_cleanup(&nuster.nosql->store.ring);
            nst_shctx_unlock(&nuster.nosql->store.ring);
        }

        while(disk_cleaner--) {
            nst_nosql_persist_cleanup();
        }

        while(disk_loader--) {
            nst_nosql_persist_load();
        }

        while(disk_saver--) {
            nst_shctx_lock(&nuster.nosql->dict);
            nst_nosql_persist_async();
            nst_shctx_unlock(&nuster.nosql->dict);
        }
    }
}

void
nst_nosql_init() {
    nuster.applet.nosql.fct = nst_nosql_handler;

    if(global.nuster.nosql.status == NST_STATUS_ON) {

        if(global.nuster.nosql.root.len) {

            if(nst_disk_mkdir(global.nuster.nosql.root.ptr) == NST_ERR) {
                ha_alert("Create `%s` failed\n", global.nuster.nosql.root.ptr);
                exit(1);
            }
        }

        global.nuster.nosql.memory = nst_memory_create("nosql.shm",
                global.nuster.nosql.dict_size + global.nuster.nosql.data_size,
                global.tune.bufsize, NST_DEFAULT_CHUNK_SIZE);

        if(!global.nuster.nosql.memory) {
            goto shm_err;
        }

        if(nst_shctx_init(global.nuster.nosql.memory) != NST_OK) {
            goto shm_err;
        }

        nuster.nosql = nst_nosql_memory_alloc(sizeof(nst_core_t));

        if(!nuster.nosql) {
            goto err;
        }

        memset(nuster.nosql, 0, sizeof(*nuster.nosql));

        if(global.nuster.nosql.root.len) {
            int  len = nst_disk_path_file_len(global.nuster.nosql.root) + 1;

            nuster.nosql->store.disk.file = nst_nosql_memory_alloc(len);

            if(!nuster.nosql->store.disk.file) {
                goto err;
            }
        }

        nuster.nosql->memory = global.nuster.nosql.memory;
        nuster.nosql->root   = global.nuster.nosql.root;

        if(nst_dict_init(&nuster.nosql->dict, global.nuster.nosql.memory,
                    global.nuster.nosql.dict_size) != NST_OK) {

            goto err;
        }

        if(nst_store_init(global.nuster.nosql.root, &nuster.nosql->store,
                    global.nuster.nosql.memory) != NST_OK) {

            goto err;
        }

        ha_notice("[nuster][nosql] on, dict_size=%"PRIu64", data_size=%"PRIu64"\n",
                global.nuster.nosql.dict_size, global.nuster.nosql.data_size);
    }

    return;

err:
    ha_alert("Out of memory when initializing nuster nosql.\n");
    exit(1);

shm_err:
    ha_alert("Error when initializing nosql.\n");
    exit(1);
}

/*
 * return 1 if the request is done, otherwise 0
 */
int
nst_nosql_check_applet(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px) {

    if(global.nuster.nosql.status == NST_STATUS_ON && px->nuster.mode == NST_MODE_NOSQL) {
        hpx_stream_interface_t  *si     = &s->si[1];
        hpx_http_txn_t          *txn    = s->txn;
        hpx_http_msg_t          *msg    = &txn->req;
        hpx_appctx_t            *appctx = NULL;
        hpx_htx_t               *htx;

        s->target = &nuster.applet.nosql.obj_type;

        if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
            nst_http_reply(s, NST_HTTP_500);

            if(!(s->flags & SF_ERR_MASK)) {
                s->flags |= SF_ERR_LOCAL;
            }

            return 1;
        } else {
            appctx      = si_appctx(si);
            appctx->st0 = NST_NOSQL_APPCTX_STATE_INIT;
            appctx->st1 = 0;
            appctx->st2 = 0;

            htx = htxbuf(&req->buf);

            if(nst_http_handle_expect(s, htx, msg) == -1) {
                return 1;
            }

            req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
            req->analysers &= ~AN_REQ_FLT_XFER_DATA;
            req->analysers |= AN_REQ_HTTP_XFER_BODY;

        }
    }

    return 0;
}

int
nst_nosql_get_headers(hpx_stream_t *s, hpx_http_msg_t *msg, nst_ctx_t *ctx) {
    hpx_http_hdr_ctx_t  hdr = { .blk = NULL };
    hpx_htx_t          *htx = htxbuf(&s->req.buf);

    if(http_find_header(htx, ist("Content-Type"), &hdr, 0)) {
        ctx->txn.req.content_type.ptr = ctx->txn.buf->area + ctx->txn.buf->data;
        ctx->txn.req.content_type.len = hdr.value.len;

        chunk_istcat(ctx->txn.buf, hdr.value);
    }

    ctx->txn.res.transfer_encoding.ptr = ctx->txn.buf->area + ctx->txn.buf->data;

    while(http_find_header(htx, ist("Transfer-Encoding"), &hdr, 0)) {

        if(ctx->txn.res.transfer_encoding.len) {
            chunk_istcat(ctx->txn.buf, ist(","));
        }

        chunk_istcat(ctx->txn.buf, hdr.value);

        ctx->txn.res.transfer_encoding.len = ctx->txn.res.transfer_encoding.len
            ? ctx->txn.res.transfer_encoding.len + hdr.value.len + 1
            : ctx->txn.res.transfer_encoding.len + hdr.value.len;

    }

    return 1;
}

int
_nst_nosql_create_header(hpx_stream_t *s, nst_ctx_t *ctx, hpx_ist_t clv) {
    nst_ring_item_t     *item_sl, *item_cl, *item_te, *item_eoh;
    hpx_htx_blk_type_t   type;
    hpx_htx_sl_t        *sl;
    uint32_t             size, info;
    hpx_ist_t            clk  = ist("Content-Length");
    hpx_ist_t            tek  = ist("Transfer-Encoding");
    hpx_ist_t            tev  = ist("Chunked");
    hpx_ist_t            p1   = ist("HTTP/1.1");
    hpx_ist_t            p2   = ist("200");
    hpx_ist_t            p3   = ist("OK");
    char                *data = NULL;

    type = HTX_BLK_RES_SL;

    info  = type << 28;
    size  = sizeof(*sl) + p1.len + p2.len + p3.len;
    info += size;

    item_sl = nst_ring_alloc_item(&nuster.nosql->store.ring, size);

    if(!item_sl) {
        goto err;
    }

    data = item_sl->data;

    ctx->txn.res.header_len += 4 + size;

    sl = (hpx_htx_sl_t *)data;
    sl->hdrs_bytes = -1;

    if(ctx->txn.res.content_length) {
        sl->flags = (HTX_SL_F_IS_RESP | HTX_SL_F_VER_11 | HTX_SL_F_XFER_LEN |HTX_SL_F_CLEN);
    } else {
        sl->flags = (HTX_SL_F_IS_RESP | HTX_SL_F_VER_11 | HTX_SL_F_XFER_ENC
                | HTX_SL_F_XFER_LEN | HTX_SL_F_CHNK);
    }

    HTX_SL_P1_LEN(sl) = p1.len;
    HTX_SL_P2_LEN(sl) = p2.len;
    HTX_SL_P3_LEN(sl) = p3.len;
    memcpy(HTX_SL_P1_PTR(sl), p1.ptr, p1.len);
    memcpy(HTX_SL_P2_PTR(sl), p2.ptr, p2.len);
    memcpy(HTX_SL_P3_PTR(sl), p3.ptr, p3.len);

    item_sl->info = info;

    ctx->store.ring.data->item = item_sl;
    ctx->store.ring.item = item_sl;

    if(ctx->txn.res.content_length) {
        type  = HTX_BLK_HDR;
        info  = type << 28;
        size  = clk.len + clv.len;
        info += (clv.len << 8) + clk.len;

        item_cl = nst_ring_alloc_item(&nuster.nosql->store.ring, size);

        if(!item_cl) {
            goto err;
        }

        data = item_cl->data;

        ctx->txn.res.header_len += 4 + size;

        ist2bin_lc(data, clk);
        memcpy(data + clk.len, clv.ptr, clv.len);

        item_cl->info = info;

        ctx->store.ring.item->next = item_cl;
        ctx->store.ring.item = item_cl;
    } else {
        type  = HTX_BLK_HDR;
        info  = type << 28;
        size  = tek.len + tev.len;
        info += (tev.len << 8) + tek.len;

        item_te = nst_ring_alloc_item(&nuster.nosql->store.ring, size);

        if(!item_te) {
            goto err;
        }

        data = item_te->data;

        ctx->txn.res.header_len += 4 + size;

        ist2bin_lc(data, tek);
        memcpy(data + tek.len, tev.ptr, tev.len);

        item_te->info = info;

        ctx->store.ring.item->next = item_te;
        ctx->store.ring.item = item_te;
    }

    type  = HTX_BLK_EOH;
    info  = type << 28;
    size  = 1;
    info += size;

    item_eoh = nst_ring_alloc_item(&nuster.nosql->store.ring, size);

    if(!item_eoh) {
        goto err;
    }

    data = item_eoh->data;

    ctx->txn.res.header_len += 4 + size;

    item_eoh->info = info;

    ctx->store.ring.item->next = item_eoh;
    ctx->store.ring.item = item_eoh;

    return NST_OK;

err:
    nst_nosql_memory_free(item_sl);
    nst_nosql_memory_free(item_cl);
    nst_nosql_memory_free(item_te);
    nst_nosql_memory_free(item_eoh);

    return NST_ERR;
}

void
nst_nosql_create(hpx_stream_t *s, hpx_http_msg_t *msg, nst_ctx_t *ctx) {
    nst_dict_entry_t    *entry   = NULL;
    nst_ring_item_t     *item  = NULL;
    nst_key_t           *key;
    int                  idx;

    idx = ctx->rule->key->idx;
    key = &(ctx->keys[idx]);

    nst_shctx_lock(&nuster.nosql->dict);

    entry = nst_dict_get(&nuster.nosql->dict, key);

    if(entry) {

        if(entry->state == NST_DICT_ENTRY_STATE_INIT) {
            ctx->state = NST_CTX_STATE_WAIT;
        } else {
            entry->state = NST_DICT_ENTRY_STATE_INIT;

            if(entry->store.ring.data) {
                entry->store.ring.data->invalid = 1;
            }

            entry->store.ring.data = nst_ring_alloc_data(&nuster.nosql->store.ring);
            ctx->state  = NST_CTX_STATE_CREATE;
        }
    } else {
        ctx->state = NST_CTX_STATE_CREATE;
        entry = nst_dict_set(&nuster.nosql->dict, key, &ctx->txn, ctx->rule, ctx->pid,
                NST_MODE_NOSQL);
    }

    nst_shctx_unlock(&nuster.nosql->dict);

    if(!entry || !entry->store.ring.data) {
        ctx->state = NST_CTX_STATE_INVALID;
    } else {

        if(ctx->state == NST_CTX_STATE_CREATE) {
            hpx_http_hdr_ctx_t  hdr = { .blk = NULL };
            hpx_htx_sl_t       *sl;
            hpx_htx_t          *htx = htxbuf(&msg->chn->buf);

            ctx->entry   = entry;
            ctx->store.ring.data = entry->store.ring.data;
            ctx->store.ring.item = entry->store.ring.data->item;

            sl = http_get_stline(htx);

            if(sl->flags & HTX_SL_F_CLEN) {
                if(http_find_header(htx, ist("Content-Length"), &hdr, 0)) {
                    long long  cl;

                    strl2llrc(hdr.value.ptr, hdr.value.len, &cl);
                    ctx->txn.res.content_length = cl;
                }
            }

            if(_nst_nosql_create_header(s, ctx, hdr.value) != NST_OK) {
                ctx->state = NST_CTX_STATE_INVALID;

                return;
            }

        }
    }


    if(ctx->state == NST_CTX_STATE_CREATE
            && (ctx->rule->disk == NST_STORE_DISK_ON || ctx->rule->disk == NST_DISK_ONLY)) {

        ctx->store.disk.file = nst_nosql_memory_alloc(
                nst_disk_path_file_len(global.nuster.nosql.root) + 1);

        if(!ctx->store.disk.file) {
            ctx->state = NST_CTX_STATE_INVALID;

            return;
        }

        if(nst_disk_data_init(global.nuster.nosql.root, ctx->store.disk.file, key->hash) != NST_OK) {
            ctx->state = NST_CTX_STATE_INVALID;

            return;
        }

        ctx->store.disk.fd = nst_disk_data_create(ctx->store.disk.file);

        nst_disk_meta_init(ctx->store.disk.meta, (char)ctx->rule->disk, key->hash,
                0, ctx->txn.res.header_len, 0, ctx->entry->key.size, 0, 0, 0, 0, 0);

        nst_disk_write_key(&ctx->store.disk, &ctx->entry->key);

        ctx->store.disk.offset = NST_DISK_META_SIZE + ctx->entry->key.size;

        item = ctx->store.ring.data->item;

        while(item) {
            int  sz = ((item->info & 0xff) + ((item->info >> 8) & 0xfffff));

            nst_disk_write(&ctx->store.disk, (char *)&item->info, 4);
            nst_disk_write(&ctx->store.disk, item->data, sz);

            item = item->next;
        }

    }

err:
    return;
}

int
nst_nosql_update(hpx_http_msg_t *msg, nst_ctx_t *ctx, unsigned int offset, unsigned int len) {

    hpx_htx_t  *htx = htxbuf(&msg->chn->buf);
    int         pos;

    for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
        hpx_htx_blk_t       *blk  = htx_get_blk(htx, pos);
        hpx_htx_blk_type_t   type = htx_get_blk_type(blk);
        uint32_t             sz   = htx_get_blksz(blk);
        nst_ring_item_t     *item;

        if(type != HTX_BLK_DATA) {
            continue;
        }

        if(ctx->rule->disk == NST_DISK_ONLY)  {
            nst_disk_write(&ctx->store.disk, htx_get_blk_ptr(htx, blk), sz);
            ctx->txn.res.payload_len += sz;
        } else {
            item = nst_ring_alloc_item(&nuster.nosql->store.ring, sz);

            if(!item) {
                goto err;
            }

            memcpy(item->data, htx_get_blk_ptr(htx, blk), sz);

            item->info = blk->info;

            if(ctx->store.ring.item) {
                ctx->store.ring.item->next = item;
            } else {
                ctx->store.ring.data->item = item;
            }

            ctx->store.ring.item = item;

            if(ctx->rule->disk == NST_STORE_DISK_ON) {
                nst_disk_write(&ctx->store.disk, htx_get_blk_ptr(htx, blk), sz);
            }

            ctx->txn.res.payload_len += sz;

        }
    }

    return NST_OK;

err:

    return NST_ERR;
}

int
nst_nosql_exists(nst_ctx_t *ctx) {
    nst_dict_entry_t  *entry = NULL;
    int                ret, idx;
    nst_key_t         *key;

    ret = NST_CTX_STATE_INIT;
    idx = ctx->rule->key->idx;
    key = &(ctx->keys[idx]);

    if(!key) {
        return ret;
    }

    nst_shctx_lock(&nuster.nosql->dict);

    entry = nst_dict_get(&nuster.nosql->dict, key);

    if(entry) {
        if(entry->state == NST_DICT_ENTRY_STATE_VALID) {
            ctx->store.ring.data = entry->store.ring.data;
            ctx->store.ring.data->clients++;
            ret = NST_CTX_STATE_HIT_MEMORY;
        }

        if(entry->state == NST_DICT_ENTRY_STATE_INVALID && entry->store.disk.file) {
            ctx->store.disk.file = entry->store.disk.file;
            ret = NST_CTX_STATE_CHECK_DISK;
        }
    } else {
        if(ctx->rule->disk != NST_STORE_DISK_OFF) {
            ctx->store.disk.file = NULL;
            ret = NST_CTX_STATE_CHECK_DISK;
        }
    }

    nst_shctx_unlock(&nuster.nosql->dict);

    if(ret == NST_CTX_STATE_CHECK_DISK) {
        if(ctx->store.disk.file) {
            if(nst_disk_data_valid(&ctx->store.disk, key) == NST_OK) {
                ret = NST_CTX_STATE_HIT_DISK;
            } else {
                ret = NST_CTX_STATE_INIT;
            }
        } else {
            ctx->store.disk.file = nst_nosql_memory_alloc(
                    nst_disk_path_file_len(global.nuster.nosql.root) + 1);

            if(!ctx->store.disk.file) {
                ret = NST_CTX_STATE_INIT;
            } else {

                if(nst_disk_data_exists(global.nuster.nosql.root, &ctx->store.disk, key) == NST_OK) {
                    ret = NST_CTX_STATE_HIT_DISK;
                } else {
                    nst_nosql_memory_free(ctx->store.disk.file);
                    ret = NST_CTX_STATE_INIT;
                }
            }
        }
    }

    return ret;
}

/*
 * -1: error
 *  0: not found
 *  1: ok
 */
int
nst_nosql_delete(nst_key_t *key) {
    nst_dict_entry_t  *entry = NULL;
    int                ret;

    nst_shctx_lock(&nuster.nosql->dict);

    entry = nst_dict_get(&nuster.nosql->dict, key);

    if(entry) {

        if(entry->state == NST_DICT_ENTRY_STATE_VALID) {
            entry->state         = NST_DICT_ENTRY_STATE_INVALID;
            entry->store.ring.data->invalid = 1;
            entry->store.ring.data          = NULL;
            entry->expire        = 0;

            ret = 1;
        }

        if(entry->store.disk.file) {
            ret = nst_disk_purge_by_path(entry->store.disk.file);
        }
    } else {
        ret = 0;
    }

    nst_shctx_unlock(&nuster.nosql->dict);

    if(!nuster.nosql->store.disk.loaded && global.nuster.nosql.root.len){
        nst_disk_data_t  disk;

        disk.file = trash.area;

        ret = nst_disk_purge_by_key(global.nuster.nosql.root, &disk, key);
    }

    return ret;
}


int
nst_nosql_finish(hpx_stream_t *s, hpx_http_msg_t *msg, nst_ctx_t *ctx) {

    if(ctx->txn.res.content_length == 0 && ctx->txn.res.payload_len == 0) {
        ctx->state = NST_CTX_STATE_INVALID;
        ctx->entry->state = NST_DICT_ENTRY_STATE_INVALID;
    } else {
        ctx->state = NST_CTX_STATE_DONE;

        if(ctx->rule->disk == NST_DISK_ONLY) {
            ctx->entry->state = NST_DICT_ENTRY_STATE_INVALID;
        } else {
            ctx->entry->state = NST_DICT_ENTRY_STATE_VALID;
        }


        if(ctx->rule->ttl == 0) {
            ctx->entry->expire = 0;
        } else {
            ctx->entry->expire = get_current_timestamp() / 1000 + ctx->rule->ttl;
        }

        if(ctx->rule->disk == NST_STORE_DISK_ON || ctx->rule->disk == NST_DISK_ONLY) {

            nst_disk_meta_set_expire(ctx->store.disk.meta, ctx->entry->expire);

            if(ctx->txn.res.content_length) {
                nst_disk_meta_set_payload_len(ctx->store.disk.meta, ctx->txn.res.content_length);
            } else {
                nst_disk_meta_set_payload_len(ctx->store.disk.meta, ctx->txn.res.payload_len);
            }

            nst_disk_write_meta(&ctx->store.disk);

            ctx->entry->store.disk.file = ctx->store.disk.file;
        }
    }

    return NST_OK;
}

void
nst_nosql_abort(nst_ctx_t *ctx) {
    ctx->entry->state = NST_DICT_ENTRY_STATE_INVALID;
}

void
nst_nosql_persist_async() {
    nst_dict_entry_t  *entry;

    if(!global.nuster.nosql.root.len || !nuster.nosql->store.disk.loaded) {
        return;
    }

    if(!nuster.nosql->dict.used) {
        return;
    }

    entry = nuster.nosql->dict.entry[nuster.nosql->dict.async_idx];

    while(entry) {

        if(entry->state == NST_DICT_ENTRY_STATE_VALID
                && entry->rule->disk == NST_STORE_DISK_ASYNC
                && entry->store.disk.file == NULL) {

            nst_ring_item_t     *item = entry->store.ring.data->item;
            nst_disk_data_t      disk;
            uint64_t             header_len, payload_len;

            header_len  = 0;
            payload_len = 0;

            entry->store.disk.file = nst_nosql_memory_alloc(
                    nst_disk_path_file_len(global.nuster.nosql.root) + 1);

            if(!entry->store.disk.file) {
                return;
            }

            if(nst_disk_data_init(global.nuster.nosql.root, entry->store.disk.file, entry->key.hash) != NST_OK) {
                return;
            }

            disk.fd = nst_disk_data_create(entry->store.disk.file);

            nst_disk_meta_init(disk.meta, (char)entry->rule->disk,
                    entry->key.hash, entry->expire, 0, 0,
                    entry->key.size, 0, 0, 0, 0, 0);

            nst_disk_write_key(&disk, &entry->key);

            while(item) {
                hpx_htx_blk_type_t  type;
                uint32_t            blksz, info;

                info  = item->info;
                type  = (info >> 28);
                blksz = ((type == HTX_BLK_HDR || type == HTX_BLK_TLR)
                        ? (info & 0xff) + ((info >> 8) & 0xfffff)
                        : info & 0xfffffff);

                if(type != HTX_BLK_DATA) {
                    nst_disk_write(&disk, (char *)&info, 4);

                    payload_len += 4;
                    header_len  += 4 + blksz;
                }

                nst_disk_write(&disk, item->data, blksz);

                payload_len += blksz;

                item = item->next;
            }

            nst_disk_meta_set_header_len(disk.meta, header_len);
            nst_disk_meta_set_payload_len(disk.meta, payload_len);

            nst_disk_write_meta(&disk);

            close(disk.fd);
        }

        entry = entry->next;

    }

    nuster.nosql->dict.async_idx++;

    /* if we have checked the whole dict */
    if(nuster.nosql->dict.async_idx == nuster.nosql->dict.size) {
        nuster.nosql->dict.async_idx = 0;
    }

}

void
nst_nosql_persist_load() {

    if(global.nuster.nosql.root.len && !nuster.nosql->store.disk.loaded) {
        hpx_ist_t      root;
        char          *file;
        char           meta[NST_DISK_META_SIZE];
        int            fd;
        DIR           *dir2;
        nst_dirent_t  *de2;
        nst_key_t      key = { .data = NULL };
        hpx_buffer_t   buf = { .area = NULL };
        hpx_ist_t      host;
        hpx_ist_t      path;

        fd   = -1;
        dir2 = NULL;
        root = global.nuster.nosql.root;
        file = nuster.nosql->store.disk.file;

        if(nuster.nosql->store.disk.dir) {
            nst_dirent_t  *de = nst_disk_dir_next(nuster.nosql->store.disk.dir);

            if(de) {

                if(strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                    return;
                }

                memcpy(file + nst_disk_path_base_len(root), "/", 1);
                memcpy(file + nst_disk_path_base_len(root) + 1, de->d_name, strlen(de->d_name));

                dir2 = opendir(file);

                if(!dir2) {
                    return;
                }

                while((de2 = readdir(dir2)) != NULL) {

                    if(strcmp(de2->d_name, ".") == 0 || strcmp(de2->d_name, "..") == 0) {
                        continue;
                    }

                    memcpy(file + nst_disk_path_hash_len(root), "/", 1);
                    memcpy(file + nst_disk_path_hash_len(root) + 1, de2->d_name,
                            strlen(de2->d_name));

                    fd = nst_disk_open(file);

                    if(fd == -1) {
                        closedir(dir2);

                        return;
                    }

                    if(nst_disk_get_meta(fd, meta) != NST_OK) {
                        goto err;
                    }

                    key.size = nst_disk_meta_get_key_len(meta);
                    key.data = nst_nosql_memory_alloc(key.size);

                    if(!key.data) {
                        goto err;
                    }

                    if(nst_disk_get_key_data(fd, meta, &key) != NST_OK) {
                        goto err;
                    }

                    host.len = nst_disk_meta_get_host_len(meta);
                    path.len = nst_disk_meta_get_path_len(meta);

                    buf.size = host.len + path.len;
                    buf.data = 0;
                    buf.area = nst_nosql_memory_alloc(buf.size);

                    if(!buf.area) {
                        goto err;
                    }

                    host.ptr = buf.area + buf.data;

                    if(nst_disk_get_host(fd, meta, host) != NST_OK) {
                        goto err;
                    }

                    path.ptr = buf.area + buf.data;

                    if(nst_disk_get_path(fd, meta, path) != NST_OK) {
                        goto err;
                    }

                    if(nst_dict_set_from_disk(&nuster.nosql->dict, &buf,
                                host, path, &key, file, meta) != NST_OK) {

                        goto err;
                    }

                    close(fd);
                }

                closedir(dir2);
            } else {
                nuster.nosql->store.disk.idx++;
                closedir(nuster.nosql->store.disk.dir);
                nuster.nosql->store.disk.dir = NULL;
            }
        } else {
            nuster.nosql->store.disk.dir = nst_disk_opendir_by_idx(
                    global.nuster.nosql.root, file, nuster.nosql->store.disk.idx);

            if(!nuster.nosql->store.disk.dir) {
                nuster.nosql->store.disk.idx++;
            }
        }

        if(nuster.nosql->store.disk.idx == 16 * 16) {
            nuster.nosql->store.disk.loaded = 1;
            nuster.nosql->store.disk.idx    = 0;
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

        nst_nosql_memory_free(key.data);
        nst_nosql_memory_free(buf.area);

    }
}

void
nst_nosql_persist_cleanup() {

    if(global.nuster.nosql.root.len && nuster.nosql->store.disk.loaded) {
        char  *file = nuster.nosql->store.disk.file;

        if(nuster.nosql->store.disk.dir) {
            nst_dirent_t *de = nst_disk_dir_next(nuster.nosql->store.disk.dir);

            if(de) {
                nst_disk_cleanup(global.nuster.nosql.root, file, de);
            } else {
                nuster.nosql->store.disk.idx++;
                closedir(nuster.nosql->store.disk.dir);
                nuster.nosql->store.disk.dir = NULL;
            }
        } else {
            nuster.nosql->store.disk.dir = nst_disk_opendir_by_idx(
                    global.nuster.nosql.root, file, nuster.nosql->store.disk.idx);

            if(!nuster.nosql->store.disk.dir) {
                nuster.nosql->store.disk.idx++;
            }
        }

        if(nuster.nosql->store.disk.idx == 16 * 16) {
            nuster.nosql->store.disk.idx = 0;
        }

    }
}
