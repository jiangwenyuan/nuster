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

#include <haproxy/stream_interface.h>

#include <nuster/nuster.h>

static void
nst_nosql_handler(hpx_appctx_t *appctx) {
    hpx_stream_interface_t  *si   = appctx->owner;
    hpx_stream_t            *s    = si_strm(si);
    hpx_channel_t           *req  = si_oc(si);
    hpx_channel_t           *res  = si_ic(si);
    nst_memory_item_t       *item = NULL;
    hpx_buffer_t            *buf;
    hpx_htx_t               *req_htx, *res_htx;
    hpx_htx_blk_type_t       type;
    hpx_htx_blk_t           *blk;
    char                    *p, *ptr;
    uint64_t                 offset, payload_len;
    uint32_t                 blksz, sz, info;
    int                      ret, max, fd, header_len, total;

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

            break;
        case NST_NOSQL_APPCTX_STATE_HIT_MEMORY:

            if(appctx->ctx.nuster.store.memory.item) {
                item = appctx->ctx.nuster.store.memory.item;

                while(item) {

                    if(nst_http_memory_item_to_htx(item, res_htx) != NST_OK) {
                        si_rx_room_blk(si);

                        goto out;
                    }

                    item = item->next;
                }
            }

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

            nst_memory_obj_detach(&nuster.nosql->store.memory, appctx->ctx.nuster.store.memory.obj);

out:
            appctx->ctx.nuster.store.memory.item = item;
            total = res_htx->data - total;

            if(total) {
                channel_add_input(res, total);
            }

            htx_to_buf(res_htx, &res->buf);

            break;
        case NST_NOSQL_APPCTX_STATE_HIT_DISK:
            {
                max         = b_room(&res->buf) - global.tune.maxrewrite;
                header_len  = appctx->ctx.nuster.store.disk.header_len;
                payload_len = appctx->ctx.nuster.store.disk.payload_len;
                offset      = appctx->ctx.nuster.store.disk.offset;
                fd          = appctx->ctx.nuster.store.disk.fd;

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
                        appctx->ctx.nuster.store.disk.offset += ret;

                        break;
                    case NST_DISK_APPLET_PAYLOAD:
                        buf = get_trash_chunk();
                        p   = buf->area;
                        max = htx_get_max_blksz(res_htx, channel_htx_recv_max(res, res_htx));

                        if(max <= 0) {
                            goto end;
                        }

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

                        /* fall through */
                    case NST_DISK_APPLET_EOP:

                        if(!htx_add_endof(res_htx, HTX_BLK_EOT)) {
                            si_rx_room_blk(si);

                            goto end;
                        }

                        if(!htx_add_endof(res_htx, HTX_BLK_EOM)) {
                            si_rx_room_blk(si);

                            goto end;
                        }

                        appctx->st1 = NST_DISK_APPLET_DONE;

                        /* fall through */
                    case NST_DISK_APPLET_DONE:

                        close(fd);

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

            if(total) {
                channel_add_input(res, total);
            }

            htx_to_buf(res_htx, &res->buf);

            break;
        case NST_NOSQL_APPCTX_STATE_END:
            nst_http_reply(s, NST_HTTP_200);

            break;
        case NST_NOSQL_APPCTX_STATE_NOT_FOUND:
            nst_http_reply(s, NST_HTTP_404);

            break;
        case NST_NOSQL_APPCTX_STATE_ERROR:
            nst_http_reply(s, NST_HTTP_500);

            break;
        case NST_NOSQL_APPCTX_STATE_FULL:
            nst_http_reply(s, NST_HTTP_507);

            break;
        case NST_NOSQL_APPCTX_STATE_NOT_ALLOWED:
            nst_http_reply(s, NST_HTTP_400);

            break;
        default:
            co_skip(si_oc(si), co_data(si_oc(si)));

            break;
    }

    return;
}

void
nst_nosql_housekeeping() {
    nst_dict_t   *dict  = &nuster.nosql->dict;
    nst_store_t  *store = &nuster.nosql->store;
    uint64_t      start;

#ifndef USE_THREAD
    uint64_t      begin = nst_time_now_ms();
#endif

    if(global.nuster.nosql.status == NST_STATUS_ON && master == 1) {
        int  dict_cleaner = global.nuster.nosql.dict_cleaner;
        int  data_cleaner = global.nuster.nosql.data_cleaner;
        int  disk_cleaner = global.nuster.nosql.disk_cleaner;
        int  disk_saver   = global.nuster.nosql.disk_saver;
        int  ms           = 10;
        int  ratio        = 1;

#ifndef USE_THREAD
        int  disk_loader  = global.nuster.nosql.disk_loader;
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
            nst_store_memory_sync_disk(nuster.nosql);

            if(nst_time_now_ms() - start >= ms) {
                break;
            }
        }

        start = nst_time_now_ms();

        while(store->disk.loaded && disk_cleaner--) {
            nst_disk_cleanup(nuster.nosql);

            if(nst_time_now_ms() - start >= ms) {
                break;
            }
        }

#ifndef USE_THREAD
        while(!store->disk.loaded && disk_loader--) {
            nst_disk_load(nuster.nosql);

            if(nst_time_now_ms() - begin >= 500) {
                break;
            }
        }
#endif

    }
}

void
nst_nosql_init() {
    hpx_ist_t     root;
    nst_shmem_t  *shmem;
    uint64_t      dict_size, data_size, size;
    int           clean_temp;

    root       = global.nuster.nosql.root;
    dict_size  = global.nuster.nosql.dict_size;
    data_size  = global.nuster.nosql.data_size;
    size       = dict_size + data_size;
    clean_temp = global.nuster.nosql.clean_temp;

    nuster.applet.nosql.fct = nst_nosql_handler;

    if(global.nuster.nosql.status == NST_STATUS_ON) {

        shmem = nst_shmem_create("nosql.shm", size, global.tune.bufsize, NST_DEFAULT_CHUNK_SIZE);

        if(!shmem) {
            ha_alert("Failed to create nuster nosql memory zone.\n");
            exit(1);
        }

        global.nuster.nosql.shmem = shmem;

        if(nst_shctx_init(shmem) != NST_OK) {
            ha_alert("Failed to init nuster nosql memory.\n");
            exit(1);
        }

        nuster.nosql = nst_shmem_alloc(shmem, sizeof(nst_core_t));

        if(!nuster.nosql) {
            ha_alert("Failed to init nuster nosql core.\n");
            exit(1);
        }

        memset(nuster.nosql, 0, sizeof(*nuster.nosql));

        nuster.nosql->shmem = shmem;
        nuster.nosql->root  = root;

        if(nst_store_init(&nuster.nosql->store, root, shmem, clean_temp, nuster.nosql) != NST_OK) {
            ha_alert("Failed to init nuster nosql store.\n");
            exit(1);
        }

        if(nst_dict_init(&nuster.nosql->dict, &nuster.nosql->store, shmem, dict_size) != NST_OK) {
            ha_alert("Failed to init nuster nosql dict.\n");
            exit(1);
        }

    }
}

/*
 * return 1 if the request is done, otherwise 0
 */
int
nst_nosql_check_applet(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px) {

    if(global.nuster.nosql.status == NST_STATUS_ON && px->nuster.mode == NST_MODE_NOSQL) {
        hpx_stream_interface_t  *si     = &s->si[1];
        hpx_http_meth_t          meth   = s->txn->meth;
        hpx_appctx_t            *appctx = NULL;

        if(meth != HTTP_METH_GET && meth != HTTP_METH_POST && meth != HTTP_METH_DELETE) {
            nst_http_reply(s, NST_HTTP_405);

            return 1;
        }

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

            req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
            req->analysers &= ~AN_REQ_FLT_XFER_DATA;
            req->analysers |= AN_REQ_HTTP_XFER_BODY;

        }
    }

    return 0;
}

nst_memory_item_t *
_nst_nosql_create_header(hpx_stream_t *s, nst_http_txn_t *txn, nst_rule_prop_t *prop) {
    nst_memory_t        *mem  = &nuster.nosql->store.memory;
    nst_memory_item_t   *item_sl, *item_ct, *item_te, *item_eoh, *item_et, *item_lm, *tail;
    hpx_htx_blk_type_t   type;
    hpx_htx_sl_t        *sl;
    hpx_ist_t            ctk  = ist("content-type");
    hpx_ist_t            tek  = ist("transfer-encoding");
    hpx_ist_t            etk  = ist("etag");
    hpx_ist_t            lmk  = ist("last-modified");
    hpx_ist_t            tev  = ist("chunked");
    hpx_ist_t            p1   = ist("HTTP/1.1");
    hpx_ist_t            p2   = ist("200");
    hpx_ist_t            p3   = ist("OK");
    char                *data = NULL;
    uint32_t             size, info;

    item_sl = item_ct = item_te = item_eoh = tail = NULL;

    /* status line */
    type  = HTX_BLK_RES_SL;
    info  = type << 28;
    size  = sizeof(*sl) + p1.len + p2.len + p3.len;
    info += size;

    txn->res.header_len += 4 + size;

    item_sl = nst_memory_alloc_item(mem, size);

    if(!item_sl) {
        goto err;
    }

    data = item_sl->data;

    sl = (hpx_htx_sl_t *)data;
    sl->hdrs_bytes = -1;

    sl->flags = HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_ENC|HTX_SL_F_XFER_LEN|HTX_SL_F_CHNK;

    HTX_SL_P1_LEN(sl) = p1.len;
    HTX_SL_P2_LEN(sl) = p2.len;
    HTX_SL_P3_LEN(sl) = p3.len;
    memcpy(HTX_SL_P1_PTR(sl), p1.ptr, p1.len);
    memcpy(HTX_SL_P2_PTR(sl), p2.ptr, p2.len);
    memcpy(HTX_SL_P3_PTR(sl), p3.ptr, p3.len);

    item_sl->info = info;

    tail = item_sl;

    /* content-type */
    type  = HTX_BLK_HDR;
    info  = type << 28;
    size  = ctk.len + txn->req.content_type.len;
    info += (txn->req.content_type.len << 8) + ctk.len;

    item_ct = nst_memory_alloc_item(mem, size);

    if(!item_ct) {
        goto err;
    }

    data = item_ct->data;

    txn->res.header_len += 4 + size;

    ist2bin_lc(data, ctk);
    memcpy(data + ctk.len, txn->req.content_type.ptr, txn->req.content_type.len);

    item_ct->info = info;

    tail->next = item_ct;
    tail       = item_ct;

    /* transfer-encoding */
    type  = HTX_BLK_HDR;
    info  = type << 28;
    size  = tek.len + tev.len;
    info += (tev.len << 8) + tek.len;

    item_te = nst_memory_alloc_item(mem, size);

    if(!item_te) {
        goto err;
    }

    data = item_te->data;

    txn->res.header_len += 4 + size;

    ist2bin_lc(data, tek);
    memcpy(data + tek.len, tev.ptr, tev.len);

    item_te->info = info;

    tail->next = item_te;
    tail       = item_te;

    /* etag */
    if(prop->etag) {
        type  = HTX_BLK_HDR;
        info  = type << 28;
        size  = etk.len + txn->res.etag.len;
        info += (txn->res.etag.len << 8) + etk.len;

        item_et = nst_memory_alloc_item(mem, size);

        if(!item_et) {
            goto err;
        }

        data = item_et->data;

        txn->res.header_len += 4 + size;

        ist2bin_lc(data, etk);
        memcpy(data + etk.len, txn->res.etag.ptr, txn->res.etag.len);

        item_et->info = info;

        tail->next = item_et;
        tail       = item_et;
    }

    /* last-modified */
    if(prop->last_modified) {
        type  = HTX_BLK_HDR;
        info  = type << 28;
        size  = lmk.len + txn->res.last_modified.len;
        info += (txn->res.last_modified.len << 8) + lmk.len;

        item_lm = nst_memory_alloc_item(mem, size);

        if(!item_lm) {
            goto err;
        }

        data = item_lm->data;

        txn->res.header_len += 4 + size;

        ist2bin_lc(data, lmk);
        memcpy(data + lmk.len, txn->res.last_modified.ptr, txn->res.last_modified.len);

        item_lm->info = info;

        tail->next = item_lm;
        tail       = item_lm;
    }

    /* eoh */
    type  = HTX_BLK_EOH;
    info  = type << 28;
    size  = 1;
    info += size;

    item_eoh = nst_memory_alloc_item(mem, size);

    if(!item_eoh) {
        goto err;
    }

    data = item_eoh->data;

    txn->res.header_len += 4 + size;

    item_eoh->info = info;

    tail->next = item_eoh;
    tail       = item_eoh;
    tail->next = NULL;

    return item_sl;

err:
    nst_shmem_free(nuster.nosql->shmem, item_sl);
    nst_shmem_free(nuster.nosql->shmem, item_ct);
    nst_shmem_free(nuster.nosql->shmem, item_te);
    nst_shmem_free(nuster.nosql->shmem, item_eoh);

    return NULL;
}

void
nst_nosql_create(hpx_stream_t *s, hpx_http_msg_t *msg, nst_ctx_t *ctx) {
    nst_dict_entry_t   *entry  = NULL;
    nst_memory_item_t  *item   = NULL;
    nst_memory_item_t  *header = NULL;
    nst_dict_t         *dict   = &nuster.nosql->dict;
    nst_memory_t       *mem    = &nuster.nosql->store.memory;
    nst_disk_t         *disk   = &nuster.nosql->store.disk;

    header = _nst_nosql_create_header(s, &ctx->txn, &ctx->rule->prop);

    if(header == NULL) {
        ctx->state = NST_CTX_STATE_FULL;

        return;
    }

    ctx->state = NST_CTX_STATE_CREATE;

    nst_shctx_lock(dict);

    entry = nst_dict_get(dict, ctx->key);

    if(entry) {

        if(entry->state == NST_DICT_ENTRY_STATE_VALID) {
            entry->state = NST_DICT_ENTRY_STATE_UPDATE;
        }

        ctx->state = NST_CTX_STATE_UPDATE;
        ctx->entry = entry;

        memcpy(entry->etag.ptr, ctx->txn.res.etag.ptr, entry->etag.len);
        memcpy(entry->last_modified.ptr, ctx->txn.res.last_modified.ptr, entry->last_modified.len);
    }

    if(ctx->state == NST_CTX_STATE_CREATE) {
        entry = nst_dict_set(dict, ctx->key, &ctx->txn, &ctx->rule->prop);

        if(entry) {
            ctx->state = NST_CTX_STATE_CREATE;
            ctx->entry = entry;
        } else {
            ctx->state = NST_CTX_STATE_FULL;
        }
    }

    nst_shctx_unlock(dict);

    /* init store data */

    if(ctx->state == NST_CTX_STATE_CREATE || ctx->state == NST_CTX_STATE_UPDATE) {
        if(nst_store_memory_on(ctx->rule->prop.store)) {
            ctx->store.memory.obj = nst_memory_obj_create(mem);
        }

        if(nst_store_disk_on(ctx->rule->prop.store)) {
            nst_disk_obj_create(disk, &ctx->store.disk.obj, ctx->key, &ctx->txn, &ctx->rule->prop);
        }
    }

    /* create header */

    if(ctx->state == NST_CTX_STATE_CREATE || ctx->state == NST_CTX_STATE_UPDATE) {

        if(nst_store_memory_on(ctx->rule->prop.store) && ctx->store.memory.obj) {
            ctx->store.memory.obj->item = header;

            item = header;

            while(item) {
                ctx->store.memory.item = item;

                item = item->next;
            }
        }

        if(nst_store_disk_on(ctx->rule->prop.store) && ctx->store.disk.obj.file) {
            item = header;

            while(item) {
                int  sz = ((item->info & 0xff) + ((item->info >> 8) & 0xfffff));

                nst_disk_obj_append(disk, &ctx->store.disk.obj, (char *)&item->info, 4);
                nst_disk_obj_append(disk, &ctx->store.disk.obj, item->data, sz);

                item = item->next;
            }
        }

        if(nst_store_memory_off(ctx->rule->prop.store)) {
            item = header;

            while(item) {
                nst_memory_item_t  *t = item;

                item = item->next;

                nst_shmem_free(nuster.nosql->shmem, t);
            }
        }
    }

err:
    return;
}

int
nst_nosql_append(hpx_http_msg_t *msg, nst_ctx_t *ctx, unsigned int offset, unsigned int len) {
    hpx_htx_blk_type_t  type;
    hpx_htx_ret_t       htxret;
    hpx_htx_blk_t      *blk;
    hpx_htx_t          *htx;
    nst_memory_t       *mem;
    nst_disk_t         *disk;
    unsigned int        forward = 0;

    htx    = htxbuf(&msg->chn->buf);
    htxret = htx_find_offset(htx, offset);
    blk    = htxret.blk;
    offset = htxret.ret;
    disk   = &nuster.nosql->store.disk;
    mem    = &nuster.nosql->store.memory;

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
                int  ret;

                ret = nst_memory_obj_append(mem, ctx->store.memory.obj,
                        &ctx->store.memory.item, data.ptr, data.len, info);

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
                int  ret;

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

void
nst_nosql_finish(hpx_stream_t *s, hpx_http_msg_t *msg, nst_ctx_t *ctx) {
    hpx_htx_blk_type_t  type;
    nst_dict_t         *dict;
    nst_memory_t       *mem;
    nst_disk_t         *disk;
    nst_dict_entry_t   *entry;
    uint32_t            size, info;

    type  = HTX_BLK_EOT;
    info  = type << 28;
    size  = 1;
    info += size;
    dict  = &nuster.nosql->dict;
    mem   = &nuster.nosql->store.memory;
    disk  = &nuster.nosql->store.disk;
    entry = ctx->entry;

    ctx->state = NST_CTX_STATE_DONE;

    entry->ctime = nst_time_now_ms();

    if(entry->prop.ttl == 0) {
        entry->expire = 0;
    } else {
        entry->expire = entry->ctime / 1000 + entry->prop.ttl;
    }

    if(nst_store_memory_on(ctx->rule->prop.store) && ctx->store.memory.obj) {

        if(!(msg->flags & HTTP_MSGF_TE_CHNK)) {
            nst_memory_obj_t    *obj  = ctx->store.memory.obj;
            nst_memory_item_t  **item = &ctx->store.memory.item;
            int                  ret;

            ret = nst_memory_obj_append(mem, obj, item, "", size, info);

            if(ret == NST_ERR) {
                ctx->store.memory.obj = NULL;
            }
        }
    }

    if(nst_store_memory_on(ctx->rule->prop.store) && ctx->store.memory.obj) {

        nst_shctx_lock(dict);

        if(entry && entry->state != NST_DICT_ENTRY_STATE_INVALID && entry->store.memory.obj) {
            entry->store.memory.obj->invalid = 1;

            nst_memory_incr_invalid(mem);
        }

        entry->state = NST_DICT_ENTRY_STATE_VALID;
        entry->store.memory.obj = ctx->store.memory.obj;

        nst_shctx_unlock(dict);
    }

    if(nst_store_disk_on(ctx->rule->prop.store) && ctx->store.disk.obj.file) {

        if(!(msg->flags & HTTP_MSGF_TE_CHNK)) {
            nst_disk_obj_append(disk, &ctx->store.disk.obj, (char *)&info, 4);
            nst_disk_obj_append(disk, &ctx->store.disk.obj, "", size);
        }
    }

    if(nst_store_disk_on(ctx->rule->prop.store) && ctx->store.disk.obj.file) {
        nst_disk_obj_t  *obj = &ctx->store.disk.obj;

        if(nst_disk_obj_finish(disk, obj, ctx->key, &ctx->txn, entry->expire) == NST_OK) {
            entry->state = NST_DICT_ENTRY_STATE_VALID;

            entry->store.disk.file = ctx->store.disk.obj.file;
        }
    }


    if(entry->state != NST_DICT_ENTRY_STATE_VALID) {
        ctx->state = NST_CTX_STATE_INVALID;
        entry->state = NST_DICT_ENTRY_STATE_INIT;
    }

}

int
nst_nosql_exists(nst_ctx_t *ctx) {
    nst_dict_entry_t  *entry = NULL;
    nst_dict_t        *dict  = &nuster.nosql->dict;
    nst_memory_t      *mem   = &nuster.nosql->store.memory;
    nst_disk_t        *disk  = &nuster.nosql->store.disk;
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
                    || entry->state == NST_DICT_ENTRY_STATE_UPDATE) {

                if(entry->store.memory.obj) {
                    ctx->store.memory.obj = entry->store.memory.obj;
                    nst_memory_obj_attach(mem, ctx->store.memory.obj);
                    ret = NST_CTX_STATE_HIT_MEMORY;
                } else if(entry->store.disk.file) {
                    ctx->store.disk.obj.file = entry->store.disk.file;
                    ret = NST_CTX_STATE_HIT_DISK;
                }

                ctx->txn.res.header_len    = entry->header_len;
                ctx->txn.res.payload_len   = entry->payload_len;
                ctx->txn.res.etag          = entry->etag;
                ctx->txn.res.last_modified = entry->last_modified;
                ctx->prop                  = &entry->prop;

                nst_dict_record_access(entry);
            }

            if(entry->state == NST_DICT_ENTRY_STATE_INIT) {
                ret = NST_CTX_STATE_INIT;
            }
        }

        nst_shctx_unlock(dict);
    }

    if(ret == NST_CTX_STATE_INIT) {

        if(!nst_store_disk_off(ctx->rule->prop.store)) {

            if(!disk->loaded || global.nuster.nosql.always_check_disk) {
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
                int  valid  = nst_disk_obj_valid(&ctx->store.disk.obj, ctx->key);
                int  expire = nst_disk_meta_check_expire(ctx->store.disk.obj.meta);

                if(valid != NST_OK && expire != NST_OK) {
                    ret = NST_CTX_STATE_INIT;

                    if(entry && entry->state == NST_DICT_ENTRY_STATE_VALID) {
                        entry->state = NST_DICT_ENTRY_STATE_INVALID;
                    }
                }
            } else {
                ret = NST_CTX_STATE_INIT;
            }
        }
    }

    if(ret == NST_CTX_STATE_CHECK_DISK) {

        if(!nst_key_disk_checked(ctx->key)) {
            char  *meta   = ctx->store.disk.obj.meta;
            int    exists = nst_disk_obj_exists(disk, &ctx->store.disk.obj, ctx->key);

            nst_key_disk_set_checked(ctx->key);

            if(exists == NST_OK && nst_disk_meta_check_expire(meta) == NST_OK) {

                ctx->prop = (nst_rule_prop_t *)(ctx->buf->area + ctx->buf->data);
                ctx->buf->data += sizeof(nst_rule_prop_t);

                ctx->prop->etag = nst_disk_meta_get_etag_prop(meta);

                if(ctx->prop->etag == NST_STATUS_ON) {
                    ctx->txn.res.etag.ptr = ctx->buf->area + ctx->buf->data;
                    ctx->txn.res.etag.len = nst_disk_meta_get_etag_len(meta);

                    nst_disk_read_etag(&ctx->store.disk.obj, ctx->txn.res.etag);

                    ctx->buf->data += ctx->txn.res.etag.len;
                }

                ctx->prop->last_modified = nst_disk_meta_get_last_modified_prop(meta);

                if(ctx->prop->last_modified == NST_STATUS_ON) {
                    ctx->txn.res.last_modified.ptr = ctx->buf->area + ctx->buf->data;
                    ctx->txn.res.last_modified.len = nst_disk_meta_get_last_modified_len(meta);

                    nst_disk_read_last_modified(&ctx->store.disk.obj, ctx->txn.res.last_modified);

                    ctx->buf->data += ctx->txn.res.last_modified.len;
                }

                ret = NST_CTX_STATE_HIT_DISK;
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
nst_nosql_abort(nst_ctx_t *ctx) {
    nst_dict_entry_t  *entry = ctx->entry;

    if(entry->state == NST_DICT_ENTRY_STATE_INIT || entry->state == NST_DICT_ENTRY_STATE_UPDATE) {

        if(ctx->store.memory.obj) {
            nst_memory_obj_abort(&nuster.nosql->store.memory, ctx->store.memory.obj);
        }

        if(ctx->store.disk.obj.file) {
            nst_disk_obj_abort(&nuster.nosql->store.disk, &ctx->store.disk.obj);
        }
    }

    entry->state = NST_DICT_ENTRY_STATE_INVALID;
}

/*
 * -1: error
 *  0: not found
 *  1: ok
 */
int
nst_nosql_delete(nst_key_t *key) {
    nst_dict_t        *dict  = &nuster.nosql->dict;
    nst_dict_entry_t  *entry = NULL;
    int                ret   = 0;

    nst_shctx_lock(dict);

    entry = nst_dict_get(dict, key);

    if(entry) {

        if(entry->state == NST_DICT_ENTRY_STATE_VALID
                || entry->state == NST_DICT_ENTRY_STATE_UPDATE) {

            entry->state  = NST_DICT_ENTRY_STATE_INIT;
            entry->expire = 0;

            if(entry->store.memory.obj) {
                entry->store.memory.obj->invalid = 1;
                entry->store.memory.obj          = NULL;

                nst_memory_incr_invalid(&nuster.nosql->store.memory);
            }

            if(entry->store.disk.file) {
                nst_disk_file_remove(entry->store.disk.file);
                nst_shmem_free(nuster.nosql->shmem, entry->store.disk.file);
                entry->store.disk.file = NULL;
            }

            ret = 1;
        }

    } else {
        ret = 0;
    }

    nst_shctx_unlock(dict);

    if(!nuster.nosql->store.disk.loaded && global.nuster.nosql.root.len){
        nst_disk_obj_t  disk;
        hpx_buffer_t    *buf = get_trash_chunk();

        disk.file = buf->area;

        ret = nst_disk_purge_by_key(&disk, key, global.nuster.nosql.root);
    }

    return ret;
}

