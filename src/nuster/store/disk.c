/*
 * nuster disk related functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <dirent.h>

#include <types/global.h>

#include <nuster/nuster.h>

int
nst_disk_mkdir(char *path) {
    char  *p = path;

    while(*p != '\0') {
        p++;

        while(*p != '/' && *p != '\0') {
            p++;
        }

        if(*p == '/') {
            *p = '\0';

            if(mkdir(path, S_IRWXU) == -1 && errno != EEXIST) {
                *p = '/';

                return NST_ERR;
            }

            *p = '/';
        }

    }

    if(mkdir(path, S_IRWXU) == -1 && errno != EEXIST) {
        return NST_ERR;
    }

    return NST_OK;
}

static inline void
nst_disk_data_init(hpx_ist_t root, char *path, nst_key_t *key) {
}

int
nst_disk_data_valid(nst_disk_data_t *data, nst_key_t *key) {
    hpx_buffer_t  *buf;
    int            ret;

    buf = get_trash_chunk();

    data->fd = nst_disk_open(data->file);

    if(data->fd == -1) {
        goto err;
    }

    ret = pread(data->fd, data->meta, NST_DISK_META_SIZE, 0);

    if(ret != NST_DISK_META_SIZE) {
        goto err;
    }

    if(memcmp(data->meta, "NUSTER", 6) !=0) {
        goto err;
    }

    if(data->meta[7] != NST_DISK_VERSION) {
        goto err;
    }

    if(nst_disk_meta_check_expire(data->meta) != NST_OK) {
        goto err;
    }

    if(nst_disk_meta_get_hash(data->meta) != key->hash
            || nst_disk_meta_get_key_len(data->meta) != key->size) {

        goto err;
    }

    ret = pread(data->fd, buf->area, key->size, NST_DISK_POS_KEY);

    if(ret != key->size) {
        goto err;
    }

    if(memcmp(key->data, buf->area, key->size) != 0) {
        goto err;
    }

    return NST_OK;

err:
    close(data->fd);

    return NST_ERR;
}

int
nst_disk_data_exists(nst_disk_t *disk, nst_disk_data_t *data, nst_key_t *key) {
    hpx_buffer_t  *buf1, *buf2;
    char          *p;

    buf1 = get_trash_chunk();
    buf2 = get_trash_chunk();
    p    = buf1->area;

    data->file = buf2->area;

    nst_key_uuid_stringify(key, p);

    p[NST_DISK_FILE_LEN] = '\0';

    sprintf(data->file, "%s/%c/%c%c/%s", disk->root.ptr, p[0], p[0], p[1], p);

    if(nst_disk_data_valid(data, key) == NST_OK) {
        return NST_OK;
    }

    return NST_ERR;
}

DIR *
nst_disk_opendir_by_idx(hpx_ist_t root, char *path, int idx) {
    sprintf(path, "%s/%x/%02x", root.ptr, idx / 16, idx);

    return opendir(path);
}

nst_dirent_t *
nst_disk_dir_next(DIR *dir) {
    return readdir(dir);
}

int
nst_disk_read_meta(nst_disk_data_t *data) {
    int  ret;

    ret = pread(data->fd, data->meta, NST_DISK_META_SIZE, 0);

    if(ret != NST_DISK_META_SIZE) {
        return NST_ERR;
    }

    if(memcmp(data->meta, "NUSTER", 6) !=0) {
        return NST_ERR;
    }

    if(data->meta[7] != NST_DISK_VERSION) {
        return NST_ERR;
    }

    if(nst_disk_meta_check_expire(data->meta) != NST_OK) {
        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_read_key(nst_disk_t *disk, nst_disk_data_t *data, nst_key_t *key) {
    int  ret;

    key->size = nst_disk_meta_get_key_len(data->meta);

    key->data = nst_memory_alloc(disk->memory, key->size);

    if(!key->data) {
        return NST_ERR;
    }

    ret = pread(data->fd, key->data, key->size, NST_DISK_POS_KEY);

    if(ret != key->size) {
        nst_memory_free(disk->memory, key->data);

        return NST_ERR;
    }

    memcpy(key->uuid, data->meta + NST_DISK_META_POS_UUID, 20);

    key->hash = nst_disk_meta_get_hash(data->meta);

    return NST_OK;
}

int
nst_disk_read_host(nst_disk_data_t *data, hpx_ist_t host) {
    int  ret, offset;

    offset = NST_DISK_POS_KEY + nst_disk_meta_get_key_len(data->meta);

    ret = pread(data->fd, host.ptr, host.len, offset);

    if(ret != host.len) {
        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_read_path(nst_disk_data_t *data, hpx_ist_t path) {
    int  ret, offset;

    offset = NST_DISK_POS_KEY + nst_disk_meta_get_key_len(data->meta)
        + nst_disk_meta_get_host_len(data->meta);

    ret = pread(data->fd, path.ptr, path.len, offset);

    if(ret != path.len) {
        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_read_etag(nst_disk_data_t *data, hpx_ist_t etag) {

    int  ret = pread(data->fd, etag.ptr, etag.len, NST_DISK_POS_KEY
            + nst_disk_meta_get_key_len(data->meta)
            + nst_disk_meta_get_host_len(data->meta)
            + nst_disk_meta_get_path_len(data->meta));

    if(ret != etag.len) {
        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_read_last_modified(nst_disk_data_t *data, hpx_ist_t last_modified) {

    int  ret = pread(data->fd, last_modified.ptr, last_modified.len,
            NST_DISK_POS_KEY
            + nst_disk_meta_get_key_len(data->meta)
            + nst_disk_meta_get_host_len(data->meta)
            + nst_disk_meta_get_path_len(data->meta)
            + nst_disk_meta_get_etag_len(data->meta));

    if(ret != last_modified.len) {
        return NST_ERR;
    }

    return NST_OK;
}

/*
 * -1: error
 *  0: not found
 *  1: ok
 */
int
nst_disk_purge_by_key(hpx_ist_t root, nst_disk_data_t *data, nst_key_t *key) {
    hpx_buffer_t  *buf;
    char          *p;
    int            ret;

    buf = get_trash_chunk();
    p   = buf->area;

    nst_key_uuid_stringify(key, p);

    p[NST_DISK_FILE_LEN] = '\0';

    sprintf(data->file, "%s/%c/%c%c/%s", root.ptr, p[0], p[0], p[1], p);

    data->fd = nst_disk_open(data->file);

    if(data->fd == -1) {

        if(errno == ENOENT) {
            ret = 0;
        } else {
            ret = -1;
        }

        return ret;
    }

    ret = pread(data->fd, p, key->size, NST_DISK_POS_KEY);

    if(ret == key->size && memcmp(key->data, p, key->size) == 0) {
        remove(data->file);
        ret = 1;
    }

    close(data->fd);

    return ret;
}

/*
 * -1: error
 *  0: not found
 *  1: ok
 */
int
nst_disk_purge_by_path(char *path) {
    int  ret = remove(path);

    if(ret == 0) {
        return 1;
    } else {
        if(errno == ENOENT) {
            return 0;
        } else {
            return -1;
        }
    }
}

void
nst_disk_update_expire(char *file, uint64_t expire) {
    int  fd;

    fd = open(file, O_WRONLY);

    if(fd == -1) {
        return;
    }

    pwrite(fd, &expire, 8, NST_DISK_META_POS_EXPIRE);

    close(fd);
}

int
nst_disk_init(hpx_ist_t root, nst_disk_t *disk, nst_memory_t *memory) {
    nst_dirent_t  *de;
    DIR           *tmp;

    if(root.len) {
        disk->memory = memory;
        disk->root   = root;
        disk->file   = nst_memory_alloc(memory, nst_disk_path_file_len(root));

        if(!disk->file) {
            return NST_ERR;
        }

        sprintf(disk->file, "%s/.tmp", root.ptr);

        if(nst_disk_mkdir(disk->file) == NST_ERR) {
            fprintf(stderr, "Create `%s` failed\n", disk->file);

            return NST_ERR;
        }

        /* remove files of tmp dir */
        tmp = opendir(disk->file);

        while((de = readdir(tmp)) != NULL) {
            if(de->d_name[0] == '.') {
                continue;
            }

            chunk_reset(&trash);
            chunk_memcat(&trash, disk->file, nst_disk_path_base_len(root));
            chunk_memcat(&trash, "/", 1);
            chunk_memcat(&trash, de->d_name, strlen(de->d_name));
            trash.area[trash.data++] = '\0';

            remove(trash.area);
        }

        closedir(tmp);
    }

    return NST_OK;
}

void
nst_disk_load(nst_core_t *core) {

    if(core->root.len && !core->store.disk.loaded) {
        hpx_ist_t        root;
        nst_disk_data_t  data;
        nst_dirent_t     *de;
        nst_key_t        key = { .data = NULL };
        hpx_buffer_t     buf = { .area = NULL };
        hpx_ist_t        host;
        hpx_ist_t        path;
        hpx_ist_t        etag;
        hpx_ist_t        last_modified;
        uint64_t         start;
        char            *file;
        int              len, ret;

        root = core->root;
        file = core->store.disk.file;

        start  = get_current_timestamp();

        if(core->store.disk.dir) {

            while((de = readdir(core->store.disk.dir)) != NULL) {

                if(strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                    continue;
                }

                len = strlen(de->d_name);

                if(len != NST_DISK_FILE_LEN) {
                    chunk_reset(&trash);
                    chunk_memcat(&trash, file, nst_disk_path_base_len(root));
                    chunk_memcat(&trash, "/", 1);
                    chunk_memcat(&trash, de->d_name, len);
                    trash.area[trash.data++] = '\0';

                    remove(trash.area);

                    continue;
                }

                memcpy(file + nst_disk_path_base_len(root), "/", 1);
                memcpy(file + nst_disk_path_base_len(root) + 1, de->d_name, NST_DISK_FILE_LEN);

                data.fd = nst_disk_open(file);

                if(data.fd == -1) {
                    continue;
                }

                if(nst_disk_read_meta(&data) != NST_OK) {
                    goto err;
                }

                if(nst_disk_read_key(&core->store.disk, &data, &key) != NST_OK) {
                    goto err;
                }

                host.len          = nst_disk_meta_get_host_len(data.meta);
                path.len          = nst_disk_meta_get_path_len(data.meta);
                etag.len          = nst_disk_meta_get_etag_len(data.meta);
                last_modified.len = nst_disk_meta_get_last_modified_len(data.meta);

                buf.size = host.len + path.len + etag.len + last_modified.len;
                buf.data = 0;
                buf.area = nst_memory_alloc(core->memory, buf.size);

                if(!buf.area) {
                    goto err;
                }

                host.ptr = buf.area + buf.data;

                if(nst_disk_read_host(&data, host) != NST_OK) {
                    goto err;
                }

                buf.data += host.len;
                path.ptr = buf.area + buf.data;

                if(nst_disk_read_path(&data, path) != NST_OK) {
                    goto err;
                }

                buf.data += path.len;
                etag.ptr = buf.area + buf.data;

                if(nst_disk_read_etag(&data, etag) != NST_OK) {
                    goto err;
                }

                buf.data += etag.len;
                last_modified.ptr = buf.area + buf.data;

                if(nst_disk_read_last_modified(&data, last_modified) != NST_OK) {
                    goto err;
                }

                buf.data += last_modified.len;

                nst_shctx_lock(&core->dict);

                ret = nst_dict_set_from_disk(&core->dict, &buf, host, path, etag, last_modified,
                        &key, file, data.meta);

                nst_shctx_unlock(&core->dict);

                if(ret != NST_OK) {
                    goto err;
                }

                close(data.fd);

                if(get_current_timestamp() - start >= 10) {
                    break;
                }
            }

            if(de == NULL) {
                core->store.disk.idx++;
                closedir(core->store.disk.dir);
                core->store.disk.dir = NULL;
            }
        } else {
            core->store.disk.dir = nst_disk_opendir_by_idx(core->root, file, core->store.disk.idx);

            if(!core->store.disk.dir) {
                core->store.disk.idx++;
            }
        }

        if(core->store.disk.idx == 16 * 16) {
            core->store.disk.loaded = 1;
            core->store.disk.idx    = 0;
        }

        return;

err:

        if(file) {
            remove(file);
        }

        if(data.fd) {
            close(data.fd);
        }

        nst_memory_free(core->memory, key.data);
        nst_memory_free(core->memory, buf.area);

    }
}

void
nst_disk_cleanup(nst_core_t *core) {
    nst_disk_data_t  data;
    nst_dirent_t    *de;
    hpx_ist_t        root;
    uint64_t         start;
    char            *file;
    int              len;

    root = core->root;
    file = core->store.disk.file;

    start  = get_current_timestamp();

    if(core->root.len && core->store.disk.loaded) {

        if(core->store.disk.dir) {

            while((de = readdir(core->store.disk.dir)) != NULL) {

                if(de->d_name[0] == '.') {
                    continue;
                }

                len = strlen(de->d_name);

                if(len != NST_DISK_FILE_LEN) {
                    chunk_reset(&trash);
                    chunk_memcat(&trash, file, nst_disk_path_base_len(root));
                    chunk_memcat(&trash, "/", 1);
                    chunk_memcat(&trash, de->d_name, len);
                    trash.area[trash.data++] = '\0';

                    remove(trash.area);

                    continue;
                }

                memcpy(file + nst_disk_path_base_len(root), "/", 1);
                memcpy(file + nst_disk_path_base_len(root) + 1, de->d_name, NST_DISK_FILE_LEN);

                data.fd = nst_disk_open(file);

                if(data.fd == -1) {
                    continue;
                }

                if(nst_disk_read_meta(&data) != NST_OK) {
                    remove(file);
                    close(data.fd);

                    continue;
                }

                if(nst_disk_meta_check_expire(data.meta) != NST_OK) {
                    remove(file);
                    close(data.fd);

                    continue;
                }

                close(data.fd);

                if(get_current_timestamp() - start >= 10) {
                    break;
                }
            }

            core->store.disk.idx++;
            closedir(core->store.disk.dir);
            core->store.disk.dir = NULL;
        } else {
            core->store.disk.dir = nst_disk_opendir_by_idx(core->root, file, core->store.disk.idx);

            if(!core->store.disk.dir) {
                core->store.disk.idx++;
            }
        }

        if(core->store.disk.idx == 16 * 16) {
            core->store.disk.idx = 0;
        }

    }
}

int
nst_disk_store_init(nst_disk_t *disk, nst_disk_data_t *data, nst_key_t *key, nst_http_txn_t *txn,
        int etag, int last_modified, uint64_t ttl_extend) {

    data->file = NULL;
    data->fd   = -1;

    data->file = nst_memory_alloc(disk->memory, nst_disk_path_file_len(disk->root));

    if(!data->file) {
        return NST_ERR;
    }

    sprintf(data->file, "%s/.tmp/%016"PRIx64"%016u%04x", disk->root.ptr, get_current_timestamp(),
            global.req_count, getpid());

    data->fd = nst_disk_data_create(data->file);

    if(data->fd == -1) {
        goto err;
    }

    nst_disk_meta_init(data->meta, key->hash, 0, 0, 0, key->size, txn->req.host.len,
            txn->req.path.len, etag, txn->res.etag.len, last_modified, txn->res.last_modified.len,
            ttl_extend);

    if(nst_disk_write_key(data, key) != NST_OK) {
        goto err;
    }

    if(nst_disk_write_host(data, txn->req.host) != NST_OK) {
        goto err;
    }

    if(nst_disk_write_path(data, txn->req.path) != NST_OK) {
        goto err;
    }

    if(nst_disk_write_etag(data, txn->res.etag) != NST_OK) {
        goto err;
    }

    if(nst_disk_write_last_modified(data, txn->res.last_modified) != NST_OK) {
        goto err;
    }

    return NST_OK;

err:

    if(data->fd != -1) {
        close(data->fd);
        data->fd = -1;
    }

    if(data->file) {
        remove(data->file);
        nst_memory_free(disk->memory, data->file);
        data->file = NULL;
    }

    return NST_ERR;
}

int
nst_disk_store_end(nst_disk_t *disk, nst_disk_data_t *data, nst_key_t *key, nst_http_txn_t *txn,
        uint64_t expire) {

    char  *p, *old_file, *new_file;

    nst_disk_meta_set_expire(data->meta, expire);
    nst_disk_meta_set_header_len(data->meta, txn->res.header_len);
    nst_disk_meta_set_payload_len(data->meta, txn->res.payload_len);
    nst_disk_meta_set_uuid(data->meta, key->uuid);

    if(nst_disk_write_meta(data) != NST_OK) {
        goto err;
    }

    p = trash.area;

    nst_key_uuid_stringify(key, p);

    /* create final file */
    p[NST_DISK_FILE_LEN] = '\0';

    new_file = p + 41;
    old_file = data->file;

    sprintf(new_file, "%s/%c/%c%c", disk->root.ptr, p[0], p[0], p[1]);

    if(nst_disk_mkdir(new_file) != NST_OK) {
        goto err;
    }

    sprintf(new_file, "%s/%c/%c%c/%s", disk->root.ptr, p[0], p[0], p[1], p);

    close(data->fd);

    if(rename(old_file, new_file) != 0) {
        goto err;
    }

    memcpy(data->file, new_file, nst_disk_path_file_len(disk->root));

    return NST_OK;

err:
    if(data->fd == -1) {
        close(data->fd);
        data->fd = -1;
    }

    if(data->file) {
        remove(data->file);
        nst_memory_free(disk->memory, data->file);
        data->file = NULL;
    }

    return NST_ERR;
}

