/*
 * nuster persist related functions.
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

int
nst_disk_data_init(hpx_ist_t root, char *path, uint64_t hash) {
    sprintf(path, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64, root.ptr, hash >> 60, hash >> 56, hash);

    nst_debug2("[nuster][persist] Path: %s\n", path);

    if(nst_disk_mkdir(path) != NST_OK) {
        return NST_ERR;
    }

    sprintf(path + nst_disk_path_hash_len(root), "/%"PRIx64"-%"PRIx64,
            get_current_timestamp() * random() * random() & hash, get_current_timestamp());

    nst_debug2("[nuster][persist] File: %s\n", path);

    return NST_OK;
}

int
nst_disk_data_init2(hpx_ist_t root, char *path, nst_key_t *key) {
    char  *p;
    int    i;

    p = trash.area;

    for(i = 0; i < 20; i++) {
        sprintf((char*)&(p[i*2]), "%02x", key->uuid[i]);
    }

    p[40] = '\0';

    sprintf(path, "%s/%c/%c%c", root.ptr, p[0], p[0], p[1]);

    if(nst_disk_mkdir(path) != NST_OK) {
        return NST_ERR;
    }

    sprintf(path, "%s/%c/%c%c/%s", root.ptr, p[0], p[0], p[1], p);

    nst_debug2("[nuster][persist] File: %s\n", path);

    return NST_OK;
}

int
nst_disk_data_valid(nst_disk_data_t *disk, nst_key_t *key) {
    int  ret;

    disk->fd = nst_disk_open(disk->file);

    if(disk->fd == -1) {
        goto err;
    }

    ret = pread(disk->fd, disk->meta, NST_DISK_META_SIZE, 0);

    if(ret != NST_DISK_META_SIZE) {
        goto err;
    }

    if(memcmp(disk->meta, "NUSTER", 6) !=0) {
        goto err;
    }

    if(nst_disk_meta_check_expire(disk->meta) != NST_OK) {
        goto err;
    }

    if(nst_disk_meta_get_hash(disk->meta) != key->hash
            || nst_disk_meta_get_key_len(disk->meta) != key->size) {

        goto err;
    }

    ret = pread(disk->fd, trash.area, key->size, NST_DISK_POS_KEY);

    if(ret != key->size) {
        goto err;
    }

    if(memcmp(key->data, trash.area, key->size) != 0) {
        goto err;
    }

    return NST_OK;

err:
    close(disk->fd);
    return NST_ERR;
}

int
nst_disk_data_exists(hpx_ist_t root, nst_disk_data_t *disk, nst_key_t *key) {
    nst_dirent_t  *de;
    DIR           *dirp;

    sprintf(disk->file, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64, root.ptr,
            key->hash >> 60, key->hash >> 56, key->hash);

    dirp = opendir(disk->file);

    if(!dirp) {
        return NST_ERR;
    }

    while((de = readdir(dirp)) != NULL) {

        if(strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
            memcpy(disk->file + nst_disk_path_hash_len(root), "/", 1);
            memcpy(disk->file + nst_disk_path_hash_len(root) + 1, de->d_name, strlen(de->d_name));

            if(nst_disk_data_valid(disk, key) == NST_OK) {
                closedir(dirp);

                return NST_OK;
            }
        }
    }

    closedir(dirp);

    return NST_ERR;
}

int
nst_disk_data_exists2(nst_disk_t *disk, nst_disk_data_t *data, nst_key_t *key) {
    hpx_buffer_t  *buf;
    char          *p;
    int            i;

    buf = get_trash_chunk();

    p = trash.area;

    data->file = buf->area;

    for(i = 0; i < 20; i++) {
        sprintf((char*)&(p[i*2]), "%02x", key->uuid[i]);
    }

    p[40] = '\0';

    sprintf(data->file, "%s/%c/%c%c/%s", disk->root.ptr, p[0], p[0], p[1], p);

    if(nst_disk_data_valid(data, key) == NST_OK) {
        return NST_OK;
    }

    return NST_ERR;
}

DIR *
nst_disk_opendir_by_idx(hpx_ist_t root, char *path, int idx) {
    memset(path, 0, nst_disk_path_file_len2(root));
    sprintf(path, "%s/%x/%02x", root.ptr, idx / 16, idx);

    return opendir(path);
}

nst_dirent_t *
nst_disk_dir_next(DIR *dir) {
    return readdir(dir);
}

int
nst_disk_get_meta(int fd, char *meta) {
    int  ret;

    ret = pread(fd, meta, NST_DISK_META_SIZE, 0);

    if(ret != NST_DISK_META_SIZE) {
        return NST_ERR;
    }

    if(memcmp(meta, "NUSTER", 6) !=0) {
        return NST_ERR;
    }

    if(nst_disk_meta_check_expire(meta) != NST_OK) {
        return NST_ERR;
    }

    return NST_OK;
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

    if(nst_disk_meta_check_expire(data->meta) != NST_OK) {
        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_get_key_data(int fd, char *meta, nst_key_t *key) {
    int  ret;

    ret = pread(fd, key->data, key->size, NST_DISK_POS_KEY);

    if(ret != key->size) {
        return NST_ERR;
    }

    memcpy(key->uuid, meta + NST_DISK_META_POS_UUID, 20);

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
nst_disk_get_host(int fd, char *meta, hpx_ist_t host) {
    int  ret;

    ret = pread(fd, host.ptr, host.len, NST_DISK_POS_KEY + nst_disk_meta_get_key_len(meta));

    if(ret != host.len) {
        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_read_host(hpx_ist_t host, nst_disk_data_t *data) {
    int  ret, offset;

    offset = NST_DISK_POS_KEY + nst_disk_meta_get_key_len(data->meta);

    ret = pread(data->fd, host.ptr, host.len, offset);

    if(ret != host.len) {
        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_get_path(int fd, char *meta, hpx_ist_t path) {

    int  ret = pread(fd, path.ptr, path.len, NST_DISK_POS_KEY
            + nst_disk_meta_get_key_len(meta)
            + nst_disk_meta_get_host_len(meta));

    if(ret != path.len) {
        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_read_path(hpx_ist_t path, nst_disk_data_t *data) {
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
nst_disk_get_etag(int fd, char *meta, hpx_ist_t etag) {

    int  ret = pread(fd, etag.ptr, etag.len, NST_DISK_POS_KEY
            + nst_disk_meta_get_key_len(meta)
            + nst_disk_meta_get_host_len(meta)
            + nst_disk_meta_get_path_len(meta));

    if(ret != etag.len) {
        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_get_last_modified(int fd, char *meta, hpx_ist_t last_modified) {

    int  ret = pread(fd, last_modified.ptr, last_modified.len,
            NST_DISK_POS_KEY
            + nst_disk_meta_get_key_len(meta)
            + nst_disk_meta_get_host_len(meta)
            + nst_disk_meta_get_path_len(meta)
            + nst_disk_meta_get_etag_len(meta));

    if(ret != last_modified.len) {
        return NST_ERR;
    }

    return NST_OK;
}

void
nst_disk_cleanup(hpx_ist_t root, char *path, nst_dirent_t *de1) {
    nst_dirent_t  *de2;
    DIR           *dir2;
    int            fd, ret;
    char           meta[NST_DISK_META_SIZE];

    if(strcmp(de1->d_name, ".") == 0 || strcmp(de1->d_name, "..") == 0) {
        return;
    }

    memcpy(path + nst_disk_path_base_len(root), "/", 1);
    memcpy(path + nst_disk_path_base_len(root) + 1, de1->d_name, strlen(de1->d_name));

    dir2 = opendir(path);

    if(!dir2) {
        return;
    }

    while((de2 = readdir(dir2)) != NULL) {

        if(strcmp(de2->d_name, ".") != 0 && strcmp(de2->d_name, "..") != 0) {

            memcpy(path + nst_disk_path_hash_len(root), "/", 1);
            memcpy(path + nst_disk_path_hash_len(root) + 1, de2->d_name, strlen(de2->d_name));

            fd = nst_disk_open(path);

            if(fd == -1) {
                closedir(dir2);

                return;
            }

            ret = pread(fd, meta, NST_DISK_META_SIZE, 0);

            if(ret != NST_DISK_META_SIZE) {
                unlink(path);
                close(fd);

                continue;
            }

            if(memcmp(meta, "NUSTER", 6) !=0) {
                unlink(path);
                close(fd);

                continue;
            }

            /* persist is complete */
            if(nst_disk_meta_check_expire(meta) != NST_OK) {
                unlink(path);
                close(fd);

                continue;
            }

            close(fd);

        }
    }

    closedir(dir2);

}

/*
 * -1: error
 *  0: not found
 *  1: ok
 */
int
nst_disk_purge_by_key(hpx_ist_t root, nst_disk_data_t *disk, nst_key_t *key) {
    nst_dirent_t  *de;
    DIR           *dirp;
    int            ret;

    sprintf(disk->file, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64, root.ptr,
            key->hash >> 60, key->hash >> 56, key->hash);

    dirp = opendir(disk->file);

    if(!dirp) {

        if(errno == ENOENT) {
            return 0;
        } else {
            return -1;
        }
    }

    ret = 0;

    while((de = readdir(dirp)) != NULL) {

        if(strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
            memcpy(disk->file + nst_disk_path_hash_len(root), "/", 1);
            memcpy(disk->file + nst_disk_path_hash_len(root) + 1, de->d_name, strlen(de->d_name));

                disk->fd = nst_disk_open(disk->file);

                if(disk->fd == -1) {
                    ret = -1;

                    goto done;
                }

                ret = pread(disk->fd, trash.area, key->size, NST_DISK_POS_KEY);

                if(ret == key->size && memcmp(key->data, trash.area, key->size) == 0) {
                    unlink(disk->file);
                    ret = 1;

                    goto done;
                }

                close(disk->fd);
        }
    }

done:
    closedir(dirp);
    close(disk->fd);

    return ret;
}

/*
 * -1: error
 *  0: not found
 *  1: ok
 */
int
nst_disk_purge_by_path(char *path) {
    int  ret = unlink(path);

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

    if(root.len) {
        if(nst_disk_mkdir(root.ptr) == NST_ERR) {
            fprintf(stderr, "Create `%s` failed\n", root.ptr);

            return NST_ERR;
        }

        disk->memory = memory;
        disk->root   = root;
        disk->file   = nst_memory_alloc(memory, nst_disk_path_file_len2(root) + 1);

        if(!disk->file) {
            return NST_ERR;
        }
    }

    return NST_OK;
}

int
nst_disk_store_init(nst_disk_t *disk, nst_disk_data_t *data, nst_key_t *key, nst_http_txn_t *txn,
        uint64_t ttl_extend) {

    data->file = nst_memory_alloc(disk->memory, nst_disk_path_file_len2(disk->root) + 1);

    if(!data->file) {
        return NST_ERR;
    }

    if(nst_disk_data_init2(disk->root, data->file, key) != NST_OK) {
        goto err;
    }

    data->fd = nst_disk_data_create(data->file);

    if(data->fd == -1) {
        goto err;
    }

    nst_disk_meta_init2(data->meta, key->hash, 0, 0, 0, key->size, txn->req.host.len,
            txn->req.path.len, txn->res.etag.len, txn->res.last_modified.len, ttl_extend);

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

    if(data->fd) {
        close(data->fd);
    }

    nst_memory_free(disk->memory, data->file);

    data->file = NULL;

    return NST_ERR;
}

int
nst_disk_store_end(nst_disk_t *disk, nst_disk_data_t *data, nst_http_txn_t *txn, uint64_t expire) {
    nst_disk_meta_set_expire(data->meta, expire);
    nst_disk_meta_set_header_len(data->meta, txn->res.header_len);
    nst_disk_meta_set_payload_len(data->meta, txn->res.payload_len);

    if(nst_disk_write_meta(data) != NST_OK) {

        if(data->fd) {
            close(data->fd);
        }

        nst_memory_free(disk->memory, data->file);

        data->file = NULL;

        return NST_ERR;
    }

    return NST_OK;
}

void
nst_disk_load(nst_core_t *core) {

    if(core->root.len && !core->store.disk.loaded) {
        hpx_ist_t        root;
        nst_disk_data_t  data;
        nst_key_t        key = { .data = NULL };
        hpx_buffer_t     buf = { .area = NULL };
        hpx_ist_t        host;
        hpx_ist_t        path;
        char            *file;

        root = core->root;
        file = core->store.disk.file;

        if(core->store.disk.dir) {
            nst_dirent_t *de = nst_disk_dir_next(core->store.disk.dir);

            while((de = readdir(core->store.disk.dir)) != NULL) {

                if(strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                    continue;
                }

                memcpy(file + nst_disk_path_base_len(root), "/", 1);
                memcpy(file + nst_disk_path_base_len(root) + 1, de->d_name, strlen(de->d_name));

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

                host.len = nst_disk_meta_get_host_len(data.meta);
                path.len = nst_disk_meta_get_path_len(data.meta);

                buf.size = host.len + path.len;
                buf.data = 0;
                buf.area = nst_memory_alloc(core->memory, buf.size);

                if(!buf.area) {
                    goto err;
                }

                host.ptr = buf.area + buf.data;

                if(nst_disk_read_host(host, &data) != NST_OK) {
                    goto err;
                }

                path.ptr = buf.area + buf.data;

                if(nst_disk_read_path(path, &data) != NST_OK) {
                    goto err;
                }

                if(nst_dict_set_from_disk2(&core->dict, &buf, host, path, &key, file, data.meta)
                        != NST_OK) {

                    goto err;
                }

                close(data.fd);
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
            core->store.disk.loaded = 1;
            core->store.disk.idx    = 0;
        }

        return;

err:

        if(file) {
            unlink(file);
        }

        if(data.fd) {
            close(data.fd);
        }

        nst_memory_free(core->memory, key.data);
        nst_memory_free(core->memory, buf.area);

    }
}

void
nst_disk_cleanup2(nst_core_t *core) {
    nst_disk_data_t  data;
    hpx_ist_t        root;
    char            *file;

    root = core->root;
    file = core->store.disk.file;

    if(core->root.len && core->store.disk.loaded) {

        if(core->store.disk.dir) {
            nst_dirent_t *de = nst_disk_dir_next(core->store.disk.dir);

            while((de = readdir(core->store.disk.dir)) != NULL) {

                if(strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                    continue;
                }

                memcpy(file + nst_disk_path_base_len(root), "/", 1);
                memcpy(file + nst_disk_path_base_len(root) + 1, de->d_name, strlen(de->d_name));

                data.fd = nst_disk_open(file);

                if(data.fd == -1) {
                    continue;
                }

                if(nst_disk_read_meta(&data) != NST_OK) {
                    unlink(file);
                    close(data.fd);

                    continue;
                }

                if(nst_disk_meta_check_expire(data.meta) != NST_OK) {
                    unlink(file);
                    close(data.fd);

                    continue;
                }

                close(data.fd);
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

