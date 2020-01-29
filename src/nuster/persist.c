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

#include <nuster/memory.h>
#include <nuster/persist.h>
#include <nuster/nuster.h>

int nst_persist_mkdir(char *path) {
    char *p = path;

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

int nst_persist_init(char *root, char *path, uint64_t hash) {
    sprintf(path, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64, root,
            hash >> 60, hash >> 56, hash);

    nst_debug("[nuster][persist] Path: %s\n", path);

    if(nst_persist_mkdir(path) != NST_OK) {
        return NST_ERR;
    }

    sprintf(path + nst_persist_path_hash_len(root), "/%"PRIx64"-%"PRIx64,
            get_current_timestamp() * random() * random() & hash,
            get_current_timestamp());

    nst_debug("[nuster][persist] File: %s\n", path);

    return NST_OK;
}

int nst_persist_valid(struct persist *disk, struct buffer *key, uint64_t hash) {
    char *buf;
    int ret;

    disk->fd = nst_persist_open(disk->file);

    if(disk->fd == -1) {
        goto err;
    }

    ret = pread(disk->fd, disk->meta, NST_PERSIST_META_SIZE, 0);

    if(ret != NST_PERSIST_META_SIZE) {
        goto err;
    }

    if(memcmp(disk->meta, "NUSTER", 6) !=0) {
        goto err;
    }

    if(nst_persist_meta_check_expire(disk->meta) != NST_OK) {
        goto err;
    }

    if(nst_persist_meta_get_hash(disk->meta) != hash
            || nst_persist_meta_get_key_len(disk->meta) != key->data) {

        goto err;
    }

    buf = malloc(key->data);

    if(!buf) {
        goto err;
    }

    ret = pread(disk->fd, buf, key->data, NST_PERSIST_POS_KEY);

    if(ret != key->data) {
        goto err;
    }

    if(memcmp(key->area, buf, key->data) != 0) {
        goto err;
    }

    free(buf);
    return NST_OK;

err:
    close(disk->fd);
    return NST_ERR;
}


int nst_persist_exists(char *root, struct persist *disk, struct buffer *key,
        uint64_t hash) {

    struct dirent *de;
    DIR *dirp;

    sprintf(disk->file, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64, root,
            hash >> 60, hash >> 56, hash);

    dirp = opendir(disk->file);

    if(!dirp) {
        return NST_ERR;
    }

    while((de = readdir(dirp)) != NULL) {

        if(strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
            memcpy(disk->file + nst_persist_path_hash_len(root), "/", 1);
            memcpy(disk->file + nst_persist_path_hash_len(root) + 1,
                    de->d_name, strlen(de->d_name));

            if(nst_persist_valid(disk, key, hash) == NST_OK) {
                closedir(dirp);
                return NST_OK;
            }
        }
    }

    closedir(dirp);
    return NST_ERR;
}

DIR *nst_persist_opendir_by_idx(char *root, char *path, int idx) {
    memset(path, 0, nst_persist_path_file_len(root));
    sprintf(path, "%s/%x/%02x", root, idx / 16, idx);

    return opendir(path);
}

struct dirent *nst_persist_dir_next(DIR *dir) {
    return readdir(dir);
}

int nst_persist_get_meta(int fd, char *meta) {
    int ret;

    ret = pread(fd, meta, NST_PERSIST_META_SIZE, 0);

    if(ret != NST_PERSIST_META_SIZE) {
        return NST_ERR;
    }

    if(memcmp(meta, "NUSTER", 6) !=0) {
        return NST_ERR;
    }

    if(nst_persist_meta_check_expire(meta) != NST_OK) {
        return NST_ERR;
    }

    return NST_OK;
}

int nst_persist_get_key(int fd, char *meta, struct buffer *key) {

    key->data = pread(fd, key->area, key->size, NST_PERSIST_POS_KEY);

    if(!b_full(key)) {
        return NST_ERR;
    }

    return NST_OK;
}

int nst_persist_get_host(int fd, char *meta, struct nst_str *host) {

    int ret = pread(fd, host->data, host->len, NST_PERSIST_POS_KEY
            + nst_persist_meta_get_key_len(meta));

    if(ret != host->len) {
        return NST_ERR;
    }

    return NST_OK;
}

int nst_persist_get_path(int fd, char *meta, struct nst_str *path) {

    int ret = pread(fd, path->data, path->len, NST_PERSIST_POS_KEY
            + nst_persist_meta_get_key_len(meta)
            + nst_persist_meta_get_host_len(meta));

    if(ret != path->len) {
        return NST_ERR;
    }

    return NST_OK;
}

int nst_persist_get_etag(int fd, char *meta, struct nst_str *etag) {

    int ret = pread(fd, etag->data, etag->len, NST_PERSIST_POS_KEY
            + nst_persist_meta_get_key_len(meta)
            + nst_persist_meta_get_host_len(meta)
            + nst_persist_meta_get_path_len(meta));

    if(ret != etag->len) {
        return NST_ERR;
    }

    return NST_OK;
}

int nst_persist_get_last_modified(int fd, char *meta,
        struct nst_str *last_modified) {

    int ret = pread(fd, last_modified->data, last_modified->len,
            NST_PERSIST_POS_KEY
            + nst_persist_meta_get_key_len(meta)
            + nst_persist_meta_get_host_len(meta)
            + nst_persist_meta_get_path_len(meta)
            + nst_persist_meta_get_etag_len(meta));

    if(ret != last_modified->len) {
        return NST_ERR;
    }

    return NST_OK;
}

void nst_persist_cleanup(char *root, char *path, struct dirent *de1) {
    DIR *dir2;
    struct dirent *de2;
    int fd, ret;
    char meta[NST_PERSIST_META_SIZE];

    if(strcmp(de1->d_name, ".") == 0 || strcmp(de1->d_name, "..") == 0) {

        return;
    }

    memcpy(path + nst_persist_path_base_len(root), "/", 1);
    memcpy(path + nst_persist_path_base_len(root) + 1, de1->d_name,
            strlen(de1->d_name));

    dir2 = opendir(path);

    if(!dir2) {
        return;
    }

    while((de2 = readdir(dir2)) != NULL) {

        if(strcmp(de2->d_name, ".") != 0
                && strcmp(de2->d_name, "..") != 0) {

            memcpy(path + nst_persist_path_hash_len(root), "/", 1);
            memcpy(path + nst_persist_path_hash_len(root) + 1, de2->d_name,
                    strlen(de2->d_name));

            fd = nst_persist_open(path);

            if(fd == -1) {
                closedir(dir2);
                return;
            }

            ret = pread(fd, meta, NST_PERSIST_META_SIZE, 0);

            if(ret != NST_PERSIST_META_SIZE) {
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
            if(nst_persist_meta_check_expire(meta) != NST_OK) {
                unlink(path);
                close(fd);
                continue;
            }

            close(fd);

        }
    }

    closedir(dir2);

}

int nst_persist_purge_by_key(char *root, struct persist *disk,
        struct buffer *key, uint64_t hash) {

    struct dirent *de;
    DIR *dirp;
    char *buf;
    int ret;

    buf = malloc(key->data);

    if(!buf) {
        return 500;
    }

    sprintf(disk->file, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64, root,
            hash >> 60, hash >> 56, hash);

    dirp = opendir(disk->file);

    if(!dirp) {
        free(buf);

        if(errno == ENOENT) {
            return 404;
        } else {
            return 500;
        }
    }

    ret = 404;

    while((de = readdir(dirp)) != NULL) {

        if(strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
            memcpy(disk->file + nst_persist_path_hash_len(root), "/", 1);
            memcpy(disk->file + nst_persist_path_hash_len(root) + 1,
                    de->d_name, strlen(de->d_name));

                disk->fd = nst_persist_open(disk->file);

                if(disk->fd == -1) {
                    ret = 500;
                    goto done;
                }

                ret = pread(disk->fd, buf, key->data, NST_PERSIST_POS_KEY);

                if(ret == key->data && memcmp(key->area, buf, key->data) == 0) {
                    unlink(disk->file);
                    ret = 200;
                    goto done;
                }

                close(disk->fd);
        }
    }

done:
    closedir(dirp);
    close(disk->fd);
    free(buf);
    return ret;
}

int nst_persist_purge_by_path(char *path) {
    int ret = unlink(path);

    if(ret == 0) {
        return 200;
    } else {
        if(errno == ENOENT) {
            return 404;
        } else {
            return 500;
        }
    }
}

void nst_persist_update_expire(char *file, uint64_t expire) {
    int fd;
    int ret;
    char meta[NST_PERSIST_META_SIZE];

    fd = open(file, O_WRONLY);

    if(fd == -1) {
        return;
    }

    pwrite(fd, &expire, 8, NST_PERSIST_META_POS_EXPIRE);

    close(fd);
}

