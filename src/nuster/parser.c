/*
 * nuster parser related variables and functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/acl.h>
#include <haproxy/tools.h>

#include <nuster/nuster.h>

const char *nst_cache_flt_id = "nuster cache id";
const char *nst_nosql_flt_id = "nuster nosql id";

static nst_key_element_t *
_nst_parse_rule_key_cast(char *str) {
    nst_key_element_t  *key = NULL;

    if(!strcmp(str, "method")) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_METHOD;
        key->data = NULL;
    } else if(!strcmp(str, "scheme")) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_SCHEME;
        key->data = NULL;
    } else if(!strcmp(str, "host")) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_HOST;
        key->data = NULL;
    } else if(!strcmp(str, "uri")) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_URI;
        key->data = NULL;
    } else if(!strcmp(str, "path")) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_PATH;
        key->data = NULL;
    } else if(!strcmp(str, "delimiter")) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_DELIMITER;
        key->data = NULL;
    } else if(!strcmp(str, "query")) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_QUERY;
        key->data = NULL;
    } else if(!strncmp(str, "param_", 6) && strlen(str) > 6) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_PARAM;
        key->data = strdup(str + 6);
    } else if(!strncmp(str, "header_", 7) && strlen(str) > 7) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_HEADER;
        key->data = strdup(str + 7);
    } else if(!strncmp(str, "cookie_", 7) && strlen(str) > 7) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_COOKIE;
        key->data = strdup(str + 7);
    } else if(!strcmp(str, "body")) {
        key       = malloc(sizeof(*key));
        key->type = NST_KEY_ELEMENT_BODY;
        key->data = NULL;
    }

    return key;
}

static nst_key_element_t **
_nst_parse_rule_key(char *str) {
    nst_key_element_t  **pk  = NULL;
    char                *tmp = strdup(str);
    int                  i   = 0;
    char                *m;

    m = strtok(tmp, ".");

    while(m) {
        nst_key_element_t  *key = _nst_parse_rule_key_cast(m);

        if(!key) {
            goto err;
        }

        pk = realloc(pk, (i + 1) * sizeof(nst_key_element_t *));
        pk[i++] = key;
        m = strtok(NULL, ".");
    }

    if(!pk) {
        goto err;
    }

    pk = realloc(pk, (i + 1) * sizeof(nst_key_element_t *));
    pk[i] = NULL;

    free(tmp);

    return pk;

err:
    if(pk) {

        while(i--) {
            free(pk[i]);
        }

        free(pk);
    }

    free(tmp);

    return NULL;
}

static nst_rule_code_t *
_nst_parse_rule_code(char *str) {

    if(!strcmp(str, "all")) {
        return NULL;
    } else {
        nst_rule_code_t  *code = NULL;
        char             *tmp  = strdup(str);
        char             *m    = strtok(tmp, ",");

        /* warn ","? */
        while(m) {
            int               i  = atoi(m);
            nst_rule_code_t  *cc = malloc(sizeof(*cc));

            cc->code = i;

            if(code) {
                cc->next = code;
            } else {
                cc->next = NULL;
            }

            code = cc;

            m = strtok(NULL, ",");
        }

        free(tmp);

        return code;
    }
}


/*
 * Parse size
 */
const char *
nst_parse_size(const char *text, uint64_t *ret) {
    uint64_t  value = 0;

    while(1) {
        unsigned int  i;

        i = *text - '0';

        if(i > 9) {
            break;
        }

        if(value > ~0ULL / 10) {
            goto end;
        }

        value *= 10;

        if(value > (value + i)) {
            goto end;
        }

        value += i;
        text++;
    }

    switch(*text) {
        case '\0':
            break;
        case 'M':
        case 'm':

            if(value > ~0ULL >> 20) {
                goto end;
            }

            value = value << 20;

            break;
        case 'G':
        case 'g':

            if(value > ~0ULL >> 30) {
                goto end;
            }

            value = value << 30;

            break;
        default:
            return text;
    }

    if(*text != '\0' && *++text != '\0') {
        return text;
    }

    if(value < NST_DEFAULT_SIZE) {
        value = NST_DEFAULT_SIZE;
    }

    *ret = value;

    return NULL;

end:
    *ret = NST_DEFAULT_SIZE;

    return NULL;
}

/*
 * Parse time
 * The value is returned in ret if everything is fine, and a NST_TIME_OK is returned
 * 0 <= ret < 2^31(2147483648)
 * If the value is equal to or greater than 2^31, NST_TIME_OVER is returned.
 * If the value is equal to or greater than 2^64, NST_TIME_UNDER is returned.
 * NST_TIME_ERR is returned in case of error
 */
int
nst_parse_time(const char *text, int len, uint32_t *ret) {
    uint64_t  imult, idiv, omult, odiv;
    uint64_t  value, result;
    int       text_len = len;

    if(*text - '0' > 9) {
        return NST_TIME_ERR;
    }

    omult = odiv = imult = idiv = 1;
    value = 0;

    while(len--) {
        unsigned int  j;

        j = *text - '0';

        if(j > 9) {

            switch(*text) {
                case 's':
                    break;
                case 'm':
                    imult = 60;
                    break;
                case 'h':
                    imult = 3600;
                    break;
                case 'd':
                    imult = 86400;
                    break;
                default:
                    return NST_TIME_ERR;
                    break;
            }

            break;
        }

        text++;
        value *= 10;
        value += j;
    }

    if(len > 0) {
        return NST_TIME_ERR;
    }

    if(text_len >= sizeof("2147483648d")) {
        return NST_TIME_OVER;
    }

    if(omult % idiv == 0) {
        omult /= idiv;
        idiv   = 1;
    }

    if(idiv % omult == 0) {
        idiv  /= omult;
        omult  = 1;
    }

    if(imult % odiv == 0) {
        imult /= odiv;
        odiv   = 1;
    }

    if(odiv % imult == 0) {
        odiv  /= imult;
        imult  = 1;
    }

    result = (value * (imult * omult) + (idiv * odiv - 1)) / (idiv * odiv);

    if(result >= 0x80000000) {
        return NST_TIME_OVER;
    }

    *ret = result;

    return NST_TIME_OK;
}

int
nuster_parse_global_manager(const char *file, int line, char **args) {
    int  err_code = 0;
    int  cur_arg  = 1;

    if(global.nuster.manager.status != NST_STATUS_UNDEFINED) {
        ha_warning("parsing [%s:%d]: [%s] already specified. Ignore.\n", file, line, args[0]);

        err_code |= ERR_ALERT;

        goto out;
    }

    if(*(args[cur_arg]) == 0) {
        ha_alert("parsing [%s:%d]: [%s] expects 'on' or 'off' as argument.\n", file, line, args[0]);

        err_code |= ERR_ALERT | ERR_FATAL;

        goto out;
    }

    if(!strcmp(args[cur_arg], "off")) {
        global.nuster.manager.status = NST_STATUS_OFF;
    } else if(!strcmp(args[cur_arg], "on")) {
        global.nuster.manager.status = NST_STATUS_ON;
    } else {
        ha_alert("parsing [%s:%d]: [%s] only supports 'on' and 'off'.\n", file, line, args[0]);

        err_code |= ERR_ALERT | ERR_FATAL;

        goto out;
    }

    global.nuster.manager.purge_method = ist(NST_MANAGER_DEFAULT_PURGE_METHOD);
    global.nuster.manager.uri          = ist(NST_MANAGER_DEFAULT_URI);

    cur_arg++;

    while(*(args[cur_arg]) !=0) {

        if(!strcmp(args[cur_arg], "purge-method")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] purge-method expects an argument.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.manager.purge_method.ptr = strdup(args[cur_arg]);
            global.nuster.manager.purge_method.len = strlen(args[cur_arg]);

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "uri")) {
            cur_arg++;

            if(*(args[cur_arg]) == 0) {
                ha_alert("parsing [%s:%d]: [%s] uri expects a uri as argument.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.manager.uri.ptr = strdup(args[cur_arg]);
            global.nuster.manager.uri.len = strlen(args[cur_arg]);

            cur_arg++;

            continue;
        }

        ha_alert("parsing [%s:%d]: [%s] Unrecognized '%s'.\n", file, line, args[0], args[cur_arg]);

        err_code |= ERR_ALERT | ERR_FATAL;

        goto out;
    }

out:
    return err_code;
}

int
nuster_parse_global_cache(const char *file, int line, char **args) {
    int  err_code = 0;
    int  cur_arg  = 1;

    if(global.nuster.cache.status != NST_STATUS_UNDEFINED) {
        ha_warning("parsing [%s:%d]: [%s] already specified. Ignore.\n", file, line, args[0]);

        err_code |= ERR_ALERT;

        goto out;
    }

    if(*(args[cur_arg]) == 0) {
        ha_alert("parsing [%s:%d]: [%s] expects 'on' or 'off' as argument.\n", file, line, args[0]);

        err_code |= ERR_ALERT | ERR_FATAL;

        goto out;
    }

    if(!strcmp(args[cur_arg], "off")) {
        global.nuster.cache.status = NST_STATUS_OFF;
    } else if(!strcmp(args[cur_arg], "on")) {
        global.nuster.cache.status = NST_STATUS_ON;
    } else {
        ha_alert("parsing [%s:%d]: [%s] only supports 'on' and 'off'.\n", file, line, args[0]);

        err_code |= ERR_ALERT | ERR_FATAL;

        goto out;
    }

    cur_arg++;

    while(*(args[cur_arg]) !=0) {

        if(!strcmp(args[cur_arg], "data-size")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] data-size expects a size.\n", file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }
            if(nst_parse_size(args[cur_arg],
                        &global.nuster.cache.data_size)) {

                ha_alert("parsing [%s:%d]: [%s] invalid data_size, expects [m|M|g|G].\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "dict-size")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] dict-size expects a size.\n", file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            if(nst_parse_size(args[cur_arg],
                        &global.nuster.cache.dict_size)) {

                ha_alert("parsing [%s:%d]: [%s] invalid dict-size, expects [m|M|g|G].\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "dir")) {
            cur_arg++;

            if(*(args[cur_arg]) == 0) {
                ha_alert("parsing [%s:%d]: [%s]: dir expects a dir as argument.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.cache.root.ptr = strdup(args[cur_arg]);
            global.nuster.cache.root.len = strlen(args[cur_arg]);

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "dict-cleaner")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] dict-cleaner expects a number.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.cache.dict_cleaner = atoi(args[cur_arg]);

            if(global.nuster.cache.dict_cleaner <= 0) {
                global.nuster.cache.dict_cleaner = NST_DEFAULT_DICT_CLEANER;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "data-cleaner")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] data-cleaner expects a number.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.cache.data_cleaner = atoi(args[cur_arg]);

            if(global.nuster.cache.data_cleaner <= 0) {
                global.nuster.cache.data_cleaner = NST_DEFAULT_DATA_CLEANER;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "disk-cleaner")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] disk-cleaner expects a number.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.cache.disk_cleaner = atoi(args[cur_arg]);

            if(global.nuster.cache.disk_cleaner <= 0) {
                global.nuster.cache.disk_cleaner = NST_DEFAULT_DISK_CLEANER;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "disk-loader")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] disk-loader expects a number.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.cache.disk_loader = atoi(args[cur_arg]);

            if(global.nuster.cache.disk_loader <= 0) {
                global.nuster.cache.disk_loader = NST_DEFAULT_DISK_LOADER;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "disk-saver")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] disk-saver expects a number.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.cache.disk_saver = atoi(args[cur_arg]);

            if(global.nuster.cache.disk_saver <= 0) {
                global.nuster.cache.disk_saver = NST_DEFAULT_DISK_SAVER;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "clean-temp")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] expects 'on' or 'off' as argument.\n", file, line,
                        args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            if(!strcmp(args[cur_arg], "off")) {
                global.nuster.cache.clean_temp = NST_STATUS_OFF;
            } else if(!strcmp(args[cur_arg], "on")) {
                global.nuster.cache.clean_temp = NST_STATUS_ON;
            } else {
                ha_alert("parsing [%s:%d]: [%s] only supports 'on' and 'off'.\n", file, line,
                        args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "always-check-disk")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] expects 'on' or 'off' as argument.\n", file, line,
                        args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            if(!strcmp(args[cur_arg], "off")) {
                global.nuster.cache.always_check_disk = NST_STATUS_OFF;
            } else if(!strcmp(args[cur_arg], "on")) {
                global.nuster.cache.always_check_disk = NST_STATUS_ON;
            } else {
                ha_alert("parsing [%s:%d]: [%s] only supports 'on' and 'off'.\n", file, line,
                        args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            cur_arg++;

            continue;
        }


        ha_alert("parsing [%s:%d]: [%s] Unrecognized '%s'.\n", file, line, args[0], args[cur_arg]);

        err_code |= ERR_ALERT | ERR_FATAL;

        goto out;
    }

out:
    return err_code;
}

int
nuster_parse_global_nosql(const char *file, int line, char **args) {
    int  err_code = 0;
    int  cur_arg  = 1;

    if(global.nuster.nosql.status != NST_STATUS_UNDEFINED) {
        ha_warning("parsing [%s:%d]: [%s] already specified. Ignore.\n", file, line, args[0]);

        err_code |= ERR_ALERT;

        goto out;
    }

    if(*(args[cur_arg]) == 0) {
        ha_alert("parsing [%s:%d]: [%s] expects 'on' or 'off' as argument.\n", file, line, args[0]);

        err_code |= ERR_ALERT | ERR_FATAL;

        goto out;
    }

    if(!strcmp(args[cur_arg], "off")) {
        global.nuster.nosql.status = NST_STATUS_OFF;
    } else if(!strcmp(args[cur_arg], "on")) {
        global.nuster.nosql.status = NST_STATUS_ON;
    } else {
        ha_alert("parsing [%s:%d]: [%s] only supports 'on' and 'off'.\n", file, line, args[0]);

        err_code |= ERR_ALERT | ERR_FATAL;

        goto out;
    }

    cur_arg++;

    while(*(args[cur_arg]) !=0) {

        if(!strcmp(args[cur_arg], "dict-size")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] dict-size expects a size.\n", file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            if(nst_parse_size(args[cur_arg], &global.nuster.nosql.dict_size)) {

                ha_alert("parsing [%s:%d]: [%s] invalid dict-size, expects [m|M|g|G].\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "data-size")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] data-size expects a size.\n", file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            if(nst_parse_size(args[cur_arg], &global.nuster.nosql.data_size)) {

                ha_alert("parsing [%s:%d]: [%s] invalid data_size, expects [m|M|g|G].\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "dir")) {
            cur_arg++;

            if(*(args[cur_arg]) == 0) {
                ha_alert("parsing [%s:%d]: [%s]: `dir` expects a dir as argument.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.nosql.root.ptr = strdup(args[cur_arg]);
            global.nuster.nosql.root.len = strlen(args[cur_arg]);

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "dict-cleaner")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] dict-cleaner expects a number.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.nosql.dict_cleaner = atoi(args[cur_arg]);

            if(global.nuster.nosql.dict_cleaner <= 0) {
                global.nuster.nosql.dict_cleaner = NST_DEFAULT_DICT_CLEANER;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "data-cleaner")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] data-cleaner expects a number.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.nosql.data_cleaner = atoi(args[cur_arg]);

            if(global.nuster.nosql.data_cleaner <= 0) {
                global.nuster.nosql.data_cleaner = NST_DEFAULT_DATA_CLEANER;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "disk-cleaner")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] disk-cleaner expects a number.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.nosql.disk_cleaner = atoi(args[cur_arg]);

            if(global.nuster.nosql.disk_cleaner <= 0) {
                global.nuster.nosql.disk_cleaner = NST_DEFAULT_DISK_CLEANER;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "disk-loader")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] disk-loader expects a number.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.nosql.disk_loader = atoi(args[cur_arg]);

            if(global.nuster.nosql.disk_loader <= 0) {
                global.nuster.nosql.disk_loader = NST_DEFAULT_DISK_LOADER;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "disk-saver")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] disk-saver expects a number.\n",
                        file, line, args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            global.nuster.nosql.disk_saver = atoi(args[cur_arg]);

            if(global.nuster.nosql.disk_saver <= 0) {
                global.nuster.nosql.disk_saver = NST_DEFAULT_DISK_SAVER;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "clean-temp")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] expects 'on' or 'off' as argument.\n", file, line,
                        args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            if(!strcmp(args[cur_arg], "off")) {
                global.nuster.nosql.clean_temp = NST_STATUS_OFF;
            } else if(!strcmp(args[cur_arg], "on")) {
                global.nuster.nosql.clean_temp = NST_STATUS_ON;
            } else {
                ha_alert("parsing [%s:%d]: [%s] only supports 'on' and 'off'.\n", file, line,
                        args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "always-check-disk")) {
            cur_arg++;

            if(*args[cur_arg] == 0) {
                ha_alert("parsing [%s:%d]: [%s] expects 'on' or 'off' as argument.\n", file, line,
                        args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            if(!strcmp(args[cur_arg], "off")) {
                global.nuster.nosql.always_check_disk = NST_STATUS_OFF;
            } else if(!strcmp(args[cur_arg], "on")) {
                global.nuster.nosql.always_check_disk = NST_STATUS_ON;
            } else {
                ha_alert("parsing [%s:%d]: [%s] only supports 'on' and 'off'.\n", file, line,
                        args[0]);

                err_code |= ERR_ALERT | ERR_FATAL;

                goto out;
            }

            cur_arg++;

            continue;
        }


        ha_alert("parsing [%s:%d]: [%s] Unrecognized '%s'.\n", file, line, args[0], args[cur_arg]);

        err_code |= ERR_ALERT | ERR_FATAL;

        goto out;
    }

out:
    return err_code;
}

int
nst_parse_proxy_cache(char **args, int section, hpx_proxy_t *px, hpx_proxy_t *defpx,
        const char *file, int line, char **err) {

    hpx_flt_conf_t  *fconf;
    nst_flt_conf_t  *conf;
    int              cur_arg = 1;

    list_for_each_entry(fconf, &px->filter_configs, list) {

        if(fconf->id == nst_cache_flt_id) {
            memprintf(err, "%s: supports only one cache filter", px->id);

            return -1;
        }

    }

    fconf = calloc(1, sizeof(*fconf));
    conf  = malloc(sizeof(*conf));

    if(!fconf || !conf) {
        memprintf(err, "out of memory");

        return -1;
    }

    memset(fconf, 0, sizeof(*fconf));
    memset(conf, 0, sizeof(*conf));

    conf->status = NST_STATUS_ON;
    cur_arg++;

    if(*args[cur_arg]) {

        if(!strcmp(args[cur_arg], "off")) {
            conf->status = NST_STATUS_OFF;
        } else if(!strcmp(args[cur_arg], "on")) {
            conf->status = NST_STATUS_ON;
        } else {
            memprintf(err, "[%s] expects [on|off], default on", args[1]);

            return -1;
        }

        cur_arg++;
    }

    fconf->id   = nst_cache_flt_id;
    fconf->conf = conf;
    fconf->ops  = &nst_cache_filter_ops;

    LIST_ADDQ(&px->filter_configs, &fconf->list);

    px->nuster.mode = NST_MODE_CACHE;

    return 0;
}

int
nst_parse_proxy_nosql(char **args, int section, hpx_proxy_t *px, hpx_proxy_t *defpx,
        const char *file, int line, char **err) {

    hpx_flt_conf_t  *fconf;
    nst_flt_conf_t  *conf;
    int              cur_arg = 1;

    list_for_each_entry(fconf, &px->filter_configs, list) {

        if(fconf->id == nst_nosql_flt_id) {
            memprintf(err, "%s: supports only one nosql filter\n", px->id);

            return -1;
        }

    }

    fconf = calloc(1, sizeof(*fconf));
    conf  = malloc(sizeof(*conf));

    if(!fconf || !conf) {
        memprintf(err, "out of memory");

        return -1;
    }

    memset(fconf, 0, sizeof(*fconf));
    memset(conf, 0, sizeof(*conf));

    conf->status = NST_STATUS_ON;
    cur_arg++;

    if(*args[cur_arg]) {

        if(!strcmp(args[cur_arg], "off")) {
            conf->status = NST_STATUS_OFF;
        } else if(!strcmp(args[cur_arg], "on")) {
            conf->status = NST_STATUS_ON;
        } else {
            memprintf(err, "[%s] expects [on|off], default on", args[1]);

            return -1;
        }

        cur_arg++;
    }

    fconf->id   = nst_nosql_flt_id;
    fconf->conf = conf;
    fconf->ops  = &nst_nosql_filter_ops;

    LIST_ADDQ(&px->filter_configs, &fconf->list);

    px->nuster.mode = NST_MODE_NOSQL;

    return 0;
}

int
nst_parse_proxy_rule(char **args, int section, hpx_proxy_t *proxy, hpx_proxy_t *defpx,
        const char *file, int line, char **err) {

    nst_rule_config_t  *rule = NULL;
    hpx_acl_cond_t     *cond = NULL;
    char               *name = NULL;
    char               *key  = NULL;
    char               *code = NULL;

    int      memory, disk, ttl, etag, last_modified, wait, stale, inactive;
    uint8_t  extend[4] = { -1 };
    int      cur_arg   = 2;
    int      ret;

    memory = disk = etag = last_modified = wait = stale = inactive = -1;
    ttl = -2;

    if(proxy == defpx || !(proxy->cap & PR_CAP_BE)) {
        memprintf(err, "rule is not allowed in a 'frontend' or 'defaults' section.");

        return -1;
    }

    if(*(args[cur_arg]) == 0) {
        memprintf(err, "[%s] expects a name.", args[1]);

        return -1;
    }

    name = args[cur_arg];
    cur_arg = 3;

    while(*(args[cur_arg]) !=0 && strcmp(args[cur_arg], "if") !=0
            && strcmp(args[cur_arg], "unless") != 0) {

        if(!strcmp(args[cur_arg], "key")) {

            if(key != NULL) {
                memprintf(err, "[%s.%s]: key already specified.", args[1], name);

                goto out;
            }

            cur_arg++;

            if(*(args[cur_arg]) == 0) {
                memprintf(err, "[%s.%s]: key expects an argument.", args[1], name);

                goto out;
            }

            key = args[cur_arg];
            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "ttl")) {

            if(ttl != -2) {
                memprintf(err, "[%s.%s]: ttl already specified.", args[1], name);

                goto out;
            }

            cur_arg++;

            if(*args[cur_arg] == 0) {
                memprintf(err, "[%s.%s]: ttl expects auto argument or a ttl(in seconds).",
                        args[1], name);

                goto out;
            }

            /*
             * "d", "h", "m", "s"
             * s is returned
             */
            if(!strcmp(args[cur_arg], "auto")) {
                ttl = -1;
            } else {
                ret = nst_parse_time(args[cur_arg], strlen(args[cur_arg]), (uint32_t *)&ttl);

                if(ret == NST_TIME_ERR) {
                    memprintf(err, "[%s.%s]: invalid ttl.", args[1], name);

                    goto out;
                } else if(ret == NST_TIME_OVER) {
                    ttl = INT_MAX;

                    ha_warning("[%s.%s]: Set ttl to max %d.\n", args[1], name, INT_MAX);
                }

            }

            cur_arg++;
            continue;
        }

        if(!strcmp(args[cur_arg], "code")) {

            if(code != NULL) {
                memprintf(err, "[%s.%s]: code already specified.", args[1], name);

                goto out;
            }

            cur_arg++;

            if(*(args[cur_arg]) == 0) {
                memprintf(err, "[%s.%s]: code expects an argument.", args[1], name);

                goto out;
            }

            code = args[cur_arg];
            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "memory")) {

            if(memory != -1) {
                memprintf(err, "[%s.%s]: memory already specified.", args[1], name);

                goto out;
            }

            cur_arg++;

            if(*args[cur_arg] == 0) {
                memprintf(err, "[%s.%s]: memory expects [on|off], default on.", args[1], name);

                goto out;
            }

            if(!strcmp(args[cur_arg], "off")) {
                memory = NST_STORE_MEMORY_OFF;
            } else if(!strcmp(args[cur_arg], "on")) {
                memory = NST_STORE_MEMORY_ON;
            } else {
                memprintf(err, "[%s.%s]: memory expects [on|off], default on.", args[1], name);

                goto out;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "disk")) {

            if(disk != -1) {
                memprintf(err, "[%s.%s]: disk already specified.", args[1], name);

                goto out;
            }

            cur_arg++;

            if(*args[cur_arg] == 0) {
                memprintf(err, "[%s.%s]: disk expects [on|off|sync], default off.", args[1], name);

                goto out;
            }

            if(!strcmp(args[cur_arg], "off")) {
                disk = NST_STORE_DISK_OFF;
            } else if(!strcmp(args[cur_arg], "on")) {
                disk = NST_STORE_DISK_ON;
            } else if(!strcmp(args[cur_arg], "sync")) {
                disk = NST_STORE_DISK_SYNC;
            } else {
                memprintf(err, "[%s.%s]: disk expects [on|off|sync], default off.", args[1], name);

                goto out;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "etag")) {

            if(etag != -1) {
                memprintf(err, "[%s.%s]: etag already specified.", args[1], name);

                goto out;
            }

            cur_arg++;

            if(*args[cur_arg] == 0) {
                memprintf(err, "[%s.%s]: etag expects [on|off], default off.", args[1], name);

                goto out;
            }

            if(!strcmp(args[cur_arg], "on")) {
                etag = NST_STATUS_ON;
            } else if(!strcmp(args[cur_arg], "off")) {
                etag = NST_STATUS_OFF;
            } else {
                memprintf(err, "[%s.%s]: etag expects [on|off], default off.", args[1], name);

                goto out;
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "last-modified")) {

            if(last_modified != -1) {
                memprintf(err, "[%s.%s]: last-modified already specified.", args[1], name);

                goto out;
            }

            cur_arg++;
            if(*args[cur_arg] == 0) {
                memprintf(err, "[%s.%s]: last-modified expects [on|off], default off.",
                        args[1], name);

                goto out;
            }

            if(!strcmp(args[cur_arg], "on")) {
                last_modified = NST_STATUS_ON;
            } else if(!strcmp(args[cur_arg], "off")) {
                last_modified = NST_STATUS_OFF;
            } else {
                memprintf(err, "[%s.%s]: last modified expects [on|off], default off.",
                        args[1], name);

                goto out;
            }

            cur_arg++;
            continue;
        }

        if(!strcmp(args[cur_arg], "extend")) {

            if(extend[0] != 0xFF) {
                memprintf(err, "[%s.%s]: extend already specified.", args[1], name);

                goto out;
            }

            cur_arg++;

            if(*args[cur_arg] == 0) {
                memprintf(err, "[%s.%s]: extend expects [on|off|N1,N2,N3,N4], default off.",
                        args[1], name);

                goto out;
            }

            if(!strcmp(args[cur_arg], "on")) {
                extend[0] = extend[1] = extend[2] = extend[3] = 33;
            } else if(!strcmp(args[cur_arg], "off")) {
                extend[0] = extend[1] = extend[2] = extend[3] = 0;
            } else {
                char  *tmp = strdup(args[cur_arg]);
                char  *ptr = tmp;
                char  *next;
                int    t, i = 0;

                while(tmp != NULL) {
                    strsep(&ptr, ",");
                    t = strtol(tmp, &next, 10);

                    if(t < 0 || t > 100) {
                        memprintf(err, "[%s.%s]: extend expects positive integer between 0 and 100",
                                args[1], name);

                        goto out;
                    }

                    extend[i++ % 4] = t;

                    if((next == tmp) || (*next != '\0')) {
                        memprintf(err, "[%s.%s]: extend expects [on|off|N1,N2,N3,N4], default off.",
                                args[1], name);

                        goto out;
                    }

                    tmp = ptr;
                }

                if(i != 4) {
                    memprintf(err, "[%s.%s]: extend expects [on|off|N1,N2,N3,N4], default off.",
                            args[1], name);

                    goto out;
                }

                if(extend[0] + extend[1] + extend[2] > 100) {
                    memprintf(err, "[%s.%s]: extend: N1 + N2 + N3 must be less than or equal"
                            " to 100", args[1], name);

                    goto out;
                }

                if(extend[3] <= 0 || extend[3] > 100) {
                    memprintf(err, "[%s.%s]: extend: N4 must be between 0 and 100", args[1], name);

                    goto out;
                }

            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "wait")) {

            if(wait != -1) {
                memprintf(err, "[%s.%s]: wait already specified.", args[1], name);

                goto out;
            }

            cur_arg++;

            if(*args[cur_arg] == 0) {
                memprintf(err, "[%s.%s]: wait expects [on|off|TIME], default off.",
                        args[1], name);

                goto out;
            }

            if(!strcmp(args[cur_arg], "on")) {
                wait = 0;
            } else if(!strcmp(args[cur_arg], "off")) {
                wait = -1;
            } else {
                ret = nst_parse_time(args[cur_arg], strlen(args[cur_arg]), (unsigned *)&wait);

                if(ret == NST_TIME_ERR) {
                    memprintf(err, "[%s.%s]: invalid wait.", args[1], name);

                    goto out;
                } else if(ret == NST_TIME_OVER) {
                    wait = INT_MAX;

                    ha_warning("[%s.%s]: Set wait to max %d.\n", args[1], name, INT_MAX);
                }
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "use-stale")) {

            if(stale != -1) {
                memprintf(err, "[%s.%s]: use-stale already specified.", args[1], name);

                goto out;
            }

            cur_arg++;

            if(*args[cur_arg] == 0) {
                memprintf(err, "[%s.%s]: use-stale expects [on|off|TIME], default off.",
                        args[1], name);

                goto out;
            }

            if(!strcmp(args[cur_arg], "on")) {
                stale = 0;
            } else if(!strcmp(args[cur_arg], "off")) {
                stale = -1;
            } else {
                ret = nst_parse_time(args[cur_arg], strlen(args[cur_arg]), (unsigned *)&stale);

                if(ret == NST_TIME_ERR) {
                    memprintf(err, "[%s.%s]: invalid use-stale.", args[1], name);

                    goto out;
                } else if(ret == NST_TIME_OVER) {
                    stale = INT_MAX;

                    ha_warning("[%s.%s]: Set use-stale to max %d.\n", args[1], name, INT_MAX);
                }
            }

            cur_arg++;

            continue;
        }

        if(!strcmp(args[cur_arg], "inactive")) {

            if(stale != -1) {
                memprintf(err, "[%s.%s]: inactive already specified.", args[1], name);

                goto out;
            }

            cur_arg++;

            if(*args[cur_arg] == 0) {
                memprintf(err, "[%s.%s]: inactive expects [off|TIME], default off.",
                        args[1], name);

                goto out;
            }

            if(!strcmp(args[cur_arg], "off")) {
                inactive = 0;
            } else {
                ret = nst_parse_time(args[cur_arg], strlen(args[cur_arg]), (unsigned *)&inactive);

                if(ret == NST_TIME_ERR) {
                    memprintf(err, "[%s.%s]: invalid inactive.", args[1], name);

                    goto out;
                } else if(ret == NST_TIME_OVER) {
                    stale = INT_MAX;

                    ha_warning("[%s.%s]: Set inactive to max %d.\n", args[1], name, INT_MAX);
                }
            }

            cur_arg++;

            continue;
        }

        memprintf(err, "[%s.%s]: Unrecognized '%s'.", args[1], name, args[cur_arg]);

        goto out;
    }

    if(!strcmp(args[cur_arg], "if") || !strcmp(args[cur_arg], "unless")) {

        if(*args[cur_arg + 1] != 0) {
            char  *errmsg = NULL;

            if((cond = build_acl_cond(file, line, &proxy->acl, proxy,
                            (const char **)args + cur_arg, &errmsg)) == NULL) {

                memprintf(err, "%s", errmsg);
                free(errmsg);

                goto out;
            }

        } else {
            memprintf(err, "[%s.%s]: [if|unless] expects an acl.", args[1], name);

            goto out;
        }
    }

    rule = malloc(sizeof(*rule));

    rule->name  = strdup(name);
    rule->proxy = proxy->id;

    rule->key.name = strdup(key == NULL ? NST_DEFAULT_KEY : key);
    rule->key.data = _nst_parse_rule_key(rule->key.name);

    if(!rule->key.data) {
        memprintf(err, "[%s.%s]: invalid key.", args[1], name);

        goto out;
    }

    rule->code = _nst_parse_rule_code(code == NULL ? NST_DEFAULT_CODE : code);

    rule->ttl = ttl == -2 ? NST_DEFAULT_TTL : ttl;

    if(disk == NST_STORE_DISK_ON || disk == NST_STORE_DISK_SYNC) {
        if((proxy->nuster.mode == NST_MODE_CACHE && !global.nuster.cache.root.len)
                || (proxy->nuster.mode == NST_MODE_NOSQL && !global.nuster.nosql.root.len)) {

            memprintf(err, "[%s.%s]: disk enabled but no `dir` defined", args[1], name);

            goto out;
        }
    }

    if(memory == NST_STORE_MEMORY_OFF && disk == NST_STORE_DISK_SYNC) {
        memprintf(err, "[%s.%s]: memory needs to be on to use disk sync", args[1], name);

        goto out;
    }

    if(memory == NST_STORE_MEMORY_OFF && disk == NST_STORE_DISK_OFF) {
        ha_warning("parsing [%s:%d]: [%s.%s]: both memory and disk are off\n", file, line,
                args[1], name);
    }

    rule->store = 0;

    if(memory == NST_STORE_MEMORY_OFF) {
        rule->store |= NST_STORE_MEMORY_OFF;
    } else {
        rule->store |= NST_STORE_MEMORY_ON;
    }

    if(disk == NST_STORE_DISK_ON) {
        rule->store |= NST_STORE_DISK_ON;
    } else if(disk == NST_STORE_DISK_SYNC) {
        rule->store |= NST_STORE_DISK_SYNC;
    } else {
        rule->store |= NST_STORE_DISK_OFF;
    }

    rule->etag          = etag          == -1 ? NST_STATUS_OFF      : etag;
    rule->last_modified = last_modified == -1 ? NST_STATUS_OFF      : last_modified;

    if(extend[0] == 0xFF) {
        rule->extend[0] = rule->extend[1] = 0;
        rule->extend[2] = rule->extend[3] = 0;
    } else {
        rule->extend[0] = extend[0];
        rule->extend[1] = extend[1];
        rule->extend[2] = extend[2];
        rule->extend[3] = extend[3];
    }

    rule->wait     = wait;
    rule->stale    = stale;
    rule->inactive = inactive == -1 ? 0 : inactive;

    rule->cond = cond;

    LIST_INIT(&rule->list);
    LIST_ADDQ(&proxy->nuster.rules, &rule->list);

    return 0;

out:
    return -1;
}

int
nst_parse_proxy(char **args, int section, hpx_proxy_t *px, hpx_proxy_t *defpx,
        const char *file, int line, char **err) {

    if(px->cap != PR_CAP_BE) {
        memprintf(err, "[proxy] '%s' is only allowed in 'backend' section.", args[0]);

        return -1;
    }

    if(*args[1]) {

        if(!strcmp(args[1], "cache")) {
            return nst_parse_proxy_cache(args, section, px, defpx, file, line, err);
        } else if(!strcmp(args[1], "nosql")) {
            return nst_parse_proxy_nosql(args, section, px, defpx, file, line, err);
        } else if(!strcmp(args[1], "rule")) {
            return nst_parse_proxy_rule(args, section, px, defpx, file, line, err);
        } else {
            memprintf(err, "%s: expects [cache|rule]", args[0]);

            return -1;
        }

    }

    return 0;
}

static struct cfg_kw_list cfg_kws = {ILH, {
    { CFG_LISTEN, "nuster", nst_parse_proxy}, { 0, NULL, NULL }, }
};

__attribute__((constructor)) static void __nst_parser_init(void) {
    cfg_register_keywords(&cfg_kws);
}
