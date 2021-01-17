# nuster

[Wiki](https://github.com/jiangwenyuan/nuster/wiki) | [English](README.md) | [中文](README-CN.md) | [日本語](README-JP.md)

A high-performance HTTP proxy cache server and RESTful NoSQL cache server based on HAProxy.

# Table of Contents

* [Introduction](#introduction)
* [Performance](#performance)
* [Getting Started](#getting-started)
* [Usage](#usage)
* [Directives](#directives)
* [Cache](#cache)
* [NoSQL](#nosql)
* [Manager](#manager)
  * [Stats](#stats)
  * [Enable disable rules](#enable-and-disable-rule)
  * [Update ttl](#update-ttl)
  * [Purging](#purging)
* [Store](#store)
* [Sample fetches](#sample-fetches)
* [FAQ](#faq)

# Introduction

nuster is a high-performance HTTP proxy cache server and RESTful NoSQL cache server based on HAProxy.
It is 100% compatible with HAProxy and takes full advantage of the ACL functionality of HAProxy to provide fine-grained caching policy based on the content of request, response or server status.

## Features

### As HTTP/TCP loader balancer

nuster can be used as an HTTP/TCP load balancer just like HAProxy.

* All features of HAProxy are inherited, 100% compatible with HAProxy
* Load balancing
* HTTPS supports on both frontend and backend
* HTTP compression
* HTTP rewriting and redirection
* HTTP fixing
* HTTP2
* Monitoring
* Stickiness
* ACLs and conditions
* Content switching

### As HTTP cache server

nuster can also be used as an HTTP proxy cache server like Varnish or Nginx to cache dynamic and static HTTP response.

* All features from HAProxy(HTTPS, HTTP/2, ACL, etc)
* Extremely fast
* Powerful dynamic cache ability
  * Based on HTTP method, URI, path, query, header, cookies, etc
  * Based on HTTP request or response contents, etc
  * Based on environment variables, server state, etc
  * Based on SSL version, SNI, etc
  * Based on connection rate, number, byte, etc
* Cache management
* Cache purging
* Cache stats
* Cache TTL
* Disk persistence

### As RESTful NoSQL cache server

nuster can also be used as a RESTful NoSQL cache server, using HTTP `POST/GET/DELETE` to set/get/delete Key/Value object.

It can be used as an internal NoSQL cache sits between your application and database like Memcached or Redis as well as a user-facing NoSQL cache that sits between end-user and your application.
It supports headers, cookies, so you can store per-user data to the same endpoint.

* All features from HAProxy(HTTPS, HTTP/2, ACL, etc)
* Conditional cache
* Internal KV cache
* User facing RESTful cache
* Support any kind of data
* Support all programming languages as long as HTTP is supported
* Disk persistence

# Performance

nuster is very fast, some test shows nuster is almost three times faster than nginx when both using single core, and nearly two times faster than nginx and three times faster than varnish when using all cores.

See [detailed benchmark](https://github.com/jiangwenyuan/nuster/wiki/Web-cache-server-performance-benchmark:-nuster-vs-nginx-vs-varnish-vs-squid)

# Getting Started

## Download

Download stable version from [Download](Download.md) page for production use, otherwise git clone the source code.

## Build

```
make TARGET=linux-glibc USE_LUA=1 LUA_INC=/usr/include/lua5.3 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1
make install PREFIX=/usr/local/nuster
```

> use `USE_PTHREAD_PSHARED=1` to use pthread lib

> omit `USE_LUA=1 LUA_INC=/usr/include/lua5.3 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1` if unnecessary

See [HAProxy INSTALL](INSTALL) for details.

## Create a config file

A minimal config file: `nuster.cfg`

```
global
    nuster cache on data-size 100m
    nuster nosql on data-size 200m
    master-worker # since v3
defaults
    mode http
frontend fe
    bind *:8080
    #bind *:4433 ssl crt example.com.pem alpn h2,http/1.1
    use_backend be2 if { path_beg /_kv/ }
    default_backend be1
backend be1
    nuster cache on
    nuster rule img ttl 1d if { path_beg /img/ }
    nuster rule api ttl 30s if { path /api/some/api }
    server s1 127.0.0.1:8081
    server s2 127.0.0.1:8082
backend be2
    nuster nosql on
    nuster rule r1 ttl 3600
```

nuster listens on port 8080 and accepts HTTP requests.
Requests start with `/_kv/` go to backend `be2`, you can make `POST/GET/DELETE` requests to `/_kv/any_key` to `set/get/delete` K/V object.
Other requests go to backend `be1`, and will be passed to servers `s1` or `s2`. Among those requests, `/img/*` will be cached for 1 day and `/api/some/api` will be cached for 30 seconds.

## Start

`/usr/local/nuster/sbin/nuster -f nuster.cfg`

## Docker

```
docker pull nuster/nuster
docker run -d -v /path/to/nuster.cfg:/etc/nuster/nuster.cfg:ro -p 8080:8080 nuster/nuster
```

# Usage

nuster is based on HAProxy, all directives from HAProxy are supported in nuster.

## Basic

There are four basic `section`s: `global`, `defaults`, `frontend` and `backend` as you can find out in the above config file.

* global
  * defines process-wide and often OS-specific parameters
  * `nuster cache on` or `nuster nosql on` must be declared in this section in order to use cache or nosql functionality
* defaults
  * defines default parameters for all other `frontend`, `backend` sections
  * and can be overwritten in specific `frontend` or `backend` section
* frontend
  * describes a set of listening sockets accepting client connections
* backend
  * describes a set of servers to which the proxy will connect to forward incoming connections
  * `nuster cache on` or `nuster nosql on` must be declared in this section
  * `nuster rule` must be declared here

You can define multiple `frontend` or `backend` sections. If `nuster cache|nosql off` is declared or no `nuster cache|nosql on|off` declared, nuster acts just like HAProxy, as a TCP and HTTP load balancer.

Although `listen` is a complete proxy with its frontend and backend parts combined in one section, you cannot use nuster in `listen`, use `frontend` and `backend` pairs.

You can find HAProxy documentation in `/doc`, and [Online HAProxy Documentation](https://cbonte.github.io/haproxy-dconv/)

## As TCP loader balancer

```
frontend mysql-lb
    bind *:3306
    mode tcp
    default_backend mysql-cluster
backend mysql-cluster
    balance roundrobin
    mode tcp
    server s1 10.0.0.101:3306
    server s2 10.0.0.102:3306
    server s3 10.0.0.103:3306
```

## As HTTP/HTTPS loader balancer

```
frontend web-lb
    bind *:80
    #bind *:443 ssl crt XXX.pem
    mode http
    default_backend apps
backend apps
    balance roundrobin
    mode http
    server s1 10.0.0.101:8080
    server s2 10.0.0.102:8080
    server s3 10.0.0.103:8080
    #server s4 10.0.0.101:8443 ssl verify none
```

## As HTTP cache server

```
global
    nuster cache on data-size 200m
frontend fe
    bind *:8080
    mode http
    default_backend be
backend be
    mode http
    nuster cache on
    nuster rule all
    server s1 127.0.0.1:8081
```

## As RESTful NoSQL cache server

```
global
    nuster nosql on data-size 200m
frontend fe
    bind *:8080
    mode http
    default_backend be
backend be
    nuster nosql on
    mode http
    nuster rule r1 ttl 3600
```

# Directives

## global: nuster manager

**syntax:**

*nuster manager on|off [uri URI] [purge-method method]*

**default:** *off*

**context:** *global*

Enable manager/stats/purge API, define the endpoint and purge method.

By default, it is disabled. When it is enabled, remember to restrict the access(see [FAQ](#how-to-restrict-access)).

See [Manager](#manager) for details.

### uri

Define endpoint URI, `/nuster` by default.

### purge-method

Define a customized HTTP method to purge, it is `PURGE` by default.

## global: nuster cache|nosql

**syntax:**

*nuster cache on|off [data-size size] [dict-size size] [dir DIR] [dict-cleaner n] [data-cleaner n] [disk-cleaner n] [disk-loader n] [disk-saver n] [clean-temp on|off] [always-check-disk on|off]*

*nuster nosql on|off [data-size size] [dict-size size] [dir DIR] [dict-cleaner n] [data-cleaner n] [disk-cleaner n] [disk-loader n] [disk-saver n] [clean-temp on|off] [always-check-disk on|off]*

**default:** *none*

**context:** *global*

Determines whether to use cache/nosql or not.

A memory zone with a size of `data-size + dict-size` will be created.

Except for temporary data created and destroyed within a request, all cache related data including HTTP response data, keys and overheads are stored in this memory zone and shared between all processes.
If no more memory can be allocated from this memory zone, new requests that should be cached according to defined rules will not be cached unless some memory is freed.
Temporary data are stored in a memory pool which allocates memory dynamically from system in case there is no available memory in the pool.
A global internal counter monitors the memory usage of all HTTP response data across all processes, new requests will not be cached if the counter exceeds `data-size`.

### data-size

Determines the size of the memory zone along with `dict-size`.

It accepts units like `m`, `M`, `g` and `G`. By default, the size is 1024 * 1024 bytes, which is also the minimal size.

### dict-size

Determines the size of memory used by the hash table.

It accepts units like `m`, `M`, `g` and `G`. By default, the size is 1024 * 1024 bytes, which is also the minimal size.

Note that it only decides the memory used by hash table buckets, not keys. In fact, keys are stored in the memory zone which is limited by `data-size`.

**dict-size(number of buckets)** is different from **number of keys**. New keys can still be added to the hash table even if the number of keys exceeds dict-size(number of buckets) as long as there is enough memory.

Nevertheless, it may lead to a potential performance drop if `number of keys` is greater than `dict-size(number of buckets)`. An approximate number of keys multiplied by 8 (normally) as `dict-size` should be fine. Basically, the bigger the better.

Enable stats API and check following stats:

```
dict.nosql.length:              131072
dict.nosql.used:                0
```

If `dict.nosql.used` is greater than `dict.nosql.length`, then increase `dict-size` would be a good idea.

> dict-size will be removed in a future release, automatically resizing the hash table in the first version will be added back.

### dir

Specify the root directory of the disk persistence. This has to be set in order to use disk persistence.

If chroot is also set, the real directory is chroot+dir. For example

```
chroot /data
nuster cache on dir /cache
```

Cache is saved to /data/cache

### dict-cleaner

Prior to v2.x, manager tasks like removing invalid cache data, resetting dict entries are executed in iterations in each HTTP request. Corresponding indicators or pointers are increased or advanced in each iteration.

In v3.x these tasks are moved to the master process and also done in iterations, and these parameters can be set to control the number of times of certain task during one iteration.

During one iteration no more than `dict-cleaner` entries are checked, invalid entries will be deleted (by default, 1000).

### data-cleaner

During one iteration no more than `data-cleaner` data are checked, invalid data will be deleted (by default, 1000).

When the invalid data ratio is greater than 20%, an internal mechanism will speed up the clean process, so it is recommended not to change this from the default value.

### disk-cleaner

If disk persistence is enabled, data are stored in files. These files are checked by master process and will be deleted if invalid, for example, expired.

During one iteration no more than `disk-cleaner` files are checked, invalid files will be deleted (by default, 100).

### disk-loader

After the start of nuster, master process will load information about data previously stored on disk into memory.

During one iteration no more than `disk-loader` files are loaded(by default, 100).

If `USE_THREAD` is used, a separate thread will be created to load disk files and this parameter is ignored.

### disk-saver

Master process will save `disk sync` cache data periodically.

During one iteration no more than `disk-saver` data are checked and saved to disk if necessary (by default, 100).

See [Store](#disk) for details.

### clean-temp on|off

Under the directory defined by `dir`, a temporary directory `.tmp` will be created to store temporary files.

Use this option to determine whether or not to remove those temporary files on startup.

By default, it is `off`.

### always-check-disk on|off

The initial load of cached data on disk only happens on startup and has such if running in a scenario where the disk is shared across multiple instances, it can lead to missed cache calls.
Using this option, the disk is always checked for the cached data.

By default, it is `off`.

## proxy: nuster cache|nosql

**syntax:**

*nuster cache [on|off]*

*nuster nosql [on|off]*

**default:** *on*

**context:** *backend*

Determines whether or not to use cache/nosql on this proxy, additional `nuster rule` should be defined.
If there are filters on this proxy, put this directive after all other filters.

## proxy: nuster rule

**syntax:**

*nuster rule name [key KEY] [ttl auto|TTL] [extend EXTEND] [wait on|off|TIME] [use-stale on|off|TIME] [inactive off|TIME] [code CODE] [memory on|off] [disk on|off|sync] [etag on|off] [last-modified on|off] [if|unless condition]*

**default:** *none*

**context:** *backend*

Define rule to specify cache/nosql creating conditions, properties. At least one rule should be defined.

```
nuster cache on

# cache request `/asdf` for 30 seconds
nuster rule asdf ttl 30 if { path /asdf }

# cache if the request path begins with /img/
nuster rule img if { path_beg /img/ }

# cache if the response header `cache` is `yes`
acl resHdrCache res.hdr(cache) yes
nuster rule r1 if resHdrCache
```

It is possible and recommended to declare multiple rules in the same section. The order is important because the matching process stops on the first match.

```
acl pathA path /a.html
nuster cache on
nuster rule all ttl 3600
nuster rule path01 ttl 60 if pathA
```

rule `path01` will never match because the first rule will cache everything.

### name

Define a name for this rule. Must be globally unique since v5.

### key KEY

Define the key for cache/nosql, it takes a string combined by following keywords with `.` separator:

 * method:       http method, GET/POST...
 * scheme:       http or https
 * host:         the host in the request
 * uri:          first slash to end of the url
 * path:         the URL path of the request
 * delimiter:    '?' if query exists otherwise empty
 * query:        the whole query string of the request
 * header\_NAME: the value of header `NAME`
 * cookie\_NAME: the value of cookie `NAME`
 * param\_NAME:  the value of query `NAME`
 * body:         the body of the request

The default key of CACHE is `method.scheme.host.uri`, and default key of NoSQL is `GET.scheme.host.uri`.

Example

```
GET http://www.example.com/q?name=X&type=Y

http header:
GET /q?name=X&type=Y HTTP/1.1
Host: www.example.com
ASDF: Z
Cookie: logged_in=yes; user=nuster;
```

Should result:

 * method:       GET
 * scheme:       http
 * host:         www.example.com
 * uri:          /q?name=X&type=Y
 * path:         /q
 * delimiter:    ?
 * query:        name=X&type=Y
 * header\_ASDF: Z
 * cookie\_user: nuster
 * param\_type:  Y
 * body:         (empty)

So default key produces `GET\0http\0www.example.com\0/q?name=X&type=Y\0`, and `key method.scheme.host.path.header_ASDF.cookie_user.param_type` produces `GET\0http\0www.example.com\0/q\0Z\0nuster\0Y\0`.

> `\0` is NULL character

If a request has the same key as a cached HTTP response data, then cached data will be sent to the client.

### ttl auto|TTL

Set a TTL on key, after the TTL has expired, the key will be deleted.

It accepts units like `d`, `h`, `m` and `s`. Default ttl is `0` which does not expire the key.

When `auto` is used, the ttl is set to the value of `s-maxage` or `max-age` directive in the `cache-control` header.

> Other directives of `cache-control` are not handled.

The max value of ttl is 2147483647.

ttl can be automatically extended by using `extend` keyword.

### extend EXTEND

Automatically extend the ttl.

#### Format

extend on|off|n1,n2,n3,n4

Default: off.

n1,n2,n3,n4: positive integer less than 100, and n1 + n2 + n3 is less than 100. Together they define four time slots as following:

```
time:       0                                                       ttl         ttl * (1 + n4%)
access:     |            A1             |   A2    |   A3    |   A4    |         |
            |---------------------------|---------|---------|---------|---------|
percentage: |<- (100 - n1 - n2 - n3)% ->|<- n1% ->|<- n2% ->|<- n3% ->|<- n4% ->|
```

ttl will be extended if:

1. A4 > A3 > A2
2. A new request takes place between `ttl` and `ttl * (1 + n4%)`

> `on` equals to 33,33,33,33

### wait on|off|TIME [cache only]

When enabled, only one request at a time will be passed to backend server to create cache. Other identical requests will either wait until the cache is created(`wait on`) or for the time expires(`wait TIME`) and be forwarded to the backend server.

By default, identical requests are forwarded to backend server and the first one will create the cache(`wait off`).

Note that other identical requests will not wait until the first request finished the initialization process(e.g. create a cache entry).

> In nosql mode, there is no wait mode. Multiple identical POST requests are served in the order it was received, and the body of the last request will be saved as the content.

The max value of wait is 2147483647.

### use-stale on|off|TIME [cache only]

Determines whether or not to serve stale cache to clients if it is being updated or the backend server is down.

When use-stale is on, the stale cache will be used to serve clients.

When use-stale is off, which is the default mode, same requests will be passed to the backend when the cache is being updated if `wait off` is set, otherwise wait if `wait on|TIME` is set.

`use-stale TIME` permits using the stale cache to serve clients for TIME seconds if the cache cannot be updated due to backend error.

The max value of use-stale is 2147483647.

### inactive off|TIME

Determines whether or not to delete the cache that are not accessed during TIME seconds regardless of the validity. By default, inactive is set to off(0).

Note that it is not guaranteed that the cache get removed after TIME inactive. If the clean process accesses the cache first, then the data get removed. If a new request comes first, then the last access time of the cache gets updated and the cache will not be deleted. In the case of disk file, the atime of the file is not used, so when nuster restarts, the last access time is set to the loaded time.

The max value of inactive is 2147483647.

### code CODE1,CODE2...

Cache only if the response status code is CODE.

By default, only 200 response is cached. You can use `all` to cache all responses.

```
nuster rule only200
nuster rule 200and404 code 200,404
nuster rule all code all
```

### memory on|off

Save data to memory or not, default on.

See [Store](#Store) for details.

### disk on|off|sync

Save data to disk or not, and how, default off.

`memory on` needs to be set in order to use `disk sync` mode.

See [Store](#Store) for details.

### etag on|off

Enable etag conditional requests handling. Add `ETag` header if absent.

Default off.

### last-modified on|off

Enable last-modified conditional requests handling. Add `Last-Modified` header if absent.

Default off.

### if|unless condition

Define when to cache using HAProxy ACL.

The evaluation involves two stages: request stage and response stage.

Cache will be performed if:

1. The evaluation in the request stage is true,
2. The evaluation in the request stage is false but true in the response stage.

**Please be very careful if you use negation in the condition or samples not available in certain stage**

For example,

1.  Cache if the request path begins with `/img/`

    nuster rule img if { path_beg /img/ }

This will work because the evaluation in the request stage will either be true or false and will never be true in the response stage as `path` is not available in the response stage.

2. Cache if `Content-Type` in response is `image/jpeg`

    nuster rule jpeg if { res.hdr(Content-Type) image/jpeg }

This will work because the evaluation in the request stage is always false as `res.hdr` is not available in the request stage, and will be either true or false in the response stage.

3. Cache if the request path begins with `/img/` and `Content-Type` in response is `image/jpeg`

It won't work if you define the rule as:

    nuster rule img if { path_beg /img/ } { res.hdr(Content-Type) image/jpeg }

because `path` is not available in the response stage and `res.hdr` is not available in the request stage, so the evaluation will never be true.

In order the make this work, `path` needs to be allocated for further use in reponse stage:

    http-request set-var(txn.pathImg) path
    acl pathImg var(txn.pathImg) -m beg /img/
    acl resHdrCT res.hdr(Content-Type) image/jpeg
    nuster rule r3 if pathImg resHdrCT

Or use `nuster.path`(v5):

    nuster rule r3 if { nuster.path -m beg /img } { res.hdr(Content-Type) image/jpeg }

4. Another example, cache if the request path does not begin with `/api/`

It won't work neither:

    acl NoCache path_beg /api/
    nuster rule r3 if !NoCache

Because the evaluation of `NoCache` against `/api/` in the request stage is true, and the negation is false, which is the desired state, but in response stage, the evaluation of `NoCache` is always false as `path` is not available in response stage, and it will be cached as the negation `!NoCache` is true.

This will work:

    http-request set-var(txn.path) path
    acl NoCache var(txn.path) -m beg /api/
    nuster rule r1 if !NoCache

See [Sample fetches](#sample-fetch) for sample fetches introduced by nuster.

See **7. Using ACLs and fetching samples** section in [HAProxy configuration](doc/configuration.txt)

# Cache

nuster can be used as an HTTP proxy cache server like Varnish or Nginx to cache dynamic and static HTTP response.

You can use HAProxy functionalities to terminate SSL, normalize HTTP, support HTTP2, rewrite the URL or modify headers and so on, and additional functionalities provided by nuster to control cache.

```
global
    nuster cache on data-size 200m
frontend fe
    bind *:8080
    mode http
    default_backend be
backend be
    mode http
    nuster cache on
    nuster rule r1 if { path /a1 }
    nuster rule r2 key method.scheme.host.path.delimiter.query.cookie_userId if { path /a2 }
    nuster rule r3 ttl 10 if { path /a3 }
    nuster rule r4 disk on if { path /a4 }

    server s1 127.0.0.1:8081
```

When a request is accepted, nuster will check the rules one by one. Key will be created and used to lookup in the cache, and if it's a HIT, the cached data will be returned to client. Otherwise the ACL will be tested, and if it passes the test, response will be cached.

# NoSQL

nuster can be used as a RESTful NoSQL cache server, using HTTP `POST/GET/DELETE` to set/get/delete Key/Value object.

## Basic Operations

### Set

```
curl -v -X POST -d value1 http://127.0.0.1:8080/key1
curl -v -X POST --data-binary @icon.jpg http://127.0.0.1:8080/imgs/icon.jpg
```

### Get

`curl -v http://127.0.0.1:8080/key1`

### Delete

`curl -v -X DELETE http://127.0.0.1:8080/key1`

## Response

Check status code.

* 200 OK
  * POST/GET: succeeds
  * DELETE: always
* 400 Bad request
  * empty value
  * incorrect acl, rules, etc
* 404 Not Found
  * POST: failed on all rule tests
  * GET: not found
* 405 Method Not Allowed
  * other methods
* 500 Internal Server Error
  * any error occurs
* 507 Insufficient Storage
  * exceeds max data-size

## Headers

Supported headers in request

| Name          | value                   | description
| ------        | -----                   | -----------
| content-type  | any   		  | Will be returned as is in GET request
| cache-control | `s-maxage` or `max-age` | used to set ttl when rule.ttl is `auto`

## Per-user data

By using header or cookie in key, you can save per-user data to the same endpoint.

```
nuster rule r1 key method.scheme.host.uri.header_userId if { path /mypoint }
nuster rule r2 key method.scheme.host.uri.cookie_sessionId if { path /mydata }
```

### Set


```
curl -v -X POST -d "333" -H "userId: 1000" http://127.0.0.1:8080/mypoint
curl -v -X POST -d "555" -H "userId: 1001" http://127.0.0.1:8080/mypoint

curl -v -X POST -d "userA data" --cookie "sessionId=ijsf023xe" http://127.0.0.1:8080/mydata
curl -v -X POST -d "userB data" --cookie "sessionId=rosre329x" http://127.0.0.1:8080/mydata
```

### Get

```
curl -v http://127.0.0.1:8080/mypoint
< 404 Not Found

curl -v -H "userId: 1000" http://127.0.0.1:8080/mypoint
< 200 OK
333

curl -v --cookie "sessionId=ijsf023xe" http://127.0.0.1:8080/mydata
< 200 OK
userA data
```

## Clients

You can use any tools or libs which support HTTP: `curl`, `postman`, python `requests`, go `net/http`, etc.

# Manager

Nuster can be managed via a manager API which endpoints is defined by `uri` and can be accessed by making HTTP requests along with some headers

**Enable and define the endpoint uri and purge method**

```
nuster manager on uri /internal/nuster purge-method PURGEX
```

## Usage matrix

| METHOD | Endpoint         | description
| ------ | --------         | -----------
| GET    | /internal/nuster | get stats
| POST   | /internal/nuster | enable and disable rule, update ttl
| DELETE | /internal/nuster | advanced purge cache
| PURGEX | /any/real/path   | basic purge

## Stats

Nuster stats can be accessed by making HTTP GET request to the endpoint defined by `uri`;

### Usage

`curl http://127.0.0.1/nuster`

### Output

```
**NUSTER**
nuster.cache:                   on
nuster.nosql:                   on
nuster.manager:                 on

**MANAGER**
manager.uri:                    /nuster
manager.purge_method:           PURGE

**DICT**
# The size of the memory used by the cache dict in bytes defined by dict-size
dict.cache.size:                1048576
# The length of the cache dict array
dict.cache.length:              131072
# The number of used entries in the cache dict
dict.cache.used:                0
dict.cache.cleanup_idx:         0
dict.cache.sync_idx:            0
dict.nosql.size:                1048576
dict.nosql.length:              131072
dict.nosql.used:                0
dict.nosql.cleanup_idx:         0
dict.nosql.sync_idx:            0

**STORE MEMORY**
# The size of the cache memory store in bytes, approximate equals to dict-size + data-size
store.memory.cache.size:        2098200576
# The size of used memory of the cache memory store
store.memory.cache.used:        1048960
# The number of stored cache entries
store.memory.cache.count:       0
store.memory.nosql.size:        11534336
store.memory.nosql.used:        1048960
store.memory.nosql.count:       0

**STORE DISK**
store.disk.cache.dir:           /tmp/nuster/cache
store.disk.cache.loaded:        yes
store.disk.nosql.dir:           /tmp/nuster/nosql
store.disk.nosql.loaded:        yes

**STATS**
# The total number of requests
stats.cache.total:              0
# The total number of HIT requests
stats.cache.hit:                0
# The total number of MISS requests
stats.cache.fetch:              0
# The total number of bypass requests
stats.cache.bypass:             0
# The total number of aborted requests
stats.cache.abort:              0
# The total response size in bytes served by cache
stats.cache.bytes:              0
stats.nosql.total:              0
stats.nosql.get:                0
stats.nosql.post:               0
stats.nosql.delete:             0

**PROXY cache app1**
app1.rule.rule1:                state=on  memory=on  disk=off   ttl=10
app1.rule.rule2:                state=on  memory=on  disk=on    ttl=10
app1.rule.rule3:                state=on  memory=on  disk=sync  ttl=10
app1.rule.rule4:                state=on  memory=off disk=on    ttl=10
app1.rule.rule5:                state=on  memory=off disk=off   ttl=10

**PROXY nosql app2**
app2.rule.ruleA:                state=on  memory=on  disk=off   ttl=10
app2.rule.ruleB:                state=on  memory=on  disk=on    ttl=10
app2.rule.ruleC:                state=on  memory=on  disk=sync  ttl=10
app2.rule.ruleD:                state=on  memory=off disk=on    ttl=10
app2.rule.ruleE:                state=on  memory=off disk=off   ttl=10
```

## Enable and disable rule

Rule can be disabled at run time through manager uri. Disabled rule will not be processed, nor will the cache created by that.

***headers***

| header | value       | description
| ------ | -----       | -----------
| state  | enable      | enable  rule
|        | disable     | disable rule
| name   | rule NAME   | the rule to be enabled/disabled
|        | proxy NAME  | all rules of proxy NAME
|        | *           | all rules

Keep in mind that if name is not unique, **all** rules with that name will be disabled/enabled.

***Examples***

* Disable rule r1

  `curl -X POST -H "name: r1" -H "state: disable" http://127.0.0.1/nuster`

* Disable all rules defined in proxy app1b

  `curl -X POST -H "name: app1b" -H "state: disable" http://127.0.0.1/nuster`

* Enable all rules

  `curl -X POST -H "name: *" -H "state: enable" http://127.0.0.1/nuster`

## Update ttl

Change the TTL. It only affects the TTL of the responses to be cached, **does not** update the TTL of existing caches.

***headers***

| header | value      | description
| ------ | -----      | -----------
| ttl    | new TTL    | see `ttl` in `nuster rule`
| name   | rule NAME  | the rule to be changed
|        | proxy NAME | all rules of proxy NAME
|        | *          | all rules

***Examples***

```
curl -X POST -H "name: r1" -H "ttl: 0" http://127.0.0.1/nuster
curl -X POST -H "name: r2" -H "ttl: 2h" http://127.0.0.1/nuster
```

### Update state and TTL

state and ttl can be updated at the same time

```
curl -X POST -H "name: r1" -H "ttl: 0" -H "state: enabled" http://127.0.0.1/nuster
```

## Purging

There are two purging mode: basic and advanced.

* basic: Send HTTP method defined by `purge-method MYPURGE` to the path you want to delete
* advanced: Send DELETE method to the manager uri defined by `uri`

### Basic purging

This method deletes the specific url that is being requested, like this:

`curl -XPURGE http://127.0.0.1/imgs/test.jpg`

Key is created in the same way when the cache created except that the `method` is `GET`.

Note by default cache key contains `Host` if you cache a request like `http://example.com/test` and purge from localhost you need to specify `Host` header:

`curl -XPURGE -H "Host: example.com" http://127.0.0.1/test`

It works for both cache and nosql, it is an alias of `DELETE` in nosql mode.

### Advanced purging: purge by name

Cache can be purged by making HTTP `DELETE` requests to the manager uri along with a `name` HEADER.

***headers***

| header | value            | description
| ------ | -----            | -----------
| name   | nuster rule NAME | caches created by rule ${NAME} will be purged
|        | proxy NAME       | caches of proxy ${NAME}

***Examples***

```
# purge all caches of proxy applb
curl -X DELETE -H "name: app1b" http://127.0.0.1/nuster
# purge all caches of rule r1
curl -X DELETE -H "name: r1" http://127.0.0.1/nuster
```

### Advanced purging: purge by host

You can also purge cache by host, all caches with that host will be deleted:

***headers***

| header      | value        | description
| ------      | -----        | -----------
| host        | HOST         | the ${HOST}
| nuster-host | HOST         | nuster-host has higher precedence over host
| mode        | cache, nosql | purge cache or nosql data

***Examples***

```
curl -X DELETE -H "nuster-host: 127.0.0.1:8080" http://127.0.0.1/nuster
```

### Advanced purging: purge by path

By default, the query part is also used as a cache key, so there will be multiple caches if the query differs.

For example, for rule `nuster rule imgs if { path_beg /imgs/ }`, and request

```
curl http://127.0.0.1/imgs/test.jpg?w=120&h=120
curl http://127.0.0.1/imgs/test.jpg?w=180&h=180
```

There will be two cache objects since the default key contains the query part.

In order to delete that, you can

***delete one by one in case you know all queries***

```
curl -XPURGE http://127.0.0.1/imgs/test.jpg?w=120&h=120
curl -XPURGE http://127.0.0.1/imgs/test.jpg?w=180&h=180
```

It does not work if you don't know all queries.

***use a customized key and delete once in case that the query part is irrelevant***

Define a key like `nuster rule imgs key method.scheme.host.path if { path_beg /imgs }`, in this way only one cache will be created, and you can purge without query:

`curl -XPURGE http://127.0.0.1/imgs/test.jpg`

It does not work if the query part is required.

***delete by rule NAME***

`curl -X DELETE -H "name: imgs" http://127.0.0.1/nuster`

It does not work if the nuster rule is defined something like `nuster rule static if { path_beg /imgs/ /css/ }`.

This method provides a way to purge just by path:

***headers***

| header      | value        | description
| ------      | -----        | -----------
| path        | PATH         | caches with ${PATH} will be purged
| host        | HOST         | and host is ${HOST}
| nuster-host | HOST         | nuster-host has higher precedence over host
| mode        | cache, nosql | purge cache or nosql data

***Examples***

```
#delete all caches which path is /imgs/test.jpg
curl -X DELETE -H "path: /imgs/test.jpg" http://127.0.0.1/nuster
#delete all caches which path is /imgs/test.jpg and with host of 127.0.0.1:8080
curl -X DELETE -H "path: /imgs/test.jpg" -H "nuster-host: 127.0.0.1:8080" http://127.0.0.1/nuster
```

### Advanced purging: purge by regex

You can also purge cache by regex, the caches which path match the regex will be deleted.

***headers***

| header      | value        | description
| ------      | -----        | -----------
| regex       | REGEX        | caches which path match with ${REGEX} will be purged
| host 	      | HOST         | and host is ${HOST}
| nuster-host | HOST         | nuster-host has higher precedence over host
| mode        | cache, nosql | purge cache or nosql data

***Examples***

```
#delete all caches which path starts with /imgs and ends with .jpg
curl -X DELETE -H "regex: ^/imgs/.*\.jpg$" http://127.0.0.1/nuster
#delete all caches which path starts with /imgs and ends with .jpg and with host of 127.0.0.1:8080
curl -X DELETE -H "regex: ^/imgs/.*\.jpg$" -H "127.0.0.1:8080" http://127.0.0.1/nuster
```

**PURGE CAUTION**

1. **ENABLE ACCESS RESTRICTION**

2. If there are mixed headers, use the precedence of `name`, `path & host`, `path`, `regex & host`, `regex`, `host`

   `curl -X DELETE -H "name: rule1" -H "path: /imgs/a.jpg"`: purge by name

3. If there are redundant headers, use the first occurrence

   `curl -X DELETE -H "name: rule1" -H "name: rule2"`: purge by `rule1`

4. `regex` is **NOT glob**

   For example, all jpg files under /imgs should be `^/imgs/.*\.jpg$` instead of `/imgs/*.jpg`

5. Purging cache files by proxy name or rule name or host or path or regex only works after the disk loader process is finished. You can check the status through stats url.

# Store

Nuster(both cache and nosql) supports different backend stores. Currently memory and disk are supported. More stores will be added.

## Memory

Data is stored into a memory area which size is defined by `data-size`. Data does not persist in memory and will lost after restarts.

## Disk

Data is stored to disk and under the path defined by `dir`. Data persists after restarts.

There are 3 modes:

* off:   default, disable disk persistence.
* on:    save data to disk.
* sync:  `memory on` has to be set in order to use this mode. Save data to memory first and data will be synced to disk later by the master process. One iteration `disk-saver` data are checked and saved to disk.

# Sample fetches

Nuster introduced following sample fetches

## [cache] nuster.cache.hit: boolean

Returns a boolean indicating whether it's a HIT or not and can be used like

    http-response set-header x-cache hit if { nuster.cache.hit }

## [cache|nosql] nuster.host: string

Same as HAProxy `req.hdr(Host)` except that `nuster.host` can be used in both request and response stage.

## [cache|nosql] nuster.uri: string

Same as HAProxy `capture.req.uri`.

## [cache|nosql] nuster.path: string

Same as HAProxy `path` except that `nuster.path` can be used in both request and response stage.

## [cache|nosql] nuster.query: string

Same as HAProxy `query` except that `nuster.query` can be used in both request and response stage.

# FAQ

## Cannot start: not in master-worker mode

Set `master-worker` in `global` section, or start `nuster` with `-W`.

## How to debug?

Start `nuster` with `-d`.

## How to cache POST request?

Enable `option http-buffer-request` and set `body` in cache rule `key`.

By default, the cache key does not include the body of the request, remember to put `body` in key field.

Note that the size of the request body must be smaller than `tune.bufsize - tune.maxrewrite - request_header_size`, which by default is `16384 - 1024 - request_header_size`.

Refer to **option http-buffer-request** and **tune.bufsize** section in [HAProxy configuration](doc/configuration.txt) for details.

Also, it might be a good idea to put it separately in a dedicated backend as the example does.

## How to restrict access?

You can use the powerful HAProxy ACL, something like this

```
acl network_allowed src 127.0.0.1
acl purge_method method PURGE
http-request deny if purge_method !network_allowed
```

## How to enable HTTP2

```
bind :443 ssl crt pub.pem alpn h2,http/1.1
```

# Example

```
global
    nuster manager on uri /_/nuster purge-method MYPURGE
    nuster cache on data-size 100m
    nuster nosql on data-size 100m
    master-worker # since v3
    # daemon
defaults
    retries 3
    option redispatch
    timeout client  30s
    timeout connect 30s
    timeout server  30s
frontend web1
    bind *:8080
    mode http
    acl pathPost path /search
    use_backend app1a if pathPost
    default_backend app1b
backend app1a
    balance roundrobin
    # mode must be http
    mode http

    # http-buffer-request must be enabled to cache post request
    option http-buffer-request

    acl pathPost path /search

    # enable cache for this proxy
    nuster cache

    # cache /search for 120 seconds. Only works when POST/PUT
    nuster rule rpost key method.scheme.host.uri.body ttl 120 if pathPost

    server s1 10.0.0.10:8080
backend app1b
    balance     roundrobin
    mode http

    nuster cache on

    # cache /a.jpg, not expire
    acl pathA path /a.jpg
    nuster rule r1 ttl 0 if pathA

    # cache /mypage, key contains cookie[userId], so it will be cached per user
    acl pathB path /mypage
    nuster rule r2 key method.scheme.host.path.delimiter.query.cookie_userId ttl 60 if pathB

    # cache /a.html if response's header[cache] is yes
    http-request set-var(txn.pathC) path
    acl pathC var(txn.pathC) -m str /a.html
    acl resHdrCache1 res.hdr(cache) yes
    nuster rule r3 if pathC resHdrCache1

    # cache /heavy for 100 seconds if be_conn greater than 10
    acl heavypage path /heavy
    acl tooFast be_conn ge 100
    nuster rule heavy ttl 100 if heavypage tooFast

    # cache all if response's header[asdf] is fdsa
    acl resHdrCache2 res.hdr(asdf)  fdsa
    nuster rule resCache ttl 0 if resHdrCache1

    server s1 10.0.0.10:8080

frontend web2
    bind *:8081
    mode http
    default_backend app2
backend app2
    balance     roundrobin
    mode http

    # disable cache on this proxy
    nuster cache off
    nuster rule all

    server s2 10.0.0.11:8080

frontend nosql_fe
    bind *:9090
    default_backend nosql_be
backend nosql_be
    nuster nosql on
    nuster rule r1 ttl 3600
```

# Contributing

* Join the development
* Give feedback
* Report issues
* Send pull requests
* Spread nuster

# License

Copyright (C) 2017-present, [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >

All rights reserved.

Licensed under GPL, the same as HAProxy

HAProxy and other sources license notices: see relevant individual files.
