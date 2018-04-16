Nuster, a web caching proxy server.


# Table of Contents

* [Introduction](#introduction)
* [Performance](#performance)
* [Setup](#setup)
  * [Download](#download)
  * [Build](#build)
  * [Start](#start)
  * [Docker](#docker)
* [Usage](#usage)
* [Directives](#directives)
  * [cache](#cache)
  * [filter cache](#filter-cache)
  * [cache-rule](#cache-rule)
* [Cache Management](#cache-management)
  * [Enable/Disable](#enable-and-disable-cache-rule)
  * [TTL](#ttl)
  * [Purging](#purge-cache)
* [Cache Stats](#cache-stats)
* [FAQ](#faq)
* [Example](#example)
* [Conventions](#conventions)
* [Contributing](#contributing)
* [TODO](#todo)
* [License](#license)

# Introduction

Nuster is a simple yet powerful web caching proxy server based on HAProxy.
It is 100% compatible with HAProxy, and takes full advantage of the ACL
functionality of HAProxy to provide fine-grained caching policy based on
the content of request, response or server status. Its features include:

 * All features of HAProxy are inherited, 100% compatible with HAProxy
 * Powerful dynamic cache ability
   * Based on HTTP method, URI, path, query, header, cookies, etc
   * Based on HTTP request or response contents, etc
   * Based on environment variables, server state, etc
   * Based on SSL version, SNI, etc
   * Based on connection rate, number, byte, etc
 * Extremely fast
 * Cache purging
 * Cache stats
 * Cache management
 * HTTPS supports on both frontend and backend
 * HTTP compression
 * HTTP rewriting and redirection

# Performance

Nuster is very fast, some test shows nuster is almost three times faster than
nginx when both using single core, and nearly two times faster than nginx and
three times faster than varnish when using all cores.

See [detailed benchmark](https://github.com/jiangwenyuan/nuster/wiki/Web-cache-server-performance-benchmark:-nuster-vs-nginx-vs-varnish-vs-squid)


# Setup

## Download

Download stable version from [releases](https://github.com/jiangwenyuan/nuster/releases) page
for production use, otherwise git clone the source code.

## Build

```
make TARGET=linux2628 USE_LUA=1 LUA_INC=/usr/include/lua5.3 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1
make install PREFIX=/usr/local/nuster
```

> use `USE_PTHREAD_PSHARED=1` to use pthread lib

> omit `USE_LUA=1 LUA_INC=/usr/include/lua5.3 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1` if unnecessary

See [HAProxy README](README) for details.

## Start

Create a config file called `nuster.conf` like [Example](#example), and

`/usr/local/nuster/sbin/nuster -f nuster.conf`

## Docker

```
docker pull nuster/nuster
docker run -d -v /path/to/nuster.cfg:/etc/nuster/nuster.cfg:ro -p 8080:8080 nuster/nuster
```

# Usage

Nuster is based on HAProxy, all directives from HAProxy are supported in nuster.

In order to use cache functionality, `cache on` should be declared in **global**
section and a cache filter along with some cache-rules should be added into
**backend** or **listen** section.

If `cache off` is declared or there is no `cache on|off` directive, nuster acts
just like HAProxy, as a TCP and HTTP load balancer.

# Directives

## global: nuster cache

**syntax:** nuster cache on|off [data-size size] [dict-size size] [purge-method method] [uri uri]

**default:** *none*

**context:** *global*

Determines whether to use cache or not.

A memory zone with a size of `data-size + dict-size` will be created. Except for
temporary data created and destroyed within request, all caches related data
including http response data, keys and overheads are stored in this memroy zone
and shared between all processes.

If no more memory can be allocated from this memory zone, new requests that should
be cached according to defined cache rules will not be cached unless some memory
are freed.

Temporary data are stored in a memory pool which allocates memory dynamically from
system in case there is no available memory in the pool.

A global internal counter monitors the memory usage of all http response data across
all processes, new requests will not be cached if the counter exceeds `data-size`.

### data-size

Determines the size of memory zone along with `dict-size`.

It accepts units like `m`, `M`, `g` and `G`. By default, the size is 1024 * 1024 bytes,
which is also the minimal size.

### dict-size

Determines the size of memory used by hash table.

It accepts units like `m`, `M`, `g` and `G`. By default, the size is 1024 * 1024 bytes,
which is also the minimal size.

Note that it only decides the memory used by hash table not keys. In fact, keys are
stored in memory zone which is limited by `data-size`.

**dict-size** is different from **number of keys**. New keys can still be added to hash
table even if the number of keys exceeds dict-size as long as there are enough memory.

Nevertheless it may lead to a performance drop if `number of keys` is greater than `dict-size`.

An approximate number of keys multiplied by 8 (normally) as `dict-size` should work.

### purge-method

Define a customized HTTP method with max length of 14 to purge cache, it is `PURGE` by default.

### uri

Enable cache manager/stats API and define the endpoint:

`nuster cache on uri /_my/_unique/_/_cache/_uri`

By default, the cache manager/stats is disabled. When it is enabled, remember to restrict the access(see FAQ).

See [Cache Management](#cache-management) and [Cache stats](#cache-stats) for details.

## proxy: nuster cache

**syntax:** nuster cache [on|off]

**default:** *on*

**context:** *backend*, *listen*

Determines whether or not use cache on this backend, additional `nuster rule` should be defined.
It can be turned off separately by including `off`.
If there are filters on this proxy, put this directive after all other filters.

## nuster rule

**syntax:** nuster rule name [key KEY] [ttl TTL] [code CODE] [if|unless condition]

**default:** *none*

**context:** *backend*, *listen*

Define cache rule. It is possible to declare multiple rules in the same section.
The order is important because the matching process stops on the first match.

```
acl pathA path /a.html
filter cache
cache-rule all ttl 3600
cache-rule path01 ttl 60 if pathA
```

cache-rule `path01` will never match because first rule will cache everything.

### name

Define a name for this cache-rule. It will be used in cache manager API, it does not
have to be unique, but it might be a good idea to make it unique. cache-rule with same
name are treated as one.

### key KEY

Define the key for cache, it takes a string combined by following keywords
with `.` separator:

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

By default the key is `method.scheme.host.uri`

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

So default key produces `GET.http.www.example.com./q?name=X&type=Y.`, and
`key method.scheme.host.path.header_ASDF.cookie_user.param_type` produces
`GET.http.www.example.com./q.Z.nuster.Y.`

If a request has the same key as a cached http response data, then cached
data will be sent to the client.

### ttl TTL

Set a TTL on key, after the TTL has expired, the key will be deleted.
It accepts units like `d`, `h`, `m` and `s`. Default ttl is `3600` seconds.
Set to `0` if you don't want to expire the key.

### code CODE1,CODE2...

Cache only if the response status code is CODE. By default, only 200 response
is cached. You can use `all` to cache all responses.

```
cache-rule only200
cache-rule 200and404 code 200,404
cache-rule all code all
```

### if|unless condition

Define when to cache using HAProxy ACL.
See **7. Using ACLs and fetching samples** section in [HAProxy configuration](doc/configuration.txt)

# Cache Management

Cache can be managed via a manager API which endpoints is defined by `uri` and can be accessed by making HTTP
requests along with some headers.

**Eanble and define the endpoint**

```
nuster cache on uri /nuster/cache
```

**Basic usage**

`curl -X POST -H "X: Y" http://127.0.0.1/nuster/cache`

**REMEMBER to enable access restriction**

## Enable and disable cache-rule

cache-rule can be disabled at run time through manager uri. Disabled cache-rule will not be processed, nor will the
cache created by that.

***headers***

| header | value           | description
| ------ | -----           | -----------
| state  | enable          | enable  cache-rule
|        | disable         | disable cache-rule
| name   | cache-rule NAME | the cache-rule to be enabled/disabled
|        | proxy NAME      | all cache-rules belong to proxy NAME
|        | *               | all cache-rules

Keep in mind that if name is not unique, **all** cache-rules with that name will be disabled/enabled.

***Examples***

* Disable cache-rule r1

  `curl -X POST -H "name: r1" -H "state: disable" http://127.0.0.1/nuster/cache`

* Disable all cache-rule defined in proxy app1b

  `curl -X POST -H "name: app1b" -H "state: disable" http://127.0.0.1/nuster/cache`

* Enable all cache-rule

  `curl -X POST -H "name: *" -H "state: enable" http://127.0.0.1/nuster/cache`

## TTL

Change the TTL. It only affects the TTL of the responses to be cached, **does not** update the TTL of existing caches.

***headers***

| header | value           | description
| ------ | -----           | -----------
| ttl    | new TTL         | see `ttl` in `cache-rule`
| name   | cache-rule NAME | the cache-rule to be changed
|        | proxy NAME      | all cache-rules belong to proxy NAME
|        | *               | all cache-rules

***Examples***

```
curl -X POST -H "name: r1" -H "ttl: 0" http://127.0.0.1/nuster/cache
curl -X POST -H "name: r2" -H "ttl: 2h" http://127.0.0.1/nuster/cache
```

## Update state and TTL

state and ttl can be updated at the same time

```
curl -X POST -H "name: r1" -H "ttl: 0" -H "state: enabled" http://127.0.0.1/nuster/cache
```

## Purge Cache

There are several ways to purge cache by making HTTP `PURGE` requests to the manager uri defined by `uri`.

You can define customized http method using `purge-method MYPURGE` other than the default `PURGE` in case
you need to forward `PURGE` to backend servers.

### Purge one specific url

This method deletes the specific url that is being requested, like this:

`curl -XPURGE https://127.0.0.1/imgs/test.jpg`

It creates a key of `GET.scheme.host.uri`, and deletes the cache with that key.

### Purge by name

Cache can be purged by making HTTP `PURGE`(or `purge-method`) requests to the manager uri along with a `name` HEADER.

***headers***

| header | value           | description
| ------ | -----           | -----------
| name   | cache-rule NAME | caches belong to cache-rule ${NAME} will be purged
|        | proxy NAME      | caches belong to proxy ${NAME}
|        | *               | all caches

***Examples***

```
# purge all caches
curl -X PURGE -H "name: *" http://127.0.0.1/nuster/cache
# purge all caches belong to proxy applb
curl -X PURGE -H "name: app1b" http://127.0.0.1/nuster/cache
# purge all caches belong to cache-rule r1
curl -X PURGE -H "name: r1" http://127.0.0.1/nuster/cache
```

### Purge by host

You can also purge cache by host, all caches belong to that host will be deleted:

***headers***

| header | value | description
| ------ | ----- | -----------
| x-host | HOST  | the ${HOST}

***Examples***

```
curl -X PURGE -H "x-host: 127.0.0.1:8080" http://127.0.0.1/nuster/cache
```

### Purge by path

By default, the query part is also used as cache key, so there will be multiple caches if the query differs.

For example, for cache-rule `cache-rule imgs if { path_beg /imgs/ }`, and request

```
curl https://127.0.0.1/imgs/test.jpg?w=120&h=120
curl https://127.0.0.1/imgs/test.jpg?w=180&h=180
```

There will be two cache objects since the default key contains query part.

In order to delete that, you can

***delete one by one in case you know all queries***

```
curl -XPURGE https://127.0.0.1/imgs/test.jpg?w=120&h=120
curl -XPURGE https://127.0.0.1/imgs/test.jpg?w=180&h=180
```

It does not work if you don't know all queries.

***use a customized key and delete once in case that the query part is irrelevant***

Define a key like `cache-rule imgs key method.scheme.host.path if { path_beg /imgs }`, in this way only one cache
will be created, and you can purge without query:

`curl -XPURGE https://127.0.0.1/imgs/test.jpg`

It does not work if the query part is required.

***delete by cache-rule NAME***

`curl -X PURGE -H "name: imgs" http://127.0.0.1/nuster/cache`

It does not work if the cache-rule is defined something like `cache-rule static if { path_beg /imgs/ /css/ }`.

This method provides a way to purge just by path:

***headers***

| header | value | description
| ------ | ----- | -----------
| path   | PATH  | caches with ${PATH} will be purged
| x-host | HOST  | and host is ${HOST}

***Examples***

```
#delete all caches which path is /imgs/test.jpg
curl -X PURGE -H "path: /imgs/test.jpg" http://127.0.0.1/nuster/cache
#delete all caches which path is /imgs/test.jpg and belongs to 127.0.0.1:8080
curl -X PURGE -H "path: /imgs/test.jpg" -H "x-host: 127.0.0.1:8080" http://127.0.0.1/nuster/cache
```

### Purge by regex

You can also purge cache by regex, the caches which path matches the regex will be deleted.

***headers***

| header | value | description
| ------ | ----- | -----------
| regex  | REGEX | caches which path matches with ${REGEX} will be purged
| x-host | HOST  | and host is ${HOST}

***Examples***

```
#delete all caches which path starts with /imgs and ends with .jpg
curl -X PURGE -H "regex: ^/imgs/.*\.jpg$" http://127.0.0.1/nuster/cache
#delete all caches which path starts with /imgs and ends with .jpg and belongs to 127.0.0.1:8080
curl -X PURGE -H "regex: ^/imgs/.*\.jpg$" -H "127.0.0.1:8080" http://127.0.0.1/nuster/cache
```

**PURGE CAUTION**

1. **ENABLE ACCESS RESTRICTION**

2. If there are mixed headers, use the precedence of `name`, `path & host`, `path`, `regex & host`, `regex`, `host`

   `curl -XPURGE -H "name: rule1" -H "path: /imgs/a.jpg"`: purge by name

3. If there are redundant headers, use the first occurrence

   `curl -XPURGE -H "name: rule1" -H "name: rule2"`: purge by `rule1`

4. `regex` is **NOT glob**

   For example, all jpg files under /imgs should be `^/imgs/.*\.jpg$` instead of `/imgs/*.jpg`

# Cache Stats

Cache stats can be accessed by making HTTP GET request to the endpoint defined by `uri`;

## Eanble and define the endpoint

```
nuster cache on uri /nuster/cache
```

## Usage

`curl http://127.0.0.1/nuster/cache`

## Output

* used\_mem:  The memory used for response, not include overheads.
* req\_total: Total request number handled by cache enabled backends, not include the requests handled by backends without cache enabled
* req\_hit:   Number of requests handled by cache
* req\_fetch: Fetched from backends
* req\_abort: Aborted when fetching from backends

Others are very straightforward.

# FAQ

## How to debug?

Set `debug` in `global` section, or start `nuster` with `-d`.

Cache related debug messages start with `[CACHE]`.

## How to cache POST request?

Enable `option http-buffer-request` and set `body` in cache-rule `key`.

By default, the cache key does not include the body of the request, remember to put
`body` in key field.

Note that the body of the request maybe incomplete, refer to **option http-buffer-request**
section in [HAProxy configuration](doc/configuration.txt) for details.

Also it might be a good idea to put it separately in a dedicated backend as example does.

## How to restrict access to PURGE?

You can use the powerful HAProxy acl, something like this

```
acl network_allowed src 127.0.0.1
acl purge_method method PURGE
http-request deny if purge_method !network_allowed
```

Note by default cache key contains `Host`, if you cache a request like `http://example.com/test`
and purge from localhost you need to specify `Host` header:

`curl -XPURGE -H "Host: example.com" http://127.0.0.1/test`

# Example

```
global
    nuster cache on data-size 100m
    #daemon
    ## to debug cache
    #debug
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

listen web3
    bind *:8082
    mode http

    nuster cache
    nuster rule everything

    server s3 10.0.0.12:8080

```

# Conventions

1. Files with same name: those with `.md` extension belong to Nuster, otherwise HAProxy

# Contributing

* Join the development
* Give feedback
* Report issues
* Send pull requests
* Spread nuster

# License

Copyright (C) 2017, [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >

All rights reserved.

Licensed under GPL, the same as HAProxy

HAProxy and other sources license notices: see relevant individual files.
