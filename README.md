Nuster, a web caching proxy server.


Introduction
============

Nuster is a simple yet powerful web caching proxy server based on HAProxy.
It is 100% compatible with HAProxy, and takes full advantage of the ACL
functionality of HAProxy to provide fine-grained caching policy based on
the content of request, response or server status, such as,

 * request url: cache only if the request url equals to X
 * request query: cache only if the request query contains X and equls to Y
 * response header: cache only if the response contains header X equals to Y
 * rate: cache only if the request rate is greater than X
 * etc


Performance
===========

Nuster is very fast, some test shows nuster is almost three times faster than 
nginx when both using single core, and nearly two times faster than nginx and
three times faster than varnish when using all cores.

See [detailed benchmark](Benchmark.md)


Installation
============

```
make TARGET=linux2628
make install
```

See [HAProxy README](README) for details.


Usage
=====

`cache on` should be declared in **global** section and a cache filter along
with some cache-rules should be added into **backend** or **listen** section.

Directives
==========

cache
-----

**syntax:** cache on|off [data-size size]

**default:** *none*

**context:** *global*

Determines whether to use cache or not.
To limit the maximum memory usage of cached http response data, set **data-size**
which accepts units like `m`, `M`, `g` and `G`. By default, the size is
1024 * 1024 bytes, which is also the minimal size.
Note that overheads used by cache are not included in it, only http response data.

filter cache
------------

**syntax:** filter cache [on|off]

**default:** *on*

**context:** *backend*, *listen*

Define a cache filter, additional `cache-rule` should be defined. It can be
turned off separately by including `off`.
If there are multiple filters, make sure that cache filter is put after
all other filters.

cache-rule
----------

**syntax:** cache-rule name [key KEY] [ttl TTL] [code CODE] [if|unless condition]

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

Define a name for this cache-rule.

### key KEY

Define the key for cache, it takes a string combined by following keywords
with `.` separator:

 * method:       http method, GET/POST...
 * scheme:       http or https
 * host:         the host in the request
 * path:         the URL path of the request
 * query:        the whole query string of the request
 * header\_NAME: the value of header `NAME`
 * cookie\_NAME: the value of cookie `NAME`
 * param\_NAME:  the value of query `NAME`
 * body:         the body of the request

By default the key is `method.scheme.host.path.query.body`

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
 * path:         /q
 * query:        name=X&type=Y
 * header\_ASDF: Z
 * cookie\_user: nuster
 * param\_type:  Y
 * body:         (empty)

So default key produces `GEThttpwww.example.com/qname=X&type=Y`, and
`key method.scheme.host.path.header_ASDF.cookie_user.param_type` produces
`GEThttpwww.example.com/qZnusterY`

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

FAQ
===

How to debug?
------------------------
Set `debug` in `global` section, or start `haproxy` with `-d`.

Cache related debug messages start with `[CACHE]`.

How to cache POST request?
------------------------
Enable `option http-buffer-request`.

By default, the cache key includes the body of the request, remember to put
`body` in key field if you use a customized key.

Note that the body of the request maybe incomplete, refer to **option http-buffer-request**
section in [HAProxy configuration](doc/configuration.txt) for details.

Also it might be a good idea to put it separately in a dedicated backend as example does.

Example
=======

```
global
    cache on data-size 100m
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
    filter cache

    # cache /search for 120 seconds. Only works when POST/PUT
    cache-rule rpost ttl 120 if pathPost

    server s1 10.0.0.10:8080
backend app1b
    balance     roundrobin
    mode http

    filter cache on

    # cache /a.jpg, not expire
    acl pathA path /a.jpg
    cache-rule r1 ttl 0 if pathA

    # cache /mypage, key contains cookie[userId], so it will be cached per user
    acl pathB path /mypage
    cache-rule r2 key method.scheme.host.path.query.cookie_userId ttl 60 if pathB

    # cache /a.html if response's header[cache] is yes
    http-request set-var(txn.pathC) path
    acl pathC var(txn.pathC) -m str /a.html
    acl resHdrCache1 res.hdr(cache) yes
    cache-rule r3 if pathC resHdrCache1

    # cache /heavy for 100 seconds if be_conn greater than 10
    acl heavypage path /heavy
    acl tooFast be_conn ge 100
    cache-rule heavy ttl 100 if heavypage tooFast 

    # cache all if response's header[asdf] is fdsa
    acl resHdrCache2 res.hdr(asdf)  fdsa
    cache-rule resCache ttl 0 if resHdrCache1

    server s1 10.0.0.10:8080

frontend web2
    bind *:8081
    mode http
    default_backend app2
backend app2
    balance     roundrobin
    mode http

    # disable cache on this proxy
    filter cache off
    cache-rule all

    server s2 10.0.0.11:8080

listen web3
    bind *:8082
    mode http

    filter cache
    cache-rule everything

    server s3 10.0.0.12:8080

```

Conventions
===========

1. Files with same name: those with `.md` extension belong to Nuster, otherwise HAProxy

License
=======

Copyright (C) 2017, [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >

All rights reserved.

Licensed under GPL, the same as HAProxy

HAProxy and other sources license notices: see relevant individual files.
