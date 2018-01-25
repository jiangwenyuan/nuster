Nuster是一个基于HAProxy的高性能缓存服务器


中文版更新可能不及时，最新版请参照英文版[README.md](README.md)

介绍
====

Nuster是一个基于HAProxy的高性能缓存服务器。Nuster完全兼容HAProxy，并且利用
HAProxy的ACL功能来提供非常细致的缓存规则，比如

 * 请求地址为某某时缓存
 * 请求参数中的X为Y时缓存
 * 响应头中的X为Y时缓存
 * 请求速率超过多少时缓存
 * 等等


性能
====

非常快, 单进程模式下是nginx的3倍，多进程下nginx的2倍，varnish的3倍。

详见[benchmark](https://github.com/jiangwenyuan/nuster/wiki/Performance-benchmark:-nuster-vs-nginx-vs-varnish)


安装
====

```
make TARGET=linux2628
make install
```

具体参照[HAProxy README](README)


使用方法
=======

在**global**中添加`cache on`, 然后在**backend**或**listen**中添加cache filter和cache rule

指令
====

cache
-----

**syntax:** cache on|off [data-size size]

**default:** *none*

**context:** *global*

控制是否开启缓存。
可以设置**data-size**来控制缓存数据的内存使用量。可以使用`m`, `M`, `g` 和 `G`.
默认是1MB，同时也是最小使用量。只有http内容计算在内，并不包括使用缓存带来的内存开销。

filter cache
------------

**syntax:** filter cache [on|off]

**default:** *on*

**context:** *backend*, *listen*

定义一个cache filter, 另外`cache-rule`也需要添加。 
可以为多个代理添加，并单独设置某个代理的缓存是否开启。
如果定义了多个filter，需要把cache filter放在最后。

cache-rule
----------

**syntax:** cache-rule name [key KEY] [ttl TTL] [code CODE] [if|unless condition]

**default:** *none*

**context:** *backend*, *listen*

定义缓存规则。可以同时定义多个，但是需要注意顺序，匹配则会停止测试。

```
acl pathA path /a.html
filter cache
cache-rule all ttl 3600
cache-rule path01 ttl 60 if pathA
```

`path01`这条规则永远不会执行，因为all会匹配所有的规则。

### name

定义一个名字。

### key KEY

定义key，由以下关键字组成：

 * method:       http method, GET/POST...
 * scheme:       http or https
 * host:         the host in the request
 * path:         the URL path of the request
 * query:        the whole query string of the request
 * header\_NAME: the value of header `NAME`
 * cookie\_NAME: the value of cookie `NAME`
 * param\_NAME:  the value of query `NAME`
 * body:         the body of the request

默认key是`method.scheme.host.path.query.body`

Example

```
GET http://www.example.com/q?name=X&type=Y

http header:
GET /q?name=X&type=Y HTTP/1.1
Host: www.example.com
ASDF: Z
Cookie: logged_in=yes; user=nuster;
```

会得到:

 * method:       GET
 * scheme:       http
 * host:         www.example.com
 * path:         /q
 * query:        name=X&type=Y
 * header\_ASDF: Z
 * cookie\_user: nuster
 * param\_type:  Y
 * body:         (empty)

所以默认的key就会得到`GEThttpwww.example.com/qname=X&type=Y`, 而
`key method.scheme.host.path.header_ASDF.cookie_user.param_type`则会生成
`GEThttpwww.example.com/qZnusterY`

一个请求的key能在缓存中找到则返回缓存内容。

### ttl TTL

定义key的失效时间，可以使用 `d`, `h`, `m` and `s`。默认`3600`秒.
如果不希望失效则设为0

### code CODE1,CODE2...

默认只缓存200的响应，如果需要缓存其他的则可以添加，`all`会缓存任何状态码。

```
cache-rule only200
cache-rule 200and404 code 200,404
cache-rule all code all
```

### if|unless condition

定义ACL条件
详见[HAProxy configuration](doc/configuration.txt)的**7. Using ACLs and fetching samples** 

FAQ
===

如何调试?
------------------------
在`global`添加`debug`， 或者带`-d`启动`haproxy`

缓存相关的调试信息以`[CACHE]`开头

如何缓存POST请求?
------------------------
添加`option http-buffer-request`

如果自定义了key的话需要使用`body`关键字

请求body可能不完整，详见[HAProxy configuration](doc/configuration.txt) 的
**option http-buffer-request**小节

另外可以为post请求单独设置一个后端

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

约定
====

1. 有相同文件名时，Nuster使用以`.md`结尾的文档

License
=======

Copyright (C) 2017, [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >

All rights reserved.

Licensed under GPL, the same as HAProxy

HAProxy and other sources license notices: see relevant individual files.
