# nuster

[Wiki](https://github.com/jiangwenyuan/nuster/wiki) | [English](README.md) | [中文](README-CN.md) | [日本語](README-JP.md)

基于HAProxy的高性能HTTP缓存服务器和RESTful NoSQL缓存服务器。

> 中文版更新可能不及时，最新版请参照英文版[README.md](README.md)

# 目录

* [介绍](#介绍)
* [性能](#性能)
* [入门指南](#入门指南)
* [使用方法](#使用方法)
* [指令](#指令)
* [Cache](#cache)
* [NoSQL](#nosql)
* [管理](#管理)
  * [统计](#统计)
  * [开启关闭rule](#开启关闭rule)
  * [更新生存时间](#更新生存时间)
  * [清除](#清除)
* [Store](#store)
* [Sample fetches](#sample-fetches)
* [FAQ](#faq)

# 介绍

nuster是一个基于HAProxy的高性能HTTP缓存服务器和RESTful NoSQL缓存服务器，完全兼容HAProxy，并且利用HAProxy的ACL功能来提供非常细致的缓存规则。

## 特性

### HTTP/TCP负载均衡器

nuster可以作为HTTP/TCP负载均衡器使用。

* 继承了HAProxy的所有特性，完全兼容HAProxy
* 负载均衡
* 前端后端HTTPS
* HTTP压缩
* HTTP重写重定向
* HTTP信息增删改
* HTTP2
* 监控
* 粘性
* 访问控制
* 内容切换

### HTTP缓存服务器

nuster也可以用作类似Varnish或者Nginx那样的HTTP缓存服务器，来缓存动态或者静态的HTTP资源。

* HAProxy的所有特性(HTTPS, HTTP/2, ACL, etc)
* 非常快
* 强大的动态缓存功能
  * 基于HTTP method, URI, path, query, header, cookies, etc
  * 基于HTTP request or response contents, etc
  * 基于environment variables, server state, etc
  * 基于SSL version, SNI, etc
  * 基于connection rate, number, byte, etc
* 缓存管理
* 缓存清除
* 缓存统计信息
* 缓存生存时间
* 持久化

### RESTful NoSQL缓存服务器

nuster也可以用作RESTful NoSQL缓存服务器, 用HTTP `POST/GET/DELETE` 来 添加/取得/删除 Key/Value.

可以像Memcached或者Redis那样放在应用和数据库之间作为内部KV缓存使用，也可以放在用户和应用之间作为面向用户的NoSQL使用。
支持header, cookie等等，所以可以将不同的用户数据存到相同的路劲。

* HAProxy的所有特性(HTTPS, HTTP/2, ACL, etc)
* 有条件的缓存
* 内部KV缓存
* 面向用户缓存
* 支持任何类型的数据
* 支持所有编程语言，不需要特定的库，只需HTTP支持
* 持久化

# 性能

非常快, 单进程模式下是nginx的3倍，多进程下nginx的2倍，varnish的3倍。

详见[benchmark](https://github.com/jiangwenyuan/nuster/wiki/Performance-benchmark:-nuster-vs-nginx-vs-varnish)

# 入门指南

## 下载

生产环境的话从[Download](Download.md)下载最新稳定版, 其他情况可以git clone。

## 编译

```
make TARGET=linux-glibc USE_LUA=1 LUA_INC=/usr/include/lua5.3 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1
make install PREFIX=/usr/local/nuster
```

> 添加`USE_PTHREAD_PSHARED=1`使用pthread

> 如果不需要可以删除`USE_LUA=1 LUA_INC=/usr/include/lua5.3 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1`

具体可以参考[HAProxy INSTALL](INSTALL)。

## 配置文件

准备一个配置文件: `nuster.cfg`

```
global
    nuster cache on data-size 100m
    nuster nosql on data-size 200m
    master-worker # v3
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

nuster监听8080端口，接受HTTP请求。
`/_kv/`开头的请求分配到backend `be2`, 可以发送HTTP `POST/GET/DELETE`到`/_kv/any_key` 来 添加/取得/删除 Key/Value.
其他的请求都被分配到backend `be1`, 并且会被转发到服务器`s1` or `s2`. 其中`/img/*`请求会被缓存1天，而`/api/some/api`会被缓存30秒。

## 启动

`/usr/local/nuster/sbin/nuster -f nuster.cfg`

## Docker

```
docker pull nuster/nuster
docker run -d -v /path/to/nuster.cfg:/etc/nuster/nuster.cfg:ro -p 8080:8080 nuster/nuster
```

# 使用方法

nuster基于HAProxy, 支持所有的HAProxy指令。

## 基本

配置文件里有四个基本的`section`s: `global`, `defaults`, `frontend` and `backend`。

* global
  * 定义全局指令
  * 需要定义`nuster cache on` or `nuster nosql on`，否则cache和nosql无法使用
* defaults
  * 定义`frontend`, `backend`的默认参数
  * 可以在`frontend` or `backend` section重新定义
* frontend
  * 定义监听端口等等面向用户的设置
* bankend
  * 定义后端服务器等等设置
  * 需要设置`nuster cache on` or `nuster nosql on`, 否则该backend没有nosql或者nosql功能
  * 需要设置`nuster rule`

可以定义多个`frontend` or `backend` . 如果定义了`nuster cache|nosql off`或者没有`nuster cache|nosql on|off`, nuster就是一个HAProxy。

无法在`listen`里定义nuster。

具体参考`/doc`下的HAProxy文档, 或者[在线HAProxy文档](https://cbonte.github.io/haproxy-dconv/)

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
    default_backend be
backend be
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
    default_backend be
backend be
    nuster nosql on
    nuster rule r1 ttl 3600
```


# 指令

## global: nuster manager

**syntax:**

*nuster manager on|off [uri URI] [purge-method method]*

**default:** *off*

**context:** *global*

定义并开启manager/stats/purge API, uri 和 purge method。

默认是关闭的. 如果开启了，注意开启访问控制(see [FAQ](#how-to-restrict-access)).

具体请参考[管理](#管理).

### uri

自定义管理URI, 默认是 `/nuster`

### purge-method

自定义PURGE用的HTTP method，默认是 `PURGE`.

## global: nuster cache|nosql

**syntax:**

*nuster cache on|off [data-size size] [dict-size size] [dir DIR] [dict-cleaner n] [data-cleaner n] [disk-cleaner n] [disk-loader n] [disk-saver n] [clean-temp on|off] [always-check-disk on|off]*

*nuster nosql on|off [data-size size] [dict-size size] [dir DIR] [dict-cleaner n] [data-cleaner n] [disk-cleaner n] [disk-loader n] [disk-saver n] [clean-temp on|off] [always-check-disk on|off]*

**default:** *none*

**context:** *global*

控制是否开启cache或者nosql。

会分配一块`data-size + dict-size`的共享内存来存储HTTP头，数据，key等等，临时数据从系统内存池分配。
如果没有足够内存，新的请求不会被缓存直到有内存被释放。

### data-size

和`dict-size`一起决定内存块的大小。

可以使用`m`, `M`, `g` 和 `G`.  默认是1MB，同时也是最小值。

### dict-size

决定hash table的大小.

可以使用`m`, `M`, `g` 和 `G`.  默认是1MB，同时也是最小值。

这个决定hash table buckets的大小，并非key的大小，key存在共享内存中。

**dict-size(bucket数)** 不等于 **key数**. 就算key的数量超过了dict-size，只要整个共享内存有空间，新的key仍然可以被添加。

不过如果key数超过dict-size(bucket数)性能也许会下降. dict-size可以设为大概的最大key数乘以8。当然越大越好。

查看stats API:

```
dict.nosql.length:              131072
dict.nosql.used:                0
```

如果`dict.nosql.used` 比`dict.nosql.length`大，调高`dict-size`比较好。

> 将来版本会删除dict-size, 像第一版本那样自动伸缩

### dir

设置硬盘缓存文件的根目录，必须设置以开启硬盘缓存功能。

如果开启了chroot，则真实路径为chroot+dir。比如

```
chroot /data
nuster cache on dir /cache
```

那么缓存的实际存放目录为：/data/cache

### dict-cleaner

每次检查最多 `dict-cleaner` 个entry，无效的entry将被删除（默认1000）

### data-cleaner

每次检查最多 `data-cleaner` 个entry，无效的data将被删除（默认1000）

当无效data比例超过20%时，内部的清理机制会加速清理，所以不建议修改这个值。

### disk-cleaner

每次检查最多 `disk-cleaner` 个硬盘缓存文件，无效的文件将被删除（默认100）

### disk-loader

启动后每次加载最多 `disk-loader` 个硬盘缓存文件的信息到内存（默认100）

`USE_THREAD` 启用时, 会有一个单独的线程进行加载，这时忽略该参数。

### disk-saver

每次检查最多 `disk-saver` 个data，并将需要保存至硬盘的data保存到硬盘（默认100）

详细请参考[Store](#disk).

### clean-temp on|off

`dir`定义的目录下会自动创建一个`.tmp`的目录来存储临时文件。

该选项定义是否在启动时删除该目录下的临时文件。默认是off。

### always-check-disk on|off

定义是否总是检查硬盘有无缓存文件，特别是硬盘被多个实例共享时有可能缓存不能命中。

默认是off。

## proxy: nuster cache|nosql

**syntax:**

*nuster cache [on|off]*

*nuster nosql [on|off]*

**default:** *on*

**context:** *backend*

决定是否在这个backend开启cache/nosql。
如果这个section有filter，记得放在最后。

## proxy: nuster rule

**syntax:**

*nuster rule name [key KEY] [ttl auto|TTL] [extend EXTEND] [wait on|off|TIME] [use-stale on|off|TIME] [inactive off|TIME] [code CODE] [memory on|off] [disk on|off|sync] [etag on|off] [last-modified on|off] [if|unless condition]*

**default:** *none*

**context:** *backend*

定义cache/nosql的生效条件，需要定义至少一个rule。

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

可以定义多个rule，按定义顺序先后匹配。

```
acl pathA path /a.html
nuster cache on
nuster rule all ttl 3600
nuster rule path01 ttl 60 if pathA
```

rule `path01`永远不会被匹配。

### name

定义rule的name。 v5开始必须全局唯一。

### key KEY

定义cache/nosql的key, 由下列关键字加`.`组成

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

CACHE的默认key是 `method.scheme.host.uri`, NoSQL的默认key是 `GET.scheme.host.uri`.

Example

```
GET http://www.example.com/q?name=X&type=Y

http header:
GET /q?name=X&type=Y HTTP/1.1
Host: www.example.com
ASDF: Z
Cookie: logged_in=yes; user=nuster;
```

生成:

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

默认key产生`GET\0http\0www.example.com\0/q?name=X&type=Y\0`, 而`key method.scheme.host.path.header_ASDF.cookie_user.param_type` 则生成 `GET\0http\0www.example.com\0/q\0Z\0nuster\0Y\0`.

> `\0`是NULL字符

相同key的请求则会直接返回cache给客户端。

### ttl auto|TTL

设置缓存生存时间，过期后缓存会被删除。 可以使用 `d`, `h`, `m` and `s`。默认`0`秒.
如果不希望失效则设为0

当使用`auto`时, ttl自动使用`cache-control` header的`s-maxage` 或者`max-age`的值。

> `cache-control`的其他指令没有处理。

ttl最大值2147483647.

可以通过设置 `extend` 关键词来自动延长缓存的ttl。

### extend EXTEND

自动延长缓存ttl。

#### 格式

extend on|off|n1,n2,n3,n4

默认: off.

n1,n2,n3,n4: 小于100的正整数, n1 + n2 + n3之和也小于100. 他们定义四个时间段：

```
time:       0                                                       ttl         ttl * (1 + n4%)
access:     |            A1             |   A2    |   A3    |   A4    |         |
            |---------------------------|---------|---------|---------|---------|
percentage: |<- (100 - n1 - n2 - n3)% ->|<- n1% ->|<- n2% ->|<- n3% ->|<- n4% ->|
```

满足下列条件缓存的ttl将被延长:

1. A4 > A3 > A2
2. 在 `ttl` 和 `ttl * (1 + n4%)` 之间有新的请求

> `on` 其实是33,33,33,33

### wait on|off|TIME [cache only]

如果同时有相同的请求时是否等待缓存完成。`wait on`表示等待直到其他请求完成缓存，`wait TIME`表示等待TIME秒后缓存还没完成的话则转发到后端服务器。

默认不会等待，相同的请求都被转发到后端，第一个请求会生成缓存(`wait off`)。

注意只有当第一个请求完成某些初始化工作后其他的请求才会等待。

> nosql模式下不会等待，相同的请求将被依次处理，最后一个请求的内容将被保存。

最大值2147483647.

### use-stale on|off|TIME [cache only]

决定是否在更新缓存时是否使用过期的缓存，以及在后端宕机时是否使用过期缓存。

当use-stale on时，在更新缓存时使用过期缓存。

当use-stale off时，如果`wait off` 那么相同的请求将被传递到后端服务器否则等待。

`use-stale TIME`则允许在因后端服务器宕机而导致更新缓存失败后继续使用缓存TIME秒。

最大值2147483647.

### inactive off|TIME

当TIME秒内没有被访问过，则删除该缓存。默认为off。

注意在TIME秒没被访问后缓存并不是百分百会删除。如果清理进程先于新的请求访问该缓存，那么缓存会被删除。如果新的请求先于清理进程访问该缓存，那么该缓存的最后访问时间就会被更新该缓存也不会被删除。并没有使用硬盘缓存文件的访问时间，当重启nuster后，缓存的最后访问时间会被设置为缓存被加载的时间。

最大值：2147483647.

### code CODE1,CODE2...

默认只缓存200的响应，如果需要缓存其他的则可以添加，`all`会缓存任何状态码。

```
cache-rule only200
cache-rule 200and404 code 200,404
cache-rule all code all
```

### memory on|off

是否保存数据到内存，默认on。

详见[Store](#Store)

### disk on|off|sync

是否保存数据到硬盘，已经如何保存，默认off

需要设置`memory on` 以使用 `disk sync`

详见[Store](#Store)

### etag on|off

定义是否处理etag条件请求. 如果没有 `ETag` 则添加。

默认off.

### last-modified on|off

定义是否处理last-modified条件请求. 如果没有 `Last-Modified` 则添加.

默认off.

### if|unless condition

定义ACL条件

ACL分别在请求阶段和响应阶段执行。

当下述条件满足时，会进行缓存：

1. 在请求阶段ACL为真
2. 请求阶段ACL为假，但是响应阶段ACL为真

**当使用否定的ACL或者某些样本获取方法时，需要特别注意**

比如

1.  缓存以`/img/`开头的请求

    nuster rule img if { path_beg /img/ }

请求阶段要么为真要么为假，因为在响应阶段无法获取path所以永远为假。

2. 缓存响应的http头部`Content-Type` 为 `image/jpeg`

    nuster rule jpeg if { res.hdr(Content-Type) image/jpeg }

因为在请求阶段无法获取res.hdr所以永远为假，在响应阶段要么为真要么为假。

3. 以`/img/`开头，并且响应头 `Content-Type` 为`image/jpeg`时缓存

如果定义为下面的规则，则不会成功：

    nuster rule img if { path_beg /img/ } { res.hdr(Content-Type) image/jpeg }

因为在响应阶段无法获取path所以永远为假，而在请求阶段无法获取res.hdr所以永远为假，那么这个ACL就永远无法匹配。

需要如下来定义：

    http-request set-var(txn.pathImg) path
    acl pathImg var(txn.pathImg) -m beg /img/
    acl resHdrCT res.hdr(Content-Type) image/jpeg
    nuster rule r3 if pathImg resHdrCT

或者`nuster.path`(v5):

    nuster rule r3 if { nuster.path -m beg /img } { res.hdr(Content-Type) image/jpeg }

4. 另一个例子，缓存所有不以 `/api/` 开头的请求

下面不正确：

    acl NoCache path_beg /api/
    nuster rule r3 if !NoCache

因为虽然在响应阶段path并不存在，所以NoCache永远为假，而 `!NoCache` 为真，所有的请求都会被缓存。

需要改成:

    http-request set-var(txn.path) path
    acl NoCache var(txn.path) -m beg /api/
    nuster rule r1 if !NoCache

新sample fetch详见[Sample fetches](#sample-fetch)

详见[HAProxy configuration](doc/configuration.txt)的**7. Using ACLs and fetching samples**

# Cache

nuster也可以用作类似Varnish或者Nginx那样的HTTP缓存服务器，来缓存动态或者静态的HTTP资源。
出了HAProxy的SSL, HTTP, HTTP2, 重写重定向，增删改Header等等，还提供了下面的功能。

```
global
    nuster cache on data-size 200m
frontend fe
    bind *:8080
    default_backend be
backend be
    nuster cache on
    nuster rule r1 if { path /a1 }
    nuster rule r2 key method.scheme.host.path.delimiter.query.cookie_userId if { path /a2 }
    nuster rule r3 ttl 10 if { path /a3 }
    nuster rule r4 disk on if { path /a4 }

    server s1 127.0.0.1:8081
```

nuster会依次检查rule, 先生成key然后查找，如果找到则返回缓存，否则就测试ACL, 如果ACL通过则缓存响应。

# NoSQL

nuster也可以用作RESTful NoSQL缓存服务器, 用HTTP `POST/GET/DELETE` 来 添加/取得/删除 Key/Value.

## 基本操作

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
  * POST/GET: 成功
  * DELETE: 总是
* 400 Bad request
  * 空值
  * 不正确的acl, rules, etc
* 404 Not Found
  * POST: rule tests失败
  * GET: not found
* 405 Method Not Allowed
  * 其他的methods
* 500 Internal Server Error
  * 发生未知错误
* 507 Insufficient Storage
  * 超过data-size

## Headers

Supported headers in request

| Name          | value                   | description
| ------        | -----                   | -----------
| content-type  | any   		  | Will be returned as is in GET request
| cache-control | `s-maxage` or `max-age` | used to set ttl when rule.ttl is `auto`

## 分用户的data

通过在key里加入header, cookie等等，可以将不同的用户数据存到相同的路劲。

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

## 客户端

支持任何支持HTTP的客户端，库: `curl`, `postman`, python `requests`, go `net/http`, etc.

# 管理

可以通过`uri`定义一个endpoint并发送HTTP请求来进行管理。

**定义并且开启**

```
nuster manager on uri /internal/nuster purge-method PURGEX
```

## 方法一览

| METHOD | Endpoint         | description
| ------ | --------         | -----------
| GET    | /internal/nuster | 获得stats
| POST   | /internal/nuster | 开启关闭rule, 更新ttl
| DELETE | /internal/nuster | 高级Purge
| PURGEX | /any/real/path   | 基础Purge

## 统计

可以通过GET `uri`定义的endpoint来获取统计信息。

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
dict.cache.size:                1048576
dict.cache.length:              131072
dict.cache.used:                0
dict.cache.cleanup_idx:         0
dict.cache.sync_idx:            0
dict.nosql.size:                1048576
dict.nosql.length:              131072
dict.nosql.used:                0
dict.nosql.cleanup_idx:         0
dict.nosql.sync_idx:            0

**STORE MEMORY**
store.memory.cache.size:        2098200576
store.memory.cache.used:        1048960
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
stats.cache.total:              0
stats.cache.hit:                0
stats.cache.fetch:              0
stats.cache.bypass:             0
stats.cache.abort:              0
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

## 开启关闭rule

rule可以通过manager uri动态开启关闭，关闭的rule不会再进行匹配。

***headers***

| header | value       | description
| ------ | -----       | -----------
| state  | enable      | enable  rule
|        | disable     | disable rule
| name   | rule NAME   | the rule to be enabled/disabled
|        | proxy NAME  | all rules of proxy NAME
|        | *           | all rules

相同name的rule都会被开启关闭。

***Examples***

* 关闭rule r1

  `curl -X POST -H "name: r1" -H "state: disable" http://127.0.0.1/nuster`

* 关闭backend app1b的所有rule

  `curl -X POST -H "name: app1b" -H "state: disable" http://127.0.0.1/nuster`

* 开启所有的rule

  `curl -X POST -H "name: *" -H "state: enable" http://127.0.0.1/nuster`

## 更新生存时间

更改TTL，只会影响后续的新缓存，不会影响已经存在的缓存。

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

### 同时设置state和ttl

同时设置state和ttl

```
curl -X POST -H "name: r1" -H "ttl: 0" -H "state: enabled" http://127.0.0.1/nuster
```

## 清除

有两种清除模式:

* 基础Purge: 发送 `purge-method MYPURGE` 定义的方法到想要删除的Path
* 高级Purge: 发送DELETE 到manager uri

### 基础Purge: 删除一个特定URL

`curl -XPURGE http://127.0.0.1/imgs/test.jpg`

根据rule生成key并删除那个key。只对GET请求生成的缓存有效。

默认key 包含`Host`, 如果缓存时用了`http://example.com/test` 而在localhost删除是需要`Host` header:

`curl -XPURGE -H "Host: example.com" http://127.0.0.1/test`

对cache和nosql都有效，nosql模式相当于 `DELETE`。

### 高级Purge: 通过name删除

可以通过带上`name` header来 `PURGE`

***headers***

| header | value            | description
| ------ | -----            | -----------
| name   | nuster rule NAME | caches of rule ${NAME} will be purged
|        | proxy NAME       | caches of proxy ${NAME}
|        | *                | all caches

***Examples***

```
# 删除所有缓存
curl -X DELETE -H "name: *" http://127.0.0.1/nuster
# 删除backend applb的所有缓存
curl -X DELETE -H "name: app1b" http://127.0.0.1/nuster
# 删除所有rule r1生成的缓存
curl -X DELETE -H "name: r1" http://127.0.0.1/nuster
```

### 高级Purge: 通过host删除

通过带上`nuster-host`header来删除所有属于这个host的缓存。

***headers***

| header      | value        | description
| ------      | -----        | -----------
| host        | HOST         | the ${HOST}
| nuster-host | HOST         | nuster-host存在则使用nuster-host
| mode        | cache, nosql | purge cache or nosql data

***Examples***

```
curl -X DELETE -H "nuster-host: 127.0.0.1:8080" http://127.0.0.1/nuster
```

### 高级Purge: 通过path删除

默认情况下，query部分也包含在key中，所以相同的path不同的query会产生不同的缓存。

比如`nuster rule imgs if { path_beg /imgs/ }`, 然后请求

```
curl http://127.0.0.1/imgs/test.jpg?w=120&h=120
curl http://127.0.0.1/imgs/test.jpg?w=180&h=180
```

会生成两个缓存，因为query不一样。

如果要删除这些缓存，可以

***如果知道所有的query，那么可以一个一个删除***

```
curl -XPURGE http://127.0.0.1/imgs/test.jpg?w=120&h=120
curl -XPURGE http://127.0.0.1/imgs/test.jpg?w=180&h=180
```

大多数情况下不知道所有的query

***如果query部分不重要，则可以从key里面删除query***

定义`nuster rule imgs key method.scheme.host.path if { path_beg /imgs }`, 这样的话只会生成一个缓存，那么就可以不用query删除缓存

`curl -XPURGE http://127.0.0.1/imgs/test.jpg`

大多数情况需要query

***通过rule name删除***

`curl -X PURGE -H "name: imgs" http://127.0.0.1/nuster/cache`

但是如果rule被定义成了 `nuster rule static if { path_beg /imgs/ /css/ }`，则无法只删除imgs

因此，可以通过path删除

***headers***

| header      | value        | description
| ------      | -----        | -----------
| path        | PATH         | caches with ${PATH} will be purged
| host        | HOST         | and host is ${HOST}
| nuster-host | HOST         | nuster-host has higher precedence over host
| mode        | cache, nosql | purge cache or nosql data

***Examples***

```
# 删除所有path是/imgs/test.jpg的缓存
curl -X DELETE -H "path: /imgs/test.jpg" http://127.0.0.1/nuster
# 删除所有path是/imgs/test.jpg 并且host是127.0.0.1:8080的缓存
curl -X DELETE -H "path: /imgs/test.jpg" -H "nuster-host: 127.0.0.1:8080" http://127.0.0.1/nuster
```

### 高级Purge: 通过正则删除

也可以通过正则删除，所有匹配正则的缓存将被删除。

***headers***

| header      | value        | description
| ------      | -----        | -----------
| regex       | REGEX        | caches which path match with ${REGEX} will be purged
| host 	      | HOST         | and host is ${HOST}
| nuster-host | HOST         | nuster-host has higher precedence over host
| mode        | cache, nosql | purge cache or nosql data

***Examples***

```
# 删除所有 /imgs 开头 .jpg结尾的缓存
curl -X DELETE -H "regex: ^/imgs/.*\.jpg$" http://127.0.0.1/nuster
#delete all caches which path starts with /imgs and ends with .jpg and with host of 127.0.0.1:8080
curl -X DELETE -H "regex: ^/imgs/.*\.jpg$" -H "127.0.0.1:8080" http://127.0.0.1/nuster
```

**PURGE 注意事项**

1. **开启访问控制**

2. 如果有多个header，按照`name`, `path & host`, `path`, `regex & host`, `regex`, `host`的顺序处理

   `curl -X DELETE -H "name: rule1" -H "path: /imgs/a.jpg"`: purge by name

3. 如果有重复的header，处理第一个

   `curl -X DELETE -H "name: rule1" -H "name: rule2"`: purge by `rule1`

4. `regex` **不是 glob**

   比如 /imgs下的.jpg文件是`^/imgs/.*\.jpg$` 而不是 `/imgs/*.jpg`

5. 只有disk load结束后才能通过proxy name or rule name or host or path or regex 来删除缓存文件。是否已经load结束可以查看stats URL。

# Store

Nuster(cache和nosql) 支持多种后端存储. 目前支持memory和disk。计划添加其他后段。

## Memory

数据被存在一个大小由`data-size`定义的内存区域。重启后数据会消失。

## Disk

数据被存到硬盘由`dir`定义的目录下。重启后数据不会消失。

有三种模式:

* off:   默认，不保存到硬盘
* on:    保存到硬盘
* sync:  需要设置`memory on`。先保存至内存然后由master进程在一定时间后同步到硬盘，每次同步`dict-saver`个缓存。

# Sample fetches

Nuster 加入了一些新的sample fetches

## [cache] nuster.cache.hit: boolean

表示是否是HIT缓存，可以像如下使用

    http-response set-header x-cache hit if { nuster.cache.hit }

## [cache|nosql] nuster.host: string

类似HAProxy的 `req.hdr(Host)`，但是请求和响应中都可使用

## [cache|nosql] nuster.uri: string

等同于HAProxy的`capture.req.uri`.

## [cache|nosql] nuster.path: string

类似HAProxy的 `path`，但是请求和响应中都可使用

## [cache|nosql] nuster.query: string

类似HAProxy的 `query`，但是请求和响应中都可使用

# FAQ

## 无法启动，报错: not in master-worker mode

在`global` 添加 `master-worker` 或者启动时使用`-W`参数。

## 如何调试?

带`-d`启动`nuster`

nuster相关的调试信息以`[nuster`开头

## 如何缓存POST请求?

添加`option http-buffer-request`

如果自定义了key的话需要使用`body`关键字

请求body可能不完整，详见[HAProxy configuration](doc/configuration.txt) 的 **option http-buffer-request**小节

另外可以为post请求单独设置一个后端

## 如何做访问控制?

类似

```
acl network_allowed src 127.0.0.1
acl purge_method method PURGE
http-request deny if purge_method !network_allowed
```

## 如何开启HTTP2?

```
bind :443 ssl crt pub.pem alpn h2,http/1.1
```

# Example

```
global
    nuster cache on data-size 100m
    nuster nosql on data-size 100m
    master-worker # v3
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
