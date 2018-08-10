Nusterは高速なキャッシュサーバー。

最近版は英語の[README.md](README.md)　を参照ください

紹介
====

NusterはHAProxyを元に開発したキャッシュサーバーで、HAProxyと互換性がある。
そしてHAProxyのACLを利用して細かいキャッシュルールを定義できる。

 * request url: request urlがXの時キャッシュする
 * request query: request queryのXがYの時キャッシュする
 * response header: response headerのXがYの時キャッシュする
 * rate: リクエスト率がXを超えた場合キャッシュする
 * など


性能
===========

スーパー早い

シングルコアでnginxより3倍、マルチコアでnginxより2倍varnishより3倍のテスト結果
があった。

詳細は[benchmark](https://github.com/jiangwenyuan/nuster/wiki/Performance-benchmark:-nuster-vs-nginx-vs-varnish)

インストール
============

```
make TARGET=linux2628
make install
```

[HAProxy README](README)参照 


使い方
=====

**global**セクションに`cache on`を定義して、**backend**セクションに
cache filterとcache-rulesも定義する 

ディレクティブ
=============

cache
-----

**syntax:** cache on|off [data-size size]

**default:** *none*

**context:** *global*

キャッシュを使うかどうかを決める。

単位`m`, `M`, `g` and `G`で**data-size**で最大キャッシュサイズが設定できる。

ディフォルトは1MBで、最小値も1MBである。 リスポンス内容だけが計算される。

filter cache
------------

**syntax:** filter cache [on|off]

**default:** *on*

**context:** *backend*

cache filterを定義する。 `cache-rule` も定義する必要がある。

on,offで単独でコントロールできる。

複数のfilterがある場合、cache filterは最後におくこと。

cache-rule
----------

**syntax:** cache-rule name [key KEY] [ttl TTL] [code CODE] [if|unless condition]

**default:** *none*

**context:** *backend*

cache ruleを定義する。複数のルールがある場合は順序を注意して定義すること。
マッチングできたら止まるので。

```
acl pathA path /a.html
filter cache
cache-rule all ttl 3600
cache-rule path01 ttl 60 if pathA
```

allが全てのリクエストをキャッシュしたので、`path01`は実行されない

### name

名前を定義する

### key KEY

下記のキーワードで`.`で繋いでkeyを定義する。

 * method:       http method, GET/POST...
 * scheme:       http or https
 * host:         the host in the request
 * path:         the URL path of the request
 * query:        the whole query string of the request
 * header\_NAME: the value of header `NAME`
 * cookie\_NAME: the value of cookie `NAME`
 * param\_NAME:  the value of query `NAME`
 * body:         the body of the request

ディフォルトkeyは`method.scheme.host.path.query.body`

Example

```
GET http://www.example.com/q?name=X&type=Y

http header:
GET /q?name=X&type=Y HTTP/1.1
Host: www.example.com
ASDF: Z
Cookie: logged_in=yes; user=nuster;
```

下記を生成する:

 * method:       GET
 * scheme:       http
 * host:         www.example.com
 * path:         /q
 * query:        name=X&type=Y
 * header\_ASDF: Z
 * cookie\_user: nuster
 * param\_type:  Y
 * body:         (empty)

ので、ディフォルトkeyは`GEThttpwww.example.com/qname=X&type=Y`で、
`key method.scheme.host.path.header_ASDF.cookie_user.param_type`は
`GEThttpwww.example.com/qZnusterY`になる。

キャッシュにリクエストと同じなkeyがあったら、キャッシュを返す。

### ttl TTL

生存期限を定義する。単位は `d`, `h`, `m`と`s`で、 ディフォルトは`3600`秒。
`0`の場合は失効しない。 

### code CODE1,CODE2...

ディフォルトは200のリスポンスしかキャッシュしない、ほかのものをキャッシュしたい場合は
定義する。 `all`の場合は全てキャッシュする。

```
cache-rule only200
cache-rule 200and404 code 200,404
cache-rule all code all
```

### if|unless condition

HAProxy ACLを使う。
See **7. Using ACLs and fetching samples** section in [HAProxy configuration](doc/configuration.txt)

FAQ
===

debug方法?
------------------------
`global`に`debug`を設定か, `haproxy`を`-d`で起動する。

キャッシュに関するメッセージは`[CACHE]`を含む。

どうやってPOSTリクエストをキャッシュする?
------------------------
`option http-buffer-request`を設定

カスタマイズしたkeyは`body`を入れること。

POST bodyは不完全な可能性があるので、**option http-buffer-request**
section in [HAProxy configuration](doc/configuration.txt) を参照

単独でPOST用のbackendを設置した方がいいかもしれない

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
