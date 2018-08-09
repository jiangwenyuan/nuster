# NuSTER

[Wiki](https://github.com/jiangwenyuan/nuster/wiki) | [English](README.md) | [中文](README-CN.md) | [日本語](README-JP.md)

高性能のHTTPキャッシュサーバーとRESTful NoSQLサーバー。

> 最近版は英語の[README.md](README.md)　を参照ください

# 目次

* [紹介](#紹介)
* [性能](#性能)
* [入門](#入門)
* [使用方法](#使用方法)
* [ディレクティブ](#ディレクティブ)
* [Cache](#cache)
  * [管理](#キャッシュ管理)
  * [有効無効](#キャッシュ有効無効)
  * [生存期間](#キャッシュ生存期間)
  * [削除](#キャッシュ削除)
  * [統計](#キャッシュ統計)
* [NoSQL](#nosql)
  * [Set](#set)
  * [Get](#get)
  * [Delete](#delete)
* [FAQ](#faq)

# 紹介

NuSTERはHAProxyを元に開発したHTTPキャッシュサーバーとRESTful NoSQLサーバーで、HAProxyと互換性がある。
そしてHAProxyのACLを利用して細かいキャッシュルールを定義できる。

## 特徴

### HTTP/TCPロードバランサ

NuSTERはHAProxyのようにHTTP/TCPロードバランサとして使える。

* HAProxyのすべての機能を持ち、HAProxyと互換性がある
* ロード・バランシング
* フロントエンドとバックエンド両方HTTPSサポート
* HTTP圧縮
* HTTPリライトとリダイレクト
* HTTP修正
* HTTP2
* モニタリング
* 粘り
* アクセス制御
* コンテンツスイッチング

### HTTPキャッシュサーバー

NuSTERはVarnishやNginxのように動的や静的なHTTPコンテンツをキャッシュするキャッシュサーバーとしても使える。

* HAProxyのすべての機能(HTTPS, HTTP/2, ACL, etc)
* とっても速い
* 優れた動的キャッシュ機能
  * Based on HTTP method, URI, path, query, header, cookies, etc
  * Based on HTTP request or response contents, etc
  * Based on environment variables, server state, etc
  * Based on SSL version, SNI, etc
  * Based on connection rate, number, byte, etc
* キャッシュ管理
* キャッシュ削除
* キャッシュ統計
* キャッシュ生存期間

### RESTful NoSQLキャッシュサーバー

NuSTERはRESTful NoSQLキャッシュサーバーとしても使える、 HTTP `POST/GET/DELETE` でKey/Valueを登録・取得・削除する。

MemcachedやRedisのようにアプリとデータベースの間に配置する内部KVキャッシュサーバーとして使えるし、アプリとユーザーの間に配置するユーザー向けのRESTful NoSQLキャッシュサーバーとしても使える。
headerやcookieなど識別できるので、同じエンドポイントにユーザー毎のデータを保存することができる。

* HAProxyのすべての機能(HTTPS, HTTP/2, ACL, etc)
* 条件付きキャッシュ
* 内部KVキャッシュ
* ユーザー向けRESTfulキャッシュ
* あらゆる種類のデータをサポート
* すべてHTTPができるプログラミング言語をサポート

# 性能

スーパー速い

シングルコアでnginxより3倍、マルチコアでnginxより2倍varnishより3倍のテスト結果があった。

詳細は[benchmark](https://github.com/jiangwenyuan/nuster/wiki/Performance-benchmark:-nuster-vs-nginx-vs-varnish)

# 入門

## Download

本番環境は[Download](Download.md)から, ほかはgit cloneで。

## Build

```
make TARGET=linux2628 USE_LUA=1 LUA_INC=/usr/include/lua5.3 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1
make install PREFIX=/usr/local/nuster
```

> `USE_PTHREAD_PSHARED=1`でpthreadを使う

> 必要なければ`USE_LUA=1 LUA_INC=/usr/include/lua5.3 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1`削除してもいい

詳細は[HAProxy README](README)。

## コンフィグファイル

最低限のコンフィグファイル: `nuster.cfg`

```
global
    nuster cache on data-size 100m uri /_nuster
    nuster nosql on data-size 200m
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

nusterは8080でリッスンしてHTTP requestsを受け取る.
`/_kv/`のリクエストはbackend `be2`に行き, `/_kv/any_key`にHTTP `POST/GET/DELETE`を送信すればK/Vオブジェクトを登録・取得・削除できる。
他のリクエストはbackend `be1`に行き, そしてサーバー`s1` or `s2`に行く。その中、`/img/*`は1日キャッシュされ、`/api/some/api`は30秒キャッシュされる。

## 機能

`/usr/local/nuster/sbin/nuster -f nuster.cfg`

## Docker

```
docker pull nuster/nuster
docker run -d -v /path/to/nuster.cfg:/etc/nuster/nuster.cfg:ro -p 8080:8080 nuster/nuster
```

# 使用方法

NuSTERはHAProxyをベースに開発したので、HAProxyのすべての機能をサポートする。

## Basic

４つの基本`section`s: `global`, `defaults`, `frontend` and `backend`.

* global
  * globalなパラメータを設定
  * `nuster cache on` or `nuster nosql on` は入れないとcacheやnosqlの機能を使えない
* defaults
  * 他の`frontend`, `backend`のディフォルトパラメータを設定
  * `frontend` or `backend` で単独で再設定できる
* frontend
  * クライアントからリクエストを受ける側についてを設定する
* bankend
  * 受けたリクエストを振り分ける先のサーバについてを設定する
  * `nuster cache on` or `nuster nosql on`は設定する必要ある
  * `nuster rule`を定義する必要がある

複数の`frontend` or `backend` 定義できる. `nuster cache off`設定したり, `nuster cache on|off`入れなかったりすると, nusterは全くHAProxy同様にとして動く。

`/doc`したのドキュメントか[オンラインのHAProxyドキュメント](https://cbonte.github.io/haproxy-dconv/)を参照ください。

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


# ディレクティブ

## global: nuster cache|nosql

**syntax:**

nuster cache on|off [data-size size] [dict-size size] [purge-method method] [uri uri]

nuster nosql on|off [data-size size] [dict-size size]

**default:** *none*

**context:** *global*

cacheやnosqlを使うかどうかを決める。

HTTPデータやキーなどを保存する、`data-size + dict-size`の大きさの共有メモリゾンを生成する。
このメモリゾンにメモリが足りない場合は、新しいリクエストはキャッシュしない。一時的なデータはメモリプールから申請する。

### data-size

`dict-size`と一緒に共有メモリゾンのサイズを決定する。

単位`m`, `M`, `g` and `G`で、 ディフォルトは1MBで、最小値も1MBである。

### dict-size

hash tableのサイズを決める.

単位`m`, `M`, `g` and `G`で、 ディフォルトは1MBで、最小値も1MBである。

これはhast tableのkeyの数を決めるわけではなく、bucketsのサイズを決めるのである。keyは共有メモリにある。

**dict-size(buckets数)**は**keys数**と違って、 keyの数がこの数を超えても、共有メモリに容量さえあれば、新しいkeyは追加できる。

でもkeyの数がdict-size(buckets数)を超えると、性能が落ちる可能性がある。`dict-size`は大体の最大key数かける８であれば十分。

> 将来のバージョンはdict-sizeを削除するかもしれない, 初版のような自動リサイズを戻す。

### purge-method [cache only]

長さ14バイトのHTTP methodを定義する。ディフォルトは`PURGE`。

### uri [cache only]

cache manager/stats APIを定義そして有効にする。

`nuster cache on uri /_my/_unique/_/_cache/_uri`

ディフォルトはcache manager/stats は無効で、有効にしたら、アクセス制御をしてください(see [FAQ](#how-to-restrict-access)).

詳細は[キャッシュ管理](#キャッシュ管理) と　[キャッシュ統計](#キャッシュ統計)。


## proxy: nuster cache|nosql

**syntax:**
nuster cache [on|off]
nuster nosql [on|off]

**default:** *on*

**context:** *backend*, *listen*

cache/nosqlの有効無効を決める。
他のfilterがある場合は、一番後ろ置く。

## nuster rule

**syntax:** nuster rule name [key KEY] [ttl TTL] [code CODE] [if|unless condition]

**default:** *none*

**context:** *backend*, *listen*

cache/nosqlの有効条件を定義する、少なくとも１つは必要。

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

複数のruleを定義できる、定義順序で実行する。

```
acl pathA path /a.html
nuster cache on
nuster rule all ttl 3600
nuster rule path01 ttl 60 if pathA
```

rule allはすべてをマッチングするので、rule `path01`は実行しない。

### name

このruleのnameを定義する。

cache manager APIに使われる。唯一にする必要ないが、唯一にしたほうがおすすめ、同じnameのruleは同じとされる。

### key KEY

cache/nosqlのkeyを定義する。下記のkeywordと`.`との組み合わせ。

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

CACHEのディフォルトkeyは `method.scheme.host.uri` で, NoSQLのディフォルトkeyは`GET.scheme.host.uri`.

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
 * uri:          /q?name=X&type=Y
 * path:         /q
 * delimiter:    ?
 * query:        name=X&type=Y
 * header\_ASDF: Z
 * cookie\_user: nuster
 * param\_type:  Y
 * body:         (empty)

ディフォルトkeyは`GET.http.www.example.com./q?name=X&type=Y.` で `key method.scheme.host.path.header_ASDF.cookie_user.param_type` は `GET.http.www.example.com./q.Z.nuster.Y.`.

リクエストのkeyが同じなら、キャッシュを返す。

### ttl TTL

生存期限を定義する。単位は `d`, `h`, `m`と`s`で、 ディフォルトは`0`秒。
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

# Cache

NuSTERはVarnishやNginxのように動的や静的なHTTPコンテンツをキャッシュするキャッシュサーバーとしても使える。

HAProxyのSSL, HTTP, HTTP2, リライト、リダイレクトなどの機能の他、NuSTERは下記も提供する。

## キャッシュ管理

cacheはランタイムでAPIで管理できる。uriを定義して、このURIにたいしてHTTPを投げることで、管理できる。


**Eanble and define the endpoint**

```
nuster cache on uri /nuster/cache
```

**Basic usage**

`curl -X POST -H "X: Y" http://127.0.0.1/nuster/cache`

**REMEMBER to enable access restriction**

## キャッシュ有効無効

***headers***

| header | value      | description
| ------ | -----      | -----------
| state  | enable     | 有効にする
|        | disable    | 無効にする
| name   | rule NAME  | NAMEという名前のruleを有効無効にする
|        | proxy NAME | NAMEという名前のProxyのすべてのruleを
|        | *          | すべてのrulesを

***Examples***

* rule r1を無効にする

  `curl -X POST -H "name: r1" -H "state: disable" http://127.0.0.1/nuster/cache`

* proxy app1bのすべてのruleを無効

  `curl -X POST -H "name: app1b" -H "state: disable" http://127.0.0.1/nuster/cache`

* すべてのruleを有効

  `curl -X POST -H "name: *" -H "state: enable" http://127.0.0.1/nuster/cache`

## キャッシュ生存期間

cacheのTTLを変更する、既存のキャッシュは変更されない。

***headers***

| header | value      | description
| ------ | -----      | -----------
| ttl    | new TTL    | TTLに変更
| name   | rule NAME  | NAMEという名前のruleのTTLを変更
|        | proxy NAME | NAMEという名前のProxyのすべてのruleを
|        | *          | すべてのrulesを

***Examples***

```
curl -X POST -H "name: r1" -H "ttl: 0" http://127.0.0.1/nuster/cache
curl -X POST -H "name: r2" -H "ttl: 2h" http://127.0.0.1/nuster/cache
```

## stateとTTLを同時に変更

```
curl -X POST -H "name: r1" -H "ttl: 0" -H "state: enabled" http://127.0.0.1/nuster/cache
```

## キャッシュ削除

いくつかの方法でPurgeできる。Purge機能はディフォルトでOffなので、Onにする必要がある。

`global`セクションで `nuster cache on uri /nuster/cache`のようにPurge用のuriを設定することでPurgeを有効にする。uriはなんでもいい。

そしてディフォルトのPurgeメソッドは`PURGE`で、`purge-method MYPURGE`で別のメソッドも設定できる。

### １つURLをPurge

`curl -XPURGE https://127.0.0.1/imgs/test.jpg`

`GET /imgs/test.jpg`で生成したキャッシュをPurgeする、HEADERなどは問わない。

### nameでPurge

ruleのname、proxyのname、もしくは`*`でPurgeできる。

***headers***

| header | value      | description
| ------ | -----      | -----------
| name   | rule NAME  | rule ${NAME} で生成したキャッシュをPurge
|        | proxy NAME | proxy ${NAME}のキャッシュをPurge
|        | *          | すべてのキャッシュをPurge

***Examples***

```
# すべてのキャッシュをPurge
curl -X PURGE -H "name: *" http://127.0.0.1/nuster/cache

# proxy app1bのすべてのキャッシュをPurge
curl -X PURGE -H "name: app1b" http://127.0.0.1/nuster/cache

# nuster-rule r1が生成したキャッシュをすべてPurgeする
# つまり /imgs/* のキャッシュをすべてPurgeする
# nuster-rule r1 imgs if { path_beg /imgs/ }
curl -X PURGE -H "name: r1" http://127.0.0.1/nuster/cache
```

### HostでPurge

そのHostのすべてのキャッシュをPurgeできる。

***headers***

| header | value | description
| ------ | ----- | -----------
| x-host | HOST  | the ${HOST}

***Examples***

```
# 127.0.0.1:8080のすべてのキャッシュをPurge
curl -X PURGE -H "x-host: 127.0.0.1:8080" http://127.0.0.1/nuster/cache
```

### pathでPurge

ディフォルトで同じpathでもqueryが違うなら、生成したキャッシュも違う。

例えば `nuster-rule imgs if { path_beg /imgs/ }`,そして

```
curl https://127.0.0.1/imgs/test.jpg?w=120&h=120
curl https://127.0.0.1/imgs/test.jpg?w=180&h=180
```
すると、２つのキャッシュが生成される。

pathでpurge以外は、いくつかの方法でPurgeできる。

***一つずつ***

```
curl -XPURGE https://127.0.0.1/imgs/test.jpg?w=120&h=120
curl -XPURGE https://127.0.0.1/imgs/test.jpg?w=180&h=180
```
でもqueryがわからない場合はできない。

***もしqueryが重要ではないなら、カスタマイズのkeyを使う***

`nuster rule imgs key method.scheme.host.path if { path_beg /imgs }`,すると１つのキャッシュしか生成されない。そして、queryなしでpurgeできる。

`curl -XPURGE https://127.0.0.1/imgs/test.jpg`

でもqueryが重要の場合はできない。

***ruleでpurge***

`curl -X PURGE -H "name: imgs" http://127.0.0.1/nuster/cache`

すると、 `/imgs/test.jpg`だけでなく、他の `/imgs/*`もPurgeされる。

なので、pathでPurge

***headers***

| header | value | description
| ------ | ----- | -----------
| path   | PATH  | pathが${PATH}のキャッシュをpurge
| x-host | HOST  | そして host が ${HOST}

***Examples***

```
# pathが/imgs/test.jpg のキャッシュをPurge
curl -X PURGE -H "path: /imgs/test.jpg" http://127.0.0.1/nuster/cache

# pathが/imgs/test.jpgで hostが127.0.0.1:8080のキャッシュをPurge
curl -X PURGE -H "path: /imgs/test.jpg" -H "x-host: 127.0.0.1:8080" http://127.0.0.1/nuster/cache
```

### regexでPurge

***headers***

| header | value | description
| ------ | ----- | -----------
| regex  | REGEX | pathが${REGEX} matchならPurge
| x-host | HOST  | そして host が ${HOST}

***Examples***

```
# /img下の.jpgファイルのキャッシュをPurge
curl -X PURGE -H "regex: ^/imgs/.*\.jpg$" http://127.0.0.1/nuster/cache

#/img下の.jpgファイルかつHostが 127.0.0.1:8080のキャッシュをPurge
curl -X PURGE -H "regex: ^/imgs/.*\.jpg$" -H "127.0.0.1:8080" http://127.0.0.1/nuster/cache
```

**PURGE注意事項**

1. **アクセス制御必ずを**

2. 複数のheaderがある場合、`name`, `path & host`, `path`, `regex & host`, `regex`, `host`の順序で処理

   `curl -XPURGE -H "name: rule1" -H "path: /imgs/a.jpg"`: purge by name

3. 重複のheaderがある場合, 一番目のheaderを使う

   `curl -XPURGE -H "name: rule1" -H "name: rule2"`: purge by `rule1`

4. `regex` は `glob` **ではない**

   /imgs配下のjpgファイルは  `/imgs/*.jpg`　ではなく、`^/imgs/.*\.jpg$` である。

## キャッシュ統計

`uri`で定義したエンドポイントにGETする

### Eanble and define the endpoint

```
nuster cache on uri /nuster/cache
```

`curl http://127.0.0.1/nuster/cache`

## Output

* used\_mem:  HTTPリスポンスが使っているメモリ
* req\_total: トータルrequest数、cacheが有効にしてないproxyのrequestは含まない
* req\_hit:   cache hitのrequest数
* req\_fetch: バックエンドから取得して返すrequest数
* req\_abort: abrotしたrequest数

# NoSQL

NuSTERはRESTful NoSQLキャッシュサーバーとしても使える、 HTTP `POST/GET/DELETE` でKey/Valueを登録・取得・削除する。

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
  * DELETE: 全部
* 400 Bad request
  * 空のvalue
  * 違うacl, rules, etc
* 404 Not Found
  * POST: rule tests失敗
  * GET: 存在しない
* 405 Method Not Allowed
  * 他のmethods
* 500 Internal Server Error
  * エラー発生
* 507 Insufficient Storage
  * dict-size超え

## userごとのdata

keyにheader や cookie を使えば、同じendpointにユーザーごとのデータを保存できる

```
nuster rule r1 key method.scheme.host.uri.header_userId if { path /mypoint }
nuster rule r2 key method.scheme.host.uri.cookie_sessionId if { path /mydata }
```

### Set

```
curl -v -X POST -d "333" -H "userId: 1000" http://127.0.0.1:8080/mypoint
curl -v -X POST -d "555" -H "userId: 1001" http://127.0.0.1:8080/mypoint

curl -v -X POST -d "userA data" --cookie "sessionId: ijsf023xe" http://127.0.0.1:8080/mydata
curl -v -X POST -d "userB data" --cookie "sessionId: rosre329x" http://127.0.0.1:8080/mydata
```

### Get

```
curl -v http://127.0.0.1:8080/mypoint
< 404 Not Found

curl -v -H "userId: 1000" http://127.0.0.1:8080/mypoint
< 200 OK
333

curl -v --cookie "sessionId: ijsf023xe" http://127.0.0.1:8080/mydata
< 200 OK
userA data
```

## Clients

あらゆるHTTPできるツールやライブラリ: `curl`, `postman`, python `requests`, go `net/http`, etc.

# FAQ

## debug方法?

`global`に`debug`を設定か, `haproxy`を`-d`で起動する。

キャッシュに関するメッセージは`[CACHE]`を含む。

## どうやってPOSTリクエストをキャッシュする?

`option http-buffer-request`を設定

カスタマイズしたkeyは`body`を入れること。

POST bodyは不完全な可能性があるので、**option http-buffer-request** section in [HAProxy configuration](doc/configuration.txt) を参照

単独でPOST用のbackendを設置した方がいいかもしれない

## アクセス制御方法?

```
acl network_allowed src 127.0.0.1
acl purge_method method PURGE
http-request deny if purge_method !network_allowed
```
みたいな

## HTTP2使いたい

```
bind :443 ssl crt pub.pem alpn h2,http/1.1
```

# Example

```
global
    nuster cache on data-size 100m
    nuster nosql on data-size 100m
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

frontend nosql_fe
    bind *:9090
    default_backend nosql_be
backend nosql_be
    nuster nosql on
    nuster rule r1 ttl 3600
```

# Conventions

1. Files with same name: those with `.md` extension belong to NuSTER, otherwise HAProxy

# Contributing

* Join the development
* Give feedback
* Report issues
* Send pull requests
* Spread nuster

# License

Copyright (C) 2017-2018, [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >

All rights reserved.

Licensed under GPL, the same as HAProxy

HAProxy and other sources license notices: see relevant individual files.
