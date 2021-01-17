# nuster

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
* [NoSQL](#nosql)
* [管理](#管理)
  * [統計](#統計)
  * [Ruleの有効無効](#Ruleの有効無効)
  * [生存期間更新](#生存期間更新)
  * [削除](#削除)
* [Store](#store)
* [Sample fetches](#sample-fetches)
* [FAQ](#faq)

# 紹介

nusterはHAProxyを元に開発したHTTPキャッシュサーバーとRESTful NoSQLサーバーで、HAProxyと互換性がある。
そしてHAProxyのACLを利用して細かいキャッシュルールを定義できる。

## 特徴

### HTTP/TCPロードバランサ

nusterはHAProxyのようにHTTP/TCPロードバランサとして使える。

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

nusterはVarnishやNginxのように動的や静的なHTTPコンテンツをキャッシュするキャッシュサーバーとしても使える。

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
* パーシステンス

### RESTful NoSQLキャッシュサーバー

nusterはRESTful NoSQLキャッシュサーバーとしても使える、 HTTP `POST/GET/DELETE` でKey/Valueを登録・取得・削除する。

MemcachedやRedisのようにアプリとデータベースの間に配置する内部KVキャッシュサーバーとして使えるし、アプリとユーザーの間に配置するユーザー向けのRESTful NoSQLキャッシュサーバーとしても使える。
headerやcookieなど識別できるので、同じエンドポイントにユーザー毎のデータを保存することができる。

* HAProxyのすべての機能(HTTPS, HTTP/2, ACL, etc)
* 条件付きキャッシュ
* 内部KVキャッシュ
* ユーザー向けRESTfulキャッシュ
* あらゆる種類のデータをサポート
* すべてHTTPができるプログラミング言語をサポート
* パーシステンス

# 性能

スーパー速い

シングルコアでnginxより3倍、マルチコアでnginxより2倍varnishより3倍のテスト結果があった。

詳細は[benchmark](https://github.com/jiangwenyuan/nuster/wiki/Performance-benchmark:-nuster-vs-nginx-vs-varnish)

# 入門

## Download

本番環境は[Download](Download.md)から, ほかはgit cloneで。

## Build

```
make TARGET=linux-glibc USE_LUA=1 LUA_INC=/usr/include/lua5.3 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1
make install PREFIX=/usr/local/nuster
```

> `USE_PTHREAD_PSHARED=1`でpthreadを使う

> 必要なければ`USE_LUA=1 LUA_INC=/usr/include/lua5.3 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1`削除してもいい

詳細は[HAProxy INSTALL](INSTALL)。

## コンフィグファイル

最低限のコンフィグファイル: `nuster.cfg`

```
global
    nuster cache on data-size 100m
    nuster nosql on data-size 200m
    master-worker # v3から
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

nusterはHAProxyをベースに開発したので、HAProxyのすべての機能をサポートする。

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

`listen`ではnusterを使えない。

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

## global: nuster manager

**syntax:**

*nuster manager on|off [uri URI] [purge-method method]*

**default:** *off*

**context:** *global*

manager/stats/purge APIを有効にする、URIとpurge methodを定義する

ディフォルトは無効で、有効にしたら、アクセス制御をしてください(see [FAQ](#how-to-restrict-access)).

詳細は[管理](#管理)。

### uri

URIを定義する、ディフォルトは `/nuster`

### purge-method

HTTP methodを定義する。ディフォルトは `PURGE`。

## global: nuster cache|nosql

**syntax:**

*nuster cache on|off [data-size size] [dict-size size] [dir DIR] [dict-cleaner n] [data-cleaner n] [disk-cleaner n] [disk-loader n] [disk-saver n] [clean-temp on|off] [always-check-disk on|off]*

*nuster nosql on|off [data-size size] [dict-size size] [dir DIR] [dict-cleaner n] [data-cleaner n] [disk-cleaner n] [disk-loader n] [disk-saver n] [clean-temp on|off] [always-check-disk on|off]*

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

stats APIに
```
dict.nosql.length:              131072
dict.nosql.used:                0
```

もし`dict.nosql.used` が`dict.nosql.length`より大きい場合、`dict-size`を上げたほうが良い。

> 将来のバージョンはdict-sizeを削除するかもしれない, 初版のような自動リサイズを戻す。

### dir

パーシステンスのrootディレクトリを設定する、パーシステンス使うには必要。

chrootある場合、実際の保存場所はchroot+dir。例えば

```
chroot /data
nuster cache on dir /cache
```

キャッシュの実際の保存場所は/data/cache

### dict-cleaner

一回で最多`dict-cleaner`個のentries をチェックして, 無効なentriesは削除する(デフォルト、1000).

### data-cleaner

一回で最多`data-cleaner`個のdataをチェックして, 無効なdataは削除する(デフォルト、1000).

無効なdataが20%を超えったら、削除プロセスが加速するので、この値を弄るのがおすすめしない。

### disk-cleaner

一回で最多`disk-cleaner`個のfileをチェックして, 無効なfileは削除する(デフォルト、100).

### disk-loader

起動後、一回で最多`disk-loader`個のfileをチェックして、情報をロードする(デフォルト、100).

`USE_THREAD`の場合, 単独のthreadでロードする、このパラメータは無視する。

### disk-saver

一回で最多`disk-saver`個のdataをチェックして、ディスクに保存する必要あるデータを保存する(デフォルト、100).

詳細は[Store](#disk)

### clean-temp on|off

`dir`で定義したディレクトリの下に一時ファイル保存用の`.tmp`というディレクトリが自動的生成される。

起動時その一時ファイルを削除するかどうかを決める。ディフォルトはoff。

### always-check-disk on|off

常にディスクキャッシュをチェックする。特にディスクが複数のインスタンスに共有された場合キャッシュがスミする可能性がある。

默认是off。

## proxy: nuster cache|nosql

**syntax:**

*nuster cache [on|off]*

*nuster nosql [on|off]*

**default:** *on*

**context:** *backend*

cache/nosqlの有効無効を決める。
他のfilterがある場合は、一番後ろ置く。

## proxy: nuster rule

**syntax:**

*nuster rule name [key KEY] [ttl auto|TTL] [extend EXTEND] [wait on|off|TIME] [use-stale on|off|TIME] [inactive off|TIME] [code CODE] [memory on|off] [disk on|off|sync] [etag on|off] [last-modified on|off] [if|unless condition]*

**default:** *none*

**context:** *backend*

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

このruleのnameを定義する。v5以降はグローバルユニーク。

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

ディフォルトkeyは`GET\0http.www.example.com\0/q?name=X&type=Y\0` で `key method.scheme.host.path.header_ASDF.cookie_user.param_type` は `GET\0http.www.example.com\0/q\0Z\0nuster\0Y\0`.

> `\0`はNULLキャラクター

リクエストのkeyが同じなら、キャッシュを返す。

### ttl auto|TTL

生存期限を定義する。単位は `d`, `h`, `m`と`s`で、 ディフォルトは`0`秒。
`0`の場合は失効しない。

`auto`を使う場合、 ttl は自動的に`cache-control` headerの`s-maxage` か `max-age`の値に設定する。

> `cache-control`の他のディレクティブは処理してない。

ttlのMaxは2147483647

`extend`でttlを自動的に延長できる。

### extend EXTEND

自動的にttlを延長する。

#### フォーマット

extend on|off|n1,n2,n3,n4

ディフォルト: off.

n1,n2,n3,n4: 100未満の整数, n1 + n2 + n3も100未満. ４つの時間帯を定義する：

```
time:       0                                                       ttl         ttl * (1 + n4%)
access:     |            A1             |   A2    |   A3    |   A4    |         |
            |---------------------------|---------|---------|---------|---------|
percentage: |<- (100 - n1 - n2 - n3)% ->|<- n1% ->|<- n2% ->|<- n3% ->|<- n4% ->|
```

下記満たさればttlは自動的に延長する:

1. A4 > A3 > A2
2. `ttl` と `ttl * (1 + n4%)` の間に新たなリクエストが発生

> `on` は 33,33,33,33

### wait on|off|TIME [cache only]

同時に来た同じなリクエストがキャッシュ完成するのを待つかどうか。 `wait on`はキャッシュ完成するまでまつ、 `wait TIME`はTIME秒待ってからバックエンドにフォーワードする。

ディフォルトは待たずに全部バックエンドにフォーワードする(`wait off`)。

最初のリクエストが初期化をするまで他の同じなリクエストが来た場合は待たずにフォーワードする。

> Nosqlモードではwaitしない。順番に処理して最後のリクエストの内容を保存する。

最大値：2147483647.

### use-stale on|off|TIME [cache only]

キャッシュが更新されているときや、バックエンドのサーバーダウンで更新失敗した時に、失効済みのキャッシュを使うかどうかを決める。

`use-stale on`: キャッシュが更新されている時、失効済みのキャッシュを使う。

`use-stale off`(ディフォルト): `wait off`の場合、同じなリクエストがバックエンドにフォーワードする, `wait on|TIME` の場合は待つ。

`use-stale TIME`: バックエンドのサーバーダウンで更新失敗した時に、失効済みのキャッシュをTIME秒間を使う。

最大値：2147483647.

### inactive off|TIME

指定した期間を過ぎてアクセスがない場合キャッシュが削除される。ディフォルトはoff(0)。

TIMEを過ぎると必ず削除されるというわけではない、cleanプロセスが先にcacheをアクセスする場合、削除されるけど、新しいリクエストが先に来る場合、キャッシュの最終アクセス時間が更新されキャッシュは削除されない。ディスクファイルの場合はファイルのアクセス時間使ってないため、nusterが再起動すると、最終アクセス時間はロード時間に設定する。

最大値：2147483647.

### code CODE1,CODE2...

ディフォルトは200のリスポンスしかキャッシュしない、ほかのものをキャッシュしたい場合は
定義する。 `all`の場合は全てキャッシュする。

```
cache-rule only200
cache-rule 200and404 code 200,404
cache-rule all code all
```

### memory on|off

メモリに保存するかどうか、ディフォルトon

詳細は[Store](#Store)

### disk on|off|sync

ディスクに保存するかどうか、どうやって保存するか、ディフォルトoff

`disk sync` を使うには`memory on`を設定する必要がある。

詳細は[Store](#Store)

### etag on|off

etag条件付きリクエストの処理、 `ETag` なければ、追加する.

ディフォルトoff.

### last-modified on|off

last-modified条件付きリクエストの処理、 `Last-Modified` なければ、追加する.

ディフォルトoff.

### if|unless condition

HAProxy ACLを使う。

ACLはリクエストとリスポンスの二段階で評価する

下記満たせばキャッシュする：

1. リクエスト段階でACLがtrue
2. リクエスト段階でACLがfalseだが、リスポンス段階でtrue

**否定のACLや特定のSample使う場合は要注意**

例えば、

1.  `/img/`で始まるリクエストをキャッシュする

    nuster rule img if { path_beg /img/ }

リクエスト段階でACLがtrueなら、キャッシュする、falseの場合はリスポンス段階でpath存在しないのでACLもfalseでキャッシュしない。

2. リスポンスの`Content-Type` が `image/jpeg`の場合キャッシュする

    nuster rule jpeg if { res.hdr(Content-Type) image/jpeg }

リクエスト段階ではres.hdrがないため、falseで、リスポンス段階ではtrueもしくはfalse

3. `/img/`で始まり、 リスポンスの`Content-Type` が`image/jpeg`ならキャッシュする

下記は正常に動かない：

    nuster rule img if { path_beg /img/ } { res.hdr(Content-Type) image/jpeg }

リクエスト段階ではres.hdrがないためfalseで、リスポンス段階ではpath存在しないのでACLもfalseのため。

下記なら大丈夫

    http-request set-var(txn.pathImg) path
    acl pathImg var(txn.pathImg) -m beg /img/
    acl resHdrCT res.hdr(Content-Type) image/jpeg
    nuster rule r3 if pathImg resHdrCT

もしくは`nuster.path`(v5):

    nuster rule r3 if { nuster.path -m beg /img } { res.hdr(Content-Type) image/jpeg }

4. `/api/`で始まるリクエスト以外はキャッシュする

下記は動かない：

    acl NoCache path_beg /api/
    nuster rule r3 if !NoCache

リスポンス段階ではpathないため、NoCacheはfalseで `!NoCache`はいつもtrueなので、すべてのリクエストがキャッシュされる

下記は大丈夫

    http-request set-var(txn.path) path
    acl NoCache var(txn.path) -m beg /api/
    nuster rule r1 if !NoCache

新しいsample取得方法は[Sample fetches](#sample-fetch)

**7. Using ACLs and fetching samples** section in [HAProxy configuration](doc/configuration.txt)も参考

# Cache

nusterはVarnishやNginxのように動的や静的なHTTPコンテンツをキャッシュするキャッシュサーバーとしても使える。

HAProxyのSSL, HTTP, HTTP2, リライト、リダイレクトなどの機能の他、nusterは下記も提供する。

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

Ruleを順番にチェックして、まずKeyを生成して探す。見つかったらキャッシュを返す。なければACLをテストして、Passした場合はバックエンドのレスポンスをキャッシュする。

# NoSQL

nusterはRESTful NoSQLキャッシュサーバーとしても使える、 HTTP `POST/GET/DELETE` でKey/Valueを登録・取得・削除する。

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

## Headers

Supported headers in request

| Name          | value                   | description
| ------        | -----                   | -----------
| content-type  | any   		  | Will be returned as is in GET request
| cache-control | `s-maxage` or `max-age` | used to set ttl when rule.ttl is `auto`

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

あらゆるHTTPできるツールやライブラリ: `curl`, `postman`, python `requests`, go `net/http`, etc.

# 管理

NusterはランタイムでAPIで管理できる。uriを定義して、このURIにたいしてHTTPを投げることで、管理できる。

**定義**

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

## 統計


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

## Ruleの有効無効

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

  `curl -X POST -H "name: r1" -H "state: disable" http://127.0.0.1/nuster`

* proxy app1bのすべてのruleを無効

  `curl -X POST -H "name: app1b" -H "state: disable" http://127.0.0.1/nuster`

* すべてのruleを有効

  `curl -X POST -H "name: *" -H "state: enable" http://127.0.0.1/nuster`

## 生存期間更新

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
curl -X POST -H "name: r1" -H "ttl: 0" http://127.0.0.1/nuster
curl -X POST -H "name: r2" -H "ttl: 2h" http://127.0.0.1/nuster
```

### stateとTTLを同時に変更

```
curl -X POST -H "name: r1" -H "ttl: 0" -H "state: enabled" http://127.0.0.1/nuster
```

## 削除

２つもモードある:

* basic: 削除したいPATHにHTTP method `purge-method MYPURGE` を送る
* advanced: manager uri にDELETEを送る

### Basic purge: １つURLをPurge

`curl -XPURGE http://127.0.0.1/imgs/test.jpg`

ruleでキーを生成して、キャッシュを探して、あったらPurgeする。GETで生成したキャッシュのみ有効。

Hostを注意してください、例えば、 `http://example.com/test` のキャッシュの場合は：

`curl -XPURGE -H "Host: example.com" http://127.0.0.1/test`

cache とnosql両方使える。Nosqlの場合は `DELETE` と同様。

### Advanced purge: nameでPurge

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
curl -X DELETE -H "name: *" http://127.0.0.1/nuster

# proxy app1bのすべてのキャッシュをPurge
curl -X DELETE -H "name: app1b" http://127.0.0.1/nuster

# nuster-rule r1が生成したキャッシュをすべてPurgeする
# つまり /imgs/* のキャッシュをすべてPurgeする
# nuster-rule r1 imgs if { path_beg /imgs/ }
curl -X DELETE -H "name: r1" http://127.0.0.1/nuster
```

### Advanced purge: HostでPurge

そのHostのすべてのキャッシュをPurgeできる。

***headers***

| header      | value        | description
| ------      | -----        | -----------
| host        | HOST         | the ${HOST}
| nuster-host | HOST         | nuster-host has higher precedence over host
| mode        | cache, nosql | purge cache or nosql data

***Examples***

```
# 127.0.0.1:8080のすべてのキャッシュをPurge
curl -X DELETE -H "nuster-host: 127.0.0.1:8080" http://127.0.0.1/nuster
```

### Advanced purge: pathでPurge

ディフォルトで同じpathでもqueryが違うなら、生成したキャッシュも違う。

例えば `nuster-rule imgs if { path_beg /imgs/ }`,そして

```
curl http://127.0.0.1/imgs/test.jpg?w=120&h=120
curl http://127.0.0.1/imgs/test.jpg?w=180&h=180
```
すると、２つのキャッシュが生成される。

pathでpurge以外は、いくつかの方法でPurgeできる。

***一つずつ***

```
curl -XPURGE http://127.0.0.1/imgs/test.jpg?w=120&h=120
curl -XPURGE http://127.0.0.1/imgs/test.jpg?w=180&h=180
```
でもqueryがわからない場合はできない。

***もしqueryが重要ではないなら、カスタマイズのkeyを使う***

`nuster rule imgs key method.scheme.host.path if { path_beg /imgs }`,すると１つのキャッシュしか生成されない。そして、queryなしでpurgeできる。

`curl -XPURGE http://127.0.0.1/imgs/test.jpg`

でもqueryが重要の場合はできない。

***ruleでpurge***

`curl -X DELETE -H "name: imgs" http://127.0.0.1/nuster

すると、 `/imgs/test.jpg`だけでなく、他の `/imgs/*`もPurgeされる。

なので、pathでPurge

***headers***

| header      | value        | description
| ------      | -----        | -----------
| path        | PATH         | caches with ${PATH} will be purged
| host        | HOST         | and host is ${HOST}
| nuster-host | HOST         | nuster-host has higher precedence over host
| mode        | cache, nosql | purge cache or nosql data

***Examples***

```
# pathが/imgs/test.jpg のキャッシュをPurge
curl -X DELETE -H "path: /imgs/test.jpg" http://127.0.0.1/nuster

# pathが/imgs/test.jpgで hostが127.0.0.1:8080のキャッシュをPurge
curl -X DELETE -H "path: /imgs/test.jpg" -H "nuster-host: 127.0.0.1:8080" http://127.0.0.1/nuster
```

### Advanced purge: regexでPurge

***headers***

| header      | value        | description
| ------      | -----        | -----------
| regex       | REGEX        | caches which path match with ${REGEX} will be purged
| host 	      | HOST         | and host is ${HOST}
| nuster-host | HOST         | nuster-host has higher precedence over host
| mode        | cache, nosql | purge cache or nosql data

***Examples***

```
# /img下の.jpgファイルのキャッシュをPurge
curl -X DELETE -H "regex: ^/imgs/.*\.jpg$" http://127.0.0.1/nuster

#/img下の.jpgファイルかつHostが 127.0.0.1:8080のキャッシュをPurge
curl -X DELETE -H "regex: ^/imgs/.*\.jpg$" -H "127.0.0.1:8080" http://127.0.0.1/nuster
```

**PURGE注意事項**

1. **アクセス制御必ずを**

2. 複数のheaderがある場合、`name`, `path & host`, `path`, `regex & host`, `regex`, `host`の順序で処理

   `curl -X DELETE -H "name: rule1" -H "path: /imgs/a.jpg"`: purge by name

3. 重複のheaderがある場合, 一番目のheaderを使う

   `curl -X DELETE -H "name: rule1" -H "name: rule2"`: purge by `rule1`

4. `regex` は `glob` **ではない**

   /imgs配下のjpgファイルは  `/imgs/*.jpg`　ではなく、`^/imgs/.*\.jpg$` である。

5. proxy name or rule name or host or path or regexでキャッシュファイルを削除するのはdisk loadが完了してからじゃないといけないです。disk loadが完了しているかどうかはstats URLで確認できます。

# Store

Nuster(cacheとnosql) は複数の保存先をサポートする。今はmemory とdisk２つある。

## Memory

大きさが`data-size`で定義されたメモリに保存する。再起動するとDataが消える。

## Disk

ディスクの`dir`の下に保存する。再起動してもDataは消えない。

* off:   ディフォルト、保存しない
* on:    保存する
* sync:  `memory on` が必須. メモリに保存して、後ほどmasterプロセスによってディスクに保存される、毎回`disk-saver`個のキャッシュが保存される。

# Sample fetches

下記のsample fetchesが使えます

## [cache] nuster.cache.hit: boolean

キャッシュHITかどうかを表します。

    http-response set-header x-cache hit if { nuster.cache.hit }

## [cache|nosql] nuster.host: string

HAProxyの`req.hdr(Host)`と同じで、ただ request とresponse 両方使える.

## [cache|nosql] nuster.uri: string

HAProxyの`capture.req.uri`と同じ.

## [cache|nosql] nuster.path: string

HAProxyの`path`と同じで、ただ request とresponse 両方使える.

## [cache|nosql] nuster.query: string

HAProxyの`query`と同じで、ただ request とresponse 両方使える.

# FAQ

## 起動できない: not in master-worker mode

`global`に`master-worker`を設定するか, `-W`で起動する

## debug方法?

`nuster`を`-d`で起動する。

nusterに関するメッセージは`[nuster`を含む。

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
    nuster manager on uri /_/nuster purge-method MYPURGE
    nuster cache on data-size 100m
    nuster nosql on data-size 100m
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
