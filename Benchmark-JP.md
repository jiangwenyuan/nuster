性能比較: nuster vs nginx vs varnish
=================================================

nuster, nginxとvarnishの性能を比較してみました。

結果は大体シングルコアでnginxより3倍、マルチコアでnginxより2倍varnishより3倍です。

`/helloworld`の結果：

data size       | CONN | nuster, 1core | nuster, 12cores | nginx, 1core | nginx, 12cores | varnish
---------       | ---- | ------------- | --------------- | ------------ | -------------- | -------
12(hello world) | 1000 | 95359         | 357013          | 33454        | 214217         | 133094

すべての結果は[here](#results)

チューニングアドバイスがあれば気軽にご連絡ください！

テスト環境
==========

サーバー
--------

2つのlinuxサーバー, server129にはオリジンウェーブサーバーで
server130はnuster/nginx/varnish。

Server     | port | app
------     | ---- | ---
10.0.0.129 |      | wrk
10.0.0.129 | 8080 | nginx, origin web server
10.0.0.130 |      | wrk
10.0.0.130 | 8080 | nuster, 1 core
10.0.0.130 | 8081 | nuster, all cores, private cache
10.0.0.130 | 8082 | nginx, 1 core
10.0.0.130 | 8083 | nginx, all cores
10.0.0.130 | 8084 | varnish, all cores


オリジンサーバーはset `server_tokens off;` でhttp headerのserverを一致させます。


ハードウェア
-----------

* Intel(R) Xeon(R) CPU X5650 @ 2.67GHz(12 cores)
* RAM 32GB
* 1Gbps ethernet card

ソフトウェア
-----------

* CentOS: 7.4.1708 (Core)
* wrk: 4.0.2-2-g91655b5
* varnish: (varnish-4.1.8 revision d266ac5c6)
* nginx: nginx/1.12.2
* nuster: nuster/1.7.9.1

システム設定
============

/etc/sysctl.conf
----------------

```
fs.file-max                    = 9999999
fs.nr_open                     = 9999999
net.core.netdev_max_backlog    = 4096
net.core.rmem_max              = 16777216
net.core.somaxconn             = 65535
net.core.wmem_max              = 16777216
net.ipv4.ip_forward            = 0
net.ipv4.ip_local_port_range   = 1025       65535
net.ipv4.tcp_fin_timeout       = 30
net.ipv4.tcp_keepalive_time    = 30
net.ipv4.tcp_max_syn_backlog   = 20480
net.ipv4.tcp_max_tw_buckets    = 400000
net.ipv4.tcp_no_metrics_save   = 1
net.ipv4.tcp_syn_retries       = 2
net.ipv4.tcp_synack_retries    = 2
net.ipv4.tcp_tw_recycle        = 1
net.ipv4.tcp_tw_reuse          = 1
net.ipv4.tcp_timestamps        = 1
vm.min_free_kbytes             = 65536
vm.overcommit_memory           = 1
```

/etc/security/limits.conf
-------------------------

```
* soft nofile 1000000
* hard nofile 1000000
* soft nproc  1000000
* hard nproc  1000000
```

コンフィグファイル
=================

nuster, 1 core
--------------

```
global
    maxconn 1000000
    cache on data-size 1g
    daemon
    tune.maxaccept -1
defaults
    retries 3
    maxconn 1000000
    option redispatch
    option dontlognull
    timeout client  300s
    timeout connect 300s
    timeout server  300s
    http-reuse always
frontend web1
    bind *:8080
    mode http
    # haproxy removes connection header in HTTP/1.1 while nginx/varnish dont
    # add this to make headers same size
    http-response add-header Connectio1 keep-aliv1
    default_backend app1
backend app1
    balance roundrobin
    mode http
    filter cache on
    cache-rule all ttl 0
    server a2 10.0.0.129:8080
```

nuster, all cores
-----------------

```
global
    maxconn 1000000
    cache on data-size 1g
    daemon
    nbproc 12
    tune.maxaccept -1
defaults
    retries 3
    maxconn 1000000
    option redispatch
    option dontlognull
    timeout client  300s
    timeout connect 300s
    timeout server  300s
    http-reuse always
frontend web1
    bind *:8081
    mode http
    default_backend app1
backend app1
    balance roundrobin
    mode http
    filter cache on
    cache-rule all ttl 0
    server a2 10.0.0.129:8080
```

nginx, 1 core
-------------

```
user  nginx;
worker_processes  1;
worker_rlimit_nofile 1000000;
error_log  /var/log/nginx/error1.log warn;
pid        /var/run/nginx1.pid;
events {
  worker_connections  1000000;
  use epoll;
  multi_accept on;
}
http {
  include                     /etc/nginx/mime.types;
  default_type                application/octet-stream;
  access_log                  off;
  sendfile                    on;
  server_tokens               off;
  keepalive_timeout           300;
  keepalive_requests          100000;
  tcp_nopush                  on;
  tcp_nodelay                 on;
  client_body_buffer_size     128k;
  client_header_buffer_size   1m;
  large_client_header_buffers 4 4k;
  output_buffers              1 32k;
  postpone_output             1460;
  open_file_cache             max=200000 inactive=20s;
  open_file_cache_valid       30s;
  open_file_cache_min_uses    2;
  open_file_cache_errors      on;
  proxy_cache_path /tmp/cache levels=1:2 keys_zone=STATIC:10m inactive=24h max_size=1g;
  server {
    listen 8082;
    location / {
      proxy_pass        http://10.0.0.129:8080/;
      proxy_cache       STATIC;
      proxy_cache_valid any 1d;
    }
  }
}
```

nginx, all cores
----------------

```
user  nginx;
worker_processes  auto;
worker_rlimit_nofile 1000000;
error_log  /var/log/nginx/errorall.log warn;
pid        /var/run/nginxall.pid;
events {
  worker_connections  1000000;
  use epoll;
  multi_accept on;
}
http {
  include                     /etc/nginx/mime.types;
  default_type                application/octet-stream;
  access_log                  off;
  sendfile                    on;
  server_tokens               off;
  keepalive_timeout           300;
  keepalive_requests          100000;
  tcp_nopush                  on;
  tcp_nodelay                 on;
  client_body_buffer_size     128k;
  client_header_buffer_size   1m;
  large_client_header_buffers 4 4k;
  output_buffers              1 32k;
  postpone_output             1460;
  open_file_cache             max=200000 inactive=20s;
  open_file_cache_valid       30s;
  open_file_cache_min_uses    2;
  open_file_cache_errors      on;
  proxy_cache_path /tmp/cache_all levels=1:2 keys_zone=STATIC:10m inactive=24h max_size=1g;
  server {
    listen 8083;
    location / {
      proxy_pass        http://10.0.0.129:8080/;
      proxy_cache       STATIC;
      proxy_cache_valid any 1d;
    }
  }
}
```

varnish
-------

### /etc/varnish/default.vcl

```
vcl 4.0;
backend default {
    .host = "10.0.0.129";
    .port = "8080";
}
sub vcl_recv {
}
sub vcl_backend_response {
    set beresp.ttl = 1d;
}
sub vcl_deliver {
    # remove these headers to make headers same
    unset resp.http.Via;
    unset resp.http.Age;
    unset resp.http.X-Varnish;
}
```

### /etc/varnish/varnish.params

```
RELOAD_VCL=1
VARNISH_VCL_CONF=/etc/varnish/default.vcl
VARNISH_LISTEN_PORT=8084
VARNISH_ADMIN_LISTEN_ADDRESS=127.0.0.1
VARNISH_ADMIN_LISTEN_PORT=6082
VARNISH_SECRET_FILE=/etc/varnish/secret
VARNISH_STORAGE="malloc,1024M"
VARNISH_USER=varnish
VARNISH_GROUP=varnish
```

HTTPリスポンスサイズをチェック
==============================

```
# curl -is http://10.0.0.130:8080/helloworld
HTTP/1.1 200 OK
Server: nginx
Date: Sun, 05 Nov 2017 07:58:02 GMT
Content-Type: application/octet-stream
Content-Length: 12
Last-Modified: Thu, 26 Oct 2017 08:56:57 GMT
ETag: "59f1a359-c"
Accept-Ranges: bytes
Connectio1: keep-aliv1

Hello World
# curl -is http://10.0.0.130:8080/helloworld | wc -c
255

# curl -is http://10.0.0.130:8081/helloworld
HTTP/1.1 200 OK
Server: nginx
Date: Sun, 05 Nov 2017 07:58:48 GMT
Content-Type: application/octet-stream
Content-Length: 12
Last-Modified: Thu, 26 Oct 2017 08:56:57 GMT
ETag: "59f1a359-c"
Accept-Ranges: bytes
Connectio1: keep-aliv1

Hello World
# curl -is http://10.0.0.130:8081/helloworld | wc -c
255

# curl -is http://10.0.0.130:8082/helloworld
HTTP/1.1 200 OK
Server: nginx
Date: Sun, 05 Nov 2017 07:59:24 GMT
Content-Type: application/octet-stream
Content-Length: 12
Connection: keep-alive
Last-Modified: Thu, 26 Oct 2017 08:56:57 GMT
ETag: "59f1a359-c"
Accept-Ranges: bytes

Hello World
# curl -is http://10.0.0.130:8082/helloworld | wc -c
255

# curl -is http://10.0.0.130:8083/helloworld
HTTP/1.1 200 OK
Server: nginx
Date: Sun, 05 Nov 2017 07:59:31 GMT
Content-Type: application/octet-stream
Content-Length: 12
Connection: keep-alive
Last-Modified: Thu, 26 Oct 2017 08:56:57 GMT
ETag: "59f1a359-c"
Accept-Ranges: bytes

Hello World
# curl -is http://10.0.0.130:8083/helloworld | wc -c
255

# curl -is http://10.0.0.130:8084/helloworld
HTTP/1.1 200 OK
Server: nginx
Date: Sun, 05 Nov 2017 08:00:05 GMT
Content-Type: application/octet-stream
Content-Length: 12
Last-Modified: Thu, 26 Oct 2017 08:56:57 GMT
ETag: "59f1a359-c"
Accept-Ranges: bytes
Connection: keep-alive

Hello World
# curl -is http://10.0.0.130:8084/helloworld | wc -c
255
```

ベンチマーク
-----------

    wrk -c CONN -d 30 -t 100 http://HOST:PORT/FILE

結果
----

RPS

### wrk on server129, cache servers on server130, 1Gbps bandwidth

data size       | CONN | nuster, 1core | nuster, 12cores | nginx, 1core | nginx, 12cores | varnish
---------       | ---- | ------------- | --------------- | ------------ | -------------- | -------
12(hello world) | 1000 | 95359         | 357013          | 33454        | 214217         | 133094
64bytes         | 1000 | 93667         | 305103          | 33383        | 215343         | 124683
128bytes        | 1000 | 84304         | 265004          | 36143        | 215078         | 128820
256bytes        | 1000 | 93123         | 206207          | 35372        | 209608         | 132182
512bytes        | 1000 | 88505         | 146042          | 36898        | 146537         | 129780
1k bytes        | 1000 | 89328         | 90866           | 36034        | 91497          | 87772

* 1 core
  * ネットワークの帯域幅は大丈夫
  * nusterはnginxより三倍ぐらい
* 12 cores
  * 256bytesより大きいファイルをテストすると帯域足りない(see [Raw output](#raw-output))
  * 帯域大丈夫な場合はnusterはnginxより2倍でvarnishより3倍ぐらい
  * 足りない場合は大体同じ

10Gbpsネットワークないので、127.0.0.1を使ってもう一度テストしてました。

### wrk and cache servers on same host, server130, use 127.0.0.1

data size       | CONN  | nuster, 1core | nuster, 12cores | nginx, 1core | nginx, 12cores | varnish
---------       | ----  | ------------- | --------------- | ------------ | -------------- | -------
12(hello world) | 1000  | 75655         | 212769          | 30996        | 136844         | 115928
64bytes         | 1000  | 76425         | 206016          | 30724        | 136409         | 108380
128bytes        | 1000  | 76389         | 205109          | 30931        | 135853         | 107382
256bytes        | 1000  | 73539         | 198264          | 30797        | 135899         | 107158
512bytes        | 1000  | 74279         | 202554          | 30839        | 135819         | 107200
1k bytes        | 1000  | 70507         | 174769          | 30823        | 134808         | 109379
12(hello world) | 5000  | 51561         | 185230          | ERROR        | 125309         | 111711
64bytes         | 5000  | 49981         | 180164          | ERROR        | 125238         | 108115
128bytes        | 5000  | 50603         | 178029          | ERROR        | 125181         | 107825
256bytes        | 5000  | 49655         | 172111          | ERROR        | 125268         | 106837
512bytes        | 5000  | 50629         | 176659          | ERROR        | 125118         | 108167
1k bytes        | 5000  | 51007         | 150375          | ERROR        | 125323         | 107596

* nusterは大体nginxやvarnishの2倍ぐらい

Raw output
==========

wrk on server129, helloworld
----------------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8080/helloworld
Running 30s test @ http://10.0.0.130:8080/helloworld
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    10.45ms  635.29us  35.45ms   93.73%
    Req/Sec     0.96k    89.66     3.75k    98.40%
  2870302 requests in 30.10s, 698.02MB read
Requests/sec:  95359.08
Transfer/sec:     23.19MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8081/helloworld
Running 30s test @ http://10.0.0.130:8081/helloworld
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     2.82ms    1.62ms 205.57ms   99.22%
    Req/Sec     3.59k   203.46     6.96k    73.75%
  10745921 requests in 30.10s, 2.55GB read
Requests/sec: 357013.95
Transfer/sec:     86.82MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8082/helloworld
Running 30s test @ http://10.0.0.130:8082/helloworld
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    29.83ms    1.11ms  40.37ms   92.38%
    Req/Sec   336.63     42.34   777.00     73.55%
  1007003 requests in 30.10s, 244.89MB read
Requests/sec:  33454.56
Transfer/sec:      8.14MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8083/helloworld
Running 30s test @ http://10.0.0.130:8083/helloworld
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.68ms    2.07ms 208.37ms   92.89%
    Req/Sec     2.15k   338.86     4.46k    75.22%
  6447791 requests in 30.10s, 1.53GB read
Requests/sec: 214217.54
Transfer/sec:     52.09MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8084/helloworld
Running 30s test @ http://10.0.0.130:8084/helloworld
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.40ms    0.93ms 244.42ms   92.23%
    Req/Sec     6.37k     1.72k    8.86k    80.98%
  4004063 requests in 30.08s, 0.95GB read
Requests/sec: 133094.01
Transfer/sec:     32.37MB
```

wrk on server129, 64b
---------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8080/64b
Running 30s test @ http://10.0.0.130:8080/64b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    10.63ms  776.50us  18.63ms   91.56%
    Req/Sec     0.94k    90.94     2.91k    90.92%
  2819397 requests in 30.10s, 828.15MB read
Requests/sec:  93667.14
Transfer/sec:     27.51MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8081/64b
Running 30s test @ http://10.0.0.130:8081/64b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     3.30ms    1.94ms 207.73ms   94.80%
    Req/Sec     3.07k   188.18     6.68k    71.76%
  9183666 requests in 30.10s, 2.63GB read
Requests/sec: 305103.34
Transfer/sec:     89.62MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8082/64b
Running 30s test @ http://10.0.0.130:8082/64b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    29.89ms    1.40ms  47.71ms   90.73%
    Req/Sec   336.04     46.16   808.00     71.42%
  1004857 requests in 30.10s, 295.16MB read
Requests/sec:  33383.63
Transfer/sec:      9.81MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8083/64b
Running 30s test @ http://10.0.0.130:8083/64b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.66ms    2.13ms 207.94ms   99.65%
    Req/Sec     2.16k   185.74     3.93k    71.71%
  6481797 requests in 30.10s, 1.86GB read
Requests/sec: 215343.12
Transfer/sec:     63.25MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8084/64b
Running 30s test @ http://10.0.0.130:8084/64b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    22.08ms  113.76ms   1.99s    98.06%
    Req/Sec     1.29k   276.86    10.05k    92.41%
  3752974 requests in 30.10s, 1.08GB read
Requests/sec: 124683.73
Transfer/sec:     36.62MB
```

wrk on server129, 128b
----------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8080/128b
Running 30s test @ http://10.0.0.130:8080/128b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    11.82ms  754.99us  19.68ms   89.25%
    Req/Sec   848.49     72.79     2.77k    95.76%
  2537610 requests in 30.10s, 0.88GB read
Requests/sec:  84304.97
Transfer/sec:     29.99MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8081/128b
Running 30s test @ http://10.0.0.130:8081/128b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     3.79ms    1.52ms 206.79ms   95.03%
    Req/Sec     2.66k   125.59     5.07k    72.31%
  7976479 requests in 30.10s, 2.77GB read
Requests/sec: 265004.46
Transfer/sec:     94.27MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8082/128b
Running 30s test @ http://10.0.0.130:8082/128b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    27.62ms    0.97ms  47.32ms   93.04%
    Req/Sec   363.76     44.41   690.00     71.64%
  1087929 requests in 30.10s, 387.00MB read
Requests/sec:  36143.90
Transfer/sec:     12.86MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8083/128b
Running 30s test @ http://10.0.0.130:8083/128b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.66ms    1.75ms 208.18ms   93.02%
    Req/Sec     2.16k   173.45     4.10k    68.28%
  6473793 requests in 30.10s, 2.25GB read
Requests/sec: 215078.69
Transfer/sec:     76.51MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8084/128b
Running 30s test @ http://10.0.0.130:8084/128b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    45.79ms  897.57ms  29.07s    99.72%
    Req/Sec     2.26k   761.86     7.94k    79.96%
  3877405 requests in 30.10s, 1.35GB read
Requests/sec: 128820.22
Transfer/sec:     45.82MB
```

wrk on server129, 256b
----------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8080/256b
Running 30s test @ http://10.0.0.130:8080/256b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    10.70ms  656.15us  24.10ms   90.77%
    Req/Sec     0.94k    98.06     4.29k    95.57%
  2803012 requests in 30.10s, 1.31GB read
Requests/sec:  93123.91
Transfer/sec:     44.58MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8081/256b
Running 30s test @ http://10.0.0.130:8081/256b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.87ms    1.83ms 209.39ms   86.08%
    Req/Sec     2.07k   177.87     6.00k    71.50%
  6206761 requests in 30.10s, 2.90GB read
Requests/sec: 206207.86
Transfer/sec:     98.72MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8082/256b
Running 30s test @ http://10.0.0.130:8082/256b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    28.21ms    1.35ms 259.75ms   93.45%
    Req/Sec   355.92     46.61   707.00     54.75%
  1064712 requests in 30.10s, 509.73MB read
Requests/sec:  35372.03
Transfer/sec:     16.93MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8083/256b
Running 30s test @ http://10.0.0.130:8083/256b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.79ms    2.21ms 208.01ms   96.04%
    Req/Sec     2.11k   249.18     4.33k    73.11%
  6309154 requests in 30.10s, 2.95GB read
Requests/sec: 209608.77
Transfer/sec:    100.35MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8084/256b
Running 30s test @ http://10.0.0.130:8084/256b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.43ms    1.21ms 239.27ms   96.83%
    Req/Sec     6.64k     1.14k    8.44k    84.66%
  3975962 requests in 30.08s, 1.86GB read
Requests/sec: 132182.92
Transfer/sec:     63.28MB
```

wrk on server129, 512b
----------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8080/512b
Running 30s test @ http://10.0.0.130:8080/512b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    11.27ms  716.99us  18.46ms   88.62%
    Req/Sec     0.89k    66.55     2.53k    84.66%
  2663970 requests in 30.10s, 1.88GB read
Requests/sec:  88505.68
Transfer/sec:     63.98MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8081/512b
Running 30s test @ http://10.0.0.130:8081/512b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     6.87ms    2.00ms 224.86ms   87.43%
    Req/Sec     1.47k   110.48     2.71k    72.79%
  4395845 requests in 30.10s, 3.10GB read
Requests/sec: 146042.73
Transfer/sec:    105.57MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8082/512b
Running 30s test @ http://10.0.0.130:8082/512b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    27.05ms    0.99ms  59.23ms   93.14%
    Req/Sec   371.30     42.48   700.00     75.83%
  1110683 requests in 30.10s, 802.90MB read
Requests/sec:  36898.79
Transfer/sec:     26.67MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8083/512b
Running 30s test @ http://10.0.0.130:8083/512b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     8.36ms   32.51ms   1.04s    99.68%
    Req/Sec     1.47k    78.34     3.22k    94.62%
  4410778 requests in 30.10s, 3.11GB read
Requests/sec: 146537.84
Transfer/sec:    105.93MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8084/512b
Running 30s test @ http://10.0.0.130:8084/512b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     3.48ms    2.69ms 136.19ms   93.69%
    Req/Sec     2.90k   448.61     5.71k    94.44%
  3906041 requests in 30.10s, 2.76GB read
Requests/sec: 129780.54
Transfer/sec:     93.82MB
```

wrk on server129, 1k
--------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8080/1k
Running 30s test @ http://10.0.0.130:8080/1k
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    11.18ms    1.71ms  25.56ms   81.47%
    Req/Sec     0.90k    62.44     1.84k    79.37%
  2688770 requests in 30.10s, 3.18GB read
Requests/sec:  89328.88
Transfer/sec:    108.28MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8081/1k
Running 30s test @ http://10.0.0.130:8081/1k
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    11.02ms    3.37ms 231.72ms   84.13%
    Req/Sec     0.91k    68.32     1.66k    73.12%
  2735063 requests in 30.10s, 3.24GB read
Requests/sec:  90866.76
Transfer/sec:    110.14MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8082/1k
Running 30s test @ http://10.0.0.130:8082/1k
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    27.70ms    1.04ms  42.43ms   93.16%
    Req/Sec   362.75     46.28   690.00     69.09%
  1084674 requests in 30.10s, 1.28GB read
Requests/sec:  36034.71
Transfer/sec:     43.68MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8083/1k
Running 30s test @ http://10.0.0.130:8083/1k
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    10.93ms    2.15ms 213.03ms   91.34%
    Req/Sec     0.92k    42.99     2.22k    87.90%
  2754065 requests in 30.10s, 3.26GB read
Requests/sec:  91497.37
Transfer/sec:    110.91MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://10.0.0.130:8084/1k
Running 30s test @ http://10.0.0.130:8084/1k
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    15.23ms   35.11ms 393.24ms   96.81%
    Req/Sec     0.92k   302.64     3.45k    83.29%
  2641941 requests in 30.10s, 3.13GB read
  Socket errors: connect 0, read 0, write 0, timeout 17
Requests/sec:  87772.69
Transfer/sec:    106.39MB
```

wrk on server130, helloworld, 1000 connections
----------------------------------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8080/helloworld
Running 30s test @ http://127.0.0.1:8080/helloworld
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    13.19ms  734.83us  27.58ms   92.94%
    Req/Sec   761.29     56.64     2.08k    83.45%
  2277112 requests in 30.10s, 553.76MB read
Requests/sec:  75655.34
Transfer/sec:     18.40MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8081/helloworld
Running 30s test @ http://127.0.0.1:8081/helloworld
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.78ms    2.58ms 165.64ms   98.74%
    Req/Sec     2.14k   244.71    14.76k    94.91%
  6404220 requests in 30.10s, 1.52GB read
Requests/sec: 212769.32
Transfer/sec:     51.74MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8082/helloworld
Running 30s test @ http://127.0.0.1:8082/helloworld
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    32.19ms    1.21ms  54.12ms   92.52%
    Req/Sec   311.90     31.45   606.00     87.67%
  933010 requests in 30.10s, 226.90MB read
Requests/sec:  30996.36
Transfer/sec:      7.54MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8083/helloworld
Running 30s test @ http://127.0.0.1:8083/helloworld
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     7.32ms    2.30ms  50.20ms   80.21%
    Req/Sec     1.37k   288.80    10.73k    81.14%
  4118949 requests in 30.10s, 0.98GB read
Requests/sec: 136844.37
Transfer/sec:     33.28MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8084/helloworld
Running 30s test @ http://127.0.0.1:8084/helloworld
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.01ms    0.89ms  59.07ms   89.09%
    Req/Sec     5.79k     2.42k   18.48k    78.33%
  3489430 requests in 30.10s, 848.58MB read
  Socket errors: connect 0, read 0, write 0, timeout 118
Requests/sec: 115928.18
Transfer/sec:     28.19MB
```

wrk on server130, 64b, 1000 connections
---------------------------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8080/64b
Running 30s test @ http://127.0.0.1:8080/64b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    13.05ms  668.57us  23.22ms   86.40%
    Req/Sec   768.90     59.46     2.10k    75.76%
  2300422 requests in 30.10s, 675.71MB read
Requests/sec:  76425.18
Transfer/sec:     22.45MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8081/64b
Running 30s test @ http://127.0.0.1:8081/64b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.92ms    2.62ms 213.57ms   93.59%
    Req/Sec     2.07k   274.98    18.74k    95.68%
  6200962 requests in 30.10s, 1.78GB read
Requests/sec: 206016.30
Transfer/sec:     60.51MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8082/64b
Running 30s test @ http://127.0.0.1:8082/64b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    32.48ms    1.15ms  45.95ms   92.73%
    Req/Sec   309.18     28.26   606.00     89.99%
  924823 requests in 30.10s, 271.65MB read
Requests/sec:  30724.40
Transfer/sec:      9.02MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8083/64b
Running 30s test @ http://127.0.0.1:8083/64b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     7.34ms    1.96ms 216.33ms   79.76%
    Req/Sec     1.37k   254.28     7.71k    74.06%
  4105897 requests in 30.10s, 1.18GB read
Requests/sec: 136409.30
Transfer/sec:     40.07MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8084/64b
Running 30s test @ http://127.0.0.1:8084/64b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    28.49ms   49.03ms 528.68ms   83.16%
    Req/Sec     1.13k   402.00     8.28k    83.06%
  3262210 requests in 30.10s, 0.94GB read
Requests/sec: 108380.03
Transfer/sec:     31.83MB
```

wrk on server130, 128b, 1000 connections
----------------------------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8080/128b
Running 30s test @ http://127.0.0.1:8080/128b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    13.06ms  702.10us  21.96ms   84.79%
    Req/Sec   768.77     55.08     1.70k    74.34%
  2299283 requests in 30.10s, 817.90MB read
Requests/sec:  76389.32
Transfer/sec:     27.17MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8081/128b
Running 30s test @ http://127.0.0.1:8081/128b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     5.00ms    3.00ms 210.05ms   94.55%
    Req/Sec     2.06k   249.21    17.74k    91.53%
  6173692 requests in 30.10s, 2.14GB read
Requests/sec: 205109.75
Transfer/sec:     72.96MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8082/128b
Running 30s test @ http://127.0.0.1:8082/128b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    32.27ms    1.03ms  56.76ms   92.57%
    Req/Sec   311.26     29.73   585.00     88.49%
  931035 requests in 30.10s, 331.19MB read
Requests/sec:  30931.52
Transfer/sec:     11.00MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8083/128b
Running 30s test @ http://127.0.0.1:8083/128b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     7.37ms    2.08ms  31.42ms   76.11%
    Req/Sec     1.36k   258.27     6.53k    73.77%
  4089136 requests in 30.10s, 1.42GB read
Requests/sec: 135853.37
Transfer/sec:     48.33MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8084/128b
Running 30s test @ http://127.0.0.1:8084/128b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    27.60ms   48.36ms 510.02ms   84.60%
    Req/Sec     1.14k   572.43    11.31k    78.01%
  3232190 requests in 30.10s, 1.12GB read
Requests/sec: 107382.58
Transfer/sec:     38.20MB
```

wrk on server130, 256b, 1000 connections
----------------------------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8080/256b
Running 30s test @ http://127.0.0.1:8080/256b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    13.57ms    0.86ms  25.20ms   97.15%
    Req/Sec   739.53     62.13     2.05k    84.78%
  2213529 requests in 30.10s, 1.03GB read
Requests/sec:  73539.94
Transfer/sec:     35.21MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8081/256b
Running 30s test @ http://127.0.0.1:8081/256b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     5.13ms    2.51ms 126.07ms   97.37%
    Req/Sec     1.99k   190.06    11.79k    88.94%
  5967699 requests in 30.10s, 2.79GB read
Requests/sec: 198264.72
Transfer/sec:     94.92MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8082/256b
Running 30s test @ http://127.0.0.1:8082/256b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    32.40ms    1.25ms  42.30ms   91.93%
    Req/Sec   309.97     29.81   646.00     88.59%
  927032 requests in 30.10s, 443.81MB read
Requests/sec:  30797.46
Transfer/sec:     14.74MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8083/256b
Running 30s test @ http://127.0.0.1:8083/256b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     7.36ms    2.08ms  31.14ms   66.01%
    Req/Sec     1.37k   280.81     9.39k    69.97%
  4090474 requests in 30.10s, 1.91GB read
Requests/sec: 135899.01
Transfer/sec:     65.06MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8084/256b
Running 30s test @ http://127.0.0.1:8084/256b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    28.62ms   49.89ms 469.84ms   83.84%
    Req/Sec     1.14k   466.19     6.47k    78.85%
  3225455 requests in 30.10s, 1.51GB read
Requests/sec: 107158.35
Transfer/sec:     51.30MB
```

wrk on server130, 512b, 1000 connections
----------------------------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8080/512b
Running 30s test @ http://127.0.0.1:8080/512b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    13.43ms  736.68us  27.49ms   87.98%
    Req/Sec   747.08     60.93     1.76k    97.30%
  2235750 requests in 30.10s, 1.58GB read
Requests/sec:  74279.72
Transfer/sec:     53.70MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8081/512b
Running 30s test @ http://127.0.0.1:8081/512b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.99ms    2.64ms 227.44ms   88.99%
    Req/Sec     2.03k   248.28    15.42k    90.71%
  6096342 requests in 30.10s, 4.30GB read
Requests/sec: 202554.75
Transfer/sec:    146.42MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8082/512b
Running 30s test @ http://127.0.0.1:8082/512b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    32.36ms    1.15ms  45.16ms   93.00%
    Req/Sec   310.49     29.41   630.00     88.84%
  928292 requests in 30.10s, 671.05MB read
Requests/sec:  30839.39
Transfer/sec:     22.29MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8083/512b
Running 30s test @ http://127.0.0.1:8083/512b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     7.38ms    2.46ms  44.67ms   81.04%
    Req/Sec     1.36k   336.02     9.62k    77.31%
  4088030 requests in 30.10s, 2.89GB read
Requests/sec: 135819.13
Transfer/sec:     98.18MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8084/512b
Running 30s test @ http://127.0.0.1:8084/512b
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    27.67ms   48.41ms 628.24ms   84.10%
    Req/Sec     1.13k   497.02     9.57k    79.17%
  3226694 requests in 30.10s, 2.28GB read
Requests/sec: 107200.41
Transfer/sec:     77.49MB
```

wrk on server130, 1k, 1000 connections
--------------------------------------

```
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8080/1k
Running 30s test @ http://127.0.0.1:8080/1k
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    14.15ms  790.27us  22.54ms   94.76%
    Req/Sec   709.70     54.99     1.72k    79.03%
  2122288 requests in 30.10s, 2.51GB read
Requests/sec:  70507.29
Transfer/sec:     85.46MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8081/1k
Running 30s test @ http://127.0.0.1:8081/1k
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     5.77ms    2.39ms 223.64ms   91.11%
    Req/Sec     1.76k   205.22    12.70k    90.98%
  5260373 requests in 30.10s, 6.23GB read
Requests/sec: 174769.39
Transfer/sec:    211.84MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8082/1k
Running 30s test @ http://127.0.0.1:8082/1k
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    32.38ms    1.15ms  44.57ms   92.99%
    Req/Sec   310.16     28.45   690.00     89.53%
  927805 requests in 30.10s, 1.10GB read
Requests/sec:  30823.63
Transfer/sec:     37.36MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8083/1k
Running 30s test @ http://127.0.0.1:8083/1k
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     7.48ms    3.19ms  67.33ms   77.79%
    Req/Sec     1.35k   434.05    16.14k    66.37%
  4057738 requests in 30.10s, 4.80GB read
Requests/sec: 134808.76
Transfer/sec:    163.40MB
# wrk --timeout 300 -c 1000 -d 30 -t 100 http://127.0.0.1:8084/1k
Running 30s test @ http://127.0.0.1:8084/1k
  100 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    27.50ms   48.42ms 623.79ms   84.59%
    Req/Sec     1.15k   564.66     9.41k    77.01%
  3292286 requests in 30.10s, 3.90GB read
Requests/sec: 109379.12
Transfer/sec:    132.58MB
```

wrk on server130, helloworld, 5000 connections
----------------------------------------------

```
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8080/helloworld
Running 30s test @ http://127.0.0.1:8080/helloworld
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    96.57ms    4.26ms 225.34ms   93.85%
    Req/Sec   519.20     69.46     1.01k    90.28%
  1551936 requests in 30.10s, 377.41MB read
Requests/sec:  51561.52
Transfer/sec:     12.54MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8081/helloworld
Running 30s test @ http://127.0.0.1:8081/helloworld
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    31.35ms   52.92ms   1.28s    98.91%
    Req/Sec     1.87k   429.97    23.95k    97.67%
  5573984 requests in 30.09s, 1.32GB read
Requests/sec: 185230.25
Transfer/sec:     45.05MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8082/helloworld
Running 30s test @ http://127.0.0.1:8082/helloworld
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   154.87ms   18.83ms 602.46ms   90.02%
    Req/Sec   314.26    144.94   505.00     53.97%
  933234 requests in 30.10s, 226.95MB read
  Socket errors: connect 0, read 0, write 417, timeout 0
Requests/sec:  31004.16
Transfer/sec:      7.54MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8083/helloworld
Running 30s test @ http://127.0.0.1:8083/helloworld
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    39.41ms   11.44ms 256.07ms   72.34%
    Req/Sec     1.26k   126.59     3.25k    76.29%
  3771836 requests in 30.10s, 0.90GB read
Requests/sec: 125309.78
Transfer/sec:     30.47MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8084/helloworld
Running 30s test @ http://127.0.0.1:8084/helloworld
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   249.53ms  343.85ms   2.23s    81.37%
    Req/Sec     1.12k   754.10     9.34k    74.09%
  3362407 requests in 30.10s, 817.69MB read
Requests/sec: 111711.42
Transfer/sec:     27.17MB
```

wrk on server130, 64b, 5000 connections
---------------------------------------

```
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8080/64b
Running 30s test @ http://127.0.0.1:8080/64b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    99.46ms    4.90ms 286.04ms   80.63%
    Req/Sec   503.82     63.37     1.01k    91.47%
  1504356 requests in 30.10s, 441.88MB read
Requests/sec:  49981.81
Transfer/sec:     14.68MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8081/64b
Running 30s test @ http://127.0.0.1:8081/64b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    30.84ms   41.78ms   1.23s    99.05%
    Req/Sec     1.82k   284.14    12.02k    97.47%
  5422881 requests in 30.10s, 1.56GB read
Requests/sec: 180164.79
Transfer/sec:     52.92MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8082/64b
Running 30s test @ http://127.0.0.1:8082/64b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   155.76ms   25.68ms   1.01s    89.62%
    Req/Sec   302.49    133.54     1.01k    62.22%
  902730 requests in 30.10s, 265.16MB read
  Socket errors: connect 0, read 0, write 956, timeout 0
Requests/sec:  29991.64
Transfer/sec:      8.81MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8083/64b
Running 30s test @ http://127.0.0.1:8083/64b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    39.49ms   10.49ms 262.93ms   78.42%
    Req/Sec     1.26k   116.04     2.88k    75.51%
  3769646 requests in 30.10s, 1.08GB read
Requests/sec: 125238.51
Transfer/sec:     36.79MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8084/64b
Running 30s test @ http://127.0.0.1:8084/64b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   237.37ms  321.51ms   1.60s    80.45%
    Req/Sec     1.09k   710.12     7.02k    72.07%
  3255057 requests in 30.11s, 0.93GB read
Requests/sec: 108115.79
Transfer/sec:     31.76MB
```

wrk on server130, 128b, 5000 connections
----------------------------------------

```
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8080/128b
Running 30s test @ http://127.0.0.1:8080/128b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    98.35ms    3.89ms 283.24ms   87.46%
    Req/Sec   508.62     52.82     1.00k    90.72%
  1523179 requests in 30.10s, 541.83MB read
Requests/sec:  50603.62
Transfer/sec:     18.00MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8081/128b
Running 30s test @ http://127.0.0.1:8081/128b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    31.93ms   48.39ms   1.31s    98.96%
    Req/Sec     1.80k   361.08    19.10k    97.69%
  5358241 requests in 30.10s, 1.86GB read
Requests/sec: 178029.30
Transfer/sec:     63.33MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8082/128b
Running 30s test @ http://127.0.0.1:8082/128b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   158.70ms   19.23ms 611.15ms   89.65%
    Req/Sec   305.13    131.15   666.00     60.93%
  904684 requests in 30.10s, 321.81MB read
  Socket errors: connect 0, read 0, write 596, timeout 0
Requests/sec:  30055.54
Transfer/sec:     10.69MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8083/128b
Running 30s test @ http://127.0.0.1:8083/128b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    39.48ms    9.67ms 261.23ms   82.29%
    Req/Sec     1.26k   126.88     3.12k    76.40%
  3767905 requests in 30.10s, 1.31GB read
Requests/sec: 125181.59
Transfer/sec:     44.53MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8084/128b
Running 30s test @ http://127.0.0.1:8084/128b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   245.42ms  330.87ms   1.57s    79.97%
    Req/Sec     1.12k   744.79     7.90k    73.45%
  3245574 requests in 30.10s, 1.13GB read
Requests/sec: 107825.54
Transfer/sec:     38.36MB
```

wrk on server130, 256b, 5000 connections
----------------------------------------

```
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8080/256b
Running 30s test @ http://127.0.0.1:8080/256b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   100.32ms    3.69ms 289.76ms   87.29%
    Req/Sec   499.58     41.38     1.01k    92.74%
  1494636 requests in 30.10s, 715.55MB read
Requests/sec:  49655.72
Transfer/sec:     23.77MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8081/256b
Running 30s test @ http://127.0.0.1:8081/256b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    33.49ms   53.31ms   1.27s    98.85%
    Req/Sec     1.74k   288.10     9.04k    97.40%
  5180310 requests in 30.10s, 2.42GB read
Requests/sec: 172111.53
Transfer/sec:     82.40MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8082/256b
Running 30s test @ http://127.0.0.1:8082/256b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   156.15ms   23.82ms 998.80ms   89.57%
    Req/Sec   303.24    128.94     1.01k    61.00%
  906641 requests in 30.10s, 434.05MB read
  Socket errors: connect 0, read 0, write 839, timeout 0
Requests/sec:  30122.07
Transfer/sec:     14.42MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8083/256b
Running 30s test @ http://127.0.0.1:8083/256b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    39.54ms   10.45ms 262.51ms   84.85%
    Req/Sec     1.26k   128.12     2.79k    76.73%
  3770563 requests in 30.10s, 1.76GB read
Requests/sec: 125268.97
Transfer/sec:     59.97MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8084/256b
Running 30s test @ http://127.0.0.1:8084/256b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   239.40ms  322.76ms   1.51s    79.78%
    Req/Sec     1.14k   738.92     7.39k    73.91%
  3215812 requests in 30.10s, 1.50GB read
Requests/sec: 106837.46
Transfer/sec:     51.15MB
```

wrk on server130, 512b, 5000 connections
----------------------------------------

```
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8080/512b
Running 30s test @ http://127.0.0.1:8080/512b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    98.39ms    4.11ms 196.74ms   87.17%
    Req/Sec   510.47     60.77     1.01k    91.51%
  1524004 requests in 30.10s, 1.08GB read
Requests/sec:  50629.70
Transfer/sec:     36.60MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8081/512b
Running 30s test @ http://127.0.0.1:8081/512b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    31.09ms   38.60ms   1.06s    99.04%
    Req/Sec     1.78k   341.45    18.61k    97.50%
  5317507 requests in 30.10s, 3.75GB read
Requests/sec: 176659.41
Transfer/sec:    127.71MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8082/512b
Running 30s test @ http://127.0.0.1:8082/512b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   157.95ms   26.85ms   1.02s    92.05%
    Req/Sec   303.43    128.91     1.01k    64.07%
  904974 requests in 30.10s, 654.19MB read
  Socket errors: connect 0, read 0, write 718, timeout 0
Requests/sec:  30065.36
Transfer/sec:     21.73MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8083/512b
Running 30s test @ http://127.0.0.1:8083/512b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    39.65ms   11.06ms 265.36ms   81.64%
    Req/Sec     1.26k   145.33     4.39k    74.26%
  3765982 requests in 30.10s, 2.66GB read
Requests/sec: 125118.40
Transfer/sec:     90.45MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8084/512b
Running 30s test @ http://127.0.0.1:8084/512b
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   239.98ms  321.89ms   1.44s    79.79%
    Req/Sec     1.12k   726.46     8.87k    73.57%
  3256202 requests in 30.10s, 2.30GB read
Requests/sec: 108167.78
Transfer/sec:     78.19MB
```

wrk on server130, 1k, 5000 connections
--------------------------------------

```
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8080/1k
Running 30s test @ http://127.0.0.1:8080/1k
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    97.67ms    3.53ms 205.18ms   93.96%
    Req/Sec   513.16     59.78     1.01k    91.24%
  1535325 requests in 30.10s, 1.82GB read
Requests/sec:  51007.16
Transfer/sec:     61.83MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8081/1k
Running 30s test @ http://127.0.0.1:8081/1k
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    37.43ms   51.20ms   1.32s    98.85%
    Req/Sec     1.52k   255.70     6.59k    96.65%
  4526361 requests in 30.10s, 5.36GB read
Requests/sec: 150375.52
Transfer/sec:    182.28MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8082/1k
Running 30s test @ http://127.0.0.1:8082/1k
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   154.69ms   21.90ms 582.71ms   88.36%
    Req/Sec   306.47    137.88   820.00     62.76%
  913009 requests in 30.10s, 1.08GB read
  Socket errors: connect 0, read 0, write 895, timeout 0
Requests/sec:  30332.79
Transfer/sec:     36.77MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8083/1k
Running 30s test @ http://127.0.0.1:8083/1k
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    39.42ms   14.20ms 440.42ms   82.08%
    Req/Sec     1.26k   177.75     2.91k    70.74%
  3772111 requests in 30.10s, 4.47GB read
Requests/sec: 125323.95
Transfer/sec:    151.91MB
# wrk --timeout 300 -c 5000 -d 30 -t 100 http://127.0.0.1:8084/1k
Running 30s test @ http://127.0.0.1:8084/1k
  100 threads and 5000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   235.72ms  316.57ms   1.41s    79.77%
    Req/Sec     1.11k   715.26     7.68k    74.03%
  3238678 requests in 30.10s, 3.83GB read
Requests/sec: 107596.34
Transfer/sec:    130.42MB
```

