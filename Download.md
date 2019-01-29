
## Latest versions

Branch | nuster version | Released        | Download                    | Notes
------ | -------------- | --------        | --------                    | -----
master |                |                 |                             | maybe broken
v1.8.x | 2.0.7.18       | [2019-01-29][3] | [nuster-2.0.7.18.tar.gz][4] | stable: cache, nosql, http2
v1.7.x | 1.0.2.17       | [2018-10-05][5] | [nuster-1.0.2.17.tar.gz][6] | stable: cache only
disk   |                |                 |                             | disk persistence
sync   |                |                 |                             | replication

[1]:https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.7.18
[2]:https://github.com/jiangwenyuan/nuster/releases/download/v2.0.7.18/nuster-2.0.7.18.tar.gz
[3]:https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.7.18
[4]:https://github.com/jiangwenyuan/nuster/releases/download/v2.0.7.18/nuster-2.0.7.18.tar.gz
[5]:https://github.com/jiangwenyuan/nuster/releases/tag/v1.0.2.17
[6]:https://github.com/jiangwenyuan/nuster/releases/download/v1.0.2.17/nuster-1.0.2.17.tar.gz

## Versioning

Previously nuster used HAPROXY_VERSION.NUSTER_VERSION(eg, v1.8.8.3) which is very straightforward to find out the base HAProxy version, but very hard to tell whether it is a major release or just bug fix from a single NUSTER_VERSION.

Starting from v1.8.8.3, nuster uses a different version system as MAJOR.MINOR.PATCH.HAPROXY_BRANCH.

* MAJOR: big feature release of nuster
* MINOR: small features, haproxy branch update
* PATCH: bug fixes, haproxy minor updates
* HAPROXY_BRANCH: 17 stands for v1.7.x, 18 for v1.8.x

## Legacy versions

https://github.com/jiangwenyuan/nuster/releases

| nuster version | HAProxy version
| -------------- | ---------------
| 2.0.7.18       | 1.8.17
| 2.0.6.18       | 1.8.17
| 2.0.5.18       | 1.8.14
| 2.0.4.18       | 1.8.14
| 2.0.3.18       | 1.8.13
| 2.0.2.18       | 1.8.13
| 2.0.1.18       | 1.8.13
| 2.0.0.18       | 1.8.12
| 1.1.1.18       | 1.8.12
| 1.0.2.17       | 1.7.11
