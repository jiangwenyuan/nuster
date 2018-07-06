
## Latest versions

Branch | nuster version | Released        | Download                    | Notes
------ | -------------- | --------        | --------                    | -----
master | 2.x.y.18       |                 |                             | maybe broken, cache and nosql
v1.8.x | 1.1.1.18       | [2018-07-06][1] | [nuster-1.1.1.18.tar.gz][2] | stable, cache only, http2
v1.7.x | 1.0.0.17       | [2018-07-06][3] | [nuster-1.0.0.17.tar.gz][4] | stable, cache only

[1]:https://github.com/jiangwenyuan/nuster/releases/tag/v1.1.1.18
[2]:https://github.com/jiangwenyuan/nuster/releases/download/v1.1.1.18/nuster-1.1.1.18.tar.gz
[3]:https://github.com/jiangwenyuan/nuster/releases/tag/v1.0.0.17
[4]:https://github.com/jiangwenyuan/nuster/releases/download/v1.0.0.17/nuster-1.0.0.17.tar.gz

## Versioning

Previously nuster used HAPROXY_VERSION.NUSTER_VERSION(eg, v1.8.8.3) which is very straightforward to find out the base HAProxy version, but very hard to tell whether it is a major release or just bug fix from a single NUSTER_VERSION.

Starting from v1.8.8.3, nuster uses a different version system as MAJOR.MINOR.PATCH.HAPROXY_BRANCH.

* MAJOR: big feature release of nuster
* MINOR: small features, haproxy branch update
* PATCH: bug fixes, haproxy minor updates
* HAPROXY_BRANCH: 17 stands for v1.7.x, 18 for v1.8.x

## Legacy versions

https://github.com/jiangwenyuan/nuster/releases

| NuSTER version | HAProxy version | Previous nuster version
| -------------- | --------------- | ------------------
| 1.1.1.18       | 1.8.12          |
| 1.1.0.18       | 1.8.8           | 1.8.8.3
| 1.0.0.17       | 1.7.11          | 1.7.11.3
|                | 1.8.8           | 1.8.8.2
|                | 1.8.8           | 1.8.8.1
|                | 1.7.11          | 1.7.11.2
|                | 1.7.11          | 1.7.11.1
|                | 1.7.10          | 1.7.10.1
|                | 1.7.9           | 1.7.9.9
|                | 1.7.9           | 1.7.9.8
|                | 1.7.9           | 1.7.9.7
|                | 1.7.9           | 1.7.9.6
|                | 1.7.9           | 1.7.9.5
|                | 1.7.9           | 1.7.9.4
|                | 1.7.9           | 1.7.9.3
|                | 1.7.9           | 1.7.9.2
|                | 1.7.9           | 1.7.9.1

