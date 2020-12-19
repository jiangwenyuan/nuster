
## Latest versions

Branch | nuster version | Released   | Status              | Download
------ | -------------- | --------   | ------              | --------
master |                |            | HAProxy v2.4-dev3   |
5.3    | 5.3.0.23       | 2020-12-19 | Mainline version    | [nuster-5.3.0.23.tar.gz][7]
5.2    | 5.2.5.22       | 2020-12-19 | Stable version      | [nuster-5.2.5.22.tar.gz][6]
5.1    | 5.1.0.21       | 2020-07-09 | Mainline version    | [nuster-5.1.0.21.tar.gz][5]
H2.1   | 5.0.13.21      | 2020-07-09 | Unmaintained        | [nuster-5.0.13.21.tar.gz][4], renumbered to 5.1.0.21
H2.0   | 4.0.1.20       | 2020-04-11 | Unmaintained        | ~nuster-4.0.1.20.tar.gz~
H1.9   | 3.2.5.19       | 2020-04-13 | Critical fixes only | [nuster-3.2.5.19.tar.gz][3]
H1.8   | 2.0.16.18      | 2020-04-13 | Critical fixes only | [nuster-2.0.16.18.tar.gz][2]
H1.7   | 1.0.3.17       | 2019-11-02 | Unmaintained        | [nuster-1.0.3.17.tar.gz][1]

[7]:https://github.com/jiangwenyuan/nuster/releases/download/v5.3.0.23/nuster-5.3.0.23.tar.gz
[6]:https://github.com/jiangwenyuan/nuster/releases/download/v5.2.5.22/nuster-5.2.5.22.tar.gz
[5]:https://github.com/jiangwenyuan/nuster/releases/download/v5.1.0.21/nuster-5.1.0.21.tar.gz
[4]:https://github.com/jiangwenyuan/nuster/releases/download/v5.0.13.21/nuster-5.0.13.21.tar.gz
[3]:https://github.com/jiangwenyuan/nuster/releases/download/v3.2.5.19/nuster-3.2.5.19.tar.gz
[2]:https://github.com/jiangwenyuan/nuster/releases/download/v2.0.16.18/nuster-2.0.16.18.tar.gz
[1]:https://github.com/jiangwenyuan/nuster/releases/download/v1.0.3.17/nuster-1.0.3.17.tar.gz

## Versioning

Starting with v5.2, nuster uses a new version system as NUSTER_VERSION.PATCH.HAPROXY_BRANCH.

* NUSTER_VERSION
  * Designated as two numbers separated by a dot, for example "5.2"
  * Grows as a decimal number increased by 0.1 per version
  * even version for stable release, based on HAProxy even version, only bugfixes will be backported, for example "5.2"
  * odd version for mainline release, based on HAProxy odd version, new features, updates, bugfixes, for example "5.1"
* PATCH: bug fixes, haproxy minor updates
* HAPROXY_BRANCH: 21 stands for HAProxy v2.1.x, 22 for HAProxy v2.2.x

## Legacy versions

https://github.com/jiangwenyuan/nuster/releases

| nuster version                                                              | Base HAProxy version
| --------------                                                              | ---------------
| [5.3.0.23](https://github.com/jiangwenyuan/nuster/releases/tag/v5.3.0.23)   | 2.3.2
| [5.2.5.22](https://github.com/jiangwenyuan/nuster/releases/tag/v5.2.5.22)   | 2.2.6
| [5.2.4.22](https://github.com/jiangwenyuan/nuster/releases/tag/v5.2.4.22)   | 2.2.5
| [5.2.3.22](https://github.com/jiangwenyuan/nuster/releases/tag/v5.2.3.22)   | 2.2.3
| [5.2.2.22](https://github.com/jiangwenyuan/nuster/releases/tag/v5.2.2.22)   | 2.2.2
| [5.2.1.22](https://github.com/jiangwenyuan/nuster/releases/tag/v5.2.1.22)   | 2.2.0
| [5.1.0.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.1.0.21)   | 2.1.7
| [5.0.13.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.13.21) | 2.1.7
| [5.2.0.22](https://github.com/jiangwenyuan/nuster/releases/tag/v5.2.0.22)   | 2.2.0
| [5.0.12.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.12.21) | 2.1.7
| [5.0.11.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.11.21) | 2.1.5
| [5.0.10.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.10.21) | 2.1.4
| [5.0.9.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.9.21)   | 2.1.4
| [5.0.8.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.8.21)   | 2.1.4
| [5.0.7.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.7.21)   | 2.1.4
| [5.0.6.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.6.21)   | 2.1.4
| [5.0.5.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.5.21)   | 2.1.4
| [5.0.4.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.4.21)   | 2.1.4
| [5.0.3.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.3.21)   | 2.1.4
| [5.0.2.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.2.21)   | 2.1.4
| [5.0.1.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.1.21)   | 2.1.4
| [3.2.5.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.2.5.19)   | 1.9.15
| [2.0.16.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.16.18) | 1.8.25
| [5.0.0.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.0.21)   | 2.1.4
|  4.0.1.20                                                                   | 2.0.14
| [3.2.4.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.2.4.19)   | 1.9.15
| [2.0.15.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.15.18) | 1.8.25
| [5.0.0.21](https://github.com/jiangwenyuan/nuster/releases/tag/v5.0.0.21)   | 2.1.3
| [2.0.14.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.14.18) | 1.8.24
|  4.0.0.20                                                                   | 2.0.12
| [3.2.3.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.2.3.19)   | 1.9.14
| [3.2.2.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.2.2.19)   | 1.9.13
| [2.0.13.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.13.18) | 1.8.23
| [3.2.1.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.2.1.19)   | 1.9.13
| [3.2.0.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.2.0.19)   | 1.9.13
| [3.1.3.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.1.3.19)   | 1.9.12
| [3.1.2.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.1.2.19)   | 1.9.12
| [3.1.1.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.1.1.19)   | 1.9.12
| [2.0.12.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.12.18) | 1.8.22
| [1.0.3.17](https://github.com/jiangwenyuan/nuster/releases/tag/v1.0.3.17)   | 1.7.12
| [3.1.0.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.1.0.19)   | 1.9.11
| [3.0.0.19](https://github.com/jiangwenyuan/nuster/releases/tag/v3.0.0.19)   | 1.9.9
| [2.0.11.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.11.18) | 1.8.21
| [2.0.10.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.10.18) | 1.8.19
| [2.0.9.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.9.18)   | 1.8.19
| [2.0.8.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.8.18)   | 1.8.19
| [2.0.7.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.7.18)   | 1.8.17
| [2.0.6.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.6.18)   | 1.8.17
| [2.0.5.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.5.18)   | 1.8.14
| [2.0.4.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.4.18)   | 1.8.14
| [2.0.3.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.3.18)   | 1.8.13
| [2.0.2.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.2.18)   | 1.8.13
| [2.0.1.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.1.18)   | 1.8.13
| [2.0.0.18](https://github.com/jiangwenyuan/nuster/releases/tag/v2.0.0.18)   | 1.8.12
| [1.1.1.18](https://github.com/jiangwenyuan/nuster/releases/tag/v1.1.1.18)   | 1.8.12
| [1.0.2.17](https://github.com/jiangwenyuan/nuster/releases/tag/v1.0.2.17)   | 1.7.11
