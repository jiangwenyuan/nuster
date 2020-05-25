# nuster Changelog

## 5.0.10.21 - 2020-05-25

### Fixed

* Improve disk load speed
* Add clean-temp, remove temp file or not on startup
* Use full search for Host header
* Use a more random code to generate temp file
* Fix fd leak, should use not equal instead of equal
* Quit if open tmp dir failed and refine alert message

## 5.0.9.21 - 2020-05-20

### Fixed

* Fix incorrectly deletetion of disk cache when use-stale is on

## 5.0.8.21 - 2020-05-19

### Added

* Add use-stale

### Changed

* Enforce unique rule name
* Use name again and check proxy and rule name in advance
* Fix incorrect purge mode check
* Save proxy and rule name into disk
* Move txn.buf to ctx
* Use prop in disk_store_init, simplify meta_init
* Use prop in various functions
* Remove unused entry.rule
* Remove unused proxy uuid in ctx and entry, remove rule.id
* Use proxy name and rule name for purging
* Add proxy to entry and ctx

## 5.0.7.21 - 2020-05-09

### Fixed

Fix premature end of nosql engine
Support etag/last-modified in nosql mode
[nosql] Handle backend server abort
Improve disk cache performance by indicating
Change disk.offset to 64 bits to support files greater than 4gb
Remove unnecessary task wake
Update debug info, correct create failed message
Handle backend server abort
Incorrect nosql vars in cache engine

### Added

Enable extend in nosql mode
Support etag last-modified in nosql mode
Check disk version
Move update_nosql_stat to filter header
Add etag and last_modified flag into ctx
Save etag and last_modified flag into disk
Move etag/last-modified handler to http
Check max ttl and wait
Update wait format, use on/off

## 5.0.6.21 - 2020-05-05

### Fixed

Fix incorrect header_len and payload_len in sync mode
Reduce disk padding in stats proxy rule
Remove stats.nosql.abort

### Added

Support wait for identical requests to cache
Add wait to rule
Add a mechanism to speed up the data clean process
Record invalid ring.data count
Add store into dict and add ring.invalid

## 5.0.5.21 - 2020-05-03

### Fixed

* Stats applet check should return 0 as the request...
* Fix unclosed fd in nosql disk hit mode
* Apply shctx fixes
* Use warning instead of alert for same rule warning
* Fix ctx.key memory leak in nosql
* Create nosql header in advance
* Fix incorrect handling of nosql full
* Fix incorrect nosql stats, use method
* Add store abort, clean resources when the store is failed
* Set nosql entry state to init if failed to create it
* Fix error check of nst_nosql_delete
* Fix incorrect nosql mode
* Set entry state to init when deleting nosql entry
* Modify break time of housekeep
* Set state to init when delete a nosql entry if...
* Lock the dict before set entry from disk...
* Limit max run time in housekeep related functions
* Fix segfault if deleting a nosql entry which is being created
* Fix incorrect handling of getting max
* Fix incorrect nosql stats, add nosql.abort
* Do not wait on nosql post
* Remove files in tmp dir on startup
* Fix needless readdir before loop
* Use a temp dir for creating temp file...
* Return not found when a key is creating
* nosql: handle trailers
* Check entry.store.ring.data before set invalid
* nosql: Add EOT if the request is not chunked
* Set ctx.state to init in exist check
* Apply incorrect handling of offset in nosql
* Fix asan error
* Do not print attach log if not on nuster enabled proxy
* Suppress build warnings
* Fix incorrect handling of offset in payload update

## 5.0.4.21 - 2020-04-22

### Fixed

* Payload does not send completely

## 5.0.3.21 - 2020-04-21

### Changed

* Lock the ring before add or del clients of ring_data
* Set header_len and payload_len to 0 before add headers
* Add ring.count and several other stats
* Handle trailers
* Ignore HTX_BLK_UNUSED
* Backport v2.2-dev6
* Update README, add new sample fetches
* Add several new sample fetch

## 5.0.2.21 - 2020-04-15

### Fixed

* Add dict to stats
* Fix manager segfault when mode is not present
* Fix segfault when get stats if both cache and nosql are off
* Add bytes to stats.cache
* Add payload_len to entry, set header_len and payload
* Fix stats url
* Use calloc instead of malloc
* Fix incorrect clients decrement
* Fix bogus stream spinning issue.

## 5.0.1.21 - 2020-04-13

### Fixed

* uint32 overflow When data-size is bigger than 4GB
* Add nst_dict_entry_valid, use it in sync
* Set entry.ring.data to NULL on invalid
* Fix incorrect nosql for cache
* Update dict_invalid check
* Only set entry.state to invalid, leave the free stuff to cleanup
* Set entry.state to invalid if its state is init on finish
* Set ctx.ring.data to NULl on ring_data_add failure
* Fix disk_cleanup readdir error

## 5.0.0.21 - 2020-04-11

A complete refactored version based on HTX version of HAProxy. Lots of changes, updates, improvements, to name a few:

* Add nuster manager, moved purge-method and uri to manager, support both cache and nosql
* Update new stats, support both cache and nosql
* Update purger, add basic and advance purger, support creating key based on rule
* Add memory on|off, disk on|off|sync, in form of backend store, more easier to add new store
* Create new key, avoided redundant compuating, improved performance
* Unified lots of components

## 5.0.0.21-dev1 - 2020-02-14

Upgrade to HAProxy v2.1.3

### Changed

* Remove legacy HTTP mode code

## 4.0.0.20 - 2020-02-13

Upgrade to HAProxy v2.0.12

### Added

* HTX support
* Extend, auto extend ttl

## 3.2.3.19 - 2020-02-13

Upgrade to HAProxy v1.9.14

## 3.2.2.19 - 2020-02-11

### Fixed

* Fix incorrect rule comparison
* Fix memory corruption
* Fix segfault when free temp key

## 3.2.1.19 - 2020-01-20

### Fixed

* Fix cache.hit not updating in disk only mode

## 3.2.0.19 - 2019-12-18

Upgrade to HAProxy v1.9.13

### Fixed

* Fix segfault when memory is full

### Added

* Last-Modified and ETAG
* Conditional request handling

## 3.1.3.19 - 2019-11-16

### Fixed

* Fix Segmentation fault on send PURGE

## 3.1.2.19 - 2019-11-03

* Enable response rule evaluation for nuster handler

## 3.1.1.19 - 2019-11-02

Upgrade to HAProxy v1.9.12

## 3.1.0.19 - 2019-10-03

### Added

* nuster.cache.hit sample fetch
* disk support in stats
* purge persistence files
* Merge HAProxy v1.9.11

### Changed

* Save host and path in persist file

### Fixed

* Close fd and remove invalid cache files
* fd is not closed in creating disk cache file
* Fix incorrect key allocation
* Fix segfault when tune.bufsize is not 16k

## 3.0.0.19 - 2019-07-29

Add disk persistence, various updates, refactoring

## 2.1.2.19 - 2019-04-26

### Fixed

* clients does not decrease on connection close

## 2.1.1.19 - 2019-04-24

### Fixed

* Empty response from Nuster for content in cache #40

## 2.1.0.19 - 2019-03-10

Upgrade to HAProxy v1.9.4

## 2.0.8.18 - 2019-03-10

Upgrade to HAProxy v1.8.19

## 2.0.7.18 - 2019-01-29

### Fixed

* ACL does not work for response

## 2.0.6.18 - 2019-01-15

Upgrade to HAProxy v1.8.17

### Changed

* Use rs,ks as key separator
* Use different separator in key header list
* Work with key headers defined as comma-separated lists

* Fix incorrect acl check

## 2.0.5.18 - 2018-12-11

### Fixed

* Fix incorrect acl check

## 2.0.4.18 - 2018-12-08

### Fixed

* Fix some init issues
* Fixed uninitialized stats shctx
* Fix missed uri.data
* Check msg len before update data
* Update cache create order to prevent potential lock
* Set entry->data to null when forward error
* Assign to temp var
* Fix missed uri.data
* Fixed bitmap overlap
* Series of fixes backported from cache part
* Fix incorrect len when build BODY cache key
* Fix improper handling of MSG_ENDING
* Send response header asap.
* This fix separate header and body, and send header along.
* Allocate entry_key before entry
* Initialise ctx.req to prevent incorrect release
* Check data before release
* Do not pass tail to _nst_cache_data_append
* Check state in io handler
* Release element when failed to allocate data
* Change incorrect CTX_PASS to CTX_BYPASS
* Upgrade HAProxy to v1.8.14

## 2.0.3.18 - 2018-10-05

### Fixed

* Fix #28, stalled response

## 2.0.2.18 - 2018-08-15

### Fixed

* Fix #24, segfault when insufficient memory
* Fix #23, disable usage of nuster in listen
* Fix #22 Wrong rule parsing

### Changed

* Change default ttl from 3600 to 0

## 1.0.1.17 - 2018-08-15

Same as 2.0.2.18

## 2.0.1.18 - 2018-08-05

Upgrade HAProxy to v1.8.13

## 2.0.0.18 - 2018-07-06

Add NoSQL mode.

nuster can be used as a RESTful NoSQL cache server, using HTTP `POST/GET/DELETE` to set/get/delete Key/Value object.

It can be used as an internal NoSQL cache sits between your application and database like Memcached or Redis as well as a user facing NoSQL cache that sits between end user and your application.
It supports headers, cookies, so you can store per-user data to same endpoint.

* All features from HAProxy(HTTPS, HTTP/2, ACL, etc)
* Conditional cache
* Internal KV cache
* User facing RESTful cache
* Support any kind of data
* Support all programming languages as long as HTTP is supported

## 1.1.1.18 - 2018-07-06

Merge HAProxy v1.8.12

## 1.1.0.18 - 2018-07-06

## 1.0.0.17 - 2018-07-06

Previously nuster used HAPROXY_VERSION.NUSTER_VERSION(eg, v1.8.8.3) which is very straightforward to find out the base HAProxy version, but very hard to tell whether it is a major r

Starting from v1.8.8.3, nuster uses a different version system as MAJOR.MINOR.PATCH.HAPROXY_BRANCH.

* MAJOR: big feature release of nuster
* MINOR: small features, haproxy branch update
* PATCH: bug fixes, haproxy minor updates
* HAPROXY_BRANCH: 17 stands for v1.7.x, 18 for v1.8.x

## 1.8.8.3 - 2018-06-08

### Fixed
- Broken rule key parser in config file (Thanks to Nelson)

## 1.7.11.3 - 2018-06-08

### Fixed
- Broken rule key parser in config file (Thanks to Nelson)

## 1.8.8.2 - 2018-05-29

### Fixed
- Rare case segfault when comparing a valid entry with null entry->key (Thanks to Martin)
- Incorrect address when appending separator to long cache key (Thanks to Klaus)

## 1.7.11.2 - 2018-05-28

### Fixed
- Rare case segfault when comparing a valid entry with null entry->key (Thanks to Martin)
- Incorrect address when appending separator to long cache key (Thanks to Klaus)

## 1.8.8.1 - 2018-05-07
Upgrade to HAProxy v1.8.8

## 1.7.11.1 - 2018-05-07
Upgrade to HAProxy v1.7.11

## 1.7.10.1 - 2018-04-22

### Added
- Upgrade to HAProxy v1.7.10
- Proxy mode

### Changed
- Refactoring
  - Separate include nuster directory
  - Split headers
  - Separate src nuster directory
  - Split source
  - Append nuster/nst to functions and variables
- Update config keyword
  - global: cache to nuster cache
  - proxy: filter cache to nuster cache
  - proxy: cache-rule to nuster rule
- Remove share on|off keyword

## 1.7.9.9 - 2018-04-01

### Added
- Cache stats applet
- Various cache stats

### Changed
- Separate cache manager file/applet
- Rename manager_uri to uri for reuse
- Simplify default key, use uri instead of path.delimiter.query

### Fixed
- A security bug which can bypass ACL by tampering with Host header(Thanks to Dan Reif)

## 1.7.9.8 - 2018-03-21

### Added
- Purge cache by host
- Purge cache by path
- Purge cache by regex

### Changed
- Incorrect host and path of cache.entry

## 1.7.9.7 - 2018-03-12

### Added
- Purge all cache
- Purge the cache belong to a proxy
- Purge the cache belong to a cache-rule

### Changed
- Performance improvement by parsing necessary data in advance instead of doing that in iterating cache-rules
- Unified cache manager entry

## 1.7.9.6 - 2018-03-01

### Added
- Update ttl at run time
- Single API to update ttl and state
- A new time parser

### Changed
- Put ttl in shared memory

## 1.7.9.5 - 2018-02-20

### Added
- Cache manager API
- Cache manager applet
- Enable and disable cache-rule at run time

### Changed
- Rename cache applet
- Change default share memory size

## 1.7.9.4 - 2018-02-03

### Added
- New uri and delimiter keywords

### Fixed
- Check query before set query_len
- Fix #6 cache key normalization

## 1.7.9.3 - 2018-01-25

### Added
- Cache purge by key
- Customize purge method

### Fixed
- Crash when serve non-standard http method

## 1.7.9.2 - 2017-12-15

### Added
- Shared memory
- Multiple processes support
- Enable/disable shared memory in config

### Changed
- Move used-memory to cache stats
- Store cache stats in shared memory
- Change cache housekeeping strategy

## 1.7.9.1 - 2017-11-06
Initial release
