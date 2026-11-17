# zmanager-unrar

Bindings for UnRAR extraction operations used as the native RAR backend in ZManager.

The vendored C++ sources are UnRAR 7.23 from
[RARLAB's release tarball](https://www.rarlab.com/rar/unrarsrc-7.2.7.tar.gz).
Its SHA-256 is `01d903a7dcf413cb2925696d7796e48e38d471f79bfe7ef3ad2aebf6c12dbefd`.
ZManager carries its Unix UTF-8 conversion fix in `unicode.cpp` and applies
portable CPU dispatch fixes to build copies of `system.cpp` and `rijndael.cpp`.

Part of the [ZManager](https://github.com/tzap-org/zmanager) universal file archiving suite.
