# Third-Party Notices

Date: 2026-05-16

This document records bundled third-party code that ships with the public
Z-Manager CLI/core workspace.

## UnRAR

Z-Manager vendors the UnRAR source under `vendor/unrar` and builds it through
the `zmanager-unrar` crate for extraction-only RAR support. The bundled copy is
used for RAR listing and extraction, including passworded RAR archives.
Z-Manager must not use this code to create RAR archives or recreate the RAR
compression algorithm.

The bundled license is stored at `vendor/unrar/license.txt`. The required
license paragraph is also included in `crates/zmanager-unrar/src/lib.rs`.

Required notice:

```text
UnRAR source code may be used in any software to handle RAR archives
without limitations free of charge, but cannot be used to develop RAR
(WinRAR) compatible archiver and to re-create RAR compression algorithm,
which is proprietary. Distribution of modified UnRAR source code in
separate form or as a part of other software is permitted, provided that
full text of this paragraph, starting from "UnRAR source code" words, is
included in license, or in documentation if license is not available, and
in source code comments of resulting package.
```
