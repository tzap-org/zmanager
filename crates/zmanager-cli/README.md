# zmanager-cli

Command-line archive manager powered by `zmanager-core`.

Part of the [ZManager](https://github.com/tzap-org/zmanager) universal file archiving suite.

## Installation

```sh
cargo install zmanager-cli
```

## Quick Start

```sh
zm -cf project.zip project/
zm -xf project.zip -C out/

zm create project.tzst project/
zm extract project.tzst -C out/

zm list project.zip
zm test project.zip
```

For full documentation and feature overview, visit the [ZManager repository](https://github.com/tzap-org/zmanager).
