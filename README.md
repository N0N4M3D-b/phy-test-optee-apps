# Physical Badge OP-TEE Applications

This repository is the single source of truth for project-owned OP-TEE
Trusted Applications (TAs), their Rich Execution Environment (REE) clients,
and shared ABI headers. OP-TEE OS itself lives in `sources/optee`.

## Current layout

```text
infra-test/
  include/test_ta.h       Shared TA/REE ABI
  ta/                     OP-TEE infrastructure test TA
  host/                   REE test client (`ta-test-app`)
LICENSES/                 Recipe license texts
docs/architecture.md      Ownership and integration rules
```

The infrastructure suite covers Client/TA echo, random generation, AES
round-trip, HMAC-SHA256, and Secure Storage. Secure UART sources and packages
were removed from the active project on 2026-08-20.

## Build and target test

```sh
source layers/openembedded-core/oe-init-build-env \
    build-nodistro-stm32mp15-disco
bitbake optee-ta-test ta-test-app
```

```sh
ta-test-app --verbose
```

The Repo manifest pins this checkout. Recipes consume the same working tree
through `externalsrc` and do not select independent revisions.
