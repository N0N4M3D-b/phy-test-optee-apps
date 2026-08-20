# Physical Badge OP-TEE Applications

This repository is the single source of truth for project-owned OP-TEE
Trusted Applications (TAs), their Rich Execution Environment (REE) host
applications, and integration tests.

OP-TEE OS itself is intentionally not included here. It is maintained in the
separate `sources/optee` project.

## Layout

```text
infra-test/
  include/                 Shared TA/REE ABI
  ta/                      OP-TEE infrastructure test TA
  host/                    REE test client (`ta-test-app`)
secure-uart/
  include/                 Shared Secure UART TA/REE ABI
  ta/                      Secure UART TA
  host/daemon/             REE UART daemon
tests/
  secure-uart-test/        Cross-component target test suite
LICENSES/                  License texts referenced by Yocto recipes
```

The headers below are ABI contracts and must be used by both sides rather
than copied into individual components:

- `infra-test/include/test_ta.h`
- `secure-uart/include/secure_uart_ta.h`

## Yocto build

From the workspace root:

```sh
source layers/openembedded-core/oe-init-build-env \
    build-nodistro-stm32mp15-disco
bitbake optee-ta-test ta-test-app
bitbake optee-ta-secure-uart secure-uart-daemon secure-uart-test
```

The Repo manifest fetches and pins this checkout. The custom layer consumes
that exact working tree through `externalsrc`; individual recipes do not fetch
or select revisions independently.

See `docs/architecture.md` for ownership and dependency rules.
