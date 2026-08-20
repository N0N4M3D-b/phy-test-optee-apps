# Repository Architecture

## Ownership boundary

This repository owns project-specific security applications:

- Trusted Application implementation and TA metadata
- REE client applications and daemons
- TA/REE ABI headers
- component Makefiles and target-side integration tests

It does not own OP-TEE OS, the OP-TEE client runtime, STM32MP BSP metadata,
or the final image composition. Those remain in their existing upstream or
Yocto layer projects.

## Component boundaries

Each TA is grouped with the REE programs that directly consume its ABI.
Shared headers live above `ta/` and `host/` so neither side becomes the
owner of the protocol definition.

The `tests/` tree is separate because an integration test may exercise more
than one TA. `secure-uart-test`, for example, validates both the
infrastructure test TA and the Secure UART TA.

```text
Repo manifest (one commit)
        |
        +-- infra-test/include/test_ta.h
        |       +-- infra-test/ta
        |       +-- infra-test/host
        |       +-- tests/secure-uart-test
        |
        +-- secure-uart/include/secure_uart_ta.h
                +-- secure-uart/ta
                +-- secure-uart/host/daemon
                +-- tests/secure-uart-test
```

## ABI rules

UUIDs, command identifiers, parameter contracts, packet structures, and
session-state values must be defined exactly once in the component's shared
header. ABI changes require coordinated TA, REE, test, recipe-revision, and
protocol documentation updates in one change set.

## Yocto integration

The workspace manifest is the only fetch and revision owner. All consuming
recipes inherit `optee-apps-source.bbclass`, which points `EXTERNALSRC` at
`sources/optee-apps`. A recipe sets only `OPTEE_APPS_SUBDIR` and inherits the
TA or host build class. This prevents a TA binary and its REE client from
being assembled from different commits and avoids parse-time source switching.

The layer owns packaging, dependencies, systemd installation, and image
composition. This repository owns C code, shared headers, component
Makefiles, and service source files.

## Change and release workflow

1. Change the ABI header, TA, host program, and tests together in this repo.
2. Build all affected recipes and run the target integration test.
3. Commit and push this repo.
4. Pin that pushed commit in the workspace manifest.
5. Commit the manifest and any layer metadata changes separately.

The manifest must reference a fixed, remotely available commit. `${AUTOREV}`
and recipe-specific Git revisions are not permitted.

## Adding another TA family

Add a top-level component directory with `include/`, `ta/`, and, when needed,
`host/`. Put UUIDs, command IDs, parameter contracts, and wire structures in
the component `include/` directory. Add layer recipes that select subdirs;
do not copy source into recipe `files/` directories.

## Security status

The Secure UART authentication verifier is still a development placeholder
in `crypto_verify_auth()`. Repository consolidation does not make that
protocol production-ready; peer authentication and protocol threat-model
review remain required before deployment.
