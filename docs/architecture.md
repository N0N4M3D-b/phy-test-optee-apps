# Repository Architecture

## Ownership boundary

This repository owns project-specific TA code, REE clients, shared ABI
headers, Makefiles, and target integration tests. OP-TEE OS, optee-client,
generic platform smoke tests, BSP metadata, and image composition belong to
their existing source or Yocto projects.

## Current component

```text
Repo manifest (one commit)
        |
        +-- infra-test/include/test_ta.h
                +-- infra-test/ta
                +-- infra-test/host
```

The shared header is the single definition of the UUID, command identifiers,
parameter contracts, and test constants. ABI changes require coordinated TA,
REE client, recipe, and documentation updates.

## Yocto integration

The workspace manifest owns fetch and revision selection. Consumer recipes
inherit `optee-apps-source.bbclass`, select an `OPTEE_APPS_SUBDIR`, and use the
common TA or host build class. Application C sources are not copied into recipe
`files/` directories.

The generic TF-A/U-Boot hand-off, Linux, userspace, and TEE smoke test lives in
`sources/userland/apps/platform-component-test`; its TEE portion invokes
`ta-test-app`.

## Change workflow

1. Change the ABI, TA, client, and tests together.
2. Build affected recipes and run the target test.
3. Commit and push this repository.
4. Pin the remotely available commit in the workspace manifest.
5. Commit manifest and layer changes separately.

`${AUTOREV}` and recipe-specific revisions are not permitted for this source.

## Adding a TA family

Add a top-level directory with `include/`, `ta/`, and, when needed, `host/`.
Keep UUIDs, command IDs, and parameter contracts in the shared header, then
add thin layer recipes that select the corresponding subdirectories.
