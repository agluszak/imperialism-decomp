# Compiler and linker

The matching build uses Visual C++ 5.0 **RTM**, with the original-era
compiler and LINK 5.00.7022. Its build definition, flags and image are
owned by the CMake and `just` configuration, not this document.

## Why RTM

The retail PE records linker version 5.0 and a 1997-10-31 link date.
VC5 SP1/SP2 use LINK 5.02.7132; SP3 uses LINK 5.10.7303 with a
1997-11-04 toolchain timestamp. Isolated full-build comparisons
also worsened by roughly 260 exact functions under SP1/SP3.
Do not switch service packs merely to improve selected functions.

## Matching configuration

- The established comparison build uses `/Oy`, `/Ob1`,
  `/OPT:NOREF`, `/OPT:NOICF`.
- `/OPT:REF` discards unreferenced functions needed for independent
  comparisons; enabling ICF collapses bodies and undermines vtable pairing.
- The retail image retains old incremental-link islands and folded
  functions. A clean rebuild cannot recreate its relink history.
  Model source normally; treat the remaining differences as linker/pairing
  evidence, not permission to add aliases, manual inlining or overrides.
- The pinned DirectX headers must expose the DirectPlay2 layout observed
  in retail, not the incompatible DirectX 1 `IDirectPlay` interface
  shipped by some historic compiler bundles.

## Separate lint compiler

`just lint` uses the pinned clang-cl toolchain with the VC5/MFC
and DirectX headers to detect structural/type problems.
It is not the matching compiler. Its diagnostics must not determine
original source spelling or override direct retail evidence.

Ghidra uses the pinned fork and Java 25; setup is in the project
[README](../README.md). The reviewed GZF archive is restored with
`just restore-project` and exported after intentional database changes.

## PE resources

Retail embeds a `.rsrc` section with MENU/ACCELERATOR 128.
The owned `resources/imperialism_game.rc` supplies these for the rebuilt
image. `just resource-check` verifies the required resource boundary.
