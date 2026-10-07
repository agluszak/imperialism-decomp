# Clang-tidy scalar analysis

The MSVC 5.0 image includes the project clang-tidy plugin built from
`ScalarFacts.cpp`, `BoolLikeByteCheck.cpp`, and `RedundantScalarCastCheck.cpp`
against pinned LLVM/Clang 21.

The native source facts collector records declaration identities, value
transfers, types, uses and source locations across selected translation
units. Its output is current-source evidence, **not** proof of original
declaration spelling or of retail integer width.

`just scalar-facts` runs the existing corpus collector; the Python
`clang-tidy-wrapper.py` can process collected facts and produce an
inspection report or a proposed source patch. Review all proposals against
independent retail, Mac source, ABI or serialization evidence before applying.
No report or patch modifies source automatically.

The byte-domain check identifies possible boolean declarations from observed
0/1 producers. Ambiguous aliases, incomplete bodies, arithmetic and ABI
boundaries must not be inferred away. Similarly, current compiler types do
not justify changing packed fields, call signatures or enum domains.

Use `just lint` for the normal compiler-backed gate. The source collector
and report writer remain tooling implementation details; this README is
not a historical campaign log or a replacement for their schemas and tests.
