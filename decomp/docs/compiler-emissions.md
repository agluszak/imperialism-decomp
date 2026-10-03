# Compiler emission identities

Authored source keeps FUNCTION, GLOBAL and VTABLE annotations. Compiler helpers,
deleting destructors, macro-generated methods and template instantiations are
binary identities in `config/compiler_emissions.csv`, combined with
`config/original_entities.csv` when `tools/generate_symbols.py` writes disposable
`build-msvc500/generated/symbols.csv`. Source does not need SYNTHETIC/TEMPLATE
markers or invented APIs to expose those emissions.

The emission catalog migrates the existing identities mechanically. Its
`legacy-marker` provenance identifies inherited recovery hypotheses rather than
independent original symbol evidence. Historical source paths are diagnostics,
not source ownership. Ownership-only entries can have no name/symbol; they still
exclude the address from generated stubs. The original inventory remains intact.

`tools/source_model.py` owns authored source claims and rejects emission markers.
`tools/emissions.py` reads compiler emission identities independently.
`tools/generate_symbols.py` combines both at the metadata boundary, and
`tools/stubgen.py` suppresses every catalog emission in addition to reviewed stub
exclusions. The library identity gate validates emission projection against the
catalog without calling it authored source.

Generating metadata does not generate a destructor or template implementation.
Retain normal period C++ and let MSVC emit the helper naturally. An ambiguous
identity stays unresolved until original inventory, PDB, vtable or corroborated
binary analysis supplies evidence; address adjacency is not evidence.
