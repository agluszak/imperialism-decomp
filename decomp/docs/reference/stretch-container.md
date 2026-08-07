# stretch<T> container evidence

`stretch<T>` is a project-local growable-array family known from Mac CodeWarrior
symbols, not an MFC/ATL/STL collection name. The vendored Mac evidence names
`stretch<char>`, `stretch<short>`, `stretch<Seapoint>`, and `stretch<SeaSegment>`
with methods such as `Add`, `operator[]`, `OverStretch`, and `~stretch`.

Windows TZone evidence does not prove Mac/Windows code identity, but it does match a
stretch-like source model better than stock MFC arrays:

| Evidence | Observation |
| --- | --- |
| `TZone::TZone` at `0x0055e700` | initializes two adjacent 0x10-byte polymorphic subobjects at `+0x24` and `+0x34` |
| `0x0055e8e0` / `0x0055e9c0` | linear-scan `data[0..count)` and append if missing |
| `0x0055ead0` / `0x0055eba0` | append one element, growing capacity by roughly 2x |
| `CPtrArray` / `CObArray` / `CArray` | stock MFC arrays are 0x14 bytes and use `m_nGrowBy` / `SetSize`, so they do not match |
| `CMap*` | stock MFC maps use hash tables and assoc nodes, not a linear pointer vector |

The current Windows source models the TZone neighbor storage as two tagged
`stretch<TZone*>` instantiations. The tags are a Windows reconstruction device for
the two distinct embedded vtables; they should not be read as Mac evidence for exact
template arguments.

