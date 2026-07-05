# Function documentation workflow (interactive Ghidra)

Methodology for documenting a function directly in the Ghidra database (GUI or MCP
tools) with high accuracy the first time: establish guidelines, do a mandatory type
audit, analyze the function, identify structures early, name and type all elements,
write documentation, verify completeness. This is for *annotating Ghidra*; for
porting a function to matching C++ use the `decomp-loop` skill.

## Execution guidelines

Apply changes directly in Ghidra (do not create files). Typical MCP tool sequence:
`rename_function_by_address`, `set_function_prototype`, `batch_create_labels`,
`rename_variables` (iterating), `set_plate_comment`, `batch_set_comments`. For
connection timeouts, retry once then switch to smaller batches. When reprocessing a
function, re-apply naming/prototype/documentation and overwrite weaker existing
values with better analysis.

## Initialization and analysis

Identify the function at the cursor and verify its boundaries (all code blocks and
return instructions belong to it); recreate the function if boundaries are wrong.
Gather decompiled code, cross-references, callees, callers, disassembly, and
variables. Study the decompiled body for purpose, examine callers for context,
review callees for dependencies, analyze disassembly for memory-access patterns.

## Function classification

Classify the role to guide documentation depth: **Leaf** (no calls — focus on the
algorithm), **Worker** (real work — full semantics), **Thunk/Wrapper** (single call —
document what it wraps), **Init/Cleanup** (state management — document the sequence),
**Callback/Handler** (event-driven — document triggers), **Public/exported API**
(comprehensive), **Internal utility** (document assumptions). APIs and init paths need
maximum rigor; thunks need only a contract.

## Mandatory undefined-type audit

After retrieving function info, examine BOTH the decompiled code and the disassembly
for undefined types: return types, locals, parameters, struct fields, and especially
assembly-only variables (stack temporaries, FPU/XMM spills, intermediate
calculations). Build a resolution plan (`undefined4` counter→`int`, flags→`uint`,
dereferenced→typed pointer, `undefined1[10]` FPU→`byte[10]`). Resolve all undefined
types before renaming.

**Phantom variables**: Ghidra may show assembly-only temporaries the decompiler
optimized away. If "Variable not found" occurs, document in the plate comment but
skip type-setting.

## Verify decompiler output against assembly

Validate where decompilers commonly err: **Loops** (bounds, counter increment, trip
count vs assembly), **Type casts** (compare with actual `mov`/`lea`; spurious casts
hint at stack-alignment issues), **Pointer arithmetic** (stride 1×/2×/4×/8×),
**Conditionals** (`JZ` may be inverted), **Early exits** (tail calls misrepresented as
returns). Document discrepancies in the plate comment. (For MSVC x86 specifically,
watch `ret 0xN` stack-cleanup sizes — they reveal hidden stack args and the real
calling convention; see `decomp-loop/heuristics.md` #5, #6.)

## Control flow and loop mapping

Map execution paths before naming. Identify all return points and their conditions.
For each loop: header, induction variable, bounds, exit condition, nesting depth,
stride — verified against disassembly. Document error paths separately. This map
becomes the Algorithm section.

## Structure identification

Identify every structure type accessed; search existing data types for a match, or
create one from assembly offsets. Use identity-based names (`Player`, not
`InitializedPlayer`). Document the memory model: who allocates/frees, pointer
lifetime, input ownership, shared globals, stack-frame layout, register preservation.

## Naming and prototype

Rename with descriptive **PascalCase**, action-verb first
(Get/Set/Init/Process/Update/Validate/Create/Free/Handle/Is/Has/Find/Load/Save/Draw/
Render/Parse/Build/Calculate). Examples: `GetPlayerHealth`, `ProcessInputEvent`,
`ValidateItemSlot`.

**Never use**: snake_case `PREFIX_*` (`SKILLS_GetLevel`→`GetSkillLevel`), lowercase
start (`processData`→`ProcessData`), single word without verb (`Player`→`GetPlayer`),
ALL_CAPS, or generic numbered suffixes (`Handler1`→`HandleSkillActivation`).

Set the return type from EAX examination. Define a complete prototype with proper
types (`TGreatPower*` not `int*`) and camelCase parameter names (`pPlayerNode`,
`nResourceCount`). Verify the calling convention from register usage:
`__cdecl` / `__stdcall` / `__fastcall` / `__thiscall`. Document implicit register
parameters explicitly.

## Hungarian notation reference

**Builtins**: byte→b, char→c, bool→f, short→n, ushort→w, int→n, uint→dw, long→l,
ulong→dw, longlong→ll, ulonglong→qw, float→fl, double→d.

**Pointers**: void*→p, byte*→pb, ushort*→pw, uint*→pdw, int*→pn, float*→pfl,
double*→pd, char*→lpsz (param)/sz (local), struct*→p+StructName; double pointers add a
second `p`. Const: const char*→lpcsz/csz, const void*→pc.

**Arrays** (stack arrays only): byte[N]→ab, ushort[N]→aw, uint[N]→ad, int[N]→an.

**Globals**: add `g_` (`g_dwProcessId`, `g_pMainWindow`). Function pointers stay
PascalCase without `g_`.

**Type normalization**: UINT→uint, DWORD→uint, USHORT→ushort, BYTE→byte, BOOL→bool,
LPVOID→void*, undefined1→byte, undefined2→ushort, undefined4→uint/int/float/pointer,
undefined8→double/longlong.

## Variable renaming

Identify ALL variables in both views (parameters, locals, SSA temporaries `iVar1`,
register inputs `in_ST0`, implicit returns `extraout_EAX`, stack params, undefined
arrays, assembly-only vars). **Step 1**: set correct normalized types. **Step 2**:
rename with Hungarian notation. For failed renames add a comment
("in_XMM1_Qa (qwBaseExponent): quad-precision parameter"); for assembly-only vars add
an EOL comment ("[EBP-0x14] - dwTempFlags").

## Global data renaming

Rename all `DAT_*`/`s_*` globals (find high-impact ones by xref count). `DAT_*`→`g_`
prefix; strings→`sz` (ANSI)/`wsz` (wide)/`szFmt`/`szPath`. For external/API calls,
document behavior, parameters, return semantics, side effects, and add an inline
comment naming the call.

## Plate and inline comments

Plate comment (plain text, no decorative borders): one-line summary; Algorithm
(numbered steps); Parameters (types + IMPLICIT keyword where relevant); Returns
(success/error values); Special Cases; Magic Numbers Reference; Error Handling;
Structure Layout table (Offset/Size/Field/Type/Description); Flag Bits (consistent
hex). Inline PRE_COMMENTs explain context, magic numbers, edge cases, and algorithm
steps; disassembly EOL_COMMENTs are concise (≤32 chars) and offset-matched to the
disassembly, not the decompiler line order.
