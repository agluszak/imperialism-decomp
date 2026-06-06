// Real definitions for read-only global data referenced by hand-written code.
//
// These exist so reccmp can pair instruction operands that reference named global
// data (float coefficient tables, named global pointers) instead of bare immediate
// addresses. reccmp maps the original symbol (config/symbols.csv) to the recomp PDB
// symbol by name (the C-linkage leading underscore is stripped), so the *values* here
// are irrelevant to matching — only the symbol identity and its use site matter.
//
// Same mechanism as the g_p* pointer globals defined in diplomacy_state.cpp.
// Symbol names below are taken verbatim from config/symbols.csv (including the few
// historically double-named float tables) so the address mapping resolves.

extern "C" {

// Minister-skill-indexed float coefficient tables (DAT_0065xxxx), indexed by a
// minister's skill value at +0x0C. Used by TGreatPower vtable slots 0x88-0x8c.
float g_DAT_Value_00653308[8] = {0};
float g_DAT_Value_00653328[8] = {0};
float g_DAT_Value_00653340[8] = {0};
float g_DAT_Value_00653360[8] = {0};
float g_DAT_Value_00653378[8] = {0};
float g_DAT_Value_00653398[8] = {0};
float g_DAT_006533b0_Value_006533B0[8] = {0};
float g_DAT_006533d0_Value_006533D0[8] = {0};
float g_DAT_006533e8_Value_006533E8[8] = {0};
float g_DAT_Value_00653408[8] = {0};

// Named global pointers read with a direct absolute load in the original (vs the
// ReadGlobalPointer(imm) shortcut, which emits an extra indirection that cannot pair).
void* g_pMapActionContextListHead = 0;

} // extern "C"
