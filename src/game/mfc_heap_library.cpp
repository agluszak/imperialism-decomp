// Retail MFC heap symbols (nafxcw.lib) — LIBRARY markers for reccmp pairing only.

// LIBRARY: IMPERIALISM 0x005e7f50
// _free (CRT free(), per symbols.csv -- not a game-specific tracking helper despite the
// Ghidra-guessed name; call the real `free()` at call sites, e.g. TZone.cpp)

// LIBRARY: IMPERIALISM 0x005e8310
// AllocateWithGlobalNewMode

// LIBRARY: IMPERIALISM 0x00606f73
// operator new

// LIBRARY: IMPERIALISM 0x00606faf
// operator delete

// CObject's PASCAL allocation pair: out-of-line COMDAT copies of the afx.inl inline
// bodies, emitted by game TUs and kept by the linker in the game-code range. MSVC500
// normally folds these inlines away to direct ::operator new/delete calls, but each TU
// has a finite inline-expansion budget; once a screen-builder TU exhausts it (verified
// empirically: allocation sequences inside the factory giants flip from inlined
// ::operator new to `call CObject::operator new` mid-function, e.g. after 39 allocs in
// 0x415fe0, after 10 in 0x41b6d0, never in 0x4601b0), every later `new TWidget()`
// calls this copy (~900 sites). Reproducing the exact flip points is a per-TU
// source-composition concern, not a flags/source-model one. CObject::operator delete
// is linked but unreferenced.

// LIBRARY: IMPERIALISM 0x0041b1c0
// CObject::operator new

// CString copy constructor: out-of-line COMDAT copy of the afx inline body, emitted by
// game TUs that pass CString by value (e.g. the nation-comparison advisory temps).
// LIBRARY: IMPERIALISM 0x0049eb00
// CString::CString(class CString const &)

// Same pattern: afx inline CString default/LPCSTR constructors spilled as COMDATs by
// game TUs.
// LIBRARY: IMPERIALISM 0x004b0970
// CString::CString(void)
// LIBRARY: IMPERIALISM 0x004ac370
// CString::CString(char const *)

// Same pattern: afx inline CString accessors spilled as COMDATs into the TViewMgr TU
// range (mis-named NoOp* callbacks by Ghidra: 0x5db2f0 is `mov eax,[ecx]; mov
// eax,[eax-8]` = GetData()->nDataLength, 0x5d5d10 is `mov eax,[ecx]` = m_pchData).
// Call sites use the real CString API (GetLength / operator LPCTSTR).
// LIBRARY: IMPERIALISM 0x005db2f0
// CString::GetLength
// LIBRARY: IMPERIALISM 0x005d5d10
// CString::operator char const *

// LIBRARY: IMPERIALISM 0x00413380
// CObject::operator delete
