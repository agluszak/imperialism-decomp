# 0x55d200 BuildInterNationEventSummaryRowsForAdvisorDialog — decode notes

Receiver: the 'main'-tagged panel of g_pDisplayMgr->activeDialog (caller 0x5d8c40
HandleTurnEvent2103_RunNationStatusReportUpdate: activeDialog->ResolveControlByTag('main'),
AssertValid, sfx 0x14b4, call 0x55d200(arg from caller's [esp+0x10]), then
activeDialog->vslot 0x4f [0x13c]). Non-virtual thiscall, RET 4, 1 int arg.
Class = unrecovered 'main' panel (TView-family; uses own fields +0x90 (cached arg)
and +0x94 (resource stream)). Sibling methods on same class: 0x55d910
FormatInterNationEventRowTokensToSharedStrings (272B, thiscall(entry, CString* tokens4)),
0x55df50 AppendInterNationEventSummaryTextEntry (532B, thiscall, 7 args
(col, y, a, b, TControlPictureRectState*, flag, CString* tokens4), returns height delta).

Body outline:
- CString tokens[4] local (eh vector ctor 0x5e8c50, ctor thunk 0x404642, dtor 0x405fa1) at F-0x1c.
- field90 = arg.
- CString strA(F-0x54, st0), strB(F-0x50, st1), strC(F-0x58, st2).
- CString texPath = g_pLanguageMgr->GetNewsTexPath() (byval temp st3);
  field94 = g_pUiViewManager->LoadTableResourceStreamByName(texPath) (0x5df430).
- 3 style descriptors + 4 zero bytes each at styleRef6:
  descA=F-0x40 Init(descA,0,0xc,0x2b67,2); descB=F-0x28 Init(descB,1,0xe,0x2b67,2);
  descC=F-0x34 Init(descC,0,0xe,0x2b67,2). InitializeUiTextStyleDescriptor=0x5c3f50.
- date = ResolveControlByTag('date'); AssertValid;
  g_pSimMgr->vslot0xd [0x34](&strC); // date-string getter
  resource = (short)((short)g_pSimMgr->field2c / 4) + 0x717; strA.Format(g_fmt_0069430c, resource);
  strB = strC + g_sz_00695760 + strA;  (concat helpers 605b87/605b21 + copy + op=)
  date->AssignTextSharedRefIfChangedAndMaybeInvalidate(&strB, 1);  // slot 0x72 0x1c8
  date->SetCityProductionDialogPictureRectAndMaybeRefresh(&descA, 1); // slot 0x6d 0x1b4 (TStaticText-family)
- spec = ResolveControlByTag('spec'); AssertValid;
  if (g_table_006a4370[GetActiveNationId()] == 0) { strB = CString(g_szEmptyString); }
  else switch ((short)(g_pSimMgr->field2c % 4)) {   // signed mod idiom cdq/xor/sub/and/xor/sub
    case 0: v = (char)*(g_table_006a4370[GetActiveNationId()] + 0x8f4);
            strA.Format(fmt, v); GetString(0x275e, 0, &strB); scanBracket(g_pSimMgr,&strB?,strB,strA)-> tail;
    case 1: n = [0x6a43cc]->0x5ba0e0 BuildInterNationEventSummaryRowsForAdvisorDialog_Impl (TTradeMgr.cpp:1186);
            strA.Format(fmt,n); if (n>0) strA = g_sz_00698494 + strA; GetString(0x275e,1,&strB); scan;
    case 2: [0x6a43d0]->RecomputeNationComparativePowerMetrics (stub 0x4f1760);
            v = *(int*)([0x6a43d0] + (GetActiveNationId()+0x183)*16); Format; GetString(0x275e,2,&strB); scan;
    case 3: same, v = *(int*)([0x6a43d0] + nid*16 + 0x1824); GetString(0x275e,3,&strB); scan;
  }
  common tail: scanBracketExpressions(g_pSimMgr, &target(F-0x54?), strB, strA);
  spec->AssignTextSharedRef(&strB,1); spec->SetCityProductionDialogPictureRect(&descA,1).
- Rows: for (col=0; col<3; col++) { y=0x50;
    base = [0x6a43e8] + arg*0x21c;   // arg*3*5*9*4; [esp+0x6c] arg slot reused as running offset
    entry = base + 0xc + i*0x3c (i=0..2, countdown 3):
    if (entry->dword2c) {
      FormatInterNationEventRowTokensToSharedStrings(entry, tokens);
      if (entry->byte38) y += Append...(col, y, entry->dword24, entry->dword28, &descC, 1, tokens);
      else               y += Append...(col, y, entry->dword24, entry->dword28, &descB?, 1, tokens);
      y += Append...(col, y, entry->dword2c, entry->dword30, &descA?, -2, tokens);
    } }
  (branch descriptor assignment needs re-check: two LEAs differ per branch.)
- g_pUiViewManager->ReleaseResourceStreamIfNotNull(field94) (0x5df6d0); dtors; ret 4.

Open items: identify 'main' panel concrete class (runtime vtable — check dialog factory
building the 0x2103 report dialog / 'main' tag construction sites); globals 0x6a43cc
(TTradeMgr?), 0x6a43d0 (power-metrics blob, rows of 16 bytes), 0x6a43e8 (event rows,
0x21c per arg-index, entries 0x3c), 0x6a4370 (per-nation ptr table), strings 0x69430c
(fmt), 0x695760, 0x698494; TSimMgr slot 0xd decl; then port 0x55d910 + 0x55df50 first
(they're the leaf callees), then 0x55d200.

## 0x55d910 FormatInterNationEventRowTokensToSharedStrings — decode

thiscall(this=TNewspaperView; entry, CString* tokens4). Computes delta = entry -
tokens, then walks k=0..3 with ESI over tokens[k] (advances +4) and [delta+ESI] over
the entry: values at entry+0x00..0x0c, token TYPES at entry+0x10..0x1c.
switch (type - 1):
- type 1: BuildLocalizedTokenListFromBitmaskWithConjunction(&tokens[k], value)
  (thiscall on this, stub 0x55da80, 462B);
- type 2: BuildLocalizedNationListFromBitmaskWithConjunction(&tokens[k], value)
  (thiscall on this, stub 0x55dcd0, 347B);
- type 3: CString tmp; g_pGlobalMapState->AssignCityRecordDisplayName(value, &tmp);
  tokens[k] = tmp;
- type 4: obj = FindMapActionContextByNodeId(value) (cdecl 0x55f100, 47B);
  obj->vslot0xb [0x2c](&tokens[k]);
- default: tokens[k] = CString(g_szEmptyString) via temp.

Port order therefore: 0x55da80, 0x55dcd0, 0x55f100 (leaves) -> 0x55d910 -> 0x55df50
-> 0x55d200. Entry struct so far (stride 0x3c, three per column, base
[0x6a43e8] + arg*0x21c + 0xc): +0x00..0x0c token values, +0x10..0x1c token types,
+0x24/+0x28 title text/style ids, +0x2c/+0x30 body text ids (0 = row absent),
+0x38 byte = style flag selecting descC vs descB for the title row.

## 0x55da80 BuildLocalizedTokenListFromBitmaskWithConjunction — decode

thiscall on TNewspaperView (this unused), RET 0x8: (CString* out, int bitmask).
- *out = CString(g_szEmptyString);
- char flags[0x17]; int setCount=0; for (c=0;c<0x17;c++) flags[c] = (bitmask>>c)&1, counting set bits.
- int emitted=0; for (i=0;i<0x17;i++) if (flags[i]):
  - CString itemText = (emitted==0) ? g_pSimMgr->AssignSharedStringFromIndexedSlot7C(i)
                                    : g_pSimMgr->LoadNormalizedCredentialName(i);
  - if (emitted == setCount-2) { CString conj; g_pSimMgr->GetString(0x275e,4,&conj); *out += itemText + conj; }
    else if (emitted == setCount-1) *out += itemText;
    else *out += itemText + g_szListSeparator_00695760;   // ", "
  - emitted++.

New string globals: 0x695760 = ", " (list separator), 0x698494 = "+" (positive-number
prefix used by 0x55d200 case 1). 0x69430c already exists as g_szDecimalFormat ("%d").

## LoadNormalizedCredentialName (0x581b20, TSimMgr) — wrong ABI + body in repo

Currently `CString* (CString* out, short slot)` with body `*out = sharedTextSlots[slot]`
at 24%. Ground truth: byval-return `CString LoadNormalizedCredentialName(short slot)`
whose body is `return g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&sharedTextSlots[slot]);`
(same normalize-step omission as the TCountry::LoadNationDisplayNameSharedRefFromField8
fix that went 21%->100%). Callsites (TCountry.cpp:370, TOfferDeskPicture.cpp:83/166,
TTerrainHelpPicture.cpp:188) pass &tmp exactly where the hidden return slot goes, so
converting them to `dst = g_pSimMgr->LoadNormalizedCredentialName(slot)` is
stack-layout-identical at the call.
