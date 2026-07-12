# 0x4acb60 TBattleReportView report-layout hook — full decode (port pending)

Working notes for the in-progress port; delete once the port lands.

# 0x4acb60 port notes (TBattleReportView, 2041 bytes, frame 0x1994)
Target: replace stub `void TBattleReportView::NoOpUiLifecycleHook(int arg)` in src/game/TBattleReportView.cpp.
Full listing: idle_hook_4acb60.asm (658 lines). Transcribed so far: lines 1-150 (0x4acb60-0x4acd24).

## Verified callees / slots (all modelled already)
- 0x406ba9 thunk -> 0x48ab70: ICF'd EMPTY no-op, takes the hook's own int arg. Call as the no-op it is.
- 0x406d61 thunk -> TDiplomacyMapView::BuildDiplomacyNationOverlayGeometryAndHitMasks() — INHERITED, call directly.
- 0x406afa thunk -> BuildUiTextStyleDescriptor(TControlPictureRectState*, int, int, int) (quickdraw_rendering.h).
- vtbl[0x94] = TView::ResolveControlByTag(unsigned int fourCC)  (slot 0x25).
- child vtbl[0x0c] = TEventHandler::QueryStepValue() (result discarded).
- child vtbl[0x1b4] = TControl slot 0x6d SetCityProductionDialogPictureRectAndMaybeRefresh(TControlPictureRectState*, int 0). Child must be cast to TControl* (or the class with slot 0x6d).

## Decoded prologue (0x4acb60-0x4acce0)
1. noop(arg); BuildDiplomacyNationOverlayGeometryAndHitMasks();
2. style buf at esp+0x28 region (TControlPictureRectState, 10 bytes + 4 zeroed tail bytes at +0xa..0xd via byte stores BEFORE first call).
3. BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b67);
4. big zero: 0x654 dwords (rep stosd) at esp+0x54 — report accumulation buffer (0x1950 bytes).
5. BuildUiTextStyleDescriptor(&style, 0, 0xe, 0x2b67); apply to 'user' (0x72657375).
   Apply = c=ResolveControlByTag(tag); c->QueryStepValue(); c->SetCityProductionDialogPictureRectAndMaybeRefresh(&style,0);
6. BuildUiTextStyleDescriptor(&style, 2, 0xe, 0x2b67); apply to 'acol' (0x6c6f6361).
7. BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b67); apply to 'mdaf' (0x6661646d) AND 'mdae' (0x6561646d) (style reused).
8. BuildUiTextStyleDescriptor(&style, 0, 0xa, 0x2b67); apply to 'phsf' (0x66736870) AND 'phse' (0x65736870).

## Main loop (starts 0x4acce0, transcribed through 0x4acd24)
- g = *(int*)0x6a3338 (manager global — identify name in symbols/global_data_tables).
- list = g->field4 ; count = list->field8 (CPtrArray m_nSize? list+8 = m_nSize => TSortedPtrList chain!).
- for (short i = count(?); ...; ) { entry = list->vtbl[0x2c](i) = GetPtrListEntryByOneBasedIndex(i);
    entry->word264 = i; cached = (int)i at esp+0x48; inner loop over entry->field4 ... }
  NOTE: OR EAX,-1 before loop; JLE exit at count<=0; loop continues at 0x4acd01 with EDI reload from esp+0x4c.
- Continue transcription at line ~150 (0x4acd24) — inner loop body next.

## Env facts
- Work directly on main; push to origin main after verified milestones (user directive).
- Docker: `sudo dockerd >/tmp/dockerd.log 2>&1 &` after any rollback; build via `sg docker -c 'just build'` SYNCHRONOUSLY in run_in_background Bash (no inner `&`).
- After every container rollback: `git fetch origin main`, `git checkout main`, `git merge --ff-only origin/main`, restart dockerd, full rebuild + detect before comparing (note 75).

## Inner loop body decoded (0x4acd24-0x4ace2b, ASM lines 150-230)
- entry->byte260 = 1; (right after entry->word264 = i)
- typeVal = entry->field4 (int).
- short cell:
  - if (typeVal==0 || typeVal==3 || typeVal==4): idx = entry->field8 (as int);
    g2 = *(int*)0x6a43d4; cell = *(short*)(g2->field10 + idx*0xa8 + 4)   // stride 0xa8=168=21*8
  - else: cell = *(short*)(entry->field8 + 0xc)   // field8 dual-used as pointer! (per typeVal)
- row/col: rowcol split by /0x6c (108) via magic 0x4bda12f7>>5: [esp+0x38]=cell/108, [esp+0x3c]=cell%108,
  flag=1, [esp+0x44]=0(EDI).
- CALL 0x40678f(&div, &mod, 4) then CALL 0x40678f(&out34, &div, savedCount?) — RESOLVE THUNK 0x40678f.
- if (outer i(EDI) < 10): bounds-check x in [0,0x3c), y in [0,0x6c) → cellIdx = y + x*0x6c (grid 60 rows x 108 cols)
  (computed twice: two adjacent grid writes; -1 sentinel when out of bounds; continue transcription at 0x4ace2b, ASM line ~230).
- Globals to identify: 0x6a3338 (manager with TSortedPtrList-chain list at +4; entries have word264/byte260/field4/field8),
  0x6a43d4 (table manager with field10 array stride 0xa8).
- 0x40678f thunk -> 0x55e550 StepHexRowColByDirectionWithWrapRules(&row, &col, direction) — hex-grid stepping.
- 0x6a3338 = g_pMapContextActionManager (entries: battle/action records).
- 0x6a43d4 = g_pGlobalMapState (field10 = per-something array, stride 0xa8; +4 short = map cell).
So the function walks the action manager's list, marks each entry (word264=i, byte260=1), finds its map cell
(direct for types 0/3/4 via g_pGlobalMapState table by index; else via the pointed object's word at +0xc),
converts to hex row/col, steps by direction 4 twice(?), and stamps values into the 60x108 report grid buffer
(the 0x654-dword zeroed frame array), for the first 10 entries specially (CMP EDI,0xA). Then the fourCC'd
TControl children get updated from the grid (later section, untranscribed: ASM lines ~230-658).

## Lines 230-310 (0x4ace16-0x4acf05): SPIRAL FREE-CELL SEARCH
The inner region is a hex spiral search for a free grid cell around the entry's map cell:
- state: row=[esp+0x38], col=[esp+0x3c], dir=[esp+0x40] (init 1), step=[esp+0x44] (init 0), radius=EDI (outer, < 10 => CMP EDI,0xA).
- iterate: idx = (0<=row<0x3c && 0<=col<0x6c) ? col + row*0x6c : -1;
  if (idx != -1 && grid[idx] (byte at esp+0x54 base) == 0) -> FOUND: recompute idx (same bounds check) -> [esp+0x24] = idx.
  else: step++ ; if (step >= radius) { dir++ ; step=0; if (dir >= 6) { dir=0; radius++(EDI, stored esp+0x48); Step(&row,&col,4); } } ; Step(&row,&col,dir); if (radius < 10) loop back to 0x4acdd7.
- After search (0x4aceb3): foundCell=[esp+0x24] (short); begins a SECOND spiral: row=found/0x6c col=found%0x6c, dir=1, step/…=0, Step(&row,&col,4) first — continue transcription at ASM line ~310 (0x4acf05).

## Lines 310-395 (0x4acf05-0x4acff8): NEIGHBORHOOD CROWDING MARK
Second spiral = increment pass around the FOUND cell (not a search):
- state at different slots: row=[esp+0x10], col=[esp+0x14], ring=[esp+0x24] (init 0, while < 3), dir=[esp+0x1c] (init 1), step=[esp+0x20], ringLen=[esp+0x18] (init = found/0x6c quotient? NO — [esp+0x18] gets INC per ring; init from the /0x6c division = actually ring length counter).
- per visited in-bounds cell: grid[idx]++ (byte INC).
- ring advance identical: step>=ringLen -> dir++/step=0; dir>=6 -> dir=0, ringLen++, Step(&row,&col,4); always Step(&row,&col,dir); while ring([esp+0x24]. hmm verify: CMP EAX,0x3 with [esp+0x24]) < 3.
- exit: grid[foundCell]++ (EDI == foundCell at 0x4acfe8).
- next phase at 0x4acff8: LEA shorts [esp+0x52]/[esp+0x50] — likely cell -> (row,col) short pair for the entry; transcription continues at ASM line ~395.

## REMAINING: ASM lines 395-658 untranscribed (entry stamping + per-fourCC grid->control updates + epilogue).

## Lines 395-470 (0x4acffc-0x4ad0fe): ENTRY STAMPING + LOOP CLOSE + SELECTION
- 0x407225 thunk -> SplitTileIndexToHexRasterColumnX2AndRow(&outColX2short, &outRowShort, cell) (0x5127e0).
- 0x403b16 thunk -> GetActiveNationId() (0x581260, thiscall on g_pSimMgr = *(0x6a20f8)).
- pixel stamp: entry->dword258 = this->dword514 + (shortColX2[esp+0x5c]*5)/2 - 9;
               entry->dword25c = this->dword518 + shortRow[esp+0x52]*5 - 9;
- side classification: n = g_pSimMgr->GetActiveNationId();
  if (entry->byteAt(entry->byte2) == n) side=1; else side = (second GetActiveNationId + compare byteAt(+1 mirrored)) 0 or something;
  entry->word262 = (side==1) ? 0 : 4-or-8;   // exact: if side==1 -> 0; else ((side+1)? via sbb) & 4 + 4 -> 4 or 8
  if (entry->field4 == 2) entry->word262 += 2;
- outer loop: [esp+0x4c]-- ; JG back to 0x4accfd (next entry, i comes from [esp+0x4c] decreasing — the loop walks ordinals DOWNWARD from count to 1!).
- selection after loop: sel=[esp+0x48] (last stamped i... verify semantics); if sel==-1 { g_pSimMgr->vtbl[0x44](); sel=1; }
  this->dword24c8 = sel-1; entryS = g_pMapContextActionManager->list->GetEntryByOrdinal(sel); push entryS; -> continue ASM line ~470 (0x4ad0fe: MOV ECX,ESI — a this-call on the view with entryS).
## REMAINING: ASM lines 470-658.

## Lines 470-560 (0x4ad0fe-0x4ad21d): ANIMATION OBJECT + CONTROL WIRING
- this->thunk0x403bca(); this->vtbl[0x54](2);
- INLINE CONSTRUCTION: p = operator new(0x2c); if (p) { p->vptr = 0x64dfb8; } — identify class by vtable 0x64dfb8 and model as real `new TClass(...)` (ctor is inlined here: the args go through thunk 0x40302b as an Init call: obj->Init(this /*view*/, &zeroedRect(4 dwords at esp+0x28), 0, 0, tag) where tag = g_nIdleMeAnimationNextRegistryTag++ (0x695934) — the TAnimator/IdleMe pattern!).
- this->dword24cc = p; then (*0x6a43e0)->thunk0x402ec8(p) — likely g_pUiAnimator->AddUiTransientRegistryObject(p). VERIFY 0x6a43e0 vs g_pUiAnimator address used in TAnimator.cpp.
- c = ResolveControlByTag('surc' 0x63757273); *(0x6a590c) = c; c->QueryStepValue();
  c->vtbl[0x1e0](0, 0xe, 0x2b6b); c->vtbl[0x1c4](1, 1); c->vtbl[0x204](0x2b67, 0x2b6c); — identify slots 0x1e0/0x1c4/0x204 on the control chain (probably TDeluxeText: SetTextFromUiStringResourceId family/BuildAndApply...).
- c2 = ResolveControlByTag('niam' 0x6d61696e); CString ops via [0x64dc30], thunk 0x401b40 (ctor?) + 0x404d22 — a CString temp built and passed (identify: likely SetText with a resource CString).
- free-helper 0x40807b(0x273d, 0x16, control) for 'mdaf' then 'phsf' then continues with 'glff' (0x66666c67) at ASM line ~560.
## REMAINING: ASM lines 560-658 (tail: more 0x40807b wiring + epilogue).
## Thunks still to resolve: 0x403bca, 0x40302b, 0x402ec8, 0x401b40, 0x404d22, 0x40807b; globals 0x64dfb8(vtable), 0x6a43e0, 0x6a590c, 0x64dc30.

## THUNK RESOLUTIONS (final)
- 0x403bca -> 0x4adfc0 RefreshMapContextSelectionPanelAndInfoLabels (thiscall on the view; check ownership/port state).
- 0x40302b -> TAnimation::ConstructTAnimationBaseState(TView*, RECT*, short, short, int, int) — PORTED (TAnimation.cpp).
- 0x402ec8 -> TAnimator::AddObjectToUiTransientRegistry(TAnimation*) — PORTED (TAnimator.cpp).
- 0x401b40 -> 0x4ac370 WrapperFor_ConstructSharedStringFromCStrOrResourceId_At004ac370.
- 0x404d22 -> 0x5c49d0 RunEnableAndProcessFlagWithScopedSharedStringCleanup.
- 0x40807b -> 0x5c4850 LoadUiStringByGroupAndIndexToControlObject(group, index, control).
- vtable 0x64dfb8 = TIdleMeAnimation (include/game/TIdleMeAnimation.h) — construction block is:
  TIdleMeAnimation* anim = new TIdleMeAnimation(); this->dword24cc = anim;
  RECT r = {0,0,0,0}; anim->ConstructTAnimationBaseState(this, &r, 0, 0, 0, g_nIdleMeAnimationNextRegistryTag++);
  g_pUiAnimator->AddObjectToUiTransientRegistry(anim);
  (push order verified: tag,0,0,0,&rect,this = 6 args right-to-left).

## Lines 560-658 (0x4ad21d-0x4ad356): TAIL — string loads + audio + epilogue. FUNCTION 100% DECODED.
- LoadUiStringByGroupAndIndexToControlObject(0x273d, idx, ResolveControlByTag(tag)) sequence:
  ('mdaf',0x16 -- earlier at 0x4ad1e6), ('phsf',0x16), ('glff',0x16), ('mdae',0x17), ('phse',0x17),
  ('glfe' 0x65666c67,0x17), ('acol',0x18), ('user',0x19), ('prev' 0x70726576,0x1a), ('next' 0x6e657874,0x1b),
  ('info' 0x696e666f,0x1c), ('okay' 0x6f6b6179,0x1d), ('requ' 0x71756572,0x1e).
- Epilogue: g_pSfxPlaybackSystem(0x6a43ec)->ResetDualAudioCuePools(); ->PushCueToDualAudioCuePools(5);
  ->SelectAndScheduleRandomAudioCue(); ret 4.
- Call idiom in repo: ResolveControlByTag(0x6d61696e); // 'main'
- 'surc' block slots to identify on control chain: 0x1e0, 0x1c4, 0x204. View slot 0x54(2) on self.
- CString block ('main' control): EDX=[0x64dc30](a string/vtable const?), two-push + ecx=esp (CString-by-value on stack!) via 0x4ac370 wrapper then 0x5c49d0 scoped-cleanup runner: pattern = control-enable call taking a SharedString BY VALUE. Check RefreshMapContextSelectionPanelAndInfoLabels (0x4adfc0) port state and other callers of 0x5c49d0 for the established idiom.
