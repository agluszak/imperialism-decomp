#pragma once

// FourCC control tags used in turn-event UI resource registration and registry sweeps.
const unsigned int kControlTagWind = 0x57494e44u; // 'WIND'
const unsigned int kControlTagBase = 0x62617365u; // 'base' — root-container tag
const unsigned int kControlTagWpam = 0x6d617057u; // 'Wpam'
const unsigned int kControlTagWnrt = 0x74726e57u; // 'Wnrt'
const unsigned int kControlTagCurs = 0x63757273u; // 'curs' — cursor panel
const unsigned int kControlTagCntl = 0x636e746cu; // 'cntl' — generic control name tag
const unsigned int kControlTagLoad = 0x6c6f6164u; // 'load' — main-menu load-game button
const unsigned int kControlTagRand = 0x72616e64u; // 'rand' — main-menu random-map button
const unsigned int kControlTagMult = 0x6d756c74u; // 'mult' — main-menu multiplayer button
const unsigned int kControlTagHigh = 0x68696768u; // 'high' — main-menu high-scores button
const unsigned int kControlTagScen = 0x7363656eu; // 'scen' — main-menu scenario button
const unsigned int kControlTagQuit = 0x71756974u; // 'quit' — main-menu quit button
const unsigned int kControlTagPref = 0x70726566u; // 'pref' — main-menu preferences button
const unsigned int kControlTagMain = 0x6d61696eu; // 'main' — council ticker panel
const unsigned int kControlTagQuer = 0x71756572u; // 'quer'
const unsigned int kControlTagCity = 0x63697479u; // 'city'
const unsigned int kControlTagDipl = 0x6469706cu; // 'dipl'
const unsigned int kControlTagTrad = 0x74726164u; // 'trad'
const unsigned int kControlTagTran = 0x7472616eu; // 'tran'
const unsigned int kControlTagBpot = 0x746f7042u; // 'Bpot'
const unsigned int kControlTagTool = 0x746f6f6cu; // 'tool'
const unsigned int kControlTagTrb1 = 0x74627231u; // 'trb1'
const unsigned int kControlTagGold =
    0x444c4f47u; // NOTE: decodes as 'DLOG' (dialog label), not 'GOLD'; rename pending a dedicated sweep
const unsigned int kControlTagCan0 = 0x63616e30u; // 'can0'
const unsigned int kControlTagCan1 = 0x63616e31u; // 'can1'
const unsigned int kControlTagCoa0 = 0x636f6130u; // 'coa0'
const unsigned int kControlTagCoa1 = 0x636f6131u; // 'coa1'
const unsigned int kControlTagEnd = 0x656e6420u;  // ' end'
const unsigned int kControlTagText = 0x74657874u; // 'text'
const unsigned int kControlTagFood = 0x646f6f66u; // 'food'
const unsigned int kControlTagOkay = 0x6f6b6179u; // 'okay' — confirm button
const unsigned int kControlTagBack = 0x6261636bu; // 'back' — dismiss/back button
const unsigned int kControlTagLcor = 0x6c636f72u; // 'lcor' — left-column control region
const unsigned int kControlTagRcor = 0x72636f72u; // 'rcor' — right-column control region
const unsigned int kControlTagLaro = 0x6c61726fu; // 'laro' — purchase-amount decrement arrow
const unsigned int kControlTagRaro = 0x7261726fu; // 'raro' — purchase-amount increment arrow
// Capitalized variants distinct from kControlTagFlag ('flag') / kTagDone ('done') --
// TToolBarCluster::HandleEvent compares against these exact byte values.
const unsigned int kControlTagFlagCaps = 0x466c6167u; // 'Flag'
const unsigned int kControlTagDoneCaps = 0x444f4e45u; // 'DONE'
const unsigned int kControlTagZmIn = 0x5a6d496eu;  // 'ZmIn' — map zoom-in hotspot
const unsigned int kControlTagZmOt = 0x5a6d4f74u;  // 'ZmOt' — map zoom-out hotspot
const unsigned int kControlTagSend = 0x73656e64u;  // 'send' — end-turn hotspot
const unsigned int kControlTagAgr2 = 0x61677232u;  // 'agr2' — last of 3 aggression-level buttons
const unsigned int kControlTagProt = 0x70726f74u; // 'prot' — network protocol option field
const unsigned int kControlTagPro0 = 0x70726f30u; // 'pro0' — default protocol option tag
const unsigned int kControlTagPass = 0x70617373u; // 'pass' — password edit field
const unsigned int kControlTagHost = 0x686f7374u; // 'host' — host-a-new-game hotspot
const unsigned int kControlTagJoin = 0x6a6f696eu; // 'join' — join-a-game hotspot
const unsigned int kControlTagSpit = 0x73706974u; // 'spit' — resume-pending-session hotspot
const unsigned int kControlTagRewa = 0x72657761u; // 'rewa' — reward picture
const unsigned int kControlTagPict = 0x70696374u; // 'pict' — generic picture name tag
const unsigned int kControlTagMovi = 0x6d6f7669u; // 'movi' — startup movie view
const unsigned int kControlTagCoat = 0x636f6174u; // 'coat' — coat-of-arms picture
const unsigned int kControlTagInfo = 0x696e666fu; // 'info' — info text block
const unsigned int kControlTagTevw = 0x74657677u; // 'tevw' — text-view name tag
const unsigned int kControlTagSeas = 0x73656173u; // 'seas' — season label
const unsigned int kControlTagTrea = 0x74726561u; // 'trea' — treasury label
const unsigned int kControlTagPatc = 0x70617463u; // 'patc' — patch picture

// New-game random-map setup screen (turn event 0x5dd) tags
const unsigned int kControlTagClus = 0x636c7573u; // 'clus' — generic cluster name tag
const unsigned int kControlTagStat = 0x73746174u; // 'stat' — static-text name tag
const unsigned int kControlTagEdit = 0x65646974u; // 'edit' — edit-text name tag
const unsigned int kControlTagHot = 0x686f7421u;  // 'hot!' — hint/info bar text
const unsigned int kControlTagStuf = 0x73747566u; // 'stuf' — right-hand settings cluster
const unsigned int kControlTagMapP = 0x6d617020u; // 'map ' — random-map preview view
const unsigned int kControlTagTcou = 0x74636f75u; // 'tcou' — country title label
const unsigned int kControlTagFlag = 0x666c6167u; // 'flag' — nation flag view
const unsigned int kControlTagCoun = 0x636f756eu; // 'coun' — country-name edit box
const unsigned int kControlTagDiff = 0x64696666u; // 'diff' — difficulty radio cluster
const unsigned int kControlTagDif0 = 0x64696630u; // 'dif0' — Introductory
const unsigned int kControlTagDif1 = 0x64696631u; // 'dif1' — Easy
const unsigned int kControlTagDif2 = 0x64696632u; // 'dif2' — Normal
const unsigned int kControlTagDif3 = 0x64696633u; // 'dif3' — Hard
const unsigned int kControlTagDif4 = 0x64696634u; // 'dif4' — Nigh-On Impossible
const unsigned int kControlTagDift = 0x64696674u; // 'dift' — difficulty title label
const unsigned int kControlTagTnam = 0x746e616du; // 'tnam' — names title label
const unsigned int kControlTagName = 0x6e616d65u; // 'name' — names radio cluster
const unsigned int kControlTagTgam = 0x7467616du; // 'tgam' — join-selector target-game label
const unsigned int kControlTagGame = 0x67616d65u; // 'game' — join-selector game-name field
const unsigned int kControlTagHist = 0x68697374u; // 'hist' — historical names option
const unsigned int kControlTagKeyP = 0x6b657920u; // 'key ' — map-key hotspot
const unsigned int kControlTagAuto = 0x6175746fu; // 'auto' — all-AutoGP label
const unsigned int kControlTagAcce = 0x61636365u; // 'acce' — accept-offer hotspot
const unsigned int kControlTagReje = 0x72656a65u; // 'reje' — reject-offer hotspot
const unsigned int kControlTagCanc = 0x63616e63u; // 'canc' — cancel hotspot (upper)
const unsigned int kControlTagCncl = 0x636e636cu; // 'cncl' — cancel hotspot (lower)
const unsigned int kControlTagGlob = 0x676c6f62u; // 'glob' — globe picture

// Game window control tags
const unsigned int kTagMain = 0x6d61696e;  // 'main'
const unsigned int kTagQuery = 0x71756572; // 'quer'

// Mac view manager control tags
const unsigned int kTagCityProductionTotal = 0x746f7461u; // 'tota'
const unsigned int kTagArrowLeft = 0x6c656674u;           // 'left'
const unsigned int kTagArrowRight = 0x72676874u;          // 'rght'
const unsigned int kTagDetailText = 0x74657874u;          // 'text'
const unsigned int kTagDetailValue = 0x76616c75u;         // 'valu'

// Display manager control tags
const unsigned int kTagOkOkOk = 0x6f6b6f6bu; // 'okok'

// Civ toolbar control tags
const unsigned int kTagStackSlotMin = 0x73746B30; // 'stk0'
const unsigned int kTagStackSlotMax = 0x73746B35; // 'stk5'
const unsigned int kTagDone = 0x646F6E65;         // 'done'
const unsigned int kTagDefend = 0x64666E64;       // 'dfnd'
const unsigned int kTagLater = 0x6C617472;        // 'latr'
const unsigned int kTagGarrison = 0x67617272;     // 'garr'

// Army toolbar control tags
const unsigned int kTagArmyRatioMin = 0x61727230;     // 'arr0'
const unsigned int kTagArmyRatioMax = 0x61727239;     // 'arr9'
const unsigned int kTagArmyModeGarrison = 0x67617272; // 'garr'
const unsigned int kTagArmyModeDefend = 0x64666E64;   // 'dfnd'
const unsigned int kTagArmyModeLater = 0x6C617472;    // 'latr'
const unsigned int kTagArmyModeDone = 0x646F6E65;     // 'done'

// Trade screen control tags
const unsigned int kControlTagMove = 0x6d6f7665; // 'move'
const unsigned int kControlTagSell = 0x53656c6c; // 'Sell'
const unsigned int kControlTagAvai = 0x61766169; // 'Avai'
const unsigned int kControlTagCard = 0x63617264; // 'Card'
const unsigned int kControlTagOffr = 0x6f666672; // 'Offr'
const unsigned int kControlTagGree = 0x67726565; // 'Gree'
const unsigned int kControlTagLeft = 0x6c656674; // 'left'
const unsigned int kControlTagRght = 0x72676874; // 'rght'

// Trade summary tags
const unsigned int kSummaryTagFood = 0x666f6f64; // 'food'
const unsigned int kSummaryTagPopu = 0x706f7075; // 'Popu'
const unsigned int kSummaryTagProf = 0x70726f66; // 'Prof'
const unsigned int kSummaryTagPowe = 0x706f7765; // 'Powe'
const unsigned int kSummaryTagRail = 0x7261696c; // 'Rail'
const unsigned int kSummaryTagIart = 0x74726169; // 'Iart'

// Trade control tags
const unsigned int kControlTagBar = 0x62617220; // 'bar '

// New-game setup screen tags (TRadioTextCluster option groups)
const unsigned int kTagNada = 0x6e616461; // 'nada' — sentinel: no option selected

// Tactical toolbar tags
const unsigned int kControlTagTarg = 0x74617267u; // 'targ' — tactical target button
const unsigned int kControlTagRetr = 0x72657472u; // 'retr' — tactical retreat button
const unsigned int kControlTagCurr = 0x63757272u; // 'curr' — tactical current-unit portrait
const unsigned int kControlTagHelp = 0x68656c70u; // 'help' — tactical toolbar help button

// Battle-intro ('hola') dialog tags
const unsigned int kControlTagAttackerCoat = 0x61636f61u; // 'acoa'
const unsigned int kControlTagDefenderCoat = 0x64636f61u; // 'dcoa'
const unsigned int kControlTagPreviewMap = 0x706d6170u;   // 'pmap'

// Turn-event trade-board builder tags (previously raw MISSING-TAG literals)
const unsigned int kControlTagTbr2 = 0x74627232u; // 'tbr2' — secondary toolbar
const unsigned int kControlTagTop = 0x746f7020u;  // 'top ' — top picture
const unsigned int kControlTagTitl = 0x7469746cu; // 'titl' — title text
const unsigned int kControlTagTex0 = 0x74657830u; // 'tex0' — first of 7 sequential text lines (tex0-tex6)
const unsigned int kControlTagScr0 = 0x73637230u; // 'scr0' — first of 7 sequential score-row labels (scr0-scr6)
const unsigned int kControlTagCred = 0x63726564u; // 'cred' — credits text line 1
const unsigned int kControlTagCre2 = 0x63726532u; // 'cre2' — credits text line 2
const unsigned int kControlTagTxt0 = 0x74787430u; // 'txt0' — first of 8 sequential option text lines (txt0-txt7)
const unsigned int kControlTagSlid = 0x736c6964u; // 'slid' — value slider control
const unsigned int kControlTagI00a = 0x69303061u; // 'i00a' — first of 12 tile context-menu item panes (i00a-i00l)
const unsigned int kControlTagI00m = 0x6930306du; // 'i00m' — exclusive upper bound of the i00a-i00l range
const unsigned int kControlTagCrew = 0x63726577u; // 'crew' — navy ship crew display mode
const unsigned int kControlTagHull = 0x68756c6cu; // 'hull' — navy ship hull display mode
const unsigned int kControlTagSail = 0x7361696cu; // 'sail' — navy ship sail display mode
const unsigned int kControlTagForM = 0x466f724du; // 'ForM' — trade-desk detail-level toggle
const unsigned int kControlTagBook = 0x626f6f6bu; // 'book' — offer-desk book control
const unsigned int kControlTagUpgr = 0x75706772u; // 'upgr' — mini-army upgrade hotspot
const unsigned int kControlTagTbr1 = 0x74627231u; // 'tbr1' — toolbar slot 1 label
const unsigned int kControlTagAgr0 = 0x61677230u; // 'agr0' — first of 3 aggression-level buttons (agr0-agr2)
const unsigned int kControlTagBomb = 0x626f6d62u; // 'bomb' — bombard hotspot
const unsigned int kControlTagDfnd = 0x64666e64u; // 'dfnd' — defend hotspot
const unsigned int kControlTagNext = 0x6e657874u; // 'next' — next-selection hotspot
const unsigned int kControlTagExpa = 0x65787061u; // 'expa' — expand-industry hotspot
const unsigned int kControlTagChec = 0x63686563u; // 'chec' — ship-check hotspot
const unsigned int kControlTagCls0 = 0x636c7330u; // 'cls0' — first of the per-resource-type class sliders
const unsigned int kControlTagScvw = 0x73637677u; // 'scvw' — scroll view
