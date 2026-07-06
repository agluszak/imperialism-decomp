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
const unsigned int kControlTagGold = 0x444c4f47u; // 'GOLD'
const unsigned int kControlTagCan0 = 0x63616e30u; // 'can0'
const unsigned int kControlTagCan1 = 0x63616e31u; // 'can1'
const unsigned int kControlTagCoa0 = 0x636f6130u; // 'coa0'
const unsigned int kControlTagCoa1 = 0x636f6131u; // 'coa1'
const unsigned int kControlTagEnd = 0x656e6420u;  // ' end'
const unsigned int kControlTagText = 0x74657874u; // 'text'
const unsigned int kControlTagFood = 0x646f6f66u; // 'food'
const unsigned int kControlTagOkay = 0x6f6b6179u; // 'okay' — confirm button
const unsigned int kControlTagRewa = 0x72657761u; // 'rewa' — reward picture
const unsigned int kControlTagPict = 0x70696374u; // 'pict' — generic picture name tag
const unsigned int kControlTagMovi = 0x6d6f7669u; // 'movi' — startup movie view
const unsigned int kControlTagCoat = 0x636f6174u; // 'coat' — coat-of-arms picture
const unsigned int kControlTagInfo = 0x696e666fu; // 'info' — info text block
const unsigned int kControlTagTevw = 0x74657677u; // 'tevw' — text-view name tag
const unsigned int kControlTagSeas = 0x73656173u; // 'seas' — season label
const unsigned int kControlTagTrea = 0x74726561u; // 'trea' — treasury label
const unsigned int kControlTagPatc = 0x70617463u; // 'patc' — patch picture

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
