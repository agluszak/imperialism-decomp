#pragma once

// FourCC control tags used in turn-event UI resource registration and registry sweeps.
const unsigned int kControlTagWind = 0x57494e44u; // 'WIND'
const unsigned int kControlTagWpam = 0x6d617057u; // 'Wpam'
const unsigned int kControlTagWnrt = 0x74726e57u; // 'Wnrt'

// Game window control tags
const unsigned int kTagMain = 0x6d61696e; // 'main'
const unsigned int kTagQuery = 0x71756572; // 'quer'

// Mac view manager control tags
const unsigned int kTagCityProductionTotal = 0x746f7461u; // 'tota'
const unsigned int kTagArrowLeft = 0x6c656674u; // 'left'
const unsigned int kTagArrowRight = 0x72676874u; // 'rght'
const unsigned int kTagDetailText = 0x74657874u; // 'text'
const unsigned int kTagDetailValue = 0x76616c75u; // 'valu'

// Display manager control tags
const unsigned int kTagOkOkOk = 0x6f6b6f6bu; // 'okok'

// Civ toolbar control tags
const unsigned int kTagStackSlotMin = 0x73746B30; // 'stk0'
const unsigned int kTagStackSlotMax = 0x73746B35; // 'stk5'
const unsigned int kTagDone = 0x646F6E65; // 'done'
const unsigned int kTagDefend = 0x64666E64; // 'dfnd'
const unsigned int kTagLater = 0x6C617472; // 'latr'
const unsigned int kTagGarrison = 0x67617272; // 'garr'

// Army toolbar control tags
const unsigned int kTagArmyRatioMin = 0x61727230; // 'arr0'
const unsigned int kTagArmyRatioMax = 0x61727239; // 'arr9'
const unsigned int kTagArmyModeGarrison = 0x67617272; // 'garr'
const unsigned int kTagArmyModeDefend = 0x64666E64; // 'dfnd'
const unsigned int kTagArmyModeLater = 0x6C617472; // 'latr'
const unsigned int kTagArmyModeDone = 0x646F6E65; // 'done'
