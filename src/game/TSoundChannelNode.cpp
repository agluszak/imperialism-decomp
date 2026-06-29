#include "game/TSoundChannelNode.h"

TSoundChannelNode::TSoundChannelNode()
    : field4(0), field8(0), fieldC(0), field10(0), field14(0), field18(10) {}

// FUNCTION: IMPERIALISM 0x00487f70
void TSoundChannelNode::SoundChannelNodeDummy02() {}

// FUNCTION: IMPERIALISM 0x00487f90
void TSoundChannelNode::SoundChannelNodeDummy03() {}

// SYNTHETIC: IMPERIALISM 0x004bec10
// TSoundChannelNode::`scalar deleting destructor'
TSoundChannelNode::~TSoundChannelNode() {}

// FUNCTION: IMPERIALISM 0x004c65d0
void TSoundChannelNode::Serialize(CArchive& ar) {
  CObject::Serialize(ar);
}

// FUNCTION: IMPERIALISM 0x004c6740
void TSoundChannelNode::SoundChannelNodeDummy00() {}

// FUNCTION: IMPERIALISM 0x004c67e0
void TSoundChannelNode::SoundChannelNodeDummy01() {}

// FUNCTION: IMPERIALISM 0x004c6880
void TSoundChannelNode::SoundChannelNodeDummy04() {}

// FUNCTION: IMPERIALISM 0x004c68c0
int TSoundChannelNode::QueryPendingPlaybackCountSlot28() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c68e0
void TSoundChannelNode::SoundChannelNodeDummy2C() {}

// FUNCTION: IMPERIALISM 0x004c69a0
int TSoundChannelNode::StopOrResetActivePlaybackSlot30() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c69e0
void TSoundChannelNode::SoundChannelNodeDummy34() {}

// FUNCTION: IMPERIALISM 0x004c6b60
void TSoundChannelNode::Dump(CDumpContext& dc) const {
  CObject::Dump(dc);
}

// FUNCTION: IMPERIALISM 0x004c6bf0
int TSoundChannelNode::ReleaseChannelNodeSlot38() {
  return 0;
}
