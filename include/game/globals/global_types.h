#pragma once

// Common ABI types and forward declarations for global declaration headers. This header
// deliberately owns no globals, subsystem APIs, or concrete game-class dependencies.

#include "decomp_types.h"

#include "game/mfc.h"
#include "game/military_domain_types.h"
#include "game/strategic_terrain.h"
#include "game/core/CString.h"

struct NationState;
struct TextStyle;
struct TQuickDrawSurfaceContext;
struct TBitmapSurfaceContextDescriptor;
struct TCdAudioDevice;
struct CRGBColor;
class TAdmiral;
class TApplication;
class TAnimator;
class TArmyMgr;
class TArmyPlayer;
class TAssetMgr;
class TBackdropWindow;
class TCivMgr;
class TControl;
class TD0TemplateDialog;
class TDiplomacyMgr;
class THelpMgr;
class TInfoBarText;
class TLanguageMgr;
class TMapMgr;
class TModuleLibraryCacheTableStateB;
class TMultiplayerMgr;
class TNavyMgr;
class TNetMgr;
class TNewsMgr;
class TOcean;
class TSetupRandomMapPicture;
class TShip;
class TSimMgr;
class TSoundPlayer;
class TSoundResourceManager;
class TTaskForce;
class TTechMgr;
class TTradeMgr;
class TTurnEventDialogFactoryRegistry;
class TView;
class TViewMgr;
class TZone;
class TAmbitApplication;
class TTacticalBattle;
class ImperialismApp;
class CDib;
class SeapointStretch;
class SeaSegmentStretch;
