#pragma once

// TSimMgr::multiplayerSessionRole. The setup UI stores it; TCountry::IsHost/IsClient
// (Mac names) and every host/client branch compare against it.
enum MultiplayerSessionRole {
  kSessionRoleStandalone = 0,
  kSessionRoleHost = 1,
  kSessionRoleClient = 2
};
