"""Known switch-case / loop internal entries demoted from standalone Functions.

These addresses sit inside a larger owned function body. Ghidra sometimes promotes
them to Function entities; apply_source demotes them to labels, and sync_exports
keeps the owner's inventory size honest.
"""

from __future__ import annotations

# (address, owner, name)
EMBEDDED_FUNCTION_LABELS: tuple[tuple[int, int, str], ...] = (
    (0x43E8B0, 0x43DBC0, "BuildMainMapAndCityCommandControls"),
    (0x440B83, 0x43DBC0, "BuildCivilianReportDialogResources"),
    (0x4418B0, 0x43DBC0, "InitializeTGarrisonViewBitmapAndControlResources"),
    (0x441948, 0x43DBC0, "BuildGarrisonViewBaseAndTabCursorUiResources"),
    (0x441FF1, 0x43DBC0, "BuildConstructionOptionsDialogResources"),
    (0x4472BB, 0x43DBC0, "InitializeTNavyRosterBitmapAndControlResources"),
    (0x447353, 0x43DBC0, "TNavyRoster::BuildNavyRosterDialogUiResourceTree"),
    (0x46503C, 0x4601B0, "BuildTradeBoardDialogUiLayoutVariantA"),
    (0x46620F, 0x4601B0, "InitializeUiResourceEntries"),
    (0x474AC5, 0x4749A0, "BuildUniversityDialogControls"),
    (0x475F82, 0x4749A0, "UniversityRecruitRadioButtonAllocNullPath"),
    (0x475F84, 0x4749A0, "PushUniversityRecruitRadioButtonUiNode"),
    (0x5370F0, 0x537090, "QueueMissionOrderEntriesAcrossSelectionRange"),
    (0x53714F, 0x537090, "QueueMissionOrderEntryAndPropagateSelectionRange"),
    (0x59C98D, 0x59C970, "ApplyDefenderHoldLineStanceCursorMode0"),
    (0x59C999, 0x59C970, "SetLinkedListEntryState2CForTacticalCategory0"),
    (0x59C9F6, 0x59C970, "ApplyDefenderBombardStanceCursorMode2"),
    (0x59CA02, 0x59C970, "ApplyAttackerSiegeStanceCursorMode3"),
    (0x59CA0E, 0x59C970, "ApplyAttackerAssaultStanceCursorMode4"),
    (0x59CA1A, 0x59C970, "ApplyAttackerStandoffStanceCursorMode5"),
    (0x59CA26, 0x59C970, "ApplyUnopposedAdvanceStanceCursorMode6"),
    (0x59CA32, 0x59C970, "SetLinkedListEntryState2CTo13ForAllNodes"),
)


def embedded_label_entries() -> list[tuple[int, str]]:
    return [(address, name) for address, _owner, name in EMBEDDED_FUNCTION_LABELS]


def embedded_owner_addresses() -> set[int]:
    return {owner for _address, owner, _name in EMBEDDED_FUNCTION_LABELS}
