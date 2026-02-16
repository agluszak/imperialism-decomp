#@author codex
#@category Analysis

from ghidra.program.model.symbol import SourceType

APPLY = True

fm = currentProgram.getFunctionManager()

renamed = 0
skipped = 0

print("=== normalize Thunk* -> thunk_* function names ===")
for fn in fm.getFunctions(True):
    old_name = fn.getName()
    if not old_name.startswith("Thunk"):
        continue

    if old_name.startswith("Thunk_"):
        new_name = "thunk" + old_name[5:]
    else:
        new_name = "thunk_" + old_name[5:]

    if new_name == old_name:
        continue

    if not APPLY:
        print("candidate: %s -> %s" % (old_name, new_name))
        continue

    try:
        fn.setName(new_name, SourceType.USER_DEFINED)
        print("renamed: %s -> %s" % (old_name, new_name))
        renamed += 1
    except Exception as e:
        print("skipped: %s -> %s (%s)" % (old_name, new_name, str(e)))
        skipped += 1

print("renamed_count=%d skipped_count=%d apply=%s" % (renamed, skipped, str(APPLY)))
