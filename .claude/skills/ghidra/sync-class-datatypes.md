---
name: sync-class-datatypes
description: Sync a reconstructed C++ class layout and its method signatures back to the vendored Ghidra project to improve decompilation output.
---

# Syncing Class Datatypes to Ghidra

When you have reconstructed a class (its fields, layout, and methods) and want Ghidra's decompiler to use these types natively, you can sync the class using the `apply-source-datatypes` tool. This is especially useful for complex classes where having the correct `this->field` layout and `__thiscall` signatures vastly improves the decompiler output.

## 1. Add the Class to `SOURCE_CLASS_MODELS`

Open `tools/ghidra/apply_source_datatypes.py` and add your class to the `SOURCE_CLASS_MODELS` dictionary.

You need to define a `ClassSpec` specifying:
- `name`: The class name.
- `size`: Total size of the class in bytes (hex).
- `source_path`: Path to the `.h` header file.
- `dependencies`: (Optional) A tuple of other class names from `SOURCE_CLASS_MODELS` that this class depends on.
- `fields`: A tuple of `FieldSpec` objects for each known field. Each `FieldSpec` requires `offset`, `name`, `type_name`, and `size`.

Example:
```python
    "CString": ClassSpec(
        name="CString",
        size=0x04,
        source_path="include/game/CString.h",
        fields=(FieldSpec(0x00, "data_ptr", "int", 4),),
    ),
```

## 2. Add Methods to `FUNCTION_MODELS`

In the same file (`tools/ghidra/apply_source_datatypes.py`), add the class's methods to the `FUNCTION_MODELS` tuple. This ensures Ghidra assigns the correct `__thiscall` signature, return type, and parameters.

You need to define a `FunctionSpec` for each method specifying:
- `address`: The function's address (e.g., `0x00605797`).
- `class_name`: The owning class.
- `method_name`: The method name.
- `return_type`: The return type (`"void"`, `"int"`, `"CString *"`, etc.).
- `params`: (Optional) A tuple of `(name, type)` tuples for the function's arguments. Note that `this` is implicit and shouldn't be included.

Example:
```python
    FunctionSpec(0x00605950, "CString", "CString", "void", (("text_or_resource_id", "char *"),)),
    FunctionSpec(0x00605d99, "CString", "EnsureCapacityAndSetLength", "int", (("new_length", "int"),)),
```

## 3. Run the Sync Command

Once the models are updated in the script, apply them to the Ghidra project by running the `just` target:

```bash
just apply-source-datatypes --classes ClassName
```

*(You can also pass multiple comma-separated classes: `--classes CString,TView`)*

This script runs headlessly via pyghidra, creates/updates the structures in the Ghidra DataTypeManager, updates the function signatures, and saves the Ghidra transaction.

## 4. Export the Project

Don't forget to pack the live Ghidra `.rep` project back into the LFS-tracked `.gzf` archive so your changes are committed!

```bash
just export-project
```
