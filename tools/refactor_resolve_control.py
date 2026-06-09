import os
import glob
import re

def main():
    src_files = glob.glob("src/game/*.cpp") + glob.glob("include/game/*.h")
    
    for fn in src_files:
        with open(fn, "r") as f:
            text = f.read()
        
        orig_text = text
        
        # 1. Rename selectedControlTagOrState1c to controlTag
        text = text.replace("selectedControlTagOrState1c", "controlTag")
        
        # 2. Replace reinterpret_cast<TView*>(this)->ResolveControlByTag(...)
        # Wait, many places do: reinterpret_cast<TAmtBar*>(ResolveOwnerControl(owner, kControlTagMove))
        # Let's replace ResolveOwnerControl(X, Y) with (reinterpret_cast<TView*>(X))->ResolveControlByTag(Y)
        # But if X is already `this` or strongly typed? Let's just use TView* cast to be safe if it's not typed.
        
        def repl(match):
            owner = match.group(1)
            tag = match.group(2)
            # If owner is 'this', we don't necessarily need cast but it's fine.
            # actually we don't know the type of owner, so reinterpret_cast<TView*>(owner) is safest,
            # unless owner is already `this` then `this->ResolveControlByTag(tag)` is best!
            if owner == "this":
                return f"this->ResolveControlByTag({tag})"
            else:
                return f"reinterpret_cast<TView*>({owner})->ResolveControlByTag({tag})"
                
        text = re.sub(r"ResolveOwnerControl\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)", repl, text)
        
        # 3. CallResolveControlByTagSlot94
        text = re.sub(r"CallResolveControlByTagSlot94\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)", repl, text)
        
        if text != orig_text:
            with open(fn, "w") as f:
                f.write(text)
            print(f"Updated {fn}")

if __name__ == "__main__":
    main()
