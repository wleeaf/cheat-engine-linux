-- il2cpp_dump.lua
-- Dump a Unity IL2CPP class's fields (with in-object byte offsets) and methods
-- (with resolved code addresses), all offline from the game's metadata + binary.
--
-- Run it in the GUI Lua console after attaching to a Unity IL2CPP game, or wrap
-- an openProcess() around it for `cescan lua`. Edit CLASS to the class you want;
-- pass a substring to match several (e.g. "Player").

local CLASS = "UnityEngine.Vector3"

local classes = getIl2CppClassLayout(CLASS)
if not classes then
  print("No IL2CPP layout available. Attach to a Unity IL2CPP game first")
  print("(needs global-metadata.dat + GameAssembly next to it).")
  return
end

for _, c in ipairs(classes) do
  print(string.format("%s  (%d fields, %d methods)  [%s]",
        c.fullName, #c.fields, #c.methods, c.image))
  for _, f in ipairs(c.fields) do
    local tag = f["const"] and " const" or (f["static"] and " static" or "")
    print(string.format("    +0x%-4X %-24s %s%s", f.offset, f.typeName or "?", f.name, tag))
  end
  for _, m in ipairs(c.methods) do
    -- getIl2CppClassLayout gives a module-relative rva; add the GameAssembly base
    -- for a live address, or use findIl2CppMethod() which does it for you.
    print(string.format("    method  rva=0x%X  %s", m.rva, m.name))
  end
end
