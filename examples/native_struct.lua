-- native_struct.lua
-- Type a struct in a NATIVE (C/C++) target from its DWARF debug info, and lay it
-- over a live object, the native analog of the IL2CPP dissector. Also lists a
-- module's PE exports (for Wine/Proton modules).

local STRUCT = "GameState"   -- edit to a struct name in the target's debug info
local BASE   = 0             -- edit: an object address to overlay the struct on

local s = getDwarfStructure(STRUCT)
if not s then
  print("No DWARF struct '" .. STRUCT .. "' (build with -g, or try listDwarfStructs()).")
else
  print(string.format("struct %s  (size 0x%X)", s.name, s.size))
  for _, f in ipairs(s.fields) do
    local line = string.format("    +0x%-4X %-8s %s", f.offset, f.typeName, f.name)
    if BASE ~= 0 then
      -- Read the live value at base+offset using the field's type.
      local addr = BASE + f.offset
      local v
      if f.typeName == "int32" then v = readInteger(addr)
      elseif f.typeName == "float" then v = readFloat(addr)
      elseif f.typeName == "pointer" then v = readPointer(addr) end
      if v ~= nil then line = line .. "  = " .. tostring(v) end
    end
    print(line)
  end
end

-- Bonus: exported functions of a Wine/Proton module (resolve by name to hook).
local exp = getModuleExports("UnityPlayer.dll")
if exp then print(string.format("UnityPlayer.dll exports %d functions", #exp)) end
