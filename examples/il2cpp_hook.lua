-- il2cpp_hook.lua
-- Resolve a game method's live code address and the il2cpp_* runtime API that
-- GameAssembly exports, the two things you need to hook or invoke IL2CPP code on
-- a live (incl. Proton) target. This example just resolves and prints them; wire
-- the address into createSimpleHook / an auto-assembler script to actually hook.

local CLASS  = "Player"
local METHOD = "TakeDamage"

-- 1. The game method's live code address (module base + rva).
local addr = findIl2CppMethod(CLASS, METHOD)
if addr then
  print(string.format("%s.%s -> 0x%X", CLASS, METHOD, addr))
else
  print(string.format("could not resolve %s.%s (abstract, generic, or missing)", CLASS, METHOD))
end

-- 2. The il2cpp_* runtime API (from GameAssembly's PE export table). These let
--    injected code call into the runtime (il2cpp_class_from_name, etc.).
local exports = getModuleExports("GameAssembly.dll") or getModuleExports("GameAssembly.so")
if exports then
  local want = { il2cpp_domain_get = true, il2cpp_class_from_name = true,
                 il2cpp_object_new = true, il2cpp_runtime_invoke = true }
  for _, e in ipairs(exports) do
    if want[e.name] then print(string.format("  %-26s @0x%X", e.name, e.address)) end
  end
else
  print("GameAssembly not mapped; attach to the game first.")
end
