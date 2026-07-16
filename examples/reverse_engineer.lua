-- reverse_engineer.lua
-- A tour of the static reverse-engineering helpers: signature generation,
-- cross-references, the call graph, and range disassembly. Point ADDR at an
-- instruction in the open process (e.g. from the memory viewer or a scan hit).

local ADDR = 0   -- edit: an instruction address in the target

if ADDR == 0 then
  print("Set ADDR to a code address in the open process, then re-run.")
  print("Available: createSignature, findReferences, enumerateFunctions,")
  print("           buildCallGraph, disassembleRange, getModuleExports/Imports.")
  return
end

-- A portable AOB signature that relocates this address across restarts / ASLR.
local sig, unique = createSignature(ADDR)
if sig then print("signature: " .. sig .. (unique and "  (unique)" or "  (NOT unique)")) end

-- Static "find what references this address" (no runtime execution).
for i, r in ipairs(findReferences(ADDR)) do
  print(string.format("  ref %-8s @0x%X  %s", r.type, r.address, r.text))
  if i >= 10 then print("  ..."); break end
end

-- Decode the next few instructions.
for _, insn in ipairs(disassembleRange(ADDR, 6)) do
  print(string.format("  0x%X  %s", insn.address, insn.text))
end

-- Function inventory + call graph of the main module.
local fns = enumerateFunctions()
print(string.format("main module: %d candidate functions, %d call edges",
      #fns, #buildCallGraph()))
