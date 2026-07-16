-- reverse_engineer.lua
-- A tour of the static reverse-engineering helpers. The first half works on any
-- attached process (no address needed); the second half needs ADDR pointed at an
-- instruction (e.g. from the memory viewer or a scan hit).

-- ── Module-level survey (main module of the open process) ──────────────────
local strs = findReferencedStrings()
if not strs then
  print("Attach to a process first (open one in the GUI, or wrap openProcess).")
else
  print(string.format("%d referenced strings, top hot globals:", #strs))
  for i, s in ipairs(strs) do
    if #s.text >= 4 then print(string.format("  0x%X -> %q", s.address, s.text)) end
    if i >= 8 then break end
  end
  for i, g in ipairs(findStatics()) do        -- globals the code touches, hottest first
    print(string.format("  global 0x%X  (%d refs)", g.address, g.references))
    if i >= 8 then break end
  end
  local caves = findCodeCaves(nil, 32)         -- 32+ byte padding runs to inject into
  if #caves > 0 then
    print(string.format("  %d code caves; first: 0x%X (%d bytes)",
          #caves, caves[1].address, caves[1].size))
  end
end

-- ── Address-specific analysis ──────────────────────────────────────────────
local ADDR = 0   -- edit: an instruction address in the target
if ADDR == 0 then
  print("Set ADDR to a code address for signature / xref / disasm output.")
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
