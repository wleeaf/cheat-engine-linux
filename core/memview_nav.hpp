#pragma once

// Memory Viewer navigation policy (Qt-free so the GUI slot stays a thin caller).
//
// Cheat Engine's Memory Viewer has two panes on one address: a disassembler for code
// and a hex dump for data. When you jump to an address (double-clicking a cheat-table
// entry, following a value), CE decides which pane to bring into focus:
//   * hold Shift  -> force the disassembler,
//   * hold Ctrl   -> force the hex dump,
//   * hold neither -> guess from the memory's executability (code -> disassembler,
//                     data -> hex dump).
// Shift wins if both modifiers are held (it is the "show as code" intent).

namespace ce {

enum class MemViewPane { Disassembler, HexDump };

inline MemViewPane chooseMemViewPane(bool executable, bool shiftHeld, bool ctrlHeld) {
    if (shiftHeld) return MemViewPane::Disassembler;
    if (ctrlHeld)  return MemViewPane::HexDump;
    return executable ? MemViewPane::Disassembler : MemViewPane::HexDump;
}

} // namespace ce
