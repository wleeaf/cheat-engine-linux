#pragma once

#include "platform/process_api.hpp"
#include "core/ct_file.hpp"
#include "arch/disassembler.hpp"
#include <memory>
#include "symbols/elf_symbols.hpp"
#include "symbols/dwarf_symbols.hpp"

#include <QMainWindow>
#include <QSplitter>
#include <QAbstractScrollArea>
#include <QLineEdit>
#include <QToolBar>
#include <QFont>
#include <QTimer>
#include <QTableWidget>
#include <functional>
#include <set>
#include <map>
#include <cstdio>

namespace ce::gui {

// Flattened readable-memory model used to drive the memory-view scrollbar: the
// (base,end) of each readable region plus the total mapped bytes. The scrollbar
// maps this (gaps removed) so the handle is a real position and stays put.
struct FlatMem {
    std::vector<std::pair<uintptr_t, uintptr_t>> regions;
    uint64_t total = 0;
    bool empty() const { return total == 0; }
};

// ── Hex View Widget ──
class HexView : public QAbstractScrollArea {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);

    // How the hex grid interprets memory (CE's "Display type"). Byte is the
    // classic per-byte hex; wider types group N bytes into one displayed value.
    enum class DisplayType { Byte, Word, Dword, Qword, Float, Double };
    void setDisplayType(DisplayType t) { displayType_ = t; viewport()->update(); }
    DisplayType displayType() const { return displayType_; }
    /// The cheat-table value type matching the current display type (so "add to list"
    /// adds a Float in float display, an 8-byte in Qword display, etc. — like CE).
    ce::ValueType valueTypeForDisplay() const {
        switch (displayType_) {
            case DisplayType::Word:   return ce::ValueType::Int16;
            case DisplayType::Dword:  return ce::ValueType::Int32;
            case DisplayType::Qword:  return ce::ValueType::Int64;
            case DisplayType::Float:  return ce::ValueType::Float;
            case DisplayType::Double: return ce::ValueType::Double;
            default:                  return ce::ValueType::Byte;
        }
    }
    void setBytesPerRow(int n) {
        if (n <= 0) return;
        bytesPerRow_ = n; selectedOffset_ = -1; selAnchor_ = -1;
        updateScrollBar(); refresh();
    }

    void setProcess(ce::ProcessHandle* proc) { proc_ = proc; }
    void setAddress(uintptr_t addr);
    uintptr_t currentAddress() const { return address_; }
    /// Address of the byte under the most recent cursor position, or `address_` if unknown.
    uintptr_t cursorAddress() const;
    void refresh();

    /// Test helper: how many bytes changed since the previous refresh (the ones the
    /// hex pane paints in the "changed" colour, CE-style).
    int changedByteCountForTest() const {
        int n = 0; for (char ch : changed_) if (ch) ++n; return n;
    }

    /// Write an AOB (e.g. "90 90 c3", "9090c3", "?? c3") from the clipboard/text into
    /// the target starting at the cursor byte, patching memory CE-style. "??"/"*"
    /// wildcards leave that byte untouched. Returns the number of bytes written.
    int pasteBytes(const QString& aob);

    /// Fill every byte in the current selection with `value` (patch memory). Returns the
    /// number of bytes written; 0 if there is no multi-byte selection.
    int fillSelection(uint8_t value);

    /// Read the pointer stored at `addr`, sized to the target (4 bytes on a 32-bit
    /// process, 8 on a 64-bit one). Returns 0 if unreadable. Used by "Follow pointer".
    uintptr_t pointerAt(uintptr_t addr) const {
        if (!proc_) return 0;
        const int psz = proc_->runs32BitCode() ? 4 : 8;
        uint64_t ptr = 0;
        auto r = proc_->read(addr, &ptr, psz);
        return (r && *r >= static_cast<size_t>(psz)) ? static_cast<uintptr_t>(ptr) : 0;
    }

    /// Select `len` bytes starting at absolute address `addr` (e.g. to highlight a
    /// search hit). No-op if the address is above the current window's top.
    void selectBytes(uintptr_t addr, int len) {
        if (len <= 0 || addr < address_) return;
        int off = static_cast<int>(addr - address_);
        selAnchor_ = off;
        selectedOffset_ = off + len - 1;
        editNibble_ = 0;
        viewport()->update();
    }

    /// Test helper: set the byte selection to offsets [lo, hi] within the visible window.
    void setSelectionForTest(int lo, int hi) { selAnchor_ = lo; selectedOffset_ = hi; }
    int selectionStartForTest() const { int lo, hi; return selRange(lo, hi) ? lo : -1; }
    int selectionSizeForTest() const { int lo, hi; return selRange(lo, hi) ? hi - lo + 1 : 0; }
    /// Test helper: scroll the view by `rows` (as the wheel/scrollbar would).
    void scrollRowsForTest(int rows) { scrollRows(rows); }

signals:
    void requestFindWhatAccesses(uintptr_t addr, bool writesOnly);
    void requestGoto(uintptr_t addr);
    void requestAddToList(uintptr_t addr, ce::ValueType type);
    void cursorMoved(uintptr_t addr);

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;

private:
    void updateScrollBar();
    /// Selected byte range [lo, hi] inclusive within the visible window. Returns
    /// false when nothing is selected; a single click yields lo == hi.
    bool selRange(int& lo, int& hi) const {
        if (selectedOffset_ < 0) return false;
        lo = (selAnchor_ < 0) ? selectedOffset_ : std::min(selAnchor_, selectedOffset_);
        hi = (selAnchor_ < 0) ? selectedOffset_ : std::max(selAnchor_, selectedOffset_);
        return true;
    }
    /// Width of the address column (single source of truth for paint + hit-test).
    int addrColumnWidth() const { return charW_ * 18; } // fits 16 hex digits + pad
    /// Scroll the view by `rows` (negative = toward lower addresses), clamped at 0
    /// and only moving up onto mapped memory. Shared by the wheel and scrollbar.
    void scrollRows(int rows);
    /// After a pure scroll changed `address_` from `oldAddr`, keep the byte selection
    /// pinned to the same absolute addresses (CE-style) instead of the same screen
    /// position. Clears the selection if it scrolled out of the visible window.
    void keepSelectionAnchored(uintptr_t oldAddr);
    int visibleRows() const;
    /// Translate a viewport-local point into a byte offset from `address_`,
    /// or -1 if outside the hex grid.
    int byteOffsetAt(QPoint p) const;
    /// Pixel width of the hex column for the current display type (shared by
    /// paintEvent/byteOffsetAt/mousePressEvent so their layouts can't drift).
    int hexColWidth() const;

    ce::ProcessHandle* proc_ = nullptr;
    uintptr_t address_ = 0;
    FlatMem flatMem_;             // cached readable-memory model for the scrollbar
    int bytesPerRow_ = 16;
    DisplayType displayType_ = DisplayType::Byte;
    QFont monoFont_{"Monospace", 10};
    int charW_ = 0;
    int charH_ = 0;
    int selectedOffset_ = -1;  // Byte offset within the visible window, -1 if none
    int selAnchor_ = -1;       // Other end of a shift/drag range, -1 if single byte
    int editNibble_ = 0;       // 0 = high nibble next, 1 = low nibble next
    bool editAscii_ = false;   // selection is in the ASCII column (type chars)
    std::vector<uint8_t> cache_;
    size_t readableBytes_ = 0;   // how many leading cache_ bytes were actually read
                                 // (the rest render as "??", not zeros)
    std::vector<uint8_t> prevCache_;   // previous refresh's bytes, for change highlight
    uintptr_t prevAddress_ = 0;        // address prevCache_ was read at (guards navigation)
    std::vector<char> changed_;        // per-byte: differs from the previous refresh
    bool hexUpper_ = false;      // uppercase hex bytes/addresses (display/hexUpper)
    int  addrDigits_ = 16;       // hex digits in the address column (8 or 16)

    /// Write a single byte to the target, making the page writable if needed.
    bool pokeByte(uintptr_t addr, uint8_t value);
};

// ── Disassembler View Widget ──
class DisasmView : public QAbstractScrollArea {
    Q_OBJECT
public:
    explicit DisasmView(QWidget* parent = nullptr);

    void setProcess(ce::ProcessHandle* proc) { proc_ = proc; }
    void setResolver(ce::SymbolResolver* resolver) { resolver_ = resolver; }
    void setDwarf(const ce::DwarfRegistry* dwarf) { dwarf_ = dwarf; viewport()->update(); }
    /// Module map used to annotate a call/jmp target with "module+offset" when it
    /// has no symbol (stripped game binaries). Shared from the browser's cache so
    /// we don't re-parse /proc/<pid>/maps on every repaint.
    void setModuleCache(std::vector<ce::ModuleInfo> m) { moduleCache_ = std::move(m); viewport()->update(); }
    void setAddress(uintptr_t addr);
    uintptr_t currentAddress() const { return address_; }
    void setActiveBreakpoints(const std::set<uintptr_t>& addrs) { breakpoints_ = addrs; viewport()->update(); }
    void setComment(uintptr_t addr, const std::string& text) {
        if (text.empty()) comments_.erase(addr); else comments_[addr] = text;
        viewport()->update();
    }
    std::string comment(uintptr_t addr) const {
        auto it = comments_.find(addr); return it == comments_.end() ? std::string() : it->second;
    }
    const std::map<uintptr_t, std::string>& comments() const { return comments_; }
    void clearComments() { comments_.clear(); viewport()->update(); }
    /// Address of the currently selected instruction (the cursor row), or 0 if none.
    uintptr_t selectedAddress() const;
    /// Size in bytes of the currently selected instruction.
    int selectedSize() const;
    /// Number of instructions in the current selection (1 for a single line, more
    /// when a range is selected via Shift+Up/Down or Shift+click). 0 if none.
    int selectionCountForTest() const { int lo, hi; return selRange(lo, hi) ? hi - lo + 1 : 0; }
    void activateRowForTest(int row) { activateRow(row); }
    void scrollRowsForTest(int rows) { scrollRows(rows); }
    /// Mark the current instruction pointer (debugger stop). The row whose address
    /// equals this is highlighted distinctly and flagged with a ► marker, like CE's
    /// Memory Viewer when paused. Pass 0 to clear (target resumed / detached).
    void setCurrentInstruction(uintptr_t addr, const ce::CpuContext& ctx = {}) {
        currentIp_ = addr; currentCtx_ = ctx; viewport()->update();
    }
    uintptr_t currentInstruction() const { return currentIp_; }
    void refresh();
    /// Re-read font + colors from QSettings (Disassembler Preferences) and repaint.
    void reloadPreferences();

signals:
    void addressChanged(uintptr_t addr);
    void requestSetSoftBreakpoint(uintptr_t addr);
    void requestSetHwExecBreakpoint(uintptr_t addr);
    void requestRemoveBreakpoint(uintptr_t addr);
    void requestNop(uintptr_t addr, int size);
    void requestAssemble(uintptr_t addr, int size, const QString& current);
    void requestXrefs(uintptr_t addr);
    void requestInstructionAccess(uintptr_t addr);   // "what addresses does this instr access"
    void requestSetSymbol(uintptr_t addr);
    void requestSetComment(uintptr_t addr);
    void requestAddToList(uintptr_t addr, ce::ValueType type);   // add the instruction addr
    void requestSaveRegion(uintptr_t addr);
    void requestLoadRegion(uintptr_t addr);
    // Generate a pre-filled auto-assembler injection template for this address.
    void requestInjection(uintptr_t addr, bool aob);

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;

private:
    void updateScrollBar();
    int addrColumnWidth() const { return charW_ * 18; } // fits 16 hex digits + pad
    /// Scroll by `rows` instructions (negative = up), region-safe. Shared by the
    /// wheel and the draggable scrollbar.
    void scrollRows(int rows);
    int visibleRows() const;
    uintptr_t scrollBack(uintptr_t addr, int count);
    int rowAtY(int y) const;
    bool followRow(int row);   // follow a row's branch target / RIP-relative data
    // Double-click / activate a row: follow a branch/data reference, else open the
    // assembler on the instruction (CE edits an instruction in place on double-click).
    void activateRow(int row);
    // Visible-row index of the instruction starting at `addr`, or -1 if it is not a
    // visible instruction start (used to keep the selection anchored across a scroll).
    int rowOfAddress(uintptr_t addr) const;
    static uintptr_t parseImmediate(const std::string& operands);

    ce::ProcessHandle* proc_ = nullptr;
    ce::SymbolResolver* resolver_ = nullptr;
    const ce::DwarfRegistry* dwarf_ = nullptr;
    std::vector<ce::ModuleInfo> moduleCache_;   // for module+offset branch annotations
    std::unique_ptr<ce::Disassembler> disasm_ = std::make_unique<ce::Disassembler>(ce::Arch::X86_64);
public:
    /// Decode in 32- or 64-bit mode (set from the target's code bitness so a
    /// 32-bit process shows eax, not rax).
    void setArch(ce::Arch arch) { disasm_ = std::make_unique<ce::Disassembler>(arch); viewport()->update(); }
private:
    uintptr_t address_ = 0;
    FlatMem flatMem_;             // cached readable-memory model for the scrollbar
    int selectedRow_ = -1;        // cursor instruction (visible-window row index)
    int selAnchorRow_ = -1;       // other end of a Shift range selection, -1 = single
    /// Selected instruction range [lo, hi] (visible-window rows), false if none.
    bool selRange(int& lo, int& hi) const {
        if (selectedRow_ < 0) return false;
        int a = selAnchorRow_ < 0 ? selectedRow_ : selAnchorRow_;
        lo = std::min(a, selectedRow_); hi = std::max(a, selectedRow_);
        return true;
    }
    uintptr_t currentIp_ = 0;     // debugger's current instruction pointer (0 = none)
    ce::CpuContext currentCtx_{}; // registers at the stop, for the jump hint + operand EA
    QFont monoFont_{"Monospace", 10};
    int charW_ = 0;
    int charH_ = 0;
    int gutterW_ = 0;
    // Disassembler palette (Disassembler Preferences → QSettings "disasm/").
    QColor defaultColor_{0xcd, 0xd6, 0xf4};
    QColor addrColor_{0x89, 0xb4, 0xfa};
    QColor condJumpColor_{0xfa, 0xb3, 0x87};
    QColor jumpColor_{0x89, 0xb4, 0xfa};
    std::vector<ce::Instruction> instructions_;
    QString emptyReason_;   // shown when a read yields no instructions (blank pane otherwise)
    bool hexUpper_ = false; // uppercase instruction addresses (display/hexUpper)
    int  addrDigits_ = 16;  // hex digits in the address column (8 or 16)
    std::set<uintptr_t> breakpoints_;
    std::map<uintptr_t, std::string> comments_;   // user-defined inline comments
};

// ── Memory Browser Window ──
class MemoryBrowser : public QMainWindow {
    Q_OBJECT
public:
    explicit MemoryBrowser(ce::ProcessHandle* proc, QWidget* parent = nullptr);

    void gotoAddress(uintptr_t addr);

    /// The two panes CE can bring to the front when you jump to an address (see
    /// ce::chooseMemViewPane): the disassembler for code, the hex dump for data.
    enum class Pane { Disassembler, HexDump };
    /// Give keyboard focus to one pane (so the arrow keys drive it) and scroll it to
    /// the current address. Used when a jump lands on an address: code focuses the
    /// disassembler, data the hex dump (Shift/Ctrl override).
    void focusPane(Pane p);
    Pane focusedPaneForTest() const { return lastFocusedPane_; }
    QString addressBarTextForTest(uintptr_t addr) const { return addressBarText(addr); }

    /// Test helper: search readable memory from `start` for `pattern` with an optional
    /// wildcard `mask` (1 = must match, 0 = any). Returns the hit address, or 0.
    uintptr_t searchMemoryForTest(const std::vector<uint8_t>& pattern,
                                  const std::vector<char>& mask, uintptr_t start,
                                  bool backward = false) {
        return searchMemory(pattern, start, /*inclusive=*/true, mask, backward);
    }

    /// The debugger stopped at `rip`: mark it as the current instruction (green ►
    /// highlight in the disassembler). When `follow` is true the view also scrolls
    /// to it (without polluting back/forward history), matching CE's Memory Viewer
    /// which follows execution. Pass through clearCurrentInstruction() on resume.
    void showCurrentInstruction(uintptr_t rip, bool follow = true, const ce::CpuContext& ctx = {});
    void clearCurrentInstruction();

    /// Test helper: renders the disassembler and counts the pixels painted in the
    /// distinct current-instruction background colour, verifying the paused-line
    /// highlight is actually drawn (0 when no current instruction is set/visible).
    int currentIpHighlightPixelsForTest();

    /// The target exited and its ProcessHandle is about to be destroyed. Stop the
    /// refresh timer and drop the process pointer (here and in the disasm/hex
    /// views) so nothing reads the freed handle. The window stays open, frozen.
    void detachFromTarget();

    /// Hooks for actions the browser cannot perform alone (need MainWindow's BpManager etc.).
    using BpToggle = std::function<void(uintptr_t addr, bool hardware)>;
    using BpQuery = std::function<std::set<uintptr_t>()>;
    using CodeFinderLauncher = std::function<void(uintptr_t addr, bool writesOnly)>;
    void setBreakpointSetter(BpToggle fn) { bpSetter_ = std::move(fn); refreshBreakpoints(); }
    void setBreakpointRemover(std::function<void(uintptr_t)> fn) { bpRemover_ = std::move(fn); }
    void setBreakpointQuery(BpQuery fn) { bpQuery_ = std::move(fn); refreshBreakpoints(); }
    void setCodeFinderLauncher(CodeFinderLauncher fn) { cfLauncher_ = std::move(fn); }
    /// "Find out what addresses this instruction accesses" (CE): MainWindow runs the
    /// instruction-access monitor and shows the results.
    void setInstructionAccessLauncher(std::function<void(uintptr_t)> fn) {
        instrAccessLauncher_ = std::move(fn);
    }
    /// Add an address (from the hex view's context menu) to the cheat table.
    void setAddToList(std::function<void(uintptr_t, ce::ValueType)> fn) { addToList_ = std::move(fn); }

    /// Notified whenever the user labels/unlabels an address here (name empty = cleared),
    /// so the owner can mirror it into the app-wide symbol table (CE global symbols).
    void setUserSymbolCallback(std::function<void(uintptr_t, const std::string&)> cb) {
        userSymbolCb_ = std::move(cb);
    }
    /// Seed this view's resolver with existing user labels so they display here too.
    void addUserSymbols(const std::map<uintptr_t, std::string>& syms);

    /// Open the full Debugger window at an address (the browser's step buttons use
    /// this — real single-stepping lives in the Debugger; MainWindow provides it).
    using DebuggerLauncher = std::function<void(uintptr_t addr)>;
    void setDebuggerLauncher(DebuggerLauncher fn) { debuggerLauncher_ = std::move(fn); }

    /// Single-step / run controls (CE parity: the Memory Viewer drives stepping).
    /// The debug session itself lives in the Debugger window; MainWindow wires these
    /// to it so the viewer's F7/F8/F9 step the paused target. Each is a no-op when no
    /// session is stopped (the wired callback checks). After a step the Debugger's
    /// stopped(rip) signal re-highlights this view's current line via MainWindow.
    void setStepControls(std::function<void()> stepInto,
                         std::function<void()> stepOver,
                         std::function<void()> run) {
        stepIntoFn_ = std::move(stepInto);
        stepOverFn_ = std::move(stepOver);
        runFn_ = std::move(run);
    }
    /// Run-to-cursor (F4): continue until the *viewer's* selected instruction. Takes
    /// the target address so it runs to this window's cursor, not the Debugger's.
    void setRunToCursor(std::function<void(uintptr_t)> fn) { runToCursorFn_ = std::move(fn); }

    /// Persistent disassembler comments (saved with the cheat table). The store is
    /// owned by MainWindow and keyed by module-relative address EXPRESSION so it
    /// survives ASLR. setAnnotationStore installs the initial set (applied now) and
    /// a saver called whenever a comment changes.
    void setAnnotationStore(std::vector<ce::DisassemblerComment> initial,
                            std::function<void(std::vector<ce::DisassemblerComment>)> saver);

    /// Hook to open a script editor pre-loaded with a generated injection script
    /// (MainWindow owns the AutoAssembler and creates the editor).
    void setAutoAssembleOpener(std::function<void(const QString&)> fn) {
        autoAssembleOpener_ = std::move(fn);
    }
    /// Hook to open a Structure Dissector at an address (Tools > Dissect data/
    /// structures). MainWindow owns the dissector windows.
    void setDissectOpener(std::function<void(uintptr_t)> fn) { dissectOpener_ = std::move(fn); }

    /// Test helper: find a Tools-menu action whose text starts with `text` and
    /// trigger it; returns false if there is no such action.
    bool triggerToolActionForTest(const QString& text);

    /// Test helper: trigger a Debug-menu action whose text starts with `text`
    /// (e.g. "Step into"); returns false if there is no such action.
    bool triggerDebugActionForTest(const QString& text);

    /// Test helper: invoke the run-to-cursor callback with an explicit target
    /// (bypasses disasm selection); returns false if no controller is wired.
    bool runToCursorForTest(uintptr_t addr);

    /// CE keeps the memory/debug tools in the Memory Viewer's own menu bar (not the
    /// main window). MainWindow populates these with the actions that need its
    /// context (process, address list) after constructing the browser.
    QMenu* viewMenu() const { return viewMenu_; }
    QMenu* toolsMenu() const { return toolsMenu_; }
    QMenu* debugMenu() const { return debugMenu_; }

protected:
    // Persist the viewer's size/position and the three splitters across runs.
    void closeEvent(QCloseEvent* ev) override;

private slots:
    void onGotoAddress();
    void onRefresh();

private:
    void refreshBreakpoints();
    // Navigation history (back/forward, like a browser). navigateTo records the
    // current spot before moving; goBack/goForward replay the stacks.
    void navigateTo(uintptr_t addr);
    void syncViews(uintptr_t addr);
    // CE-style symbolic label for the address box: "module+offset" inside a mapped
    // module (round-trips through the expression parser), otherwise raw hex.
    QString addressBarText(uintptr_t addr) const;
    void goBack();
    void goForward();
    void updateNavActions();

    // Find a byte pattern or ASCII text forward from the current address.
    void findInMemory(bool findNext, bool backward = false);
    uintptr_t searchMemory(const std::vector<uint8_t>& pattern, uintptr_t start,
                           bool inclusive = false, const std::vector<char>& mask = {},
                           bool backward = false);

    void writeNop(uintptr_t addr, int size);
    void assembleAt(uintptr_t addr, int origSize, const QString& current);
    bool patchBytes(uintptr_t addr, const std::vector<uint8_t>& bytes);
    void showXrefs(uintptr_t addr);
    void saveRegionToFile(uintptr_t addr);
    void loadRegionFromFile(uintptr_t addr);

    ce::ProcessHandle* proc_;
    ce::SymbolResolver resolver_;
    ce::DwarfRegistry dwarf_;
    DisasmView* disasmView_;
    HexView* hexView_;
    Pane lastFocusedPane_ = Pane::Disassembler;  // pane focusPane() last raised
    QTableWidget* registerPanel_ = nullptr;  // CE register panel (right of disasm)
    QTableWidget* stacktracePanel_ = nullptr; // CE stacktrace panel (right of hex)
    QLineEdit* addressEdit_;
    QTimer* refreshTimer_;

    std::vector<uintptr_t> backStack_;
    std::vector<uintptr_t> forwardStack_;
    uintptr_t currentAddr_ = 0;
    std::vector<ce::ModuleInfo> modules_;   // cached for module+offset status display
    std::vector<uint8_t> lastSearch_;
    std::vector<char> lastSearchMask_;   // wildcard mask for Find Next (parallel to lastSearch_)
    QAction* backAct_ = nullptr;
    QAction* fwdAct_ = nullptr;

    std::set<uintptr_t> bookmarks_;
    QMenu* bookmarksMenu_ = nullptr;
    QMenu* viewMenu_ = nullptr;    // CE Memory Viewer "View" menu
    QMenu* toolsMenu_ = nullptr;   // CE Memory Viewer "Tools" menu
    QMenu* debugMenu_ = nullptr;   // CE Memory Viewer "Debug" menu
    void buildMenuBar();
    void toggleBookmark();
    void rebuildBookmarksMenu();

    BpToggle bpSetter_;
    std::function<void(uintptr_t)> bpRemover_;
    std::function<void(uintptr_t, ce::ValueType)> addToList_;
    std::function<void(uintptr_t, const std::string&)> userSymbolCb_;   // label mirror to owner
    BpQuery bpQuery_;
    CodeFinderLauncher cfLauncher_;
    std::function<void(uintptr_t)> instrAccessLauncher_;
    DebuggerLauncher debuggerLauncher_;
    std::function<void()> stepIntoFn_, stepOverFn_, runFn_;   // delegate to the debug session
    std::function<void(uintptr_t)> runToCursorFn_;            // run to the viewer's selected line

    std::function<void(const QString&)> autoAssembleOpener_;
    std::function<void(uintptr_t)> dissectOpener_;
    // Persistent-comment plumbing (see setAnnotationStore).
    std::function<void(std::vector<ce::DisassemblerComment>)> annotationSaver_;
    std::string addrToExpr(uintptr_t addr) const;   // absolute -> "module+0xoff"
    uintptr_t exprToAddr(const std::string& expr) const; // inverse (0 if unresolved)
    void persistComments();                         // gather + call annotationSaver_
};

} // namespace ce::gui
