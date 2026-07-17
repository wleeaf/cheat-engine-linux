#pragma once

#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/linux/ceserver_client.hpp"
#include "platform/linux/process_watcher.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/snapshot.hpp"
#include "core/autoasm.hpp"
#include "core/address_list.hpp"
#include "core/ct_file.hpp"
#include "scripting/lua_engine.hpp"
#include "symbols/elf_symbols.hpp"
#include "debug/breakpoint_manager.hpp"
#include "debug/code_finder.hpp"

#include <QMainWindow>
#include <QPointer>
#include <QTableView>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QCheckBox>
#include <QSplitter>
#include <QGroupBox>
#include <QProgressBar>
#include <QSlider>
#include <QShortcut>
#include <QHash>
#include <functional>
#include "gui/globalhotkeys.hpp"
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <optional>

namespace ce::gui {

class ScanResultsModel;
class AddressListModel;
class OverlayWindow;
class MemoryBrowser;
class AdvancedOptionsWindow;
class DebuggerWindow;
class StructureDissector;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;
    void loadTableFromPath(const QString& path);  // load .ct/.json without a dialog
    /// Push `path` to the front of the persisted recent-tables list and rebuild
    /// the File > Load Recent submenu.
    void addRecentTable(const QString& path);
    void rebuildRecentMenu();
    /// Open the Memory Viewer, optionally at `addr` (0 = default / selected result).
    /// Returns the window, or null if no process is attached.
    MemoryBrowser* openMemoryView(uintptr_t addr = 0);

    /// Open the Settings dialog (non-modal) and return it. Used by the Edit menu
    /// and the `--settings` launch flag.
    QDialog* openSettingsDialog();
    /// Attach to a running process by pid (no dialog). `name` is display-only.
    /// Used by the process picker and by `--pid <N>` on the command line.
    void attachToPid(pid_t pid, const QString& name);

private slots:
    void onOpenProcess();
    void onConnectCeserver();
    void onFirstScan();
    void onNextScan();
    void onUndoScan();
    void onResultDoubleClicked(const QModelIndex& index);
    void onMemoryView();
    void onDeleteAddresses();
    void onCopyAddresses();
    void onPasteAddresses();
    void onSaveTable();
    void onLoadTable();
    void onSaveScanResults();   // export the current found-address list to txt/csv
    void onCreateTrainer();
    void onFreezeTimer();

protected:
    // Keeps the empty-results hint sized to the results viewport.
    bool eventFilter(QObject* obj, QEvent* ev) override;
    // Persist window size/position (and the main splitter) across runs.
    void closeEvent(QCloseEvent* ev) override;

private:
    void setupUi();
    /// Move the cheat-table entry at `row` up (-1) or down (+1) and keep it selected.
    void moveSelectedEntry(int row, int delta);
    void setupMenus();
    void loadAddressEntries(const QJsonArray& entries);
    // Build the address list + table comment/annotations/Lua from a parsed table
    // (shared by the CE XML .CT and protected .CETRAINER load paths).
    void loadCheatTableModel(const ce::CheatTable& table);
    void updateScanButtons();
    void startCodeFinder(int row, bool writesOnly);
    void startCodeFinderForAddress(uintptr_t addr, bool writesOnly);
    // Stop active code finders so their ptrace attachment is released (a target
    // can have only one tracer; code injection needs to attach).
    void stopCodeFindersForInjection();
    /// Construct a Debugger appropriate for the currently attached process —
    /// LinuxDebugger for local pids, RemoteDebugger for ceserver-backed.
    std::unique_ptr<ce::Debugger> createDebuggerForCurrentProcess();
    /// Show the shared Debugger window, creating it on first use and just raising
    /// it thereafter (a second one could not ptrace-attach anyway).
    void showDebugger();
    /// Register an open Structure Dissector so it is frozen on target exit/re-attach
    /// (drops stale closed entries first).
    void trackStructDissector(StructureDissector* sd);
    /// Resolve a scan-range field: hex, symbol, or module+offset expression.
    std::optional<uintptr_t> parseAddressExpr(const QString& text);
    void rebuildValueHotkeys();
    // Run a scan on a worker thread while driving progressBar_ from
    // scanner_.progress(), keeping the UI responsive. Rethrows the scan's
    // exception on the caller thread; returns the result on success.
    std::unique_ptr<ce::ScanResult> runScanWithProgress(
        const std::function<ce::ScanResult()>& scanFn);
    ce::CheatTable buildCheatTable() const;
    // Install the persistent disassembler-comment store (module-relative, saved
    // with the table) into a freshly-created memory browser.
    void wireBrowserAnnotations(MemoryBrowser* browser);
    // Open the auto-assembler editor loaded with an existing script entry's
    // script; saving updates that same entry in place (found by stable id).
    void editScriptEntry(int row);
    void showOverlayDialog();
    void updateOverlayStatus();
    // Table "Comments" window (CE CommentsUnit): a free-text memo saved with the
    // cheat table (persisted in CheatTable.comment via build/loadTable).
    void showComments();
    void showTableLuaScript();   // Table > Show Cheat Table Lua Script (Ctrl+Alt+L)
    // Open a shipped doc (e.g. docs/SCRIPTING.md) in a rendered viewer, falling
    // back to the GitHub copy at `url` if the file is not found locally.
    void openHelpDoc(const QString& relPath, const QString& title, const QString& url);
    QString tableComment_;
    QString tableLuaScript_;     // table-level Lua (runs on load, saved with the table)
    // Populate a Memory Viewer's View/Tools/Debug menus with the tools that need
    // MainWindow's context (CE keeps these in the Memory Viewer, not the main menu).
    void populateBrowserMenus(MemoryBrowser* b);
    // Advanced Options — the CE "Code list" (created once, kept so entries persist).
    void showAdvancedOptions();
    ce::gui::AdvancedOptionsWindow* advancedOptions_ = nullptr;

    // Process — local (LinuxProcessHandle) or remote (RemoteProcessHandle).
    std::unique_ptr<ce::ProcessHandle> process_;
    std::unique_ptr<ce::os::CEServerClient> ceserverClient_;  // Outlives the remote handle.
    std::unique_ptr<ce::Snapshot> snapshot_;  // Captured baseline for diff/restore.
    std::vector<QPair<qulonglong, qulonglong>> allocations_;  // (address,size) blocks we allocated.
    std::unique_ptr<ce::os::ProcessWatcher> processWatcher_;
    pid_t currentPid_ = 0;
    int moduleCacheTick_ = 0;   // throttles the address-list module cache refresh
    bool pauseWhileScanning_ = false;   // SIGSTOP the target during each scan

    // Scanner + AutoAssembler + Lua + Debug
    MemoryScanner scanner_;
    AutoAssembler autoAsm_;
    LuaEngine luaEngine_;
    ce::SymbolResolver luaResolver_;   // symbols for Lua name/expression resolution
    BreakpointManager bpManager_;
    std::vector<std::unique_ptr<CodeFinder>> codeFinders_;
    std::vector<std::unique_ptr<ce::Debugger>> codeFinderDebuggers_;
    std::unique_ptr<ScanResult> lastResult_;
    std::unique_ptr<ScanResult> undoResult_;
    ce::ValueType lastResultType_ = ce::ValueType::Int32;
    ce::ValueType undoResultType_ = ce::ValueType::Int32;
    size_t lastResultValueSize_ = 0;
    size_t undoResultValueSize_ = 0;

    QMenu* recentMenu_ = nullptr;   // File > Load Recent, rebuilt from QSettings
    // A single shared Debugger window: it attaches via ptrace on construction, and
    // only one tracer per target is allowed, so opening a second would just fail
    // to attach. QPointer auto-nulls when the user closes it (WA_DeleteOnClose).
    QPointer<DebuggerWindow> debuggerWindow_;
    // Open Memory Viewers, so we can freeze them when the target exits (their raw
    // process pointer would otherwise dangle). QPointer entries auto-null on close.
    std::vector<QPointer<MemoryBrowser>> memoryViewers_;
    // Open Structure Dissectors: same story (they poll proc_ on a refresh timer).
    std::vector<QPointer<StructureDissector>> structDissectors_;

    // Top panel — process & scan
    QLabel* processLabel_;
    QLineEdit* scanValueEdit_;
    QLineEdit* scanValue2Edit_;   // upper bound for "Value between..."
    QLabel* betweenAndLabel_;
    QComboBox* scanTypeCombo_;
    QComboBox* valueTypeCombo_;
    QComboBox* floatRoundingCombo_;
    QPushButton* firstScanBtn_;
    QPushButton* nextScanBtn_;
    QPushButton* undoScanBtn_;
    QLabel* foundLabel_;
    QProgressBar* progressBar_;
    QLabel* resultsEmptyHint_ = nullptr;   // centered hint over an empty result list
    QLabel* tableEmptyHint_ = nullptr;     // centered hint over an empty cheat table

    // Scan options
    QLineEdit* fromAddressEdit_;
    QLineEdit* toAddressEdit_;
    QCheckBox* writableCheck_;
    QCheckBox* executableCheck_;
    QCheckBox* fastScanCheck_;
    QCheckBox* percentCheck_;
    QCheckBox* hexCheck_ = nullptr;   // parse integer scan values as hex
    QCheckBox* caseSensitiveCheck_ = nullptr;  // string scans: case sensitivity
    QLineEdit* alignEdit_;
    QLineEdit* percentValueEdit_;
    QLineEdit* percentValue2Edit_;
    QLineEdit* floatToleranceEdit_;
    QComboBox* stringEncodingCombo_;

    // Results
    QTableView* resultsView_;
    ScanResultsModel* resultsModel_;

    // Bottom panel — address list
    QTableView* addressListView_;
    AddressListModel* addressListModel_;
    std::vector<QShortcut*> valueHotkeyShortcuts_;
    GlobalHotkeyManager* globalHotkeys_ = nullptr;     // system-wide (X11) hotkeys
    QHash<int, std::function<void()>> hotkeyActions_;  // hotkey id -> action
    OverlayWindow* overlayWindow_ = nullptr;
    QTimer* valueRefreshTimer_ = nullptr;   // address-list/results live refresh
    // Persistent disassembler comments (module-relative address expressions),
    // synced to/from open memory browsers and saved with the cheat table.
    std::vector<ce::DisassemblerComment> disasmAnnotations_;
};

// ── Models ──

class ScanResultsModel : public QAbstractTableModel {
    Q_OBJECT
public:
    explicit ScanResultsModel(QObject* parent = nullptr);
    void setResult(ScanResult* result, ce::ValueType vt, size_t valueSize = 0);
    void clear();

    int rowCount(const QModelIndex& = {}) const override;
    int columnCount(const QModelIndex& = {}) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation, int role) const override;

    uintptr_t addressAt(int row) const;

    // Live-value support: re-read the current value of the visible rows from the
    // target so the Value column tracks the process in real time (CE does the
    // same — only the on-screen rows are refreshed, since results can be huge).
    void setProcess(ce::ProcessHandle* proc) { proc_ = proc; }
    void refreshRange(int firstRow, int lastRow);
    void setDisplayHex(bool h) {
        displayHex_ = h;
        if (rowCount() > 0) emit dataChanged(index(0, 1), index(rowCount() - 1, 1), {Qt::DisplayRole});
    }

private:
    size_t valueSizeBytes() const;

    bool displayHex_ = false;
    ScanResult* result_ = nullptr;
    ce::ValueType valueType_ = ce::ValueType::Int32;
    size_t valueSize_ = 0;
    ce::ProcessHandle* proc_ = nullptr;
    std::vector<ce::ModuleInfo> modules_;                      // cached for static-address (green) coloring
    std::unordered_map<int, std::vector<uint8_t>> liveValues_; // row -> current bytes (empty = unreadable)
    std::unordered_map<int, bool> changed_;                    // row -> value changed on last refresh
};

struct AddressEntry {
    int id = 0;               // Stable identifier for Lua references (survives row reorder)
    bool active = false;
    QString description;
    uintptr_t address = 0;
    ce::ValueType type = ce::ValueType::Int32;
    size_t byteCount = 0;     // element length for ByteArray/String/Unicode (0=unknown)
    QString currentValue;
    QString frozenValue;      // Value to continuously write when active
    ce::FreezeMode freezeMode = ce::FreezeMode::Normal;
    QString autoAsmScript;    // Auto-assembler script to run on enable/disable
    ce::DisableInfo autoAsmDisableInfo;
    QString color;            // Hex color for display
    QString dropdownList;     // "value:label;value:label" choices
    QString hotkeyKeys;       // Portable key sequence string
    QString increaseHotkeyKeys;
    QString decreaseHotkeyKeys;
    QString setValueHotkeyKeys;   // hotkey that sets the value to setValueHotkeyValue
    QString setValueHotkeyValue;  // target value written by the set-value hotkey
    QString hotkeyStep = "1";
    int indent = 0;           // Nesting level (0 = root, 1 = child, etc.)
    bool isGroup = false;     // Group header (no address, just a label)
    bool showAsHex = false;   // Display/edit the value in hexadecimal
    QString addressExpr;      // If set, re-evaluated each refresh (pointer records)
};

class AddressListModel : public QAbstractTableModel, public ce::IAddressList {
    Q_OBJECT
public:
    explicit AddressListModel(QObject* parent = nullptr);
    void addEntry(uintptr_t addr, ce::ValueType type, const QString& desc = "No description",
                  const QString& addressExpr = {}, size_t byteCount = 0);
    // Add a cheat-table entry whose checkbox runs an auto-assembler script's
    // [ENABLE]/[DISABLE] (an "(Auto Assembler script)" row, like CE).
    void addScriptEntry(const QString& desc, const QString& script);
    void addGroup(const QString& desc = "-- Group --");
    // Replace the auto-assembler script (and optionally description) of an
    // existing script entry, found by its stable id so it survives row reorder.
    void updateScriptEntryById(int id, const QString& desc, const QString& script);
    bool isScriptEntry(int row) const;
    // Edit individual fields of an entry (address/description) with proper
    // dataChanged notification, for inline editing and the copy/edit menu.
    void setEntryAddress(int row, uintptr_t addr, const QString& expr = {});
    void setEntryDescription(int row, const QString& desc);
    void removeEntry(int row);
    void removeEntries(QList<int> rows);
    /// Swap the entry at `row` with its neighbour `delta` rows away (-1 up, +1
    /// down). Returns the entry's new row, or `row` if it couldn't move.
    int moveEntry(int row, int delta);
    void indentRows(QList<int> rows);
    void outdentRows(QList<int> rows);
    void setFreezeMode(int row, ce::FreezeMode mode);
    void setAllActive(bool active);
    void setShowAsHex(int row, bool hex);
    void setEntryType(int row, ce::ValueType t);
    void setHotkeyKeys(int row, const QString& keys);
    void setValueHotkeys(int row, const QString& increaseKeys, const QString& decreaseKeys,
                         const QString& step, const QString& setKeys, const QString& setValue);
    bool adjustEntryValue(int row, double delta);
    const std::vector<AddressEntry>& entries() const { return entries_; }
    void toggleActive(int row);   // flip active state (hotkey target)
    void setEntryValueTo(int row, const QString& value);  // set-value hotkey target
    void setProcess(ce::ProcessHandle* proc) { proc_ = proc; refreshModuleCache(); }
    /// Refresh the cached module list used to display addresses as module+offset.
    /// Cheap enough to call from the periodic value refresh so it tracks modules
    /// that load after attach.
    void refreshModuleCache();
    void setAutoAssembler(ce::AutoAssembler* autoAsm) { autoAsm_ = autoAsm; }
    // Called just before a script entry's [ENABLE]/[DISABLE] runs, so the owner
    // can release any debugger traces that would block the injection's attach.
    void setBeforeAaExecute(std::function<void()> fn) { beforeAaExecute_ = std::move(fn); }
    void setActivationErrorCallback(std::function<void(const QString&, const QString&)> cb) {
        activationErrorCb_ = std::move(cb);
    }
    // Resolves an address expression (hex, symbol, module+offset, [pointer]+off)
    // typed into the Address column, so inline edits accept the same syntax as
    // "Add Address Manually". Set by MainWindow, which owns the symbol resolver.
    void setAddressResolver(std::function<std::optional<uintptr_t>(const QString&)> fn) {
        addressResolver_ = std::move(fn);
    }
    void updateValues(ce::ProcessHandle* proc);
    void freezeWrite(ce::ProcessHandle* proc);
    QJsonArray toJson() const;
    void fromJson(const QJsonArray& arr);

    int rowCount(const QModelIndex& = {}) const override;
    int columnCount(const QModelIndex& = {}) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation, int role) const override;
    Qt::ItemFlags flags(const QModelIndex& index) const override;
    bool setData(const QModelIndex& index, const QVariant& value, int role) override;

    // ── ce::IAddressList ──
    int count() const override;
    std::optional<ce::AddressEntrySnapshot> at(int index) const override;
    std::optional<ce::AddressEntrySnapshot> byId(int id) const override;
    int findIdByDescription(const std::string& desc) const override;
    std::vector<int> ids() const override;
    int createEntry(uintptr_t addr, ce::ValueType type, const std::string& description) override;
    int createGroup(const std::string& description) override;
    bool deleteById(int id) override;
    bool disableAllWithoutExecute() override;
    bool setDescription(int id, const std::string& desc) override;
    bool setAddress(int id, uintptr_t addr) override;
    bool setAddressExpression(int id, const std::string& expr) override;
    bool setType(int id, ce::ValueType t) override;
    bool setValue(int id, const std::string& valStr) override;
    bool setActive(int id, bool active) override;
    bool setColor(int id, const std::string& color) override;
    bool setDropdownList(int id, const QString& list);
    QString dropdownList(int row) const;
    bool setScript(int id, const std::string& script) override;
    bool setFreezeMode(int id, int mode) override;
    bool setHexView(int id, bool hex) override;
    bool setIndent(int id, int indent) override;
    std::string liveValue(int id) override;
    void setActivationCallback(ce::IAddressList::ActivationCallback cb) override {
        activationCb_ = std::move(cb);
    }

private:
    bool setEntryActive(int row, bool active);
    void reportActivationError(const QString& title, const QString& message);
    int rowOfId(int id) const;
    int allocId() { return nextId_++; }

    std::vector<AddressEntry> entries_;
    std::vector<ce::ModuleInfo> moduleCache_;   // for module+offset address display
    ce::ProcessHandle* proc_ = nullptr;
    ce::AutoAssembler* autoAsm_ = nullptr;
    std::function<void()> beforeAaExecute_;
    std::function<void(const QString&, const QString&)> activationErrorCb_;
    std::function<std::optional<uintptr_t>(const QString&)> addressResolver_;
    ce::IAddressList::ActivationCallback activationCb_;
    int nextId_ = 1;
};

} // namespace ce::gui
