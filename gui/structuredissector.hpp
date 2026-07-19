#pragma once
#include "platform/process_api.hpp"
#include "core/types.hpp"
#include <QMainWindow>
#include <QTableWidget>
#include <QLineEdit>
#include <QSpinBox>
#include <QTimer>
#include <functional>

namespace ce::gui {

class StructureDissector : public QMainWindow {
    Q_OBJECT
public:
    explicit StructureDissector(ce::ProcessHandle* proc, uintptr_t baseAddr = 0, QWidget* parent = nullptr);

    /// The target exited (its ProcessHandle is about to be freed): stop the refresh
    /// timer and drop the process pointer so nothing reads the freed handle. The
    /// last dissection stays frozen on screen.
    void detachFromTarget();

    // Called when the user adds a field to the address list.
    using AddToListFn = std::function<void(uintptr_t addr, ce::ValueType type, const QString& desc)>;
    void setAddToListCallback(AddToListFn fn) { addToListCb_ = std::move(fn); }

    // Add every named field to the address list (base+offset, guessed type, field
    // name), so a labelled or type-as'd struct lands in the cheat table in one action.
    // Returns the number of fields added.
    int addAllFieldsToList();

    // Test helpers (offscreen smoke): drive compare mode and inspect the result.
    void setCompareAddressesForTest(std::vector<uintptr_t> addrs) {
        compareAddrs_ = std::move(addrs); if (baseAddr_) populateTable();
    }
    void nameFieldForTest(int offset, const QString& name) { fieldNames_[offset] = name; }
    // Type an expression into the Base Address field, resolve it, and report the base.
    uintptr_t resolveBaseForTest(const QString& expr) {
        addressEdit_->setText(expr); onGotoAddress(); return baseAddr_;
    }
    void typeFieldForTest(int offset, ce::ValueType t) { fieldTypes_[offset] = t; }
    int  columnCountForTest() const { return table_->columnCount(); }
    // Follow the pointer in the cell at (row, col); returns true if it re-based.
    bool followPointerForTest(int row, int col) { return followPointerAt(row, col); }
    uintptr_t baseAddressForTest() const { return baseAddr_; }
    // True if the cell at (row, col) is painted in the "differs from base" colour.
    bool cellDiffColoredForTest(int row, int col) const;
    // True if `row`'s value changed since the previous refresh (live-change highlight).
    bool rowValueChangedForTest(int row) const;
    // True if `row`'s Pointer? cell is painted as a valid pointer (CE-style coloring).
    bool pointerColoredForTest(int row) const;
    void refreshNowForTest() { if (proc_) populateTable(); }
    // Type an expression into the Compare field and apply it; returns the column count.
    int setCompareExpressionForTest(const QString& expr) {
        compareEdit_->setText(expr); applyCompareAddresses(); return table_->columnCount();
    }

private slots:
    void onGotoAddress();
    void onRefresh();
    void onContextMenu(const QPoint& pos);
    void onSaveDefinition();
    void onLoadDefinition();
    void onTypeAsIl2Cpp();
    void onTypeAsCStruct();

private:
    void populateTable();
    // Base address of the struct instance shown in table column `col` (Base col -> the
    // dissector base; a compare column -> that instance's address); 0 if not a value col.
    uintptr_t instanceBaseForColumn(int col) const;
    // If (row, col) holds a pointer, re-base the dissector to the pointed-to address
    // (CE Dissect Data "follow pointer" / spider). Returns true when it followed.
    bool followPointerAt(int row, int col);
    uintptr_t resolveAddress(const QString& text);   // CE-style address expression -> address
    void applyCompareAddresses();                    // parse the Compare field, repopulate
    QString formatValue(const uint8_t* data, int offset, const QString& type) const;
    void onCopyAsCpp();
    ce::ValueType guessType(const uint8_t* data, int offset) const;
    bool looksLikePointer(uintptr_t p) const;

    std::map<int, QString> fieldNames_;       // offset -> user field name
    std::map<int, ce::ValueType> fieldTypes_; // offset -> type (from Type-as; else guessed)
    ce::ProcessHandle* proc_;
    uintptr_t baseAddr_ = 0;
    int structSize_ = 256;
    int validBytes_ = 0;
    QLineEdit* addressEdit_;
    QLineEdit* compareEdit_ = nullptr;      // one or more compare struct addresses
    std::vector<uintptr_t> compareAddrs_;   // N instances to diff the base against
    std::vector<std::vector<uint8_t>> compareCaches_;
    QSpinBox* sizeSpin_ = nullptr;
    QTableWidget* table_;
    QTimer* refreshTimer_;
    std::vector<ce::ModuleInfo> moduleCache_;  // for "-> module+offset" on pointer fields
    std::vector<uint8_t> cache_;
    std::vector<uint8_t> prevCache_;        // previous refresh's bytes (live-change hl)
    uintptr_t prevBaseForChange_ = 0;       // base prevCache_ was read at (guards goto)
    AddToListFn addToListCb_;
};

} // namespace ce::gui
