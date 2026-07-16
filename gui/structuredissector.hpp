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

    // Called when the user adds a field to the address list.
    using AddToListFn = std::function<void(uintptr_t addr, ce::ValueType type, const QString& desc)>;
    void setAddToListCallback(AddToListFn fn) { addToListCb_ = std::move(fn); }

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
    QString formatValue(const uint8_t* data, int offset, const QString& type) const;
    void onCopyAsCpp();
    ce::ValueType guessType(const uint8_t* data, int offset) const;
    bool looksLikePointer(uintptr_t p) const;

    std::map<int, QString> fieldNames_;   // offset -> user field name
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
    std::vector<uint8_t> cache_;
    AddToListFn addToListCb_;
};

} // namespace ce::gui
