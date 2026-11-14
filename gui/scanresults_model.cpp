// ScanResultsModel: the scan result list, loaded in batches as it scrolls.
#include <bit>
#include "core/target_capabilities.hpp"
#include "arch/target_arch.hpp"
#include <csignal>
#include "gui/mainwindow.hpp"
#include "gui/code_editor.hpp"
#include "core/local_target.hpp"
#include "gui/gdbconnectiondialog.hpp"
#include "gui/theme.hpp"
#include "gui/i18n.hpp"
#include "core/expression.hpp"
#include "core/value_io.hpp"
#include "core/memview_nav.hpp"
#include "gui/processlistdialog.hpp"
#include "gui/registereditor.hpp"
#include "gui/debuggerwindow.hpp"
#include "gui/memorybrowser.hpp"
#include "gui/advancedoptions.hpp"
#include "gui/changeaddressdialog.hpp"
#include "gui/graphicalmemoryview.hpp"
#include "scanner/pointer_scanner.hpp"
#include "gui/scripteditor.hpp"
#include "gui/pointerscan_dialog.hpp"
#include "gui/guest_scan_dialog.hpp"
#include "gui/structuredissector.hpp"
#include "gui/monodissector.hpp"
#include "gui/luaconsole.hpp"
#include "gui/breakpointlist.hpp"
#include "gui/codefinder.hpp"
#include "debug/instruction_access.hpp"
#include "gui/codereferences.hpp"
#include "gui/heapregions.hpp"
#include "gui/memoryregions.hpp"
#include "gui/modulelist.hpp"
#include "gui/overlay.hpp"
#include "gui/stackview.hpp"
#include "gui/threadlist.hpp"
#include "gui/settingsdialog.hpp"
#include "gui/tracerwindow.hpp"
#include "gui/filepatcher.hpp"
#include "gui/branchmapper.hpp"
#include "gui/elfinspector.hpp"
#include "gui/formdesigner.hpp"
#include "gui/findstaticswindow.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/linux/ceserver_debugger.hpp"
#include "scripting/lua_gui.hpp"
#include "core/ct_file.hpp"
#include "core/ct_file_stream.hpp"
#include <streambuf>
#include <sstream>
#include <limits>
#include <unordered_set>
#include <stdexcept>
#include "core/target_profile.hpp"
#include "core/trainer.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/mono_dissector.hpp"
#include <dlfcn.h>

#include "gui/autoasmoperation.hpp"
#include <thread>
#include <sys/utsname.h>
#include <atomic>
#include <fstream>
#include "platform/linux/injector.hpp"
#include <sys/prctl.h>
#include <sys/wait.h>

#include "gui/agent_panel.hpp"
#include <cerrno>
#include <QBrush>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <charconv>
#include <exception>

#include "gui/mainwindow_internal.hpp"
#include <QFont>
namespace ce::gui {
using namespace mainwindow_detail;
// Load rows as the user scrolls, keeping large first scans responsive.
static constexpr int kResultBatchSize = 1000;

// ═══════════════════════════════════════════════════════════════
// ScanResultsModel
// ═══════════════════════════════════════════════════════════════

ScanResultsModel::ScanResultsModel(QObject* parent) : QAbstractTableModel(parent) {
    // Unset colours follow the theme.
    onApplicationPaletteChange(this, [this]() { reloadPreferences(); });
}

size_t ScanResultsModel::valueSizeBytes() const {
    switch (valueType_) {
        case ValueType::Byte:    return 1;
        case ValueType::Int16:   return 2;
        case ValueType::Int32:   return 4;
        case ValueType::Int64:   return 8;
        case ValueType::Pointer: return valueSize_ == 4 || valueSize_ == 8 ? valueSize_ : sizeof(uintptr_t);
        case ValueType::Float:   return 4;
        case ValueType::Double:  return 8;
        case ValueType::All: return std::max<size_t>(1,valueSize_);
        // Variable-width types carry their byte length in valueSize_ (set at scan
        // time from the pattern / string length). Without this, AOB and string
        // results read only 4 bytes and rendered as "?".
        case ValueType::Grouped:
        case ValueType::Custom:
        case ValueType::ByteArray:
        case ValueType::Binary:
        case ValueType::String:
        case ValueType::UnicodeString: return std::max<size_t>(1, valueSize_);
        default:                 return 4;
    }
}

void ScanResultsModel::refreshRange(int firstRow, int lastRow) {
    if (!result_ || !proc_) return;
    int n = rowCount();
    if (n == 0) return;
    firstRow = std::max(0, firstRow);
    lastRow  = std::min(n - 1, lastRow);
    if (firstRow > lastRow) return;

    size_t vs = valueSizeBytes();
    // Bound the cache to what's on screen — drop rows outside the window.
    for (auto it = liveValues_.begin(); it != liveValues_.end(); ) {
        if (it->first < firstRow || it->first > lastRow) {
            changed_.erase(it->first);
            it = liveValues_.erase(it);
        } else ++it;
    }
    for (int row = firstRow; row <= lastRow; ++row) {
        const size_t readSize=result_->hasAllTypeCandidates() ? result_->allTypeValueSize(row) : vs;
        std::vector<uint8_t> buf(readSize);
        auto r=readSize ? proc_->read(result_->address(row),buf.data(),readSize) :
            Result<size_t>(std::unexpected(std::make_error_code(std::errc::invalid_argument)));
        std::vector<uint8_t> nv = (r && *r >= readSize) ? std::move(buf) : std::vector<uint8_t>{};
        // Flag rows whose value changed since the previous refresh (CE-style
        // red highlight for live-changing values).
        auto it = liveValues_.find(row);
        changed_[row] = (it != liveValues_.end()) && !it->second.empty()
                        && !nv.empty() && it->second != nv;
        liveValues_[row] = std::move(nv);
    }
    emit dataChanged(index(firstRow, 1), index(lastRow, 1), {Qt::DisplayRole, Qt::ForegroundRole});
}

void ScanResultsModel::setResult(ScanResult* result, ValueType vt, size_t valueSize,
                                 const std::string& stringEncoding) {
    beginResetModel();
    result_ = result;
    shownRows_ = result ? static_cast<int>(std::min<size_t>(result->count(), kResultBatchSize)) : 0;
    valueType_ = vt;
    valueSize_ = result && result->valueSize() ? result->valueSize() : valueSize;
    stringEncoding_ = stringEncoding.empty() ? "UTF-8" : stringEncoding;
    liveValues_.clear();
    changed_.clear();
    // Cache the module map so the Address column can flag "static" results (those
    // inside a loaded module) in green — CE's cue for pointer-stable addresses
    // that survive a restart, the ones worth turning into a pointer path.
    modules_ = proc_ ? proc_->modules() : std::vector<ce::ModuleInfo>{};
    endResetModel();
}

void ScanResultsModel::clear() {
    beginResetModel();
    result_ = nullptr;
    shownRows_ = 0;
    valueSize_ = 0;
    liveValues_.clear();
    changed_.clear();
    endResetModel();
}

int ScanResultsModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : shownRows_;
}

bool ScanResultsModel::canFetchMore(const QModelIndex& parent) const {
    return !parent.isValid() && static_cast<size_t>(shownRows_) < resultCount() && shownRows_ < INT_MAX;
}

void ScanResultsModel::fetchMore(const QModelIndex& parent) {
    if (!canFetchMore(parent)) return;
    int next = static_cast<int>(std::min<size_t>(resultCount(),
        std::min<size_t>(INT_MAX, static_cast<size_t>(shownRows_) + kResultBatchSize)));
    beginInsertRows({}, shownRows_, next - 1);
    shownRows_ = next;
    endInsertRows();
}

int ScanResultsModel::columnCount(const QModelIndex& parent) const { return parent.isValid() ? 0 : 3; }

QVariant ScanResultsModel::headerData(int section, Qt::Orientation o, int role) const {
    if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
    switch (section) {
        case 0:  return tr("Address");
        case 1:  return tr("Value");       // current (live) value
        default: return tr("Previous");    // value captured at scan time
    }
}

// Format `vs` bytes at `buf` as `vt` (shared by the live Value and the scan-time
// Previous columns).
static QString formatScanValue(ValueType vt,bool displayHex,const uint8_t* buf,size_t size,
                               const std::string& encoding="UTF-8",ByteOrder order=ByteOrder::Little) {
    if (vt==ValueType::Binary || vt==ValueType::Grouped || vt==ValueType::Custom || vt==ValueType::All) vt=ValueType::ByteArray;
    ce::ValueIoOptions options;options.hex=displayHex;options.size=size;options.encoding=encoding;
    options.byteOrder=order;options.pointerWidth=static_cast<int>(size);
    auto decoded=ce::decodeTypedValue(vt,{buf,size},options);
    return decoded ? QString::fromStdString(*decoded) : QStringLiteral("??");
}

QVariant ScanResultsModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= shownRows_ || !result_) return {};
    // Red foreground on the Value column when it changed since the last refresh.
    if (role == Qt::ForegroundRole) {
        // Colours from the Foundlist Customizer (theme-aware defaults).
        if (index.column() == 1) {
            auto it = changed_.find(index.row());
            if (it != changed_.end() && it->second) return QBrush(options_.changed);
        } else if (index.column() == 0) {
            // A static address lives inside a loaded module, so it keeps the
            // same module+offset across restarts (CE's green cue).
            const bool isStatic = !modules_.empty() &&
                !ce::moduleOffsetString(modules_, result_->address(index.row())).empty();
            if (isStatic) return QBrush(options_.staticAddress);
            if (options_.dynamicAddress.isValid()) return QBrush(options_.dynamicAddress);
            return {};
        }
        return options_.normal.isValid() ? QVariant(QBrush(options_.normal)) : QVariant();
    }
    if (role == Qt::BackgroundRole)
        return options_.background.isValid() ? QVariant(QBrush(options_.background)) : QVariant();
    if (role == Qt::FontRole && options_.fontSize > 0) {
        QFont font;
        font.setPointSize(options_.fontSize);
        return font;
    }
    // Hovering a static address reveals its module+offset (the durable identity).
    if (role == Qt::ToolTipRole && index.column() == 0 && !modules_.empty()) {
        std::string modOff = ce::moduleOffsetString(modules_, result_->address(index.row()));
        if (!modOff.empty()) return QString::fromStdString(modOff);
    }
    if (role != Qt::DisplayRole && role != Qt::ToolTipRole) return {};

    return displayValueAt(static_cast<size_t>(index.row()), index.column());
}

QString ScanResultsModel::displayValueAt(size_t row, int column) const {
    if (!result_ || row >= result_->count() || column < 0 || column > 2) return {};
    if (column == 0) {
        if (options_.staticNotation && !modules_.empty()) {
            const std::string modOff = ce::moduleOffsetString(modules_, result_->address(row));
            if (!modOff.empty()) return QString::fromStdString(modOff);
        }
        return formatListAddress(result_->address(row));
    }

    const size_t vs=valueSizeBytes();
    const size_t shownSize=result_->hasAllTypeCandidates() ? result_->allTypeValueSize(row) : vs;
    if (!shownSize) return QStringLiteral("??");
    std::vector<uint8_t> buf(vs);
    if (column == 2) {
        // Previous: always the value captured at scan time.
        result_->value(row, buf.data(), vs);
        return formatScanValue(valueType_, displayHex_, buf.data(), shownSize, stringEncoding_, result_->hasDataFormat() ? result_->byteOrder() : valueType_==ValueType::UnicodeString ? ce::ByteOrder::Little : std::endian::native==std::endian::big ? ce::ByteOrder::Big : ce::ByteOrder::Little);
    }
    // Value: prefer the live re-read for on-screen rows; fall back to the
    // scan-time value for rows not currently refreshed.
    auto it = row <= INT_MAX ? liveValues_.find(static_cast<int>(row)) : liveValues_.end();
    if (it != liveValues_.end()) {
        if (it->second.size() == shownSize) std::copy(it->second.begin(),it->second.end(),buf.begin());
        else return QStringLiteral("??");   // unreadable this refresh
    } else {
        result_->value(row, buf.data(), vs);
    }
    return formatScanValue(valueType_, displayHex_, buf.data(), shownSize, stringEncoding_, result_->hasDataFormat() ? result_->byteOrder() : valueType_==ValueType::UnicodeString ? ce::ByteOrder::Little : std::endian::native==std::endian::big ? ce::ByteOrder::Big : ce::ByteOrder::Little);
}

void ScanResultsModel::reloadPreferences() {
    options_ = FoundListOptions::load();
    if (shownRows_ > 0) emit dataChanged(index(0, 0), index(shownRows_ - 1, columnCount() - 1));
}

uintptr_t ScanResultsModel::addressAt(int row) const {
    return result_ ? result_->address(row) : 0;
}
} // namespace ce::gui
