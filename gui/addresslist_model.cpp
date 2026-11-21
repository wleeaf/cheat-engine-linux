// AddressListModel: the address list (values, freezing, scripts, groups,
// hotkeys, JSON form) and its ce::IAddressList implementation for Lua.
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

#include <QScopedValueRollback>
#include "gui/autoasmoperation.hpp"
#include <thread>
#include <sys/utsname.h>
#include <atomic>
#include <fstream>
#include "platform/linux/injector.hpp"
#include <sys/prctl.h>
#include <sys/wait.h>

#include "gui/agent_panel.hpp"
#include <QCoreApplication>
#include <QTimer>
#include <cerrno>
#include <QColor>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <QJsonObject>
#include <QJsonArray>
#include <QStringList>
#include <QMimeData>
#include <QDataStream>
#include <QMap>
#include <cmath>
#include <charconv>
#include <exception>

#include "gui/mainwindow_internal.hpp"
namespace ce::gui {
using namespace mainwindow_detail;

// Defined with the Type-column helpers near the end of the file; data() needs it.
static QString valueTypeLabel(ce::ValueType t);

// ═══════════════════════════════════════════════════════════════
// AddressListModel
// ═══════════════════════════════════════════════════════════════

AddressListModel::AddressListModel(QObject* parent) : QAbstractTableModel(parent) {}

int AddressListModel::allocId() {
    const int first=nextId_;
    do {
        const int candidate=nextId_;
        if (nextId_==std::numeric_limits<int>::max()) {nextId_=1;idWrapped_=true;}
        else ++nextId_;
        // Ordinary sequential allocation stays constant-time. After wrapping,
        // imported sparse IDs can occupy the next slot, so search for a gap.
        if (!idWrapped_ || rowOfId(candidate)<0) return candidate;
    } while (nextId_!=first);
    throw std::overflow_error("No unused record ID is available");
}

int AddressListModel::addEntry(uintptr_t addr, ValueType type, const QString& desc,
                               const QString& addressExpr, size_t byteCount) {
    beginInsertRows({}, entries_.size(), entries_.size());
    AddressEntry entry;
    entry.id = allocId();
    entry.description = desc;
    entry.address = addr;
    entry.addressExpr = addressExpr;  // non-empty => pointer record, re-resolved live
    entry.type = type;
    entry.byteCount = byteCount;       // element length for AOB/string (0 = unknown)
    entry.currentValue = "?";
    int id = entry.id;
    entries_.push_back(std::move(entry));
    endInsertRows();
    return id;
}

void AddressListModel::addScriptEntry(const QString& desc, const QString& script) {
    beginInsertRows({}, entries_.size(), entries_.size());
    AddressEntry entry;
    entry.id = allocId();
    entry.description = desc.isEmpty() ? tr("Auto Assembler script") : desc;
    entry.autoAsmScript = script;   // toggling the checkbox runs [ENABLE]/[DISABLE]
    entry.type = ValueType::Int32;
    entry.currentValue = tr("(Auto Assembler script)");
    entries_.push_back(std::move(entry));
    endInsertRows();
}

bool AddressListModel::isScriptEntry(int row) const {
    return row >= 0 && row < (int)entries_.size() && !entries_[row].autoAsmScript.isEmpty();
}

bool AddressListModel::updateScriptEntryById(int id, const QString& desc, const QString& script) {
    if (scriptBusy_ || mutationBusy_ || AutoAsmUiOperation::retiring(autoAsm_)) return false;
    QScopedValueRollback mutation(mutationBusy_, true);
    int row = rowOfId(id);
    if (row < 0 || !setEntryActive(row, false)) return false;
    row = rowOfId(id);
    if (row < 0) return false;
    auto& e = entries_[row];
    e.autoAsmScript = script;
    if (!desc.isEmpty()) e.description = desc;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
    return true;
}

void AddressListModel::setEntryAddress(int row, uintptr_t addr, const QString& expr) {
    if (row < 0 || row >= (int)entries_.size()) return;
    auto& e = entries_[row];
    if (e.isGroup || !e.autoAsmScript.isEmpty()) return;  // not addressable
    e.address = addr;
    e.addressExpr = expr;      // pointer expression re-resolves each refresh
    e.currentValue.clear();    // force a re-read at the new address
    emit dataChanged(index(row, 2), index(row, columnCount() - 1),
                     {Qt::DisplayRole, Qt::EditRole});
}

void AddressListModel::setEntryDescription(int row, const QString& desc) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].description = desc;
    emit dataChanged(index(row, 1), index(row, 1), {Qt::DisplayRole, Qt::EditRole});
}

void AddressListModel::addGroup(const QString& desc) {
    beginInsertRows({}, entries_.size(), entries_.size());
    AddressEntry entry;
    entry.id = allocId();
    entry.description = desc;
    entry.currentValue.clear();
    entry.isGroup = true;
    entries_.push_back(std::move(entry));
    endInsertRows();
}

static const char* typeToStr(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:   return "byte";
        case ValueType::Int16:  return "i16";
        case ValueType::Int32:  return "i32";
        case ValueType::Int64:  return "i64";
        case ValueType::Pointer: return "pointer";
        case ValueType::Float:  return "float";
        case ValueType::Double: return "double";
        case ValueType::String: return "string";
        case ValueType::UnicodeString: return "unicode";
        case ValueType::ByteArray: return "aob";
        case ValueType::Binary: return "binary";
        case ValueType::Grouped: return "grouped";
        case ValueType::Custom: return "custom";
        default: return "i32";
    }
}

static ValueType strToType(const QString& s) {
    if (s == "byte")   return ValueType::Byte;
    if (s == "i16")    return ValueType::Int16;
    if (s == "i32")    return ValueType::Int32;
    if (s == "i64")    return ValueType::Int64;
    if (s == "pointer") return ValueType::Pointer;
    if (s == "float")  return ValueType::Float;
    if (s == "double") return ValueType::Double;
    if (s == "string") return ValueType::String;
    if (s == "unicode") return ValueType::UnicodeString;
    if (s == "aob")    return ValueType::ByteArray;
    if (s == "binary") return ValueType::Binary;
    if (s == "grouped") return ValueType::Grouped;
    if (s == "custom") return ValueType::Custom;
    bool ok = false;
    int raw = s.toInt(&ok);
    if (ok) {
        switch (raw) {
            case 0: return ValueType::Byte;
            case 1: return ValueType::Int16;
            case 2: return ValueType::Int32;
            case 3: return ValueType::Int64;
            case 4: return ValueType::Float;
            case 5: return ValueType::Double;
            case 6: return ValueType::String;
            case 7: return ValueType::UnicodeString;
            case 8: return ValueType::ByteArray;
            case 9: return ValueType::Binary;
            case 10: return ValueType::All;
            case 13: return ValueType::Pointer;
            case 11: return ValueType::Grouped;
            case 12: return ValueType::Custom;
            default: break;
        }
    }
    return ValueType::Int32;
}

// Cheat Engine keeps one dropdown choice per line; older tables of this program
// put ';' between them.
static QString normalizedDropdownList(QString list) {
    list.remove('\r');
    if (!list.contains('\n')) list.replace(';', '\n');
    return list;
}

static QMap<QString, QString> parseDropdownList(const QString& dropdownList) {
    QMap<QString, QString> choices;
    for (const auto& rawItem : normalizedDropdownList(dropdownList).split('\n', Qt::SkipEmptyParts)) {
        auto item = rawItem.trimmed();
        auto sep = item.indexOf(':');
        if (sep <= 0) continue;
        auto value = item.left(sep).trimmed();
        auto label = item.mid(sep + 1).trimmed();
        if (!value.isEmpty())
            choices[value] = label.isEmpty() ? value : label;
    }
    return choices;
}

static QString displayDropdownValue(const QString& value, const QString& dropdownList) {
    auto choices = parseDropdownList(dropdownList);
    auto it = choices.find(value.trimmed());
    return it == choices.end() ? value : QString("%1 (%2)").arg(it.value(), it.key());
}

static QString resolveDropdownInput(const QString& input, const QString& dropdownList) {
    auto choices = parseDropdownList(dropdownList);
    auto trimmed = input.trimmed();
    if (choices.contains(trimmed))
        return trimmed;
    for (auto it = choices.begin(); it != choices.end(); ++it) {
        if (QString::compare(it.value(), trimmed, Qt::CaseInsensitive) == 0)
            return it.key();
    }
    return input;
}

static QVariant entryForeground(const QString& color) {
    if (color.isEmpty())
        return {};
    auto name = color.startsWith('#') ? color : "#" + color;
    QColor parsed(name);
    return parsed.isValid() ? QVariant(parsed) : QVariant();
}

// Adapt a GUI value to shared typed I/O, terminating shortened strings within
// their known capacity.
static std::expected<size_t, std::string> writeValueToProcess(
    ProcessHandle* proc, uintptr_t addr, ValueType type, const QString& value,
    const ce::ValueCodec& codec = {}, bool bigEndian = false, bool showHex = false, size_t capacity = 0,
    ByteOrder order = ByteOrder::Unknown, uint8_t pointerWidth = 0) {
    ce::ValueIoOptions options;
    options.codec = codec; options.bigEndian = bigEndian; options.hex = showHex;
    if (order != ByteOrder::Unknown) options.byteOrder = order;
    if (pointerWidth) options.pointerWidthOverride = pointerWidth;
    if (!proc) return std::unexpected(QCoreApplication::translate("ce::gui::AddressListModel", "No process attached").toStdString());
    auto resolved = ce::valueOptionsForTarget(*proc, addr, type, options);
    if (!resolved) return std::unexpected(resolved.error());
    options = *resolved;
    if (type == ValueType::String || type == ValueType::UnicodeString) {
        auto bytes = ce::encodeTypedValue(type, value.toStdString(), options);
        if (!bytes) return std::unexpected(bytes.error());
        options.terminate = bytes->empty() || bytes->size() < capacity;
    }
    return ce::writeTypedValue(*proc, addr, type, value.toStdString(), options);
}

static bool parseComparableValue(ValueType type, const QString& valStr, double& value);
static bool readComparableValue(ProcessHandle* proc, uintptr_t addr, ValueType type,
                                double& value, const ce::ValueCodec& codec = {},
                                bool bigEndian = false, bool isSigned = true,
                                ByteOrder order = ByteOrder::Unknown, uint8_t pointerWidth = 0) {
    if (!proc) return false;
    ce::ValueIoOptions options;
    options.codec = codec; options.bigEndian = bigEndian; options.isSigned = isSigned;
    if (order != ByteOrder::Unknown) options.byteOrder = order;
    if (pointerWidth) options.pointerWidthOverride = pointerWidth;
    auto decoded = ce::readTypedValue(*proc, addr, type, options);
    return decoded && parseComparableValue(type, QString::fromStdString(*decoded), value);
}

static bool parseComparableValue(ValueType type, const QString& valStr, double& value) {
    bool ok = false;
    switch (type) {
        case ValueType::Byte:
        case ValueType::Int16:
        case ValueType::Int32:
        case ValueType::Int64:
            // Parse via the shared helper so a hex-display record's value ("0xff", with
            // the prefix the formatter emits) compares correctly. Base-10 toLongLong
            // failed on it, which silently degraded a directional freeze to unconditional.
            value = static_cast<double>(ce::parseIntegerScalar(valStr.toStdString(), false, ok));
            return ok;
        case ValueType::Pointer:
            value = static_cast<double>(valStr.toULongLong(&ok, 0));
            return ok;
        case ValueType::Float:
        case ValueType::Double:
            // Accept ',' or '.' as the decimal separator, matching
            // writeValueToProcess — otherwise a comma-locale frozen value would
            // silently degrade a directional freeze to an unconditional write.
            value = QString(valStr).replace(',', '.').toDouble(&ok);
            return ok;
        default:
            return false;
    }
}

bool AddressListModel::reresolveAddress(AddressEntry& e, const ExpressionParser* parser) {
    if (e.addressExpr.isEmpty() || !proc_) return true;
    std::string expr = e.addressExpr.toStdString();
    // CE: an address starting with + or - is relative to the nearest ancestor
    // that has an address of its own (an address group header or a record).
    auto chain = ce::parsePointerExpression(expr);
    std::string base = chain ? chain->base : expr;
    const auto first = base.find_first_not_of(" \t");
    const auto row = &e - entries_.data();
    if (first != std::string::npos && (base[first] == '+' || base[first] == '-') &&
        row > 0 && row < static_cast<std::ptrdiff_t>(entries_.size())) {
        for (auto r = row - 1, indent = static_cast<std::ptrdiff_t>(e.indent) - 1; r >= 0 && indent >= 0; --r) {
            auto& ancestor = entries_[static_cast<size_t>(r)];
            if (ancestor.indent != indent) continue;
            --indent;
            const QString text = ancestor.addressExpr.trimmed();
            if (!text.isEmpty() && text != "0" && text != "0x0") {
                if (!reresolveAddress(ancestor, parser)) return false;
            } else if (!(text.isEmpty() && !ancestor.isGroup && ancestor.address)) {
                continue;   // no address here: ask the next ancestor
            }
            base = QString("0x%1").arg(ancestor.address, 0, 16).toStdString() + base.substr(first);
            expr = chain ? ce::buildPointerExpression(base, chain->offsets) : base;
            break;
        }
    }
    // Pass the shared resolver so a record can be addressed by a user-defined label
    // (or a module export) set in the Memory Viewer, not just a raw/module+offset expr.
    std::optional<ExpressionParser> own;
    if (!parser) parser = &own.emplace(proc_, symbolResolver_);
    auto v = parser->parse(expr);
    if (!v) return false;   // keep e.address for display, but nothing may write there:
    e.address = *v;         // the object it pointed into may be freed by now
    return true;
}

void AddressListModel::freezeWrite(ProcessHandle* proc) {
    // One parser for the pass: it reads the module list once, when a record needs it.
    const ExpressionParser parser(proc_, symbolResolver_);
    for (auto& e : entries_) {
        if (e.isGroup) continue;
        if (!e.active || (e.frozenValue.isEmpty() && e.type != ValueType::String && e.type != ValueType::UnicodeString)) continue;

        // Re-resolve pointer records so the freeze writes to the current target, not the
        // up-to-500ms-stale cached address (the value refresh runs slower than this 100ms
        // freeze); a moved pointer would otherwise clobber unrelated memory.
        if (!reresolveAddress(e, &parser)) continue;   // a broken chain freezes nothing

        if (e.freezeMode == FreezeMode::Normal) {
            (void)writeValueToProcess(proc, e.address, e.type, e.frozenValue, e.codec, e.bigEndian, e.showAsHex, e.byteCount, e.dataByteOrder, e.pointerWidth);
            continue;
        }

        ce::ValueIoOptions options;
        options.hex = e.showAsHex; options.isSigned = e.showAsSigned;
        options.codec = e.codec; options.bigEndian = e.bigEndian;
        if (e.dataByteOrder != ByteOrder::Unknown) options.byteOrder = e.dataByteOrder;
        if (e.pointerWidth) options.pointerWidthOverride = e.pointerWidth;
        auto comparison = ce::compareTypedValue(*proc, e.address, e.type, e.frozenValue.toStdString(), options);
        if (comparison && ((e.freezeMode == ce::FreezeMode::NeverDecrease || e.freezeMode == ce::FreezeMode::IncreaseOnly) ? *comparison < 0 : *comparison > 0))
            (void)writeValueToProcess(proc, e.address, e.type, e.frozenValue, e.codec, e.bigEndian, e.showAsHex, e.byteCount, e.dataByteOrder, e.pointerWidth);
    }
}

QJsonArray AddressListModel::toJson() const {
    QJsonArray arr;
    std::vector<int> lastRowAtIndent;
    for (int row = 0; row < (int)entries_.size(); ++row) {
        const auto& e = entries_[row];
        QJsonObject obj;
        obj["id"] = e.id;
        obj["description"] = e.description;
        obj["address"] = QString("0x%1").arg(e.address, 0, 16);
        if (!e.addressExpr.isEmpty()) obj["addressExpr"] = e.addressExpr;
        obj["type"] = typeToStr(e.type);
        if (e.byteCount > 0) obj["byteCount"] = (int)e.byteCount;   // AOB/string length
        // A frozen record saves the value it holds, as before the list showed live values.
        obj["value"] = e.active && e.autoAsmScript.isEmpty() && !e.isGroup ? e.frozenValue : e.currentValue;
        obj["active"] = e.active;
        obj["asm"] = e.autoAsmScript;
        obj["color"] = e.color;
        obj["dropdown"] = e.dropdownList;
        obj["hotkeys"] = e.hotkeyKeys;
        obj["increaseHotkey"] = e.increaseHotkeyKeys;
        obj["setValueHotkey"] = e.setValueHotkeyKeys;
        obj["setValueHotkeyValue"] = e.setValueHotkeyValue;
        obj["decreaseHotkey"] = e.decreaseHotkeyKeys;
        obj["hotkeyStep"] = e.hotkeyStep;
        obj["indent"] = e.indent;
        obj["group"] = e.isGroup;
        obj["collapsed"] = e.collapsed;
        obj["activateChildren"] = e.activateChildren;
        obj["deactivateChildren"] = e.deactivateChildren;
        if (!e.optionsXml.isEmpty()) obj["optionsXml"] = e.optionsXml;
        if (!e.luaScript.isEmpty()) obj["lua"] = e.luaScript;
        for (auto it = e.tableFields.begin(); it != e.tableFields.end(); ++it) obj[it.key()] = it.value();
        obj["showAsHex"] = e.showAsHex;
        obj["showAsSigned"] = e.showAsSigned;
        obj["freezeMode"] = (int)e.freezeMode;
        if (e.codec.active())   // obfuscation codec, as its round-trippable spec string
            obj["codec"] = QString::fromStdString(e.codec.describe());
        if (e.bigEndian) obj["bigEndian"] = true;
        if (e.dataByteOrder != ByteOrder::Unknown) obj["dataByteOrder"] = e.dataByteOrder == ByteOrder::Big ? "big" : "little";
        if (e.pointerWidth) obj["pointerWidth"] = e.pointerWidth;
        if (e.indent > 0 && e.indent - 1 < (int)lastRowAtIndent.size())
            obj["parent"] = lastRowAtIndent[e.indent - 1];
        arr.append(obj);

        if (e.indent >= (int)lastRowAtIndent.size())
            lastRowAtIndent.resize(e.indent + 1, -1);
        lastRowAtIndent[e.indent] = row;
        if ((int)lastRowAtIndent.size() > e.indent + 1)
            lastRowAtIndent.resize(e.indent + 1);
    }
    return arr;
}

static bool hasSavedUndo(const ce::DisableInfo& info) {
    return info.ownership || info.image || !info.originals.empty() || !info.allocs.empty() ||
        !info.protections.empty() || !info.symbols.empty();
}

// The longest String / Array of byte record: its bytes are read on every refresh.
constexpr int kMaxRecordBytes = 65536;

bool AddressListModel::fromJson(const QJsonArray& arr, bool preserveExisting) {
    if (scriptBusy_ || mutationBusy_ || AutoAsmUiOperation::retiring(autoAsm_)) return false;
    QScopedValueRollback mutation(mutationBusy_, true);
    if (!validRecordFormats(arr)) {
        reportActivationError(tr("Table format"), tr("Invalid record data order or pointer size.")); return false;
    }
    std::unordered_set<int> reserved,assigned;
    int largest=0;
    for (const auto& value:arr) {
        const int id=value.toObject().value("id").toInt(-1);
        if (id>=0) {reserved.insert(id);largest=std::max(largest,id);}
    }
    int fresh=largest==std::numeric_limits<int>::max() ? 1:largest+1;
    auto nextFresh=[&] {
        const int first=fresh;
        while (reserved.contains(fresh) || assigned.contains(fresh)) {
            fresh=fresh==std::numeric_limits<int>::max() ? 1:fresh+1;
            if (fresh==first) throw std::overflow_error("No unused record ID is available");
        }
        const int result=fresh;
        fresh=fresh==std::numeric_limits<int>::max() ? 1:fresh+1;
        assigned.insert(result);
        return result;
    };
    std::vector<AddressEntry> incoming;
    incoming.reserve(arr.size());
    std::vector<int> activate;
    std::unordered_set<int> retained;
    std::vector<int> parentIndentById;
    for (auto val : arr) {
        auto obj = val.toObject();
        AddressEntry e;
        const int imported=obj.value("id").toInt(-1);
        e.id=imported>=0 && assigned.insert(imported).second ? imported:nextFresh();
        largest=std::max(largest,e.id);
        e.description = obj["description"].toString();
        e.address = obj["address"].toString().toULongLong(nullptr, 16);
        e.addressExpr = obj["addressExpr"].toString();
        e.type = strToType(obj["type"].toString());
        // AOB/string length (0 if absent). Read on every refresh: a table or the
        // clipboard must not make it huge.
        e.byteCount = (size_t)std::clamp(obj["byteCount"].toInt(0), 0, kMaxRecordBytes);
        e.currentValue = obj["value"].toString();
        e.active = obj["active"].toBool();
        e.autoAsmScript = obj["asm"].toString();
        e.color = obj["color"].toString();
        e.dropdownList = normalizedDropdownList(obj["dropdown"].toString());
        e.hotkeyKeys = obj["hotkeys"].toString();
        e.increaseHotkeyKeys = obj["increaseHotkey"].toString();
        e.setValueHotkeyKeys = obj["setValueHotkey"].toString();
        e.setValueHotkeyValue = obj["setValueHotkeyValue"].toString();
        e.decreaseHotkeyKeys = obj["decreaseHotkey"].toString();
        e.hotkeyStep = obj["hotkeyStep"].toString("1");
        e.luaScript = obj["lua"].toString();
        for (const char* key : {"customType", "async", "dropdownAttributes", "entryAttributes", "unparsedAddress",
                                "unparsedOffsets", "extraHotkeys", "extraXml"})
            if (obj.contains(key)) e.tableFields[key] = obj[key];
        e.indent = std::max(0, obj.contains("indent")
            ? obj["indent"].toInt()
            : (obj["parent"].toInt(-1) >= 0 && obj["parent"].toInt(-1) < (int)parentIndentById.size()
                ? parentIndentById[obj["parent"].toInt()] + 1
                : 0));
        // A record nests at most one level below the one before it; a huge
        // indent from a table would build a prefix of that many characters.
        const int previousIndent = !incoming.empty() ? incoming.back().indent
                                 : preserveExisting && !entries_.empty() ? entries_.back().indent : -1;
        e.indent = std::min(e.indent, previousIndent + 1);
        e.isGroup = obj["group"].toBool();
        e.collapsed = obj["collapsed"].toBool();
        e.activateChildren = obj["activateChildren"].toBool(true);
        e.deactivateChildren = obj["deactivateChildren"].toBool(true);
        e.optionsXml = obj["optionsXml"].toString();
        e.showAsHex = obj["showAsHex"].toBool();
        e.showAsSigned = obj["showAsSigned"].toBool(true);
        if (obj.contains("freezeMode"))
            e.freezeMode = (ce::FreezeMode)obj["freezeMode"].toInt();
        if (obj.contains("codec")) {
            if (auto c = ce::ValueCodec::parse(obj["codec"].toString().toStdString()))
                e.codec = *c;
        }
        e.bigEndian = obj["bigEndian"].toBool();
        const auto order = obj["dataByteOrder"].toString();
        e.dataByteOrder = order == "little" ? ByteOrder::Little : order == "big" ||
            (!obj.contains("dataByteOrder") && e.bigEndian) ? ByteOrder::Big : ByteOrder::Unknown;
        if (obj.contains("dataByteOrder")) e.bigEndian = e.dataByteOrder == ByteOrder::Big;
        const auto width = obj["pointerWidth"].toInt();
        e.pointerWidth = width == 4 || width == 8 ? width : 0;
        if (e.isGroup) {
            e.address = 0;
            e.currentValue.clear();
            e.frozenValue.clear();
        }
        if (e.active) e.frozenValue = e.currentValue;
        const int oldRow = preserveExisting ? rowOfId(e.id) : -1;
        if (oldRow >= 0 && entries_[oldRow].autoAsmScript == e.autoAsmScript &&
            entries_[oldRow].active == e.active) {
            e.autoAsmDisableInfo = entries_[oldRow].autoAsmDisableInfo;
            e.autoAsmOrder = entries_[oldRow].autoAsmOrder;
            e.frozenValue = entries_[oldRow].frozenValue;
            retained.insert(e.id);
        } else if (e.active && !e.autoAsmScript.isEmpty()) {
            e.active = false;
            e.frozenValue.clear();
            activate.push_back(e.id);
        }
        parentIndentById.push_back(e.indent);
        incoming.push_back(std::move(e));
    }
    // Parse first, then retire owners while their original process is valid.
    // On failure retain every row, including the remaining undo for retry.
    for (int id : cleanupOrder()) {
        const int row = rowOfId(id);
        if (!retained.contains(id) && row >= 0 && !setEntryActive(row, false)) return false;
    }
    beginResetModel();
    entries_ = std::move(incoming);
    if (!preserveExisting) ++replaceGeneration_;   // ids now come from the loaded table
    const auto revision = ++targetRevision_;
    idWrapped_=largest==std::numeric_limits<int>::max();
    nextId_=idWrapped_ ? 1:largest+1;
    endResetModel();
    mutationBusy_ = false;
    for (int id : activate) {
        // A completed activation callback may replace the table or target.
        // Remaining IDs then belong to a different import, even if reused.
        if (targetRevision_ != revision) break;
        setActive(id, true);
    }
    return true;
}

void AddressListModel::setFreezeMode(int row, FreezeMode mode) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].freezeMode = mode;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

// A frozen value is text in the record's format: written with another type,
// codec or byte order it would change what memory holds (100 frozen as 4 Bytes
// written as the float 100.0, or as 8 bytes over the next field). The freeze
// ends with the old format, as in setEntryType.
bool AddressListModel::endFreezeForFormatChange(int& row) {
    if (!entries_[row].active || !entries_[row].autoAsmScript.isEmpty() || entries_[row].isGroup) return true;
    const int id = entries_[row].id;
    if (!setEntryActive(row, false)) return false;
    row = rowOfId(id);
    return row >= 0;
}

void AddressListModel::setEntryCodec(int row, ce::ValueCodec codec) {
    if (row < 0 || row >= (int)entries_.size()) return;
    if (entries_[row].codec.describe() != codec.describe() && !endFreezeForFormatChange(row)) return;
    entries_[row].codec = codec;
    entries_[row].currentValue.clear();   // force a re-read/reformat through the codec
    emit dataChanged(index(row, 4), index(row, 4), {Qt::DisplayRole, Qt::EditRole});
}

std::string AddressListModel::entryCodecSpec(int row) const {
    if (row < 0 || row >= (int)entries_.size()) return "none";
    return entries_[row].codec.describe();
}

void AddressListModel::setEntryBigEndian(int row, bool bigEndian) {
    if (row < 0 || row >= (int)entries_.size()) return;
    if (entries_[row].dataByteOrder != (bigEndian ? ByteOrder::Big : ByteOrder::Little) &&
        !endFreezeForFormatChange(row)) return;
    entries_[row].bigEndian = bigEndian;
    entries_[row].dataByteOrder = bigEndian ? ByteOrder::Big : ByteOrder::Little;
    entries_[row].currentValue.clear();   // re-read/reformat in the new byte order
    emit dataChanged(index(row, 4), index(row, 4), {Qt::DisplayRole, Qt::EditRole});
}

void AddressListModel::setEntryDataFormat(int row, ByteOrder order, uint8_t width) {
    if (row < 0 || row >= rowCount() || (width && width != 4 && width != 8) ||
        (order != ByteOrder::Unknown && order != ByteOrder::Little && order != ByteOrder::Big)) return;
    if ((entries_[row].dataByteOrder != order || entries_[row].pointerWidth != width) &&
        !endFreezeForFormatChange(row)) return;
    auto& entry = entries_[row];
    entry.dataByteOrder = order; entry.pointerWidth = width;
    entry.bigEndian = order == ByteOrder::Big;
    entry.currentValue.clear();
    emit dataChanged(index(row, 3), index(row, 4));
}

bool AddressListModel::entryBigEndian(int row) const {
    return (row >= 0 && row < (int)entries_.size()) && entries_[row].bigEndian;
}

void AddressListModel::setShowAsHex(int row, bool hex) {
    if (row < 0 || row >= (int)entries_.size()) return;
    auto& e = entries_[row];
    // The frozen value is text in the old base: "100" frozen in decimal would
    // be written as 0x100 once hex is on. Re-express it (and the shown value)
    // through its bytes.
    const bool integer = e.type == ValueType::Byte || e.type == ValueType::Int16 || e.type == ValueType::Int32 ||
                         e.type == ValueType::Int64 || e.type == ValueType::Pointer;
    if (integer && e.showAsHex != hex) {
        ce::ValueIoOptions from;
        from.hex = e.showAsHex; from.isSigned = e.showAsSigned; from.codec = e.codec;
        if (e.pointerWidth) { from.pointerWidth = e.pointerWidth; from.pointerWidthOverride = e.pointerWidth; }
        else if (proc_) from.pointerWidth = static_cast<int>(proc_->pointerWidth(e.address));
        ce::ValueIoOptions to = from;
        to.hex = hex;
        for (QString* text : {&e.frozenValue, &e.currentValue}) {
            if (text->isEmpty() || *text == QStringLiteral("??")) continue;
            auto bytes = ce::encodeTypedValue(e.type, text->toStdString(), from);
            if (!bytes) continue;
            if (auto converted = ce::decodeTypedValue(e.type, *bytes, to)) *text = QString::fromStdString(*converted);
        }
    }
    e.showAsHex = hex;
    emit dataChanged(index(row, 4), index(row, 4));
}

void AddressListModel::setEntryType(int row, ValueType t) {
    if (row < 0 || row >= (int)entries_.size()) return;
    if (entries_[row].isGroup || entries_[row].type == t) return;
    if (!endFreezeForFormatChange(row)) return;
    entries_[row].type = t;
    entries_[row].currentValue.clear();   // re-read and format with the new type
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

void AddressListModel::setHotkeyKeys(int row, const QString& keys) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].hotkeyKeys = keys;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

std::vector<ce::CheatHotkey> AddressListModel::hotkeysOf(int row) const {
    if (row < 0 || row >= (int)entries_.size()) return {};
    const auto& e = entries_[row];
    ce::CheatEntry record;
    record.hotkeyKeys = e.hotkeyKeys.toStdString();
    record.increaseHotkeyKeys = e.increaseHotkeyKeys.toStdString();
    record.decreaseHotkeyKeys = e.decreaseHotkeyKeys.toStdString();
    record.setValueHotkeyKeys = e.setValueHotkeyKeys.toStdString();
    record.setValueHotkeyValue = e.setValueHotkeyValue.toStdString();
    record.hotkeyStep = e.hotkeyStep.toStdString();
    record.extraHotkeysXml = e.tableFields.value("extraHotkeys").toString().toStdString();
    return ce::recordHotkeys(record);
}

void AddressListModel::setHotkeys(int row, const std::vector<ce::CheatHotkey>& hotkeys) {
    if (row < 0 || row >= (int)entries_.size()) return;
    auto& e = entries_[row];
    ce::CheatEntry record;
    record.extraHotkeysXml = e.tableFields.value("extraHotkeys").toString().toStdString();
    ce::setRecordHotkeys(record, hotkeys);
    e.hotkeyKeys = QString::fromStdString(record.hotkeyKeys);
    e.increaseHotkeyKeys = QString::fromStdString(record.increaseHotkeyKeys);
    e.decreaseHotkeyKeys = QString::fromStdString(record.decreaseHotkeyKeys);
    e.setValueHotkeyKeys = QString::fromStdString(record.setValueHotkeyKeys);
    e.setValueHotkeyValue = QString::fromStdString(record.setValueHotkeyValue);
    e.hotkeyStep = record.hotkeyStep.empty() ? QStringLiteral("1") : QString::fromStdString(record.hotkeyStep);
    if (record.extraHotkeysXml.empty()) e.tableFields.remove("extraHotkeys");
    else e.tableFields["extraHotkeys"] = QString::fromStdString(record.extraHotkeysXml);
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

void AddressListModel::setValueHotkeys(int row, const QString& increaseKeys, const QString& decreaseKeys,
                                       const QString& step, const QString& setKeys, const QString& setValue) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].increaseHotkeyKeys = increaseKeys;
    entries_[row].decreaseHotkeyKeys = decreaseKeys;
    entries_[row].hotkeyStep = step.isEmpty() ? "1" : step;
    entries_[row].setValueHotkeyKeys = setKeys;
    entries_[row].setValueHotkeyValue = setValue;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

bool AddressListModel::adjustEntryValue(int row, double delta) {
    if (row < 0 || row >= (int)entries_.size() || !proc_) return false;
    auto& e = entries_[row];
    if (e.isGroup) return false;

    // Re-resolve pointer records so the hotkey acts on the current target, not a stale
    // cached address (a moved pointer would otherwise hit unrelated memory).
    if (!reresolveAddress(e)) return false;

    // Integers with a whole step: exact 64-bit arithmetic. Through a double,
    // an Int64 above 2^53 lost its low bits (+1 on 9007199254740993 wrote
    // 9007199254740992).
    const bool integer = e.type == ValueType::Byte || e.type == ValueType::Int16 ||
                         e.type == ValueType::Int32 || e.type == ValueType::Int64;
    if (integer && delta == std::trunc(delta) && std::abs(delta) < 9.2e18) {
        ce::ValueIoOptions options;
        options.hex = false; options.isSigned = e.showAsSigned;
        options.codec = e.codec; options.bigEndian = e.bigEndian;
        if (e.dataByteOrder != ByteOrder::Unknown) options.byteOrder = e.dataByteOrder;
        if (auto text = ce::readTypedValue(*proc_, e.address, e.type, options)) {
            const char* first = text->data();
            const char* last = first + text->size();
            const auto step = static_cast<int64_t>(delta);
            uint64_t bits = 0;
            bool parsed = false;
            if (e.showAsSigned) {
                int64_t v = 0;
                parsed = std::from_chars(first, last, v).ec == std::errc{};
                bits = static_cast<uint64_t>(v) + static_cast<uint64_t>(step);   // wraps like the target's integer
            } else {
                uint64_t v = 0;
                parsed = std::from_chars(first, last, v).ec == std::errc{};
                bits = v + static_cast<uint64_t>(step);
            }
            if (parsed) {
                const QString nextText = QString::fromStdString(
                    ce::formatIntegerScalar(bits, ce::scalarWidth(e.type), e.showAsSigned, e.showAsHex));
                auto written = writeValueToProcess(proc_, e.address, e.type, nextText, e.codec, e.bigEndian, e.showAsHex, 0, e.dataByteOrder, e.pointerWidth);
                if (!written) { reportActivationError(tr("Value edit failed"), QString::fromStdString(written.error())); return false; }
                e.currentValue = nextText;
                if (e.active) e.frozenValue = nextText;
                emit dataChanged(index(row, 4), index(row, 4), {Qt::DisplayRole, Qt::EditRole});
                return true;
            }
        }
    }

    double current = 0;
    if (!readComparableValue(proc_, e.address, e.type, current, e.codec, e.bigEndian, e.showAsSigned, e.dataByteOrder, e.pointerWidth) &&
        !parseComparableValue(e.type, e.currentValue, current)) {
        return false;
    }

    double next = current + delta;
    QString nextText;
    switch (e.type) {
        case ValueType::Byte:
        case ValueType::Int16:
        case ValueType::Int32:
        case ValueType::Int64: {
            // Render in the record's display format (hex/signed). This is both what the
            // column shows until the next refresh AND what writeValueToProcess parses
            // back: a hex record must NOT receive a bare decimal, which its hex-aware
            // parse would misread (e.g. "256" as 0x256).
            uint64_t bits = static_cast<uint64_t>(static_cast<int64_t>(std::llround(next)));
            nextText = QString::fromStdString(
                ce::formatIntegerScalar(bits, ce::scalarWidth(e.type), e.showAsSigned, e.showAsHex));
            break;
        }
        case ValueType::Pointer:
            nextText = QString("0x%1").arg(static_cast<qulonglong>(std::llround(next)), 0, 16);
            break;
        case ValueType::Float:
            nextText = QString::fromStdString(ce::formatFloatScalar(next, false));
            break;
        case ValueType::Double:
            nextText = QString::fromStdString(ce::formatFloatScalar(next, true));
            break;
        default:
            return false;
    }

    auto written = writeValueToProcess(proc_, e.address, e.type, nextText, e.codec, e.bigEndian, e.showAsHex, 0, e.dataByteOrder, e.pointerWidth);
    if (!written) { reportActivationError(tr("Value edit failed"), QString::fromStdString(written.error())); return false; }
    e.currentValue = nextText;
    if (e.active) e.frozenValue = nextText;
    emit dataChanged(index(row, 4), index(row, 4), {Qt::DisplayRole, Qt::EditRole});
    return true;
}

// Shift each selected record's indent by delta, together with the rows nested
// under it (taken before any change): indenting a group header alone turned
// its children into its siblings.
void AddressListModel::shiftIndentRows(QList<int> rows, int delta) {
    if (scriptBusy_ || mutationBusy_) return;
    if (rows.isEmpty()) return;
    std::sort(rows.begin(), rows.end());
    std::vector<int> indents;
    indents.reserve(entries_.size());
    for (const auto& e : entries_) indents.push_back(e.indent);
    int done = -1;   // rows below this were already shifted with their parent
    // A layout change, so the view hides a row indented into a collapsed group.
    emit layoutAboutToBeChanged();
    for (int row : rows) {
        if (row < 0 || row >= (int)entries_.size() || row < done) continue;
        const auto sub = ce::descendantRange(indents, static_cast<std::size_t>(row));
        int shift = delta;
        if (delta > 0) {
            if (row == 0) continue;
            shift = std::min(delta, entries_[row - 1].indent + 1 - entries_[row].indent);   // at most one under the row above
        } else {
            shift = std::max(delta, -entries_[row].indent);
        }
        if (shift == 0) { done = static_cast<int>(sub.second); continue; }
        for (std::size_t i = static_cast<std::size_t>(row); i < sub.second; ++i)
            entries_[i].indent = std::max(0, entries_[i].indent + shift);
        done = static_cast<int>(sub.second);
    }
    emit layoutChanged();
    emit dataChanged(index(rows.first(), 0), index(std::max(rows.last(), done - 1), columnCount() - 1));
}

void AddressListModel::indentRows(QList<int> rows) { shiftIndentRows(std::move(rows), +1); }
void AddressListModel::outdentRows(QList<int> rows) { shiftIndentRows(std::move(rows), -1); }

void AddressListModel::reportActivationError(const QString& title, const QString& message) {
    if (activationErrorCb_)
        activationErrorCb_(title, message);
}

void AddressListModel::setAllActive(bool active) {
    if (!active) { deactivateAll(); return; }
    for (int id : ids()) {
        const int row = rowOfId(id);
        if (row >= 0 && !entries_[row].isGroup) setEntryActive(row, active);
    }
    if (!entries_.empty())
        emit dataChanged(index(0, 0), index((int)entries_.size() - 1, columnCount() - 1));
}

// The check box path, so a group header's toggle reaches its children when
// the group says so.
void AddressListModel::toggleActive(int row) {
    if (row < 0 || row >= (int)entries_.size()) return;
    setData(index(row, 0), entries_[row].active ? Qt::Unchecked : Qt::Checked, Qt::CheckStateRole);
}

bool AddressListModel::toggleGroupCollapse(int row) {
    if (row < 0 || row >= (int)entries_.size() || !entries_[row].isGroup) return false;
    entries_[row].collapsed = !entries_[row].collapsed;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));  // refresh the ▸/▾ marker
    return true;
}

void AddressListModel::setEntryValueTo(int row, const QString& value) {
    if (row < 0 || row >= (int)entries_.size() || !proc_) return;
    setData(index(row, 4), value, Qt::EditRole);
}

bool AddressListModel::setEntryActive(int row, bool active) {
    if (row < 0 || row >= (int)entries_.size()) return false;
    if (scriptBusy_ || (active && (mutationBusy_ || AutoAsmUiOperation::retiring(autoAsm_)))) return false;
    const int id = entries_[row].id;
    const bool pending = hasSavedUndo(entries_[row].autoAsmDisableInfo);
    if (entries_[row].active == active && !(pending && !active)) return true;
    // A flag-only disable must not permit a second enable over live patches.
    if (active && pending && !entries_[row].active) {
        if (!setEntryActive(row, false)) return false;
        row = rowOfId(id);
        if (row < 0) return false;
    }
    const QString script = entries_[row].autoAsmScript;
    if (!script.isEmpty() || pending) {
        if (!proc_ || !autoAsm_) {
            reportActivationError(tr("Process required"),
                tr("Open a process before activating this auto-assembler record."));
            return false;
        }

        AutoAsmUiOperation operation(autoAsm_, active ? AutoAsmUiOperation::Purpose::Execute : AutoAsmUiOperation::Purpose::Cleanup);
        if (!operation) return false;
        QScopedValueRollback busy(scriptBusy_, true);
        // Both hooks and Lua evaluation may append records and reallocate the
        // vector. Keep a stable ID and reacquire the row after each callback.
        const auto before = beforeAaExecute_;
        if (before) before();
        row = rowOfId(id);
        if (row < 0) return false;
        const auto undo = entries_[row].autoAsmDisableInfo;
        auto result = active ? autoAsm_->execute(*proc_, script.toStdString())
                             : autoAsm_->disable(*proc_, script.toStdString(), undo);
        row = rowOfId(id);
        if (row < 0) return false;
        entries_[row].autoAsmDisableInfo = std::move(result.disableInfo);
        if (active && hasSavedUndo(entries_[row].autoAsmDisableInfo))
            entries_[row].autoAsmOrder = AutoAsmUiOperation::nextOrder();
        else if (!hasSavedUndo(entries_[row].autoAsmDisableInfo)) entries_[row].autoAsmOrder = 0;
        if (!result.success) {
            if (hasSavedUndo(entries_[row].autoAsmDisableInfo)) entries_[row].active = true;
            emit dataChanged(index(row, 0), index(row, columnCount() - 1));
            reportActivationError(active ? tr("Auto-assembler activation failed") : tr("Auto-assembler deactivation failed"),
                QString::fromStdString(result.error));
            return false;
        }
    }
    auto& e = entries_[row];
    // Freeze what memory holds now, not the cached display text: right after a
    // record is made or edited that is "?" or empty until the next refresh.
    // "??"/"?" are placeholders, not values: frozen into a String record they
    // would be written into the game as text.
    if (active && e.autoAsmScript.isEmpty() && !e.isGroup) {
        if (proc_) {
            const int id = e.id;
            const auto live = liveValue(id);
            row = rowOfId(id);
            if (row < 0) return false;
            if (!live.empty()) entries_[row].currentValue = QString::fromStdString(live);
        }
        const auto& current = entries_[row].currentValue;
        const bool text = entries_[row].type == ValueType::String || entries_[row].type == ValueType::UnicodeString;
        // An empty string is a value a String record can hold (and freeze).
        if (current == QStringLiteral("??") || current == QStringLiteral("?") || (current.isEmpty() && !text)) {
            reportActivationError(tr("Freeze failed"), tr("The value cannot be read right now, so there is nothing to freeze."));
            return false;
        }
    }
    e.active = active;
    if (e.active)
        e.frozenValue = e.currentValue;
    else
        e.frozenValue.clear();
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
    const auto callback = activationCb_;
    if (callback) callback(id, active);
    return true;
}

bool AddressListModel::deactivateAll() {
    if (scriptBusy_ || mutationBusy_) return false;
    QScopedValueRollback mutation(mutationBusy_, true);
    for (int id : cleanupOrder()) {
        const int row = rowOfId(id);
        if (row >= 0 && !setEntryActive(row, false)) return false;
    }
    if (!entries_.empty()) emit dataChanged(index(0, 0), index(entries_.size() - 1, columnCount() - 1));
    return true;
}

bool AddressListModel::setProcess(ce::ProcessHandle* proc) {
    if (scriptBusy_ || mutationBusy_ || AutoAsmUiOperation::busy(autoAsm_)) return false;
    if (proc_ != proc && !deactivateAll()) return false;
    if (proc_ != proc) ++targetRevision_;
    proc_ = proc;
    refreshModuleCache();
    return true;
}

bool AddressListModel::removeEntry(int row) {
    return removeEntries({row});
}

bool AddressListModel::removeEntries(const QList<int>& rows) {
    if (scriptBusy_ || mutationBusy_ || AutoAsmUiOperation::retiring(autoAsm_)) return false;
    QScopedValueRollback mutation(mutationBusy_, true);
    // Deleting a group header takes its whole subtree with it (CE: a group carries its
    // descendants), so children are never left orphaned at a now-invalid indent.
    std::vector<int> indents;
    indents.reserve(entries_.size());
    for (const auto& e : entries_) indents.push_back(e.indent);
    std::vector<std::size_t> sel;
    sel.reserve(rows.size());
    for (int r : rows) if (r >= 0 && r < (int)entries_.size()) sel.push_back((std::size_t)r);
    auto expanded = ce::expandGroupDeletion(indents, sel);
    auto cleanup = expanded;
    std::stable_sort(cleanup.begin(), cleanup.end(), [&](auto a, auto b) { return entries_[a].autoAsmOrder > entries_[b].autoAsmOrder; });
    for (auto row : cleanup) if (!setEntryActive(static_cast<int>(row), false)) return false;
    // Delete high-to-low so earlier indices stay valid as rows are removed, a
    // run of adjacent rows (a group and its subtree) at a time.
    for (auto it = expanded.rbegin(); it != expanded.rend();) {
        const int last = static_cast<int>(*it);
        int first = last;
        for (++it; it != expanded.rend() && static_cast<int>(*it) == first - 1; ++it) --first;
        beginRemoveRows({}, first, last);
        entries_.erase(entries_.begin() + first, entries_.begin() + last + 1);
        endRemoveRows();
    }
    return !expanded.empty();
}

// Move a record, with the rows nested under it, past its previous or next
// sibling (and that sibling's subtree). Swapping single rows left a group's
// children behind and could move a record into or out of a group.
int AddressListModel::moveEntry(int row, int delta) {
    if (scriptBusy_ || mutationBusy_) return row;
    const int n = (int)entries_.size();
    if (row < 0 || row >= n || delta == 0) return row;
    std::vector<int> indents;
    indents.reserve(n);
    for (const auto& e : entries_) indents.push_back(e.indent);
    const int level = indents[row];
    const int end = static_cast<int>(ce::descendantRange(indents, static_cast<std::size_t>(row)).second);
    if (delta < 0) {
        int previous = row - 1;
        while (previous >= 0 && indents[previous] > level) --previous;
        if (previous < 0 || indents[previous] != level) return row;   // first in its group
        moveEntryBlock(row, previous, -1);
        return previous;
    }
    if (end >= n || indents[end] != level) return row;   // last in its group
    const int nextEnd = static_cast<int>(ce::descendantRange(indents, static_cast<std::size_t>(end)).second);
    moveEntryBlock(row, nextEnd, -1);
    return row + (nextEnd - end);
}

// Read+format a variable-length value (String/UnicodeString/ByteArray) for display.
// nullopt if `type` isn't variable-length; "??" on read failure. Shared by the
// address-list refresh and the Lua mr.Value read so both agree.
static std::optional<QString> formatVariableLengthValue(ProcessHandle* proc, uintptr_t addr,
                                                        ValueType type, size_t byteCount, bool bigEndian, ByteOrder order) {
    if (type != ValueType::String && type != ValueType::UnicodeString && type != ValueType::ByteArray)
        return std::nullopt;
    ce::ValueIoOptions options;
    options.size = byteCount ? byteCount : (type == ValueType::ByteArray ? 16 : 64);
    options.bigEndian = bigEndian;
    if (order != ByteOrder::Unknown) options.byteOrder = order;
    auto value = ce::readTypedValue(*proc, addr, type, options);
    return value ? QString::fromStdString(*value) : QStringLiteral("??");
}

void AddressListModel::updateValues(ProcessHandle* proc) {
    const ExpressionParser parser(proc_, symbolResolver_);   // one module list per pass
    for (size_t i = 0; i < entries_.size(); ++i) {
        auto& e = entries_[i];
        if (e.isGroup) continue;
        if (!e.autoAsmScript.isEmpty()) continue;   // a script has no value to read (it would show "??")
        // Frozen records show what memory holds too (an Increase Only floor, a
        // broken pointer); the freeze writes frozenValue, not this text.

        // Pointer records: re-evaluate the address expression so a moving pointer
        // chain is followed live (CE re-resolves every refresh).
        if (!reresolveAddress(e, &parser)) { e.currentValue = QStringLiteral("??"); continue; }

        // Variable-length types: read the element (exact length if known) and format.
        if (auto fv = formatVariableLengthValue(proc, e.address, e.type, e.byteCount, e.bigEndian, e.dataByteOrder)) {
            e.currentValue = *fv;
            continue;
        }

        ce::ValueIoOptions options;
        options.hex = e.showAsHex; options.isSigned = e.showAsSigned;
        options.codec = e.codec; options.bigEndian = e.bigEndian;
        if (e.dataByteOrder != ByteOrder::Unknown) options.byteOrder = e.dataByteOrder;
        if (e.pointerWidth) options.pointerWidthOverride = e.pointerWidth;
        auto value = ce::readTypedValue(*proc, e.address, e.type, options);
        e.currentValue = value ? QString::fromStdString(*value) : "??";
    }
    if (!entries_.empty())
        emit dataChanged(index(0, 4), index(entries_.size() - 1, 4));
}

std::string AddressListModel::liveValue(int id) {
    int row = rowOfId(id);
    if (row < 0 || !proc_) return {};
    auto& e = entries_[row];
    if (e.isGroup) return {};
    // Re-resolve pointer expressions and read the process now (CE's mr.Value does a
    // live read on access, not a cached refresh value).
    if (!reresolveAddress(e)) return {};
    if (auto fv = formatVariableLengthValue(proc_, e.address, e.type, e.byteCount, e.bigEndian, e.dataByteOrder))
        return fv->toStdString();

    ce::ValueIoOptions options;
    options.hex = e.showAsHex; options.isSigned = e.showAsSigned;
    options.codec = e.codec; options.bigEndian = e.bigEndian;
    if (e.dataByteOrder != ByteOrder::Unknown) options.byteOrder = e.dataByteOrder;
    if (e.pointerWidth) options.pointerWidthOverride = e.pointerWidth;
    auto value = ce::readTypedValue(*proc_, e.address, e.type, options);
    return value ? *value : "??";
}

int AddressListModel::rowCount(const QModelIndex&) const { return entries_.size(); }
int AddressListModel::columnCount(const QModelIndex&) const { return 5; }

QVariant AddressListModel::headerData(int section, Qt::Orientation o, int role) const {
    if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
    switch (section) {
        case 0: return tr("Active");
        case 1: return tr("Description");
        case 2: return tr("Address");
        case 3: return tr("Type");
        case 4: return tr("Value");
        default: return {};
    }
}

void AddressListModel::refreshModuleCache() {
    moduleCache_ = proc_ ? proc_->modules() : std::vector<ce::ModuleInfo>{};
}

QVariant AddressListModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= (int)entries_.size())
        return {};
    if (role == Qt::CheckStateRole && index.column() == 0)
        return entries_[index.row()].active ? Qt::Checked : Qt::Unchecked;

    auto& e = entries_[index.row()];
    if (role == Qt::ToolTipRole) {
        if (index.column() == 1) return e.description;
        if (index.column() == 2 && !e.addressExpr.isEmpty()) return e.addressExpr;
        return data(index, Qt::DisplayRole);
    }
    if (role == Qt::ForegroundRole)
        return entryForeground(e.color);
    if (role == Qt::EditRole) {
        if (index.column() == 1) return e.description;
        // Pre-fill the address editor with the pointer expression if it is a
        // pointer record, otherwise the plain hex address.
        if (index.column() == 2)
            return e.addressExpr.isEmpty()
                ? QString("0x%1").arg(e.address, 0, 16) : e.addressExpr;
        // The type editor starts from the record's type: an empty editor
        // committed by clicking away changed every record to 4 Bytes.
        if (index.column() == 3) return valueTypeLabel(e.type);
        if (index.column() == 4) return e.currentValue;
        return {};
    }
    if (role != Qt::DisplayRole) return {};

    switch (index.column()) {
        case 1: {
            QString prefix;
            for (int i = 0; i < e.indent; ++i) prefix += "  ";
            // A group shows a collapse indicator (CE tree node): open vs collapsed.
            if (e.isGroup) prefix += e.collapsed ? QString::fromUtf8("▸ ")
                                                 : QString::fromUtf8("▾ ");
            return prefix + e.description;
        }
        case 2: {
            if (e.isGroup) return QString("");
            // Show the address relative to its module ("game.bin+0x1234") when it
            // falls inside one -- CE's convention, and stable across restarts.
            // Otherwise a plain hex address. Pointer records keep the "P->" prefix.
            std::string modOff = ce::moduleOffsetString(moduleCache_, e.address);
            QString addrStr = modOff.empty()
                ? formatListAddress(e.address)
                : QString::fromStdString(modOff);
            return e.addressExpr.isEmpty() ? addrStr : ("P->" + addrStr);
        }
        case 3: {
            if (e.isGroup) return "";
            // CE-canonical name; String/Array records also show their element length
            // in brackets (e.g. "String[10]", "Array of byte[8]"), like Cheat Engine.
            QString name = valueTypeLabel(e.type);
            if ((e.type == ValueType::String || e.type == ValueType::UnicodeString ||
                 e.type == ValueType::ByteArray) && e.byteCount > 0)
                name += QString("[%1]").arg(e.byteCount);
            return name;
        }
        case 4: return e.isGroup ? QString("") : e.dropdownList.isEmpty()
            ? e.currentValue
            : displayDropdownValue(e.currentValue, e.dropdownList);
        default: return {};
    }
}

Qt::ItemFlags AddressListModel::flags(const QModelIndex& index) const {
    auto f = QAbstractTableModel::flags(index);
    // Empty area (invalid index) accepts drops so an entry can be moved to the end.
    if (!index.isValid() || index.row() < 0 || index.row() >= (int)entries_.size())
        return f | Qt::ItemIsDropEnabled;
    const auto& e = entries_[index.row()];
    bool isScript = !e.autoAsmScript.isEmpty();
    if (index.column() == 0) f |= Qt::ItemIsUserCheckable;
    // Description is always editable. Address/Type/Value are editable for real
    // (non-group, non-script) entries — a script entry has no meaningful address,
    // type, or value; edit its script via the context menu / double-click.
    if (index.column() == 1)
        f |= Qt::ItemIsEditable;
    else if (!e.isGroup && !isScript &&
             (index.column() == 2 || index.column() == 3 || index.column() == 4))
        f |= Qt::ItemIsEditable;
    // Rows are draggable, and drop-enabled so a drop onto a row targets that row.
    f |= Qt::ItemIsDragEnabled | Qt::ItemIsDropEnabled;
    return f;
}

QStringList AddressListModel::mimeTypes() const {
    return {QStringLiteral("application/x-ce-addresslist-row")};
}

QMimeData* AddressListModel::mimeData(const QModelIndexList& indexes) const {
    // Encode the single source row (the smallest selected row); dropMimeData extends it
    // to the whole group block if it is a header. One row keeps the reorder unambiguous.
    int src = -1;
    for (const auto& idx : indexes)
        if (idx.isValid() && (src < 0 || idx.row() < src)) src = idx.row();
    if (src < 0) return nullptr;
    auto* mime = new QMimeData;
    QByteArray buf;
    QDataStream st(&buf, QIODevice::WriteOnly);
    st << src;
    mime->setData(mimeTypes().first(), buf);
    return mime;
}

bool AddressListModel::dropMimeData(const QMimeData* data, Qt::DropAction action, int row,
                                    int /*column*/, const QModelIndex& parent) {
    if (action != Qt::MoveAction || !data || !data->hasFormat(mimeTypes().first()))
        return false;
    QByteArray buf = data->data(mimeTypes().first());
    QDataStream st(&buf, QIODevice::ReadOnly);
    int src = -1; st >> src;
    if (src < 0 || src >= (int)entries_.size()) return false;
    // Qt's drop row: >=0 means "before this row" (drop between rows); onto a row gives
    // row=-1 + parent; an empty-area drop gives row=-1 + invalid parent (append at end).
    int dest, nestIndent = -1;
    if (row >= 0) {
        dest = row;                                   // between rows: flat move
    } else if (parent.isValid()) {
        int pr = parent.row();
        if (pr >= 0 && pr < (int)entries_.size() && entries_[pr].isGroup && pr != src) {
            // Dropped onto a group header: nest the entry as the group's first child (CE).
            dest = pr + 1;
            nestIndent = entries_[pr].indent + 1;
        } else {
            dest = pr;
        }
    } else {
        dest = (int)entries_.size();                  // empty area: move to the end
    }
    moveEntryBlock(src, dest, nestIndent);
    // Return false: the move is done here, so Qt must not also remove the source rows
    // (its default InternalMove completion would corrupt the list).
    return false;
}

void AddressListModel::moveEntryBlock(int srcRow, int destRow, int newRootIndent) {
    if (scriptBusy_ || mutationBusy_) return;
    const int n = (int)entries_.size();
    if (srcRow < 0 || srcRow >= n) return;
    // A group header drags its whole subtree; a leaf is a block of one.
    std::vector<int> indents;
    indents.reserve(n);
    for (const auto& e : entries_) indents.push_back(e.indent);
    // A record drags the rows nested under it: a group's subtree, and also the
    // children Cheat Engine tables put under script records, which would
    // otherwise be re-parented to whatever row precedes them.
    auto sub = ce::descendantRange(indents, srcRow);
    int len = (int)(sub.second - srcRow);
    if (len < 1) len = 1;
    // Dropping inside the moved block leaves the order unchanged, but a drop
    // onto the group right above still nests the block (re-indent only).
    if (destRow >= srcRow && destRow <= srcRow + len) {
        if (newRootIndent < 0 || entries_[srcRow].indent == newRootIndent) return;
        const int delta = newRootIndent - entries_[srcRow].indent;
        emit layoutAboutToBeChanged();   // see shiftIndentRows
        for (int i = srcRow; i < srcRow + len; ++i) entries_[i].indent = std::max(0, entries_[i].indent + delta);
        emit layoutChanged();
        emit dataChanged(index(srcRow, 0), index(srcRow + len - 1, columnCount() - 1));
        return;
    }
    auto perm = ce::moveRangePermutation(n, srcRow, len, destRow);
    if ((int)perm.size() != n) return;
    // Re-indent the block before permuting (indents ride along with the entries), so a
    // drop onto a group nests the whole subtree one level under it.
    if (newRootIndent >= 0) {
        int delta = newRootIndent - entries_[srcRow].indent;
        for (int i = srcRow; i < srcRow + len; ++i) {
            int ni = entries_[i].indent + delta;
            entries_[i].indent = ni < 0 ? 0 : ni;
        }
    }
    beginResetModel();
    std::vector<AddressEntry> reordered;
    reordered.reserve(n);
    for (int oldIdx : perm) reordered.push_back(std::move(entries_[oldIdx]));
    entries_ = std::move(reordered);
    endResetModel();
}

void AddressListModel::groupSelectedRows(const QList<int>& rows, const QString& desc) {
    if (scriptBusy_ || mutationBusy_) return;
    const int n = (int)entries_.size();
    std::vector<int> indents;
    indents.reserve(n);
    for (const auto& e : entries_) indents.push_back(e.indent);
    std::vector<std::size_t> sel;
    sel.reserve(rows.size());
    for (int r : rows) if (r >= 0 && r < n) sel.push_back((std::size_t)r);
    auto plan = ce::groupSelection(indents, sel);
    if (!plan.ok) return;

    // Each original index appears exactly once in plan.order (plus one -1 for the new
    // header), so moving out of entries_ never double-moves.
    beginResetModel();
    std::vector<AddressEntry> rebuilt;
    rebuilt.reserve(plan.order.size());
    for (std::size_t i = 0; i < plan.order.size(); ++i) {
        const int oldIdx = plan.order[i];
        if (oldIdx < 0) {
            AddressEntry g;
            g.id = allocId();
            g.description = desc;
            g.isGroup = true;
            g.indent = plan.indent[i];
            rebuilt.push_back(std::move(g));
        } else {
            AddressEntry e = std::move(entries_[oldIdx]);
            e.indent = plan.indent[i];
            rebuilt.push_back(std::move(e));
        }
    }
    entries_ = std::move(rebuilt);
    endResetModel();
}

// Localized name of the Type column. The canonical English ce::valueTypeName() stays
// the format used by cheat tables, Lua and the CLI; only the table and its editor
// show this translation.
static QString valueTypeLabel(ce::ValueType t) {
    switch (t) {
        case ValueType::Byte:          return QCoreApplication::translate("ce::gui::AddressListModel", "Byte");
        case ValueType::Int16:         return QCoreApplication::translate("ce::gui::AddressListModel", "2 Bytes");
        case ValueType::Int32:         return QCoreApplication::translate("ce::gui::AddressListModel", "4 Bytes");
        case ValueType::Int64:         return QCoreApplication::translate("ce::gui::AddressListModel", "8 Bytes");
        case ValueType::Float:         return QCoreApplication::translate("ce::gui::AddressListModel", "Float");
        case ValueType::Double:        return QCoreApplication::translate("ce::gui::AddressListModel", "Double");
        case ValueType::String:        return QCoreApplication::translate("ce::gui::AddressListModel", "String");
        case ValueType::UnicodeString: return QCoreApplication::translate("ce::gui::AddressListModel", "Unicode String");
        case ValueType::ByteArray:     return QCoreApplication::translate("ce::gui::AddressListModel", "Array of byte");
        case ValueType::Binary:        return QCoreApplication::translate("ce::gui::AddressListModel", "Binary");
        case ValueType::All:           return QCoreApplication::translate("ce::gui::AddressListModel", "All");
        case ValueType::Grouped:       return QCoreApplication::translate("ce::gui::AddressListModel", "Grouped");
        case ValueType::Custom:        return QCoreApplication::translate("ce::gui::AddressListModel", "Custom");
        case ValueType::Pointer:       return QCoreApplication::translate("ce::gui::AddressListModel", "Pointer");
    }
    return QCoreApplication::translate("ce::gui::AddressListModel", "4 Bytes");
}

// Parse a Type-column display name back to a ValueType. First matches the canonical
// name (ce::valueTypeName) and its translation, so every name the column can show
// round-trips ("String", "Unicode String", "Array of byte", "All", ...); then a few
// common synonyms. Int32 fallback. A record's type from its name; nothing for an
// unknown name or a scan-only type (All, Grouped), which a record cannot hold.
static std::optional<ValueType> valueTypeFromDisplayName(const QString& s) {
    QString n = s.trimmed().toLower();
    if (const auto bracket = n.indexOf('['); bracket > 0) n = n.left(bracket).trimmed();   // "string[10]"
    for (auto t : {ValueType::Byte, ValueType::Int16, ValueType::Int32, ValueType::Int64,
                   ValueType::Float, ValueType::Double, ValueType::String, ValueType::UnicodeString,
                   ValueType::ByteArray, ValueType::Binary, ValueType::Custom, ValueType::Pointer})
        if (n == QString(ce::valueTypeName(t)).toLower() ||
            n == valueTypeLabel(t).toLower()) return t;
    if (n == "word" || n == "short") return ValueType::Int16;
    if (n == "dword" || n == "int") return ValueType::Int32;
    if (n == "qword" || n == "long" || n == "int64") return ValueType::Int64;
    if (n == "text") return ValueType::String;
    if (n == "unicode text" || n == "unicode" || n == "utf-16") return ValueType::UnicodeString;
    if (n == "array of bytes" || n == "aob" || n == "bytes") return ValueType::ByteArray;
    return std::nullopt;
}

bool AddressListModel::setData(const QModelIndex& index, const QVariant& value, int role) {
    if (!index.isValid() || index.row() < 0 || index.row() >= (int)entries_.size() ||
        index.column() < 0 || index.column() >= columnCount()) return false;
    if (role == Qt::CheckStateRole && index.column() == 0) {
        const int id = entries_[index.row()].id;
        const bool group = entries_[index.row()].isGroup;
        const int parentIndent = entries_[index.row()].indent;
        bool requestedActive = (value.toInt() == Qt::Checked);
        const bool cascade = requestedActive ? entries_[index.row()].activateChildren
                                             : entries_[index.row()].deactivateChildren;
        std::vector<std::pair<uint64_t, int>> children;
        if (group && cascade) {
            for (int i = index.row() + 1; i < (int)entries_.size() && entries_[i].indent > parentIndent; ++i)
                children.emplace_back(entries_[i].autoAsmOrder, entries_[i].id);
        }
        if (group && !requestedActive) {
            std::stable_sort(children.begin(), children.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
            for (const auto& child : children) {
                if (rowOfId(child.second) >= 0 && !setActive(child.second, false)) return false;
            }
            children.clear();
        }
        const int parentRow = rowOfId(id);
        if (parentRow < 0) return true;
        if (!setEntryActive(parentRow, requestedActive))
            return false;
        const int row = rowOfId(id);
        if (row >= 0) emit dataChanged(this->index(row, 0), this->index(row, 0));
        bool success = true;
        for (const auto& child : children) {
            const int childRow = rowOfId(child.second);
            if (childRow >= 0 && !setActive(child.second, requestedActive)) success = false;
        }
        return success;
    }
    if (role == Qt::EditRole) {
        if (index.column() == 1) {
            entries_[index.row()].description = value.toString();
            emit dataChanged(index, index, {Qt::DisplayRole, Qt::EditRole});
            return true;
        }
        if (index.column() == 2) {   // Address
            auto& e = entries_[index.row()];
            if (e.isGroup || !e.autoAsmScript.isEmpty()) return false;
            QString text = value.toString().trimmed();
            if (text.isEmpty()) return false;
            std::optional<uintptr_t> addr;
            if (addressResolver_) addr = addressResolver_(text);
            if (!addr) {   // fall back to a bare hex address if no resolver
                bool ok = false;
                QString h = text;
                if (h.startsWith("0x") || h.startsWith("0X")) h = h.mid(2);
                uintptr_t v = h.toULongLong(&ok, 16);
                if (ok) addr = v;
            }
            if (!addr) return false;
            // Anything but a plain number (a [pointer] path, module+offset, a
            // symbol) is kept as an expression that re-resolves on every
            // refresh, so it survives ASLR and moving pointers (CE convention).
            QString digits = text;
            if (digits.startsWith("0x") || digits.startsWith("0X")) digits = digits.mid(2);
            const bool plain = !digits.isEmpty() && std::all_of(digits.begin(), digits.end(),
                [](QChar c) { return c.isDigit() || (c.toLower() >= 'a' && c.toLower() <= 'f'); });
            setEntryAddress(index.row(), *addr, plain ? QString() : text);
            return true;
        }
        if (index.column() == 3) {   // Type
            if (entries_[index.row()].isGroup) return false;
            const auto type = valueTypeFromDisplayName(value.toString());
            if (!type) return false;   // a typo keeps the type it had
            setEntryType(index.row(), *type);
            return true;
        }
        if (index.column() == 4) {
            auto& e = entries_[index.row()];
            if (e.isGroup) return false;
            auto rawValue = e.dropdownList.isEmpty()
                ? value.toString()
                : resolveDropdownInput(value.toString(), e.dropdownList);
            // Keep the display form: a hex entry stays "0x..." and the integer parser
            // reads the 0x prefix as hex. Pre-converting to a bare decimal here and
            // still passing showHex=true re-read "255" as 0x255 (wrong value), and
            // the decimal frozenValue was then written the same wrong way.
            if (e.showAsHex && (ce::isIntegerScalar(e.type) || e.type == ValueType::Pointer)) {
                QString h = rawValue.trimmed();
                if (h.startsWith("0x") || h.startsWith("0X")) h = h.mid(2);
                bool okh = false;
                qulonglong hv = h.toULongLong(&okh, 16);
                if (okh) rawValue = "0x" + QString::number(hv, 16);
            }
            ce::ValueIoOptions options;
            options.codec = e.codec; options.bigEndian = e.bigEndian;
            if (e.dataByteOrder != ByteOrder::Unknown) options.byteOrder = e.dataByteOrder;
            if (e.pointerWidth) options.pointerWidthOverride = e.pointerWidth;
            options.hex = e.showAsHex;
            options.pointerWidth = e.pointerWidth ? e.pointerWidth : proc_ ? proc_->pointerWidth(e.address) : sizeof(uintptr_t);
            if (proc_) {
                if (!reresolveAddress(e)) {
                    reportActivationError(tr("Value edit failed"), tr("The pointer path does not resolve right now."));
                    return false;
                }
                auto resolved = ce::valueOptionsForTarget(*proc_, e.address, e.type, options);
                if (!resolved) { reportActivationError(tr("Value edit failed"), QString::fromStdString(resolved.error())); return false; }
                options = *resolved;
            }
            auto bytes = ce::encodeTypedValue(e.type, rawValue.toStdString(), options);
            if (!bytes) { reportActivationError(tr("Value edit failed"), QString::fromStdString(bytes.error())); return false; }
            size_t nextByteCount = bytes->size();
            if (e.type == ValueType::String || e.type == ValueType::UnicodeString) {
                size_t capacity = e.byteCount;
                if (!capacity && e.currentValue != "?" && e.currentValue != "??") {
                    auto previous = ce::encodeTypedValue(e.type, e.currentValue.toStdString(), options);
                    if (previous) capacity = previous->size();
                }
                options.terminate = bytes->empty() || bytes->size() < capacity;
                if (options.terminate) nextByteCount += e.type == ValueType::UnicodeString ? 2 : 1;
            }
            if (proc_) {
                if (!reresolveAddress(e)) {
                    reportActivationError(tr("Value edit failed"), tr("The pointer path does not resolve right now."));
                    return false;
                }
                auto written = ce::writeTypedValue(*proc_, e.address, e.type, rawValue.toStdString(), options);
                if (!written) { reportActivationError(tr("Value edit failed"), QString::fromStdString(written.error())); return false; }
                if (!e.active) scheduleEditVerify(e.address, e.type, rawValue, e.codec, e.bigEndian, e.showAsSigned, e.dataByteOrder, e.pointerWidth);
            }
            if (e.type == ValueType::String || e.type == ValueType::UnicodeString || e.type == ValueType::ByteArray)
                e.byteCount = nextByteCount;
            e.currentValue = rawValue;
            if (e.active) e.frozenValue = rawValue;
            emit dataChanged(index, index);
            return true;
        }
    }
    return false;
}

void AddressListModel::scheduleEditVerify(uintptr_t addr, ce::ValueType type,
                                          const QString& wroteStr, const ce::ValueCodec& codec,
                                          bool bigEndian, bool isSigned, ByteOrder order, uint8_t pointerWidth) {
    if (!proc_) return;
    double target = 0;
    // Parse the written text the same way the read side interprets memory (hex-aware
    // for integers, so a "0xff" edit verifies), else no revert check (string/AOB).
    if (!parseComparableValue(type, wroteStr, target)) return;
    // `this` as the timer context: the callback is skipped if the model is destroyed.
    QTimer::singleShot(250, this, [this, addr, type, wroteStr, target, codec, bigEndian, isSigned, order, pointerWidth]() {
        if (!proc_) return;
        double now = 0;
        if (!readComparableValue(proc_, addr, type, now, codec, bigEndian, isSigned, order, pointerWidth)) return;
        const double tol = (type == ce::ValueType::Float || type == ce::ValueType::Double)
                         ? std::abs(target) * 1e-5 + 1e-6 : 0.5;
        if (std::abs(now - target) > tol)
            emit valueReverted(addr, wroteStr, QString::number(now, 'g', 10));
    });
}

// ── ce::IAddressList implementation ──

int AddressListModel::rowOfId(int id) const {
    for (size_t i = 0; i < entries_.size(); ++i)
        if (entries_[i].id == id) return (int)i;
    return -1;
}

int AddressListModel::count() const { return (int)entries_.size(); }

static AddressEntrySnapshot snapshotOf(const AddressEntry& e) {
    AddressEntrySnapshot s;
    s.id = e.id;
    s.description = e.description.toStdString();
    s.address = e.address;
    s.type = e.type;
    s.value = e.currentValue.toStdString();
    s.color = e.color.toStdString();
    s.script = e.autoAsmScript.toStdString();
    s.hotkeyKeys = e.hotkeyKeys.toStdString();
    s.active = e.active;
    s.isGroup = e.isGroup;
    s.showAsHex = e.showAsHex;
    s.indent = e.indent;
    s.addressExpression = e.addressExpr.toStdString();
    s.showAsSigned = e.showAsSigned;
    s.byteCount = e.byteCount;
    s.dataByteOrder = e.dataByteOrder;
    s.pointerWidth = e.pointerWidth;
    s.freezeMode = static_cast<int>(e.freezeMode);
    return s;
}

bool AddressListModel::setHexView(int id, bool hex) {
    int row = rowOfId(id);
    if (row < 0) return false;
    setShowAsHex(row, hex);   // existing row-based method: updates + emits dataChanged
    return true;
}

bool AddressListModel::setByteCount(int id, std::size_t count) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].byteCount = std::min<std::size_t>(count, kMaxRecordBytes);   // String / Array of byte length
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
    return true;
}

bool AddressListModel::setSigned(int id, bool isSigned) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].showAsSigned = isSigned;   // CE ShowAsSigned: re-render the value column
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
    return true;
}

bool AddressListModel::setIndent(int id, int indent) {
    if (scriptBusy_ || mutationBusy_) return false;
    int row = rowOfId(id);
    if (row < 0 || row >= (int)entries_.size()) return false;
    emit layoutAboutToBeChanged();   // see shiftIndentRows
    entries_[row].indent = indent < 0 ? 0 : indent;
    emit layoutChanged();
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
    return true;
}

std::optional<AddressEntrySnapshot> AddressListModel::at(int index) const {
    if (index < 0 || index >= (int)entries_.size()) return std::nullopt;
    return snapshotOf(entries_[index]);
}

std::optional<AddressEntrySnapshot> AddressListModel::byId(int id) const {
    int row = rowOfId(id);
    if (row < 0) return std::nullopt;
    return snapshotOf(entries_[row]);
}

int AddressListModel::findIdByDescription(const std::string& desc) const {
    QString q = QString::fromStdString(desc);
    for (const auto& e : entries_)
        if (e.description == q) return e.id;
    return -1;
}

std::vector<int> AddressListModel::ids() const {
    std::vector<int> out;
    out.reserve(entries_.size());
    for (const auto& e : entries_) out.push_back(e.id);
    return out;
}

std::vector<int> AddressListModel::cleanupOrder() const {
    std::vector<std::pair<uint64_t, int>> owners;
    owners.reserve(entries_.size());
    for (const auto& entry : entries_) owners.emplace_back(entry.autoAsmOrder, entry.id);
    std::stable_sort(owners.begin(), owners.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
    std::vector<int> result;
    result.reserve(owners.size());
    for (const auto& owner : owners) result.push_back(owner.second);
    return result;
}

int AddressListModel::createEntry(uintptr_t addr, ValueType type, const std::string& description) {
    addEntry(addr, type, QString::fromStdString(description));
    return entries_.empty() ? -1 : entries_.back().id;
}

int AddressListModel::createGroup(const std::string& description) {
    addGroup(QString::fromStdString(description));
    return entries_.empty() ? -1 : entries_.back().id;
}

bool AddressListModel::deleteById(int id) {
    int row = rowOfId(id);
    if (row < 0) return false;
    return removeEntry(row);
}

bool AddressListModel::disableAllWithoutExecute() {
    if (scriptBusy_ || mutationBusy_) return false;
    bool any = false;
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].active && !entries_[i].isGroup) {
            entries_[i].active = false;
            entries_[i].frozenValue.clear();
            any = true;
        }
    }
    if (any)
        emit dataChanged(index(0, 0), index((int)entries_.size() - 1, columnCount() - 1));
    return any;
}

bool AddressListModel::setDescription(int id, const std::string& desc) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].description = QString::fromStdString(desc);
    emit dataChanged(index(row, 1), index(row, 1));
    return true;
}

bool AddressListModel::setAddress(int id, uintptr_t addr) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].address = addr;
    entries_[row].addressExpr.clear();   // a plain address clears any pointer expr
    emit dataChanged(index(row, 2), index(row, 2));
    return true;
}

bool AddressListModel::setAddressExpression(int id, const std::string& expr) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].addressExpr = QString::fromStdString(expr);
    // Resolve once now so the address column is populated immediately.
    ExpressionParser parser(proc_, nullptr);
    if (auto v = parser.parse(expr)) entries_[row].address = *v;
    emit dataChanged(index(row, 2), index(row, 2));
    return true;
}

bool AddressListModel::setType(int id, ValueType t) {
    int row = rowOfId(id);
    if (row < 0) return false;
    setEntryType(row, t);   // ends a freeze of the old type
    return true;
}

bool AddressListModel::setValue(int id, const std::string& value) {
    int row = rowOfId(id);
    return row >= 0 && setData(index(row, 4), QString::fromStdString(value), Qt::EditRole);
}

bool AddressListModel::setActive(int id, bool active) {
    int row = rowOfId(id);
    if (row < 0) return false;
    bool ok = setEntryActive(row, active);
    row = rowOfId(id);
    if (row >= 0) emit dataChanged(index(row, 0), index(row, columnCount() - 1));
    return ok;
}

bool AddressListModel::setColor(int id, const std::string& color) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].color = QString::fromStdString(color);
    emit dataChanged(index(row, 1), index(row, columnCount() - 1));
    return true;
}

bool AddressListModel::setDropdownList(int id, const QString& list) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].dropdownList = normalizedDropdownList(list);
    emit dataChanged(index(row, 1), index(row, columnCount() - 1));
    return true;
}

QString AddressListModel::dropdownList(int row) const {
    return (row >= 0 && row < (int)entries_.size()) ? entries_[row].dropdownList : QString();
}

bool AddressListModel::setScript(int id, const std::string& script) {
    return updateScriptEntryById(id, {}, QString::fromStdString(script));
}

bool AddressListModel::setFreezeMode(int id, int mode) {
    int row = rowOfId(id);
    if (row < 0 || mode < 0 || mode > 4) return false;
    entries_[row].freezeMode = static_cast<ce::FreezeMode>(mode);
    return true;
}
} // namespace ce::gui
