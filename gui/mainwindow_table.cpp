// MainWindow: building, saving and loading cheat tables.
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
#include <QSaveFile>
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
#include <QCoreApplication>
#include <fstream>
#include "platform/linux/injector.hpp"
#include <QMessageBox>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <QFile>
#include <QFileInfo>

#include "gui/agent_panel.hpp"
#include <cerrno>
#include <QMenu>
#include <QInputDialog>
#include <QSettings>
#include <QStatusBar>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <QFileDialog>
#include <cstdio>
#include <cstring>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStringList>
#include <cmath>
#include <charconv>
#include <exception>

#include "gui/mainwindow_internal.hpp"
#include <QAction>
namespace ce::gui {
using namespace mainwindow_detail;

ce::CheatTable MainWindow::buildCheatTable() const {
    ce::CheatTable table=tableMetadata_;
    if (table.gameName.empty()) table.gameName = (currentProcessName_.isEmpty() ? processLabel_->text() : currentProcessName_).toStdString();
    table.comment = tableComment_.toStdString();   // table notes (Comments window)
    table.luaScript = tableLuaScript_.toStdString();  // table-level Lua (CE <LuaScript>)
    auto json = addressListModel_->toJson();
    int saveIdx = 0;
    for (auto val : json) {
        auto obj = val.toObject();
        ce::CheatEntry e;
        // Keep stable record IDs; translate the GUI parent row to its ID below.
        e.id = obj.value("id").toInt(saveIdx++);
        e.description = obj["description"].toString().toStdString();
        e.address = obj["address"].toString().toULongLong(nullptr, 16);
        auto exprStr = obj["addressExpr"].toString();
        if (!exprStr.isEmpty()) e.addressString = exprStr.toStdString();
        // A loaded pointer path is shown as one expression ("[[game.exe+1C]+8]+10");
        // a table keeps it as a base and offsets. Split back only what
        // buildPointerExpression made, so a hand-written expression stays as typed.
        // A script record's table entry has an address but no offsets.
        if (auto chain = ce::parsePointerExpression(e.addressString);
            chain && obj["asm"].toString().isEmpty() &&
            ce::buildPointerExpression(chain->base, chain->offsets) == e.addressString) {
            e.addressString = chain->base;
            e.offsets = chain->offsets;
            // A numeric base is written the way Cheat Engine writes addresses.
            QString base = QString::fromStdString(chain->base);
            bool plain = false;
            if (base.startsWith("0x")) (void)base.mid(2).toULongLong(&plain, 16);
            if (plain) e.addressString = base.mid(2).toStdString();
        }
        auto typeStr = obj["type"].toString().toStdString();
        if (typeStr == "byte") e.type = ce::ValueType::Byte;
        else if (typeStr == "i16") e.type = ce::ValueType::Int16;
        else if (typeStr == "i32") e.type = ce::ValueType::Int32;
        else if (typeStr == "i64") e.type = ce::ValueType::Int64;
        else if (typeStr == "pointer") e.type = ce::ValueType::Pointer;
        else if (typeStr == "float") e.type = ce::ValueType::Float;
        else if (typeStr == "double") e.type = ce::ValueType::Double;
        else if (typeStr == "string") e.type = ce::ValueType::String;
        else if (typeStr == "unicode") e.type = ce::ValueType::UnicodeString;
        else if (typeStr == "aob") e.type = ce::ValueType::ByteArray;
        else if (typeStr == "binary") e.type = ce::ValueType::Binary;
        else if (typeStr == "grouped") e.type = ce::ValueType::Grouped;
        else if (typeStr == "custom") e.type = ce::ValueType::Custom;
        else e.type = ce::ValueType::Int32;
        e.length = obj["byteCount"].toInt(0);   // String/AoB element length -> CE <Length>
        e.value = obj["value"].toString().toStdString();
        e.active = obj["active"].toBool();
        e.showAsHex = obj["showAsHex"].toBool();
        e.showAsSigned = obj["showAsSigned"].toBool(true);
        const auto order = obj["dataByteOrder"].toString();
        e.dataByteOrder = order == "big" || (order.isEmpty() && obj["bigEndian"].toBool()) ? ByteOrder::Big : order == "little" ? ByteOrder::Little : ByteOrder::Unknown;
        e.pointerWidth = static_cast<uint8_t>(obj["pointerWidth"].toInt());
        e.freezeMode = (ce::FreezeMode)obj["freezeMode"].toInt();
        e.autoAsmScript = obj["asm"].toString().toStdString();
        e.color = obj["color"].toString().toStdString();
        e.dropdownList = obj["dropdown"].toString().toStdString();
        e.hotkeyKeys = obj["hotkeys"].toString().toStdString();
        e.increaseHotkeyKeys = obj["increaseHotkey"].toString().toStdString();
        e.setValueHotkeyKeys = obj["setValueHotkey"].toString().toStdString();
        e.setValueHotkeyValue = obj["setValueHotkeyValue"].toString().toStdString();
        e.decreaseHotkeyKeys = obj["decreaseHotkey"].toString().toStdString();
        e.hotkeyStep = obj["hotkeyStep"].toString().toStdString();
        e.isGroup = obj["group"].toBool();
        e.collapsed = obj["collapsed"].toBool();
        e.activateChildren = obj["activateChildren"].toBool(true);
        e.deactivateChildren = obj["deactivateChildren"].toBool(true);
        e.optionsXml = obj["optionsXml"].toString().toStdString();
        e.luaScript = obj["lua"].toString().toStdString();
        e.customTypeName = obj["customType"].toString().toStdString();
        e.asyncScript = obj["async"].toBool();
        e.dropdownAttributes = obj["dropdownAttributes"].toString().toStdString();
        e.unparsedAddress = obj["unparsedAddress"].toString().toStdString();
        for (const auto& text : obj["unparsedOffsets"].toArray())
            e.unparsedOffsets.push_back(text.toString().toStdString());
        e.extraHotkeysXml = obj["extraHotkeys"].toString().toStdString();
        e.extraXml = obj["extraXml"].toString().toStdString();
        const int parentRow=obj["parent"].toInt(-1);
        e.parentId=parentRow>=0 && parentRow<json.size()
            ? json[parentRow].toObject().value("id").toInt(parentRow) : -1;
        table.entries.push_back(e);
    }
    table.disassemblerComments = disasmAnnotations_;
    return table;
}

namespace {
class TableDeviceBuffer : public std::streambuf {
    QIODevice& device_;
protected:
    std::streamsize xsputn(const char* bytes,std::streamsize size) override {
        auto written=device_.write(bytes,static_cast<qint64>(size));
        return written<0 ? 0 : static_cast<std::streamsize>(written);
    }
    int_type overflow(int_type c) override {
        if (traits_type::eq_int_type(c,traits_type::eof())) return traits_type::not_eof(c);
        char byte=traits_type::to_char_type(c);
        return device_.write(&byte,1)==1 ? c : traits_type::eof();
    }
public:
    explicit TableDeviceBuffer(QIODevice& device) : device_(device) {}
};
}

void MainWindow::onSaveTable() {
    // A deleted file is simply written again; saveTableToPath reports real errors.
    if (currentTablePath_.isEmpty()) { onSaveTableAs(); return; }
    // The saver picks the format from the name (.ct: XML, otherwise JSON). A
    // table loaded from something else (a password-protected .CETRAINER, CE
    // XML without .ct) would be replaced by a different format, a protected
    // one in plain text: ask where to save instead.
    const auto onDisk = ce::detectTableFormat(currentTablePath_.toStdString());
    const bool ct = currentTablePath_.endsWith(".ct", Qt::CaseInsensitive);
    if (onDisk == ce::TableFormat::Protected || (onDisk == ce::TableFormat::Xml && !ct) ||
        (onDisk == ce::TableFormat::Json && ct)) {
        onSaveTableAs();
        return;
    }
    saveTableToPath(currentTablePath_);
}

// Cheat Engine writes ".CT"; GTK's file chooser matches patterns case-sensitively,
// so list both spellings or a user's existing tables would be hidden.
static QString tableFileFilter() {
    return QCoreApplication::translate("MainWindow",
        "Cheat Tables (*.ct *.CT);;JSON Tables (*.json *.JSON);;All Files (*)");
}

void MainWindow::onSaveTableAs() {
    QString filter;
    auto path=QFileDialog::getSaveFileName(this,tr("Save Cheat Table"),currentTablePath_,tableFileFilter(),&filter);
    if (path.isEmpty()) return;
    // Native choosers don't add an extension; take it from the chosen file type,
    // since saveTableToPath picks the format from the name.
    if (QFileInfo(path).suffix().isEmpty())
        path += filter.contains("*.json") ? ".json" : ".CT";
    saveTableToPath(path);
}

bool MainWindow::saveTableToPath(const QString& path) {
    auto fail=[&](const QString& reason) {
        QMessageBox::critical(this,tr("Save Cheat Table"),QString(tr("Could not save %1:\n%2")).arg(path,reason));
        return false;
    };
    try {
        QSaveFile file(path);
        // Never fall back to truncating the previous table if staging fails.
        file.setDirectWriteFallback(false);
        if (!file.open(QIODevice::WriteOnly)) return fail(file.errorString());
        if (path.endsWith(".ct",Qt::CaseInsensitive)) {
            auto table=buildCheatTable();
            TableDeviceBuffer buffer(file);std::ostream output(&buffer);
            if (!ce::writeTableXml(table,output)) {file.cancelWriting();return fail(tr("Invalid table data or incomplete write."));}
        } else {
            // Keep the GUI's richer native records (including codecs), while
            // serializing shared table metadata through the core JSON writer.
            auto metadata=tableMetadata_;
            if (metadata.gameName.empty()) metadata.gameName=(currentProcessName_.isEmpty() ? processLabel_->text() : currentProcessName_).toStdString();
            metadata.comment=tableComment_.toStdString();metadata.luaScript=tableLuaScript_.toStdString();
            metadata.disassemblerComments=disasmAnnotations_;
            std::ostringstream output;
            if (!ce::writeTableJson(metadata,output)) {file.cancelWriting();return fail(tr("Invalid table metadata."));}
            auto root=QJsonDocument::fromJson(QByteArray::fromStdString(output.str())).object();
            root["process"]=processLabel_->text();root["entries"]=addressListModel_->toJson();
            const auto bytes=QJsonDocument(root).toJson();
            if (file.write(bytes)!=bytes.size()) {const auto error=file.errorString();file.cancelWriting();return fail(error);}
        }
        // Older Qt can commit a partial buffered write without reporting its
        // flush error. Check the device flush before replacing the old table.
        if (!file.flush()) {const auto error=file.errorString();file.cancelWriting();return fail(error);}
        if (!file.commit()) return fail(file.errorString());
        addRecentTable(path);
        statusBar()->showMessage(QString(tr("Saved table to %1")).arg(QFileInfo(path).fileName()),4000);
        return true;
    } catch (const std::exception& ex) {return fail(QString::fromUtf8(ex.what()));}
      catch (...) {return fail(tr("Unknown save error."));}
}

void MainWindow::onLoadTable() {
    if (!maybeSaveTable()) return;
    auto path = QFileDialog::getOpenFileName(this, tr("Load Cheat Table"),
        currentTablePath_.isEmpty() ? QString() : QFileInfo(currentTablePath_).absolutePath(), tableFileFilter());
    if (path.isEmpty()) return;
    loadTableFromPath(path);
}

namespace mainwindow_detail {
// Load a cheat table from a path (no dialog). Shared by onLoadTable and the
// command-line "cheatengine <table.ct>" entry point.
// Convert a parsed CheatTable's records into the address-list JSON schema
// (the same shape AddressListModel::toJson emits), computing each record's indent
// from the parentId tree. Shared by full-table load (replace) and clipboard paste
// of CE XML (append).
QJsonArray cheatEntriesToJson(const ce::CheatTable& table) {
    QJsonArray arr;
    // Compute each entry's nesting level from the parentId tree (entries are in
    // document order, parents before children) so imported groups indent in the
    // address list, which tracks hierarchy by indent depth.
    std::unordered_map<int, int> indentById;
    for (const auto& e : table.entries) {
        QJsonObject obj;
        obj["id"]=e.id;
        int indent = 0;
        if (e.parentId != -1) {
            auto it = indentById.find(e.parentId);
            if (it != indentById.end()) indent = it->second + 1;
        }
        indentById[e.id] = indent;
        obj["indent"] = indent;
        obj["description"] = QString::fromStdString(e.description);
        obj["address"] = QString("0x%1").arg(e.address, 0, 16);
        // Preserve CE symbolic bases ("game.exe+1C") and pointer offset chains
        // as an address expression that is re-evaluated each refresh.
        if (!e.addressString.empty() || !e.offsets.empty()) {
            std::string base = e.addressString.empty()
                ? "0x" + QString::number(e.address, 16).toStdString()
                : e.addressString;
            obj["addressExpr"] = QString::fromStdString(ce::buildPointerExpression(base, e.offsets));
        }
        obj["type"] = QString::number((int)e.type);
        obj["value"] = QString::fromStdString(e.value);
        // CE <Length> for String / Array-of-byte elements; without it the record
        // reads/displays at the 64-byte default and a re-save drops the length.
        if (e.length > 0) obj["byteCount"] = (int)e.length;
        obj["active"] = e.active;
        obj["showAsHex"] = e.showAsHex;
        obj["showAsSigned"] = e.showAsSigned;
        if (e.dataByteOrder != ByteOrder::Unknown) obj["dataByteOrder"] = e.dataByteOrder == ByteOrder::Big ? "big" : "little";
        if (e.pointerWidth) obj["pointerWidth"] = e.pointerWidth;
        obj["freezeMode"] = (int)e.freezeMode;
        obj["asm"] = QString::fromStdString(e.autoAsmScript);
        obj["color"] = QString::fromStdString(e.color);
        obj["dropdown"] = QString::fromStdString(e.dropdownList);
        obj["hotkeys"] = QString::fromStdString(e.hotkeyKeys);
        obj["increaseHotkey"] = QString::fromStdString(e.increaseHotkeyKeys);
        obj["setValueHotkey"] = QString::fromStdString(e.setValueHotkeyKeys);
        obj["setValueHotkeyValue"] = QString::fromStdString(e.setValueHotkeyValue);
        obj["decreaseHotkey"] = QString::fromStdString(e.decreaseHotkeyKeys);
        obj["hotkeyStep"] = QString::fromStdString(e.hotkeyStep);
        obj["group"] = e.isGroup;
        obj["collapsed"] = e.collapsed;
        obj["activateChildren"] = e.activateChildren;
        obj["deactivateChildren"] = e.deactivateChildren;
        obj["optionsXml"] = QString::fromStdString(e.optionsXml);
        obj["lua"] = QString::fromStdString(e.luaScript);
        // Fields the list only keeps for the save, under the table JSON names.
        if (!e.customTypeName.empty()) obj["customType"] = QString::fromStdString(e.customTypeName);
        if (e.asyncScript) obj["async"] = true;
        if (!e.dropdownAttributes.empty()) obj["dropdownAttributes"] = QString::fromStdString(e.dropdownAttributes);
        if (!e.unparsedOffsets.empty()) {
            QJsonArray texts;
            for (const auto& text : e.unparsedOffsets) texts.append(QString::fromStdString(text));
            obj["unparsedAddress"] = QString::fromStdString(e.unparsedAddress);
            obj["unparsedOffsets"] = texts;
        }
        if (!e.extraHotkeysXml.empty()) obj["extraHotkeys"] = QString::fromStdString(e.extraHotkeysXml);
        if (!e.extraXml.empty()) obj["extraXml"] = QString::fromStdString(e.extraXml);
        obj["parent"] = e.parentId;
        arr.append(obj);
    }
    return arr;
}
} // namespace mainwindow_detail

// Populate the address list (and table comment / disassembler annotations / table
// Lua) from a parsed CheatTable. Shared by every load path that yields a
// CheatTable model (CE XML .CT and password-protected .CETRAINER), so they behave
// identically. JSON may add codec/presentation settings to the common records.
bool MainWindow::loadCheatTableModel(const ce::CheatTable& table,const QJsonArray* originalJson) {
    QJsonArray arr = cheatEntriesToJson(table);
    if (originalJson && originalJson->size()==arr.size()) {
        for (qsizetype i=0;i<arr.size();++i) {
            auto record=arr[i].toObject();const auto original=(*originalJson)[i].toObject();
            for (const auto* field:{"codec","indent"})
                if (original.contains(field)) record[field]=original[field];
            arr[i]=record;
        }
    }
    // A table's saved <Activated> is not acted on: enabling a record writes to
    // the game or runs its script (and the script's {$lua}) before the user was
    // asked anything. Records load switched off, as paste does.
    for (qsizetype i=0;i<arr.size();++i) {
        auto record=arr[i].toObject();
        record["active"]=false;
        arr[i]=record;
    }
    if (!loadAddressEntries(arr)) return false;
    tableMetadata_.gameName=table.gameName;tableMetadata_.gameVersion=table.gameVersion;
    tableMetadata_.author=table.author;tableMetadata_.structures=table.structures;
    tableMetadata_.rawFormsXml=table.rawFormsXml;tableMetadata_.rawSectionsXml=table.rawSectionsXml;
    // An open Comments or Lua Script window holds the previous table's text,
    // and its next edit would overwrite the loaded table's.
    for (auto& window : tableTextWindows_) if (window) window->close();
    tableTextWindows_.clear();
    tableComment_ = QString::fromStdString(table.comment);
    // Retain the table-level Lua script so it can be viewed/edited (Table > Show
    // Cheat Table Lua Script) and re-saved, not just run once on load.
    tableLuaScript_ = QString::fromStdString(table.luaScript);
    // Run the table-level Lua script (CE's <LuaScript>) after the records are
    // loaded, so it can define trainer functions/hooks and reference records.
    if (!table.luaScript.empty()) {
        // CE asktorunluascript: never auto-run an untrusted table's Lua, ask first.
        auto answer = QMessageBox::question(this, tr("Execute this lua script?"),
            tr("This cheat table contains a Lua script.\n\n"
            "Only execute scripts from tables you trust, a table's Lua can hook "
            "and manipulate the target. Execute it?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (answer == QMessageBox::Yes) {
            luaEngine_.setProcess(process_.get());
            luaEngine_.setAddressList(addressListModel_);
            auto res = luaEngine_.evalToString(table.luaScript);
            if (!res.has_value())
                statusBar()->showMessage(
                    QString(tr("Table Lua error: %1")).arg(QString::fromStdString(res.error())), 8000);
        }
    }
    // Open Memory Viewers hold the previous table's comments and labels; their
    // next save would write those over the loaded table's.
    for (auto& viewer : memoryViewers_)
        if (viewer) viewer->replaceAnnotations(disasmAnnotations_, table.disassemblerComments);
    disasmAnnotations_ = table.disassemblerComments;
    return true;
}

void MainWindow::addRecentTable(const QString& path) {
    QString abs = QFileInfo(path).absoluteFilePath();
    if (abs.isEmpty()) return;
    QSettings s;
    QStringList recent = s.value("recentTables").toStringList();
    recent.removeAll(abs);        // de-dup, then promote to the front (most recent)
    recent.prepend(abs);
    while (recent.size() > 10) recent.removeLast();
    s.setValue("recentTables", recent);
    rebuildRecentMenu();
    // Every successful load and save lands here: that file is now the table's own,
    // so File > Save writes back to it and the title names it.
    currentTablePath_ = abs;
    markTableSaved();   // what this file holds is now the unchanged state
    updateWindowTitle();
}

// "Cheat Engine - Game (1234) - table.ct": the process, then the table's file.
void MainWindow::updateWindowTitle() {
    QString title = "Cheat Engine";
    if (process_ && !currentProcessName_.isEmpty())
        title += currentPid_ > 0 ? QString(" - %1 (%2)").arg(currentProcessName_).arg(currentPid_)
                                 : " - " + currentProcessName_;
    if (!currentTablePath_.isEmpty()) title += " - " + QFileInfo(currentTablePath_).fileName();
    setWindowTitle(title);
    syncAgentTarget();   // every change of target ends here
    if (process_) {
        // Script editors opened before any target take this one.
        for (auto& editor : unboundEditors_)
            if (editor) { editor->attachProcess(process_.get()); trackTargetWindow(editor); }
        unboundEditors_.clear();
    }
}

void MainWindow::syncAgentTarget() {
    if (!agentPanel_) return;
    // The agent tools work on local processes only: a ceserver PID belongs to
    // another machine, and a GDB target has none.
    const bool local = process_ && !ceserverClient_ && currentPid_ > 0;
    agentPanel_->setTarget(local ? currentPid_ : 0, process_ ? currentProcessName_ : QString());
}

void MainWindow::rebuildRecentMenu() {
    if (!recentMenu_) return;
    recentMenu_->clear();
    const QStringList recent = QSettings().value("recentTables").toStringList();
    if (recent.isEmpty()) {
        recentMenu_->addAction(tr("(no recent tables)"))->setEnabled(false);
        return;
    }
    for (const QString& p : recent) {
        // Basename in the menu, full path in the tooltip; a missing file is greyed
        // (it stays listed so the user can see what went away, like CE).
        const bool exists = QFileInfo::exists(p);
        auto* a = recentMenu_->addAction(QFileInfo(p).fileName());
        a->setToolTip(exists ? p : p + "  " + tr("(missing)"));
        a->setEnabled(exists);
        if (exists) connect(a, &QAction::triggered, this, [this, p]() { if (maybeSaveTable()) loadTableFromPath(p); });
    }
    recentMenu_->addSeparator();
    connect(recentMenu_->addAction(tr("Clear list")), &QAction::triggered, this, [this]() {
        QSettings().remove("recentTables");
        rebuildRecentMenu();
    });
}

void MainWindow::loadTableFromPath(const QString& path) {
  try {
    // Detect the format from the file's contents, not its extension: CE tables are
    // commonly `.CT` (uppercase) or extensionless when downloaded, which a
    // case-sensitive ".ct" check silently rejected.
    const ce::TableFormat fmt = ce::detectTableFormat(path.toStdString());
    if (fmt == ce::TableFormat::Protected) {
        bool ok = false;
        QString pw = QInputDialog::getText(this, tr("Protected Cheat Table"),
            tr("This table is password-protected (.CETRAINER).\nEnter its password:"),
            QLineEdit::Password, QString(), &ok);
        if (!ok) return;
        CheatTable table;
        if (!table.loadProtected(path.toStdString(), pw.toStdString())) {
            QMessageBox::warning(this, tr("Load Cheat Table"),
                tr("Could not decrypt the table (wrong password or corrupt file)."));
            return;
        }
        if (!loadCheatTableModel(table)) return;
        addRecentTable(path);
        return;
    }
    if (fmt != ce::TableFormat::Json) {
        // CE XML .CT format (Xml, or Unknown which load() self-validates).
        CheatTable table;
        if (!table.load(path.toStdString())) {QMessageBox::warning(this,tr("Load Cheat Table"),tr("Could not read a valid cheat table."));return;}
        if (!loadCheatTableModel(table)) return;
        addRecentTable(path);
    } else {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {QMessageBox::warning(this,tr("Load Cheat Table"),f.errorString());return;}
        const auto bytes=f.readAll();
        if (f.error()!=QFileDevice::NoError) {QMessageBox::warning(this,tr("Load Cheat Table"),f.errorString());return;}
        QJsonParseError parseError;auto doc=QJsonDocument::fromJson(bytes,&parseError);
        if (!doc.isObject() || !doc.object()["entries"].isArray()) {
            QMessageBox::warning(this,tr("Load Cheat Table"),tr("Invalid JSON cheat table."));return;
        }
        for (const auto& value:doc.object()["entries"].toArray()) if (!value.isObject()) {
            QMessageBox::warning(this,tr("Load Cheat Table"),tr("Invalid JSON record."));return;
        }
        CheatTable parsed;
        if (!parsed.loadJsonFromString(bytes.toStdString())) {QMessageBox::warning(this,tr("Load Cheat Table"),tr("Invalid JSON record data."));return;}
        // Use the exact validated common fields for either JSON schema. Only
        // GUI codec/presentation settings come from Qt's parsed representation.
        const auto original=doc.object()["entries"].toArray();
        if (!loadCheatTableModel(parsed,&original)) return;
        addRecentTable(path);
    }
  } catch (const std::exception& ex) {
    // A parse/load path (e.g. ct_file) may throw; never let it escape the slot
    // into std::terminate.
    QMessageBox::critical(this, tr("Load Cheat Table"),
        QString(tr("Failed to load table:\n%1")).arg(ex.what()));
  } catch (...) {
    QMessageBox::critical(this, tr("Load Cheat Table"), tr("Failed to load table (unknown error)."));
  }
}

namespace mainwindow_detail {
bool validRecordFormats(const QJsonArray& entries) {
    for (const auto& value : entries) {
        const auto object = value.toObject();
        const auto order = object.value("dataByteOrder"), width = object.value("pointerWidth");
        if ((!order.isUndefined() && (!order.isString() ||
             (order.toString() != "auto" && order.toString() != "little" && order.toString() != "big"))) ||
            (!width.isUndefined() && (!width.isDouble() ||
             (width.toDouble() != 0 && width.toDouble() != 4 && width.toDouble() != 8)))) return false;
    }
    return true;
}
} // namespace mainwindow_detail

bool MainWindow::loadAddressEntries(const QJsonArray& entries) {
    // The model owns both activation and its resulting undo state.
    return addressListModel_->fromJson(entries);
}
} // namespace ce::gui
