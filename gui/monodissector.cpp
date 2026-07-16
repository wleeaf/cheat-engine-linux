#include "gui/monodissector.hpp"
#include "analysis/il2cpp_binary.hpp"

#include <QApplication>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QToolBar>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <unordered_map>

namespace ce::gui {

// Convert a resolved IL2CPP layout into the MonoDissection shape so the same tree
// UI renders it. Const fields (no storage) are dropped; instance/static keep their
// offsets. Each field's managed type name (resolved offline from the binary's
// Il2CppType table) drives both the displayed type and its scan value-type.
static ce::MonoDissection il2cppToMonoDissection(const ce::Il2CppBinaryLayout& layout,
                                                uintptr_t moduleBase) {
    ce::MonoDissection d;
    d.ready = layout.ok;
    d.error = layout.error;
    std::unordered_map<std::string, size_t> imageIndex;
    for (const auto& c : layout.classes) {
        size_t idx;
        auto it = imageIndex.find(c.image);
        if (it == imageIndex.end()) {
            idx = d.images.size();
            imageIndex[c.image] = idx;
            ce::MonoImageInfo mi;
            mi.name = c.image.empty() ? "<unknown>" : c.image;
            d.images.push_back(std::move(mi));
        } else {
            idx = it->second;
        }
        ce::MonoClassInfo cls;
        cls.namespaceName = c.namespaceName;
        cls.name = c.name;
        for (const auto& f : c.fields) {
            if (f.isConst) continue;
            ce::MonoField mf;
            mf.name = f.name;
            mf.offset = static_cast<uint32_t>(f.offset);
            mf.isStatic = f.isStatic;
            mf.typeName = f.typeName;   // "UnityEngine.Vector3", "System.Single", …
            cls.fields.push_back(std::move(mf));
        }
        for (const auto& m : c.methods) {
            ce::MonoMethod mm;
            mm.name = m.name;
            mm.address = moduleBase + m.rva;   // live code address
            cls.methods.push_back(std::move(mm));
        }
        d.images[idx].classes.push_back(std::move(cls));
    }
    return d;
}

ce::ValueType monoTypeToValueType(const QString& t) {
    // Common BCL primitives -> our scan/display types; default to Int32.
    if (t == "System.Byte" || t == "System.SByte" || t == "System.Boolean") return ce::ValueType::Byte;
    if (t == "System.Int16" || t == "System.UInt16" || t == "System.Char")  return ce::ValueType::Int16;
    if (t == "System.Int32" || t == "System.UInt32")                        return ce::ValueType::Int32;
    if (t == "System.Int64" || t == "System.UInt64")                        return ce::ValueType::Int64;
    if (t == "System.Single")  return ce::ValueType::Float;
    if (t == "System.Double")  return ce::ValueType::Double;
    if (t == "System.String")  return ce::ValueType::String;
    if (t == "System.IntPtr" || t == "System.UIntPtr") return ce::ValueType::Pointer;
    // Reference-type fields hold a pointer to the object.
    return ce::ValueType::Pointer;
}

// A tree item role marking a field, carrying its offset + type for the add action.
static constexpr int kOffsetRole = Qt::UserRole + 1;
static constexpr int kTypeRole   = Qt::UserRole + 2;
static constexpr int kLabelRole  = Qt::UserRole + 3;
static constexpr int kKindRole   = Qt::UserRole + 4;   // "img" / "cls" / "fld"

MonoDissectorWindow::MonoDissectorWindow(ce::ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Mono Dissector");
    resize(720, 640);

    auto* bar = new QToolBar;
    auto* dissectAct = bar->addAction("Dissect (inject agent)");
    dissectAct->setToolTip("Inject the Mono agent and read the target's class/field layout");
    connect(dissectAct, &QAction::triggered, this, &MonoDissectorWindow::runDissect);
    bar->addSeparator();
    bar->addWidget(new QLabel(" Filter: "));
    filter_ = new QLineEdit;
    filter_->setPlaceholderText("class or field name…");
    filter_->setClearButtonEnabled(true);
    connect(filter_, &QLineEdit::textChanged, this, &MonoDissectorWindow::applyFilter);
    bar->addWidget(filter_);
    addToolBar(bar);

    auto* central = new QWidget;
    auto* v = new QVBoxLayout(central);
    tree_ = new QTreeWidget;
    tree_->setColumnCount(3);
    tree_->setHeaderLabels({"Name", "Offset", "Type"});
    tree_->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    tree_->setAlternatingRowColors(true);
    // Double-click a field row -> request it be added to the address list.
    connect(tree_, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* it, int) {
        if (!it || it->data(0, kKindRole).toString() != "fld") return;
        emit addFieldRequested(it->data(0, kOffsetRole).toUInt(),
                               it->data(0, kTypeRole).toInt(),
                               it->data(0, kLabelRole).toString());
    });
    v->addWidget(tree_);
    status_ = new QLabel("Click \"Dissect\" to read the target's Mono layout.");
    v->addWidget(status_);
    setCentralWidget(central);
}

void MonoDissectorWindow::setDissection(const ce::MonoDissection& d) {
    dissection_ = d;
    tree_->clear();
    size_t fieldCount = 0;
    for (const auto& img : d.images) {
        auto* imgItem = new QTreeWidgetItem(tree_, {QString::fromStdString(img.name)});
        imgItem->setData(0, kKindRole, "img");
        imgItem->setFirstColumnSpanned(true);
        for (const auto& c : img.classes) {
            auto* clsItem = new QTreeWidgetItem(imgItem, {QString::fromStdString(c.fullName())});
            clsItem->setData(0, kKindRole, "cls");
            for (const auto& f : c.fields) {
                QString name = QString::fromStdString(f.name) + (f.isStatic ? " (static)" : "");
                auto* fldItem = new QTreeWidgetItem(clsItem, {
                    name,
                    QString("0x%1").arg(f.offset, 0, 16),
                    QString::fromStdString(f.typeName),
                });
                fldItem->setData(0, kKindRole, "fld");
                fldItem->setData(0, kOffsetRole, static_cast<uint>(f.offset));
                fldItem->setData(0, kTypeRole, static_cast<int>(
                    monoTypeToValueType(QString::fromStdString(f.typeName))));
                fldItem->setData(0, kLabelRole,
                    QString::fromStdString(c.name + "." + f.name));
                ++fieldCount;
            }
            // Methods (IL2CPP): display name + resolved code address. Not addable
            // to the address list (code, not a value), so no field roles.
            for (const auto& m : c.methods) {
                auto* mItem = new QTreeWidgetItem(clsItem, {
                    QString::fromStdString(m.name) + "()",
                    m.address ? QString("0x%1").arg(m.address, 0, 16) : QString(),
                    QStringLiteral("method"),
                });
                mItem->setData(0, kKindRole, "method");
            }
        }
    }
    status_->setText(QString("%1 %2 · %3 classes · %4 fields%5")
        .arg(d.images.size()).arg(d.images.size() == 1 ? "assembly" : "assemblies")
        .arg(d.classCount()).arg(fieldCount)
        .arg(d.ready ? QString() : QString("  (incomplete%1)")
            .arg(d.error.empty() ? QString() : ": " + QString::fromStdString(d.error))));
    applyFilter(filter_->text());
}

void MonoDissectorWindow::runDissect() {
    if (!proc_) { status_->setText("No target process."); return; }
    // Only Mono is queryable in-process; report IL2CPP / non-managed distinctly.
    switch (ce::detectManagedKind(*proc_)) {
        case ce::ManagedKind::Il2Cpp: {
            // IL2CPP has no live runtime to query; resolve the class layout
            // statically from global-metadata.dat + the GameAssembly binary.
            status_->setText("IL2CPP target: locating metadata + GameAssembly…");
            QApplication::setOverrideCursor(Qt::WaitCursor);
            QApplication::processEvents();
            auto layout = ce::resolveIl2CppForProcess(*proc_);
            QApplication::restoreOverrideCursor();
            if (!layout.ok) {
                status_->setText("IL2CPP: " + QString::fromStdString(layout.error));
                return;
            }
            // GameAssembly runtime base, so method RVAs become live addresses.
            uintptr_t modBase = 0;
            {
                std::vector<std::string> paths;
                for (const auto& m : proc_->modules()) if (!m.path.empty()) paths.push_back(m.path);
                for (const auto& r : proc_->queryRegions()) if (!r.path.empty()) paths.push_back(r.path);
                std::string ga = ce::findGameAssemblyPath(paths);
                for (const auto& m : proc_->modules()) if (m.path == ga) { modBase = m.base; break; }
            }
            setDissection(il2cppToMonoDissection(layout, modBase));
            return;
        }
        case ce::ManagedKind::None:
            status_->setText("No Mono runtime detected in this process.");
            return;
        case ce::ManagedKind::Mono:
            break;
    }
    std::string agent = ce::findMonoAgentPath();
    if (agent.empty()) {
        status_->setText("libcecore_mono_agent.so not found next to the binary.");
        return;
    }
    status_->setText("Injecting agent and reading Mono layout…");
    QApplication::setOverrideCursor(Qt::WaitCursor);
    QApplication::processEvents();
    // A loaded resolver is needed so injection can find dlopen in the target.
    ce::SymbolResolver resolver;
    resolver.loadProcess(*proc_);
    auto d = ce::dissectMono(*proc_, resolver, agent);
    QApplication::restoreOverrideCursor();
    if (!d) { status_->setText("Agent injection failed (see CE_LOG=general:debug)."); return; }
    setDissection(*d);
}

void MonoDissectorWindow::applyFilter(const QString& text) {
    const QString needle = text.trimmed();
    for (int i = 0; i < tree_->topLevelItemCount(); ++i) {
        QTreeWidgetItem* img = tree_->topLevelItem(i);
        bool imgVisible = false;
        for (int j = 0; j < img->childCount(); ++j) {
            QTreeWidgetItem* cls = img->child(j);
            // A class matches if its own name matches or any field name matches.
            bool clsMatch = needle.isEmpty() ||
                cls->text(0).contains(needle, Qt::CaseInsensitive);
            bool anyField = clsMatch;
            for (int k = 0; k < cls->childCount(); ++k) {
                bool fMatch = needle.isEmpty() ||
                    cls->child(k)->text(0).contains(needle, Qt::CaseInsensitive);
                cls->child(k)->setHidden(!clsMatch && !fMatch);
                anyField = anyField || fMatch;
            }
            cls->setHidden(!anyField);
            imgVisible = imgVisible || anyField;
        }
        img->setHidden(!imgVisible);
    }
}

} // namespace ce::gui
