#include "gui/monodissector.hpp"

#include <QApplication>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QToolBar>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QWidget>

namespace ce::gui {

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
