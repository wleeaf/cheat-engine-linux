#include "gui/peinfo.hpp"

#include "analysis/pe_exports.hpp"
#include "platform/process_api.hpp"

#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenu>
#include <QPushButton>
#include <QRadioButton>
#include <QSplitter>
#include <QTabWidget>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <functional>

namespace ce::gui {

namespace {
constexpr int kBaseRole = Qt::UserRole + 1;
constexpr int kPathRole = Qt::UserRole + 2;

QString hex(uint64_t value, int width = 0) {
    return QString("%1").arg(static_cast<qulonglong>(value), width, 16, QChar('0')).toUpper();
}

// IMAGE_DIRECTORY_ENTRY_* names, in order.
const char* const kDirectoryNames[] = {
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Export"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Import"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Resource"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Exception"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Security"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Base relocation"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Debug"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Architecture"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Global pointer"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "TLS"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Load config"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Bound import"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "IAT"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Delay import"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "COM descriptor"),
    QT_TRANSLATE_NOOP("ce::gui::PEInfoWindow", "Reserved")};

QString machineName(uint16_t machine) {
    switch (machine) {
        case 0x14c: return "i386";
        case 0x8664: return "x86-64";
        case 0xaa64: return "ARM64";
        case 0xa641: return "ARM64EC";
        case 0x1c0: case 0x1c4: return "ARM";
        default: return hex(machine, 4);
    }
}

QString sectionFlags(uint32_t characteristics) {
    QString flags;
    flags += characteristics & 0x40000000 ? 'R' : '-';
    flags += characteristics & 0x80000000 ? 'W' : '-';
    flags += characteristics & 0x20000000 ? 'X' : '-';
    return flags;
}
} // namespace

PEInfoWindow::PEInfoWindow(ProcessHandle* process, QWidget* parent) : QMainWindow(parent), process_(process) {
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(tr("Portable Executable (PE) Info"));
    auto* central = new QWidget(this);
    auto* layout = new QHBoxLayout(central);
    auto* splitter = new QSplitter(central);

    auto* left = new QWidget(splitter);
    auto* leftLayout = new QVBoxLayout(left);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    auto* modeRow = new QHBoxLayout;
    fileMode_ = new QRadioButton(tr("File"), left);
    memoryMode_ = new QRadioButton(tr("Memory"), left);
    memoryMode_->setChecked(true);
    modeRow->addWidget(fileMode_);
    modeRow->addWidget(memoryMode_);
    leftLayout->addLayout(modeRow);
    modules_ = new QListWidget(left);
    leftLayout->addWidget(modules_, 1);
    auto* addressRow = new QHBoxLayout;
    addressRow->addWidget(new QLabel(tr("MZ-Start"), left));
    address_ = new QLineEdit(left);
    address_->setPlaceholderText(tr("address"));
    addressRow->addWidget(address_, 1);
    leftLayout->addLayout(addressRow);
    auto* buttons = new QHBoxLayout;
    auto* infoButton = new QPushButton(tr("Info"), left);
    auto* openButton = new QPushButton(tr("Open file..."), left);
    buttons->addWidget(infoButton);
    buttons->addWidget(openButton);
    leftLayout->addLayout(buttons);

    auto* right = new QWidget(splitter);
    auto* rightLayout = new QVBoxLayout(right);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    status_ = new QLabel(tr("No file opened"), right);
    rightLayout->addWidget(status_);
    tabs_ = new QTabWidget(right);
    all_ = new QTreeWidget(tabs_);
    all_->setHeaderHidden(true);
    imports_ = new QListWidget(tabs_);
    exports_ = new QListWidget(tabs_);
    relocations_ = new QListWidget(tabs_);
    tabs_->addTab(all_, tr("All"));
    tabs_->addTab(imports_, tr("Imports"));
    tabs_->addTab(exports_, tr("Exports"));
    tabs_->addTab(relocations_, tr("Base Relocations"));
    for (QWidget* view : std::initializer_list<QWidget*>{all_, imports_, exports_, relocations_}) {
        view->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(view, &QWidget::customContextMenuRequested, this, [this, view](const QPoint& pos) {
            QMenu menu(this);
            menu.addAction(tr("Copy tab to clipboard"), [this]() {
                QApplication::clipboard()->setText(tabText(tabs_->currentIndex()));
            });
            menu.addAction(tr("Copy everything to clipboard"), [this]() {
                QApplication::clipboard()->setText(allTextForTest());
            });
            menu.exec(view->mapToGlobal(pos));
        });
    }
    rightLayout->addWidget(tabs_, 1);
    splitter->setStretchFactor(1, 3);
    layout->addWidget(splitter);
    setCentralWidget(central);
    resize(900, 560);

    connect(modules_, &QListWidget::currentItemChanged, this, [this](QListWidgetItem* item) {
        if (item) address_->setText(hex(item->data(kBaseRole).toULongLong()));
    });
    connect(modules_, &QListWidget::itemDoubleClicked, infoButton, &QPushButton::click);
    connect(infoButton, &QPushButton::clicked, this, [this]() {
        auto* item = modules_->currentItem();
        const QString path = item ? item->data(kPathRole).toString() : QString();
        if (fileMode_->isChecked()) {
            if (!path.isEmpty()) showFile(path);
            return;
        }
        bool ok = false;
        const uintptr_t base = address_->text().trimmed().toULongLong(&ok, 16);
        if (ok) showMemory(base, item && item->data(kBaseRole).toULongLong() == base ? path : QString());
    });
    connect(openButton, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getOpenFileName(this, tr("Open a PE file"), QString(),
                                                          tr("Windows modules (*.exe *.dll *.sys);;All files (*)"));
        if (!path.isEmpty()) { fileMode_->setChecked(true); showFile(path); }
    });
    loadModules();
}

void PEInfoWindow::loadModules() {
    modules_->clear();
    if (!process_) return;
    for (const auto& module : process_->modules()) {
        const QString path = QString::fromStdString(module.path);
        const QString lower = path.toLower();
        if (!lower.endsWith(".dll") && !lower.endsWith(".exe") && !lower.endsWith(".sys")) continue;
        auto* item = new QListWidgetItem(QString("%1  %2").arg(hex(module.base), QString::fromStdString(module.name)),
                                         modules_);
        item->setData(kBaseRole, static_cast<qulonglong>(module.base));
        item->setData(kPathRole, path);
    }
}

bool PEInfoWindow::showFile(const QString& path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        status_->setText(tr("Could not open %1: %2").arg(path, file.errorString()));
        return false;
    }
    showInfo(file.read(64 * 1024), path, path);
    return all_->topLevelItemCount() > 0;
}

bool PEInfoWindow::showMemory(uintptr_t base, const QString& path) {
    if (!process_) return false;
    QByteArray header(4096, '\0');
    auto read = process_->read(base, header.data(), static_cast<size_t>(header.size()));
    if (!read || *read < 0x40) {
        status_->setText(tr("Could not read the memory at %1").arg(hex(base)));
        return false;
    }
    header.resize(static_cast<qsizetype>(*read));
    showInfo(header, path, tr("%1 (memory)").arg(hex(base)));
    return all_->topLevelItemCount() > 0;
}

void PEInfoWindow::showInfo(const QByteArray& header, const QString& path, const QString& title) {
    all_->clear();
    imports_->clear();
    exports_->clear();
    relocations_->clear();
    const auto info = parsePEHeaderInfo(
        std::span(reinterpret_cast<const uint8_t*>(header.constData()), static_cast<size_t>(header.size())));
    if (!info) {
        status_->setText(tr("%1 is not a PE image").arg(title));
        return;
    }
    status_->setText(title);
    auto add = [](QTreeWidgetItem* parent, const QString& text) { return new QTreeWidgetItem(parent, {text}); };
    auto* root = new QTreeWidgetItem(all_, {info->pe32Plus ? "PE32+" : "PE32"});
    auto* coff = add(root, tr("File header"));
    add(coff, tr("Machine: %1").arg(machineName(info->machine)));
    add(coff, tr("Sections: %1").arg(info->sections.size()));
    add(coff, tr("Time stamp: %1").arg(hex(info->timestamp, 8)));
    add(coff, tr("Characteristics: %1").arg(hex(info->characteristics, 4)));
    auto* optional = add(root, tr("Optional header"));
    add(optional, tr("Entry point: %1").arg(hex(info->entryPoint)));
    add(optional, tr("Image base: %1").arg(hex(info->imageBase)));
    add(optional, tr("Size of image: %1").arg(hex(info->sizeOfImage)));
    add(optional, tr("Size of headers: %1").arg(hex(info->sizeOfHeaders)));
    add(optional, tr("Checksum: %1").arg(hex(info->checksum, 8)));
    add(optional, tr("Subsystem: %1").arg(info->subsystem));
    add(optional, tr("DLL characteristics: %1").arg(hex(info->dllCharacteristics, 4)));
    auto* directories = add(root, tr("Data directories"));
    for (size_t i = 0; i < info->directories.size(); ++i) {
        const auto [rva, size] = info->directories[i];
        if (!rva && !size) continue;
        add(directories, tr("%1: %2 (%3 bytes)").arg(tr(kDirectoryNames[i]), hex(rva)).arg(size));
    }
    auto* sections = add(root, tr("Sections"));
    for (const auto& section : info->sections)
        add(sections, tr("%1  rva %2  size %3  raw %4+%5  %6")
                          .arg(QString::fromStdString(section.name), -8)
                          .arg(hex(section.rva), hex(section.virtualSize), hex(section.rawOffset), hex(section.rawSize),
                               sectionFlags(section.characteristics)));
    all_->expandAll();

    // Imports, exports and relocations come from the file.
    if (path.isEmpty() || !QFileInfo(path).isFile()) return;
    const std::string file = path.toStdString();
    for (const auto& import : parsePEImports(file))
        imports_->addItem(tr("%1  %2  (IAT %3)")
                              .arg(QString::fromStdString(import.dll),
                                   import.name.empty() ? QString("#%1").arg(import.ordinal) : QString::fromStdString(import.name),
                                   hex(import.iatRva)));
    for (const auto& exported : parsePEExports(file))
        exports_->addItem(QString("%1  %2%3")
                              .arg(hex(exported.rva, 8),
                                   exported.name.empty() ? QString("#%1").arg(exported.ordinal) : QString::fromStdString(exported.name),
                                   exported.forward.empty() ? QString() : " -> " + QString::fromStdString(exported.forward)));
    for (const auto& relocation : parsePERelocations(file))
        relocations_->addItem(tr("%1  type %2").arg(hex(relocation.rva, 8)).arg(relocation.type));
}

QString PEInfoWindow::tabText(int tab) const {
    QStringList lines;
    if (tab == 0) {
        std::function<void(QTreeWidgetItem*, int)> walk = [&](QTreeWidgetItem* item, int depth) {
            lines << QString(depth * 2, ' ') + item->text(0);
            for (int i = 0; i < item->childCount(); ++i) walk(item->child(i), depth + 1);
        };
        for (int i = 0; i < all_->topLevelItemCount(); ++i) walk(all_->topLevelItem(i), 0);
    } else {
        auto* list = qobject_cast<QListWidget*>(tabs_->widget(tab));
        for (int i = 0; list && i < list->count(); ++i) lines << list->item(i)->text();
    }
    return lines.join('\n');
}

QString PEInfoWindow::allTextForTest() const {
    QStringList parts;
    for (int tab = 0; tab < tabs_->count(); ++tab) parts << "[" + tabs_->tabText(tab) + "]" << tabText(tab);
    return parts.join('\n');
}

} // namespace ce::gui
