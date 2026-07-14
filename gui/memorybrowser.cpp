#include "gui/memorybrowser.hpp"
#include "gui/memviewpreferences.hpp"
#include "core/injection_gen.hpp"
#include "arch/assembler.hpp"
#include "analysis/code_analysis.hpp"
#include "core/expression.hpp"

#include <QPainter>
#include <QDialog>
#include <QTableWidget>
#include <QHeaderView>
#include <QScrollBar>
#include <QKeyEvent>
#include <QWheelEvent>
#include <QMouseEvent>
#include <QContextMenuEvent>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QInputDialog>
#include <QFileDialog>
#include <QMessageBox>
#include <QApplication>
#include <QClipboard>
#include <QMenu>
#include <QToolButton>
#include <QStatusBar>
#include <QSettings>
#include <QFontMetrics>
#include <QShortcut>
#include <QFile>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <sstream>

namespace ce::gui {

// Effective address of an instruction's RIP-relative memory operand (or 0).
static uintptr_t ripEffectiveAddress(const ce::Instruction& inst);

// ═══════════════════════════════════════════════════════════════
// HexView
// ═══════════════════════════════════════════════════════════════

HexView::HexView(QWidget* parent) : QAbstractScrollArea(parent) {
    setFont(monoFont_);
    QFontMetrics fm(monoFont_);
    charW_ = fm.horizontalAdvance('0');
    charH_ = fm.height();
    setMinimumHeight(charH_ * 8);
    viewport()->setCursor(Qt::IBeamCursor);
    setFocusPolicy(Qt::StrongFocus);
}

uintptr_t HexView::cursorAddress() const {
    if (selectedOffset_ < 0) return address_;
    return address_ + (uintptr_t)selectedOffset_;
}

static int hexGroupBytes(HexView::DisplayType t);
static int hexGroupChars(HexView::DisplayType t);

// Pixel width of the hex column for the current display type. Single source of
// truth for paintEvent, byteOffsetAt, and mousePressEvent — they must agree or the
// ASCII-column boundary and click hit-testing drift apart in grouped modes.
int HexView::hexColWidth() const {
    return (displayType_ == DisplayType::Byte)
        ? charW_ * 3 * bytesPerRow_ + charW_
        : (bytesPerRow_ / hexGroupBytes(displayType_)) * charW_ * (hexGroupChars(displayType_) + 1);
}

int HexView::byteOffsetAt(QPoint p) const {
    if (charW_ <= 0 || charH_ <= 0) return -1;
    int row = p.y() / charH_;
    if (row < 0) return -1;
    int addrColW = charW_ * 18;
    int hexColW = hexColWidth();
    int x = p.x();
    if (x < addrColW) return -1;
    // Hex column: 3 chars per byte (byte mode) or one field per N-byte group.
    int col = -1;
    if (x < addrColW + hexColW) {
        x -= addrColW;
        if (displayType_ != DisplayType::Byte) {
            int fieldW = charW_ * (hexGroupChars(displayType_) + 1);
            int g = fieldW > 0 ? x / fieldW : 0;
            col = g * hexGroupBytes(displayType_);   // group's first byte
            if (col >= bytesPerRow_) col = -1;
        } else
        // Reverse-map x into a byte column. Each byte takes 3*charW_; the gap before col 8 adds charW_.
        for (int c = 0; c < bytesPerRow_; ++c) {
            int colStart = c * 3 * charW_ + (c >= 8 ? charW_ : 0);
            int colEnd = colStart + 3 * charW_;
            if (x >= colStart && x < colEnd) { col = c; break; }
        }
    } else {
        int asciiX = addrColW + hexColW + charW_;
        if (x >= asciiX) {
            int c = (x - asciiX) / charW_;
            if (c >= 0 && c < bytesPerRow_) col = c;
        }
    }
    if (col < 0) return -1;
    int offset = row * bytesPerRow_ + col;
    if (offset >= (int)cache_.size()) return -1;
    return offset;
}

void HexView::mousePressEvent(QMouseEvent* e) {
    QPoint pt = e->position().toPoint();
    int off = byteOffsetAt(pt);
    if (off >= 0) {
        selectedOffset_ = off;
        editNibble_ = 0;   // fresh byte, edit high nibble first
        // Editing happens in whichever column was clicked: hex digits vs. chars.
        // The hex column width must match byteOffsetAt/paintEvent for the current
        // display type, or the ASCII-column boundary is wrong in grouped modes.
        int addrColW = charW_ * 18;
        int hexColW = hexColWidth();
        editAscii_ = pt.x() >= addrColW + hexColW + charW_;
        viewport()->update();
        emit cursorMoved(address_ + (uintptr_t)off);
    }
    QAbstractScrollArea::mousePressEvent(e);
}

void HexView::contextMenuEvent(QContextMenuEvent* e) {
    int off = byteOffsetAt(e->pos());
    if (off >= 0) selectedOffset_ = off;
    viewport()->update();

    uintptr_t addr = (selectedOffset_ >= 0) ? address_ + selectedOffset_ : address_;
    // Capture the byte by value: the auto-refresh timer can resize cache_ or
    // reset selectedOffset_ while menu.exec() runs, so re-reading it in the
    // handler afterwards would be out-of-bounds.
    bool haveByte = selectedOffset_ >= 0 && selectedOffset_ < (int)cache_.size();
    uint8_t selByte = haveByte ? cache_[selectedOffset_] : 0;

    QMenu menu(this);
    menu.addAction(QString("Address: 0x%1").arg(addr, 16, 16, QChar('0')))->setEnabled(false);
    menu.addSeparator();

    auto* copyAddr = menu.addAction("Copy address");
    auto* copyByte = haveByte
        ? menu.addAction(QString("Copy byte (0x%1)").arg(selByte, 2, 16, QChar('0')))
        : nullptr;
    auto* gotoAct = menu.addAction("Goto…");
    auto* followPtr = menu.addAction("Follow pointer here (qword)");

    menu.addSeparator();
    auto* findWrites = menu.addAction("Find what writes this address");
    auto* findAccesses = menu.addAction("Find what accesses this address");

    // Bytes-per-row display option (CE's memory-view width). bytesPerRow_
    // parameterizes paint/hit-testing/refresh, so changing it adapts everything.
    menu.addSeparator();
    auto* bprMenu = menu.addMenu("Bytes per row");
    for (int n : {8, 16, 32}) {
        auto* a = bprMenu->addAction(QString::number(n));
        a->setCheckable(true);
        a->setChecked(bytesPerRow_ == n);
        connect(a, &QAction::triggered, this, [this, n]() {
            bytesPerRow_ = n;
            selectedOffset_ = -1;
            updateScrollBar();
            refresh();
        });
    }

    // Display type (CE's "Display as"): interpret the grid as byte/word/dword/etc.
    auto* dtMenu = menu.addMenu("Display type");
    const std::pair<const char*, DisplayType> dtChoices[] = {
        {"Byte", DisplayType::Byte}, {"Word (2)", DisplayType::Word},
        {"Dword (4)", DisplayType::Dword}, {"Qword (8)", DisplayType::Qword},
        {"Float", DisplayType::Float}, {"Double", DisplayType::Double},
    };
    for (auto& [name, dt] : dtChoices) {
        auto* a = dtMenu->addAction(name);
        a->setCheckable(true);
        a->setChecked(displayType_ == dt);
        connect(a, &QAction::triggered, this, [this, dt]() { setDisplayType(dt); });
    }

    QAction* picked = menu.exec(e->globalPos());
    if (!picked) return;

    auto* clip = QApplication::clipboard();
    if (picked == copyAddr) {
        clip->setText(QString("0x%1").arg(addr, 0, 16));
    } else if (copyByte && picked == copyByte) {
        clip->setText(QString("%1").arg(selByte, 2, 16, QChar('0')));
    } else if (picked == gotoAct) {
        emit requestGoto(addr);
    } else if (picked == followPtr) {
        // Read the 8-byte value under the cursor and jump both views to where it
        // points — manual pointer traversal, like CE's memory view.
        uint64_t ptr = 0;
        if (proc_) {
            auto r = proc_->read(addr, &ptr, sizeof(ptr));
            if (r && *r >= sizeof(ptr) && ptr) emit requestGoto((uintptr_t)ptr);
        }
    } else if (picked == findWrites) {
        emit requestFindWhatAccesses(addr, /*writesOnly=*/true);
    } else if (picked == findAccesses) {
        emit requestFindWhatAccesses(addr, /*writesOnly=*/false);
    }
}

void HexView::setAddress(uintptr_t addr) {
    address_ = addr & ~0xFULL; // Align to 16
    refresh();
}

int HexView::visibleRows() const {
    return viewport()->height() / charH_;
}

void HexView::updateScrollBar() {
    verticalScrollBar()->setRange(0, 0xFFFF);
    verticalScrollBar()->setPageStep(visibleRows());
}

void HexView::refresh() {
    int rows = visibleRows() + 1;
    size_t total = rows * bytesPerRow_;
    cache_.resize(total);
    if (proc_) {
        auto r = proc_->read(address_, cache_.data(), total);
        // Zero any bytes not actually read (partial read or failure) so the
        // grid never renders stale data past the readable end of the region.
        size_t got = r ? *r : 0;
        if (got < cache_.size())
            std::fill(cache_.begin() + got, cache_.end(), 0);
    } else {
        std::fill(cache_.begin(), cache_.end(), 0);
    }
    // cache_ may have shrunk (window resized smaller); drop a now-stale selection
    // so the context menu does not dereference past the end of cache_.
    if (selectedOffset_ >= (int)cache_.size()) selectedOffset_ = -1;
    viewport()->update();
}

void HexView::resizeEvent(QResizeEvent* e) {
    QAbstractScrollArea::resizeEvent(e);
    updateScrollBar();
    refresh();
}

static int hexGroupBytes(HexView::DisplayType t) {
    switch (t) {
        case HexView::DisplayType::Word:  return 2;
        case HexView::DisplayType::Dword: case HexView::DisplayType::Float:  return 4;
        case HexView::DisplayType::Qword: case HexView::DisplayType::Double: return 8;
        default: return 1;
    }
}

static int hexGroupChars(HexView::DisplayType t) {
    switch (t) {
        case HexView::DisplayType::Word:   return 4;
        case HexView::DisplayType::Dword:  return 8;
        case HexView::DisplayType::Qword:  return 16;
        case HexView::DisplayType::Float:  return 14;   // e.g. "-1.234568e+10"
        case HexView::DisplayType::Double: return 18;
        default: return 2;
    }
}

// Format `bytes` (little-endian) as one display value for the current type.
static QString formatHexGroup(const uint8_t* bytes, HexView::DisplayType t) {
    switch (t) {
        case HexView::DisplayType::Word:  { uint16_t v; std::memcpy(&v, bytes, 2); return QString("%1").arg(v, 4, 16, QChar('0')); }
        case HexView::DisplayType::Dword: { uint32_t v; std::memcpy(&v, bytes, 4); return QString("%1").arg(v, 8, 16, QChar('0')); }
        case HexView::DisplayType::Qword: { quint64 v; std::memcpy(&v, bytes, 8); return QString("%1").arg(v, 16, 16, QChar('0')); }
        case HexView::DisplayType::Float: { float v;  std::memcpy(&v, bytes, 4); return QString::number(v, 'g', 6); }
        case HexView::DisplayType::Double:{ double v; std::memcpy(&v, bytes, 8); return QString::number(v, 'g', 8); }
        default: { return QString("%1").arg(bytes[0], 2, 16, QChar('0')); }
    }
}

void HexView::paintEvent(QPaintEvent*) {
    QPainter p(viewport());
    p.setFont(monoFont_);

    int rows = visibleRows();
    int addrColW = charW_ * 18;     // "0x0000000000000000"
    int hexColW = hexColWidth();
    int asciiX = addrColW + hexColW + charW_;

    // Background
    p.fillRect(viewport()->rect(), QColor(0x1e, 0x1e, 0x2e)); // Dark background
    p.setPen(QColor(0x89, 0xb4, 0xfa)); // Address color

    for (int row = 0; row < rows && row * bytesPerRow_ < (int)cache_.size(); ++row) {
        int y = (row + 1) * charH_;
        uintptr_t rowAddr = address_ + row * bytesPerRow_;

        // Address
        p.setPen(QColor(0x89, 0xb4, 0xfa));   // HexView address column
        p.drawText(0, y, QString("%1").arg(rowAddr, 16, 16, QChar('0')));

        // Hex bytes. Byte mode keeps the classic per-byte grid (with edit cursor
        // and zero-dimming); wider display types group N bytes into one value.
        if (displayType_ == DisplayType::Byte) {
            for (int col = 0; col < bytesPerRow_; ++col) {
                int idx = row * bytesPerRow_ + col;
                if (idx >= (int)cache_.size()) break;
                uint8_t b = cache_[idx];

                int x = addrColW + col * charW_ * 3;
                if (col == 8) x += charW_; // gap in middle

                // Selection highlight on the selected byte.
                if (idx == selectedOffset_) {
                    p.fillRect(x - 1, y - charH_ + 2, charW_ * 2 + 2, charH_,
                               QColor(0x45, 0x47, 0x5a));
                }

                p.setPen(b == 0 ? QColor(0x58, 0x5b, 0x70) : QColor(0xcd, 0xd6, 0xf4));
                p.drawText(x, y, QString("%1").arg(b, 2, 16, QChar('0')));
            }
        } else {
            int gsize = hexGroupBytes(displayType_);
            int fieldW = charW_ * (hexGroupChars(displayType_) + 1);
            p.setPen(QColor(0xcd, 0xd6, 0xf4));
            for (int g = 0; g * gsize < bytesPerRow_; ++g) {
                int idx = row * bytesPerRow_ + g * gsize;
                if (idx + gsize > (int)cache_.size()) break;
                p.drawText(addrColW + g * fieldW, y, formatHexGroup(&cache_[idx], displayType_));
            }
        }

        // ASCII
        p.setPen(QColor(0xa6, 0xad, 0xc8));
        for (int col = 0; col < bytesPerRow_; ++col) {
            int idx = row * bytesPerRow_ + col;
            if (idx >= (int)cache_.size()) break;
            uint8_t b = cache_[idx];
            char c = (b >= 32 && b < 127) ? (char)b : '.';
            p.drawText(asciiX + col * charW_, y, QString(QChar(c)));
        }
    }
}

bool HexView::pokeByte(uintptr_t addr, uint8_t value) {
    if (!proc_) return false;
    auto r = proc_->write(addr, &value, 1);
    if (!r || *r < 1) {
        // r-x / read-only page — make it writable and retry (same as the disasm).
        proc_->protect(addr, 1, ce::MemProt::All);
        r = proc_->write(addr, &value, 1);
        if (!r || *r < 1) return false;
    }
    return true;
}

void HexView::keyPressEvent(QKeyEvent* e) {
    int rows = visibleRows();
    QString t = e->text();
    // ASCII-column editing: typing a printable character overwrites the byte.
    if (editAscii_ && selectedOffset_ >= 0 && selectedOffset_ < (int)cache_.size() &&
        t.size() == 1) {
        char c = t[0].toLatin1();
        if (c >= 0x20 && c < 0x7f) {
            if (pokeByte(address_ + (uintptr_t)selectedOffset_, (uint8_t)c)) {
                cache_[selectedOffset_] = (uint8_t)c;
                if (selectedOffset_ + 1 < (int)cache_.size()) ++selectedOffset_;
            }
            viewport()->update();
            return;
        }
    }

    // In-place hex editing: with a byte selected, typing a hex digit edits the
    // high then low nibble (CE-style), writing to the target and advancing.
    if (!editAscii_ && selectedOffset_ >= 0 && selectedOffset_ < (int)cache_.size() &&
        t.size() == 1 && std::isxdigit((unsigned char)t[0].toLatin1())) {
        int digit = QString(t).toInt(nullptr, 16);
        uint8_t cur = cache_[selectedOffset_];
        uint8_t nb = editNibble_ == 0 ? (uint8_t)((digit << 4) | (cur & 0x0F))
                                      : (uint8_t)((cur & 0xF0) | digit);
        uintptr_t target = address_ + (uintptr_t)selectedOffset_;
        if (pokeByte(target, nb)) {
            cache_[selectedOffset_] = nb;
            if (editNibble_ == 0) {
                editNibble_ = 1;                       // stay, edit low nibble next
            } else {
                editNibble_ = 0;
                if (selectedOffset_ + 1 < (int)cache_.size()) ++selectedOffset_;  // advance
            }
        }
        viewport()->update();
        return;
    }

    if (e->key() == Qt::Key_Left)  { if (selectedOffset_ > 0) { --selectedOffset_; editNibble_ = 0; viewport()->update(); } }
    else if (e->key() == Qt::Key_Right) { if (selectedOffset_ >= 0 && selectedOffset_ + 1 < (int)cache_.size()) { ++selectedOffset_; editNibble_ = 0; viewport()->update(); } }
    else if (e->key() == Qt::Key_Down) { address_ += bytesPerRow_; editNibble_ = 0; refresh(); }
    else if (e->key() == Qt::Key_Up) { address_ -= bytesPerRow_; editNibble_ = 0; refresh(); }
    else if (e->key() == Qt::Key_PageDown) { address_ += rows * bytesPerRow_; editNibble_ = 0; refresh(); }
    else if (e->key() == Qt::Key_PageUp) { address_ -= rows * bytesPerRow_; editNibble_ = 0; refresh(); }
    else QAbstractScrollArea::keyPressEvent(e);
}

void HexView::wheelEvent(QWheelEvent* e) {
    int delta = e->angleDelta().y() / 120;
    address_ -= delta * bytesPerRow_ * 3;
    refresh();
}

// ═══════════════════════════════════════════════════════════════
// DisasmView
// ═══════════════════════════════════════════════════════════════

void DisasmView::reloadPreferences() {
    QSettings s;
    monoFont_.fromString(s.value("disasm/font", QFont("Monospace", 10).toString()).toString());
    setFont(monoFont_);
    QFontMetrics fm(monoFont_);
    charW_ = fm.horizontalAdvance('0');
    charH_ = fm.height();
    gutterW_ = charH_;  // square red dot column
    auto col = [&s](const char* key, QColor def) {
        return QColor(s.value(QString("disasm/") + key, def.name()).toString());
    };
    defaultColor_  = col("colorDefault",  QColor(0xcd, 0xd6, 0xf4));
    addrColor_     = col("colorHex",      QColor(0x89, 0xb4, 0xfa));
    condJumpColor_ = col("colorCondJump", QColor(0xfa, 0xb3, 0x87));
    jumpColor_     = col("colorJump",     QColor(0x89, 0xb4, 0xfa));
    viewport()->update();
}

DisasmView::DisasmView(QWidget* parent) : QAbstractScrollArea(parent) {
    reloadPreferences();
    setMinimumHeight(charH_ * 8);
    setFocusPolicy(Qt::StrongFocus);
    viewport()->setMouseTracking(true);
}

uintptr_t DisasmView::selectedAddress() const {
    if (selectedRow_ < 0 || selectedRow_ >= (int)instructions_.size()) return 0;
    return instructions_[selectedRow_].address;
}

int DisasmView::selectedSize() const {
    if (selectedRow_ < 0 || selectedRow_ >= (int)instructions_.size()) return 0;
    return (int)instructions_[selectedRow_].size;
}

int DisasmView::rowAtY(int y) const {
    if (charH_ <= 0) return -1;
    int row = y / charH_;
    if (row < 0 || row >= (int)instructions_.size()) return -1;
    return row;
}

uintptr_t DisasmView::parseImmediate(const std::string& operands) {
    // Only DIRECT branches carry an absolute immediate target ("jmp 0x401234").
    // An indirect branch is a memory/register operand ("call qword ptr
    // [rip + 0x2ed3]", "jmp [rax]"): its hex is a displacement, not a target, so
    // bail and let the caller follow the effective data address instead.
    if (operands.find('[') != std::string::npos) return 0;
    // Capstone yields targets like "0x401234" for direct branches; pull the first hex literal.
    auto pos = operands.find("0x");
    if (pos == std::string::npos) return 0;
    try {
        return (uintptr_t)std::stoull(operands.substr(pos + 2), nullptr, 16);
    } catch (...) {
        return 0;
    }
}

void DisasmView::mousePressEvent(QMouseEvent* e) {
    int row = rowAtY(e->position().toPoint().y());
    if (row < 0) {
        QAbstractScrollArea::mousePressEvent(e);
        return;
    }

    if (e->button() == Qt::LeftButton && e->position().toPoint().x() < gutterW_) {
        // Click in gutter — toggle SW BP.
        uintptr_t addr = instructions_[row].address;
        if (breakpoints_.count(addr))
            emit requestRemoveBreakpoint(addr);
        else
            emit requestSetSoftBreakpoint(addr);
        // Don't change selection on gutter clicks.
        return;
    }

    selectedRow_ = row;
    viewport()->update();
    QAbstractScrollArea::mousePressEvent(e);
}

bool DisasmView::followRow(int row) {
    if (row < 0 || row >= (int)instructions_.size()) return false;
    const auto& inst = instructions_[row];
    // Branch target (call/jmp/jcc) → follow to the code.
    if (inst.mnemonic == "call" || inst.mnemonic == "jmp" ||
        (inst.mnemonic.size() > 1 && inst.mnemonic[0] == 'j')) {
        uintptr_t target = parseImmediate(inst.operands);
        if (target) {
            setAddress(target);
            emit addressChanged(target);
            return true;
        }
    }
    // Otherwise, a RIP-relative data reference → follow to the data address.
    if (uintptr_t eff = ripEffectiveAddress(inst)) {
        setAddress(eff);
        emit addressChanged(eff);
        return true;
    }
    return false;
}

void DisasmView::mouseDoubleClickEvent(QMouseEvent* e) {
    if (followRow(rowAtY(e->position().toPoint().y()))) return;
    QAbstractScrollArea::mouseDoubleClickEvent(e);
}

void DisasmView::contextMenuEvent(QContextMenuEvent* e) {
    int row = rowAtY(e->pos().y());
    if (row < 0) return;
    selectedRow_ = row;
    viewport()->update();

    // Copy by value: the auto-refresh timer can re-disassemble (reallocating
    // instructions_) while menu.exec() runs its nested event loop, which would
    // dangle a reference and make the action handlers read garbage.
    const ce::Instruction inst = instructions_[row];
    QMenu menu(this);
    menu.addAction(QString("Address: 0x%1").arg(inst.address, 16, 16, QChar('0')))->setEnabled(false);
    menu.addSeparator();

    auto* copyAddr = menu.addAction("Copy address");
    auto* copyBytes = menu.addAction("Copy bytes");
    auto* copyLine = menu.addAction("Copy line");
    menu.addSeparator();

    QAction* followAct = nullptr;
    bool isBranch = inst.mnemonic == "call" || inst.mnemonic == "jmp" ||
                    (inst.mnemonic.size() > 1 && inst.mnemonic[0] == 'j');
    if ((isBranch && parseImmediate(inst.operands)) || ripEffectiveAddress(inst))
        followAct = menu.addAction("Follow operand");

    bool haveBp = breakpoints_.count(inst.address) > 0;
    QAction* setSwBp = nullptr;
    QAction* setHwBp = nullptr;
    QAction* removeBp = nullptr;
    if (haveBp) {
        removeBp = menu.addAction("Remove breakpoint");
    } else {
        setSwBp = menu.addAction("Set software breakpoint");
        setHwBp = menu.addAction("Set hardware exec breakpoint");
    }

    menu.addSeparator();
    auto* labelAct = menu.addAction("Label this address…");
    auto* commentAct = menu.addAction("Set comment…");
    auto* xrefAct = menu.addAction("Find references to this address");
    auto* asmAct = menu.addAction("Assemble instruction…");
    auto* nopAct = menu.addAction(QString("NOP this instruction (%1 byte%2)")
        .arg(inst.size).arg(inst.size == 1 ? "" : "s"));
    // Auto Assemble injection templates, pre-filled for the pointed-at instruction.
    auto* aaMenu = menu.addMenu("Auto Assemble");
    auto* codeInjAct = aaMenu->addAction("Create code injection here");
    auto* aobInjAct = aaMenu->addAction("Create AOB injection here");
    auto* saveAct = menu.addAction("Save region to file…");

    QAction* picked = menu.exec(e->globalPos());
    if (!picked) return;

    auto* clip = QApplication::clipboard();
    if (picked == copyAddr) {
        clip->setText(QString("0x%1").arg(inst.address, 0, 16));
    } else if (picked == copyBytes) {
        QString s;
        for (auto b : inst.bytes) s += QString("%1 ").arg(b, 2, 16, QChar('0'));
        clip->setText(s.trimmed());
    } else if (picked == copyLine) {
        QString bytes;
        for (auto b : inst.bytes) bytes += QString("%1 ").arg(b, 2, 16, QChar('0'));
        QString text = QString::fromStdString(inst.operands.empty()
            ? inst.mnemonic : inst.mnemonic + " " + inst.operands);
        clip->setText(QString("%1 - %2 - %3")
            .arg(inst.address, 0, 16).arg(bytes.trimmed(), text));
    } else if (picked == followAct) {
        // Branch → immediate target; otherwise the RIP-relative data address.
        uintptr_t target = isBranch ? parseImmediate(inst.operands) : ripEffectiveAddress(inst);
        if (target) { setAddress(target); emit addressChanged(target); }
    } else if (picked == setSwBp) {
        emit requestSetSoftBreakpoint(inst.address);
    } else if (picked == setHwBp) {
        emit requestSetHwExecBreakpoint(inst.address);
    } else if (picked == removeBp) {
        emit requestRemoveBreakpoint(inst.address);
    } else if (picked == labelAct) {
        emit requestSetSymbol(inst.address);
    } else if (picked == commentAct) {
        emit requestSetComment(inst.address);
    } else if (picked == xrefAct) {
        emit requestXrefs(inst.address);
    } else if (picked == asmAct) {
        emit requestAssemble(inst.address, (int)inst.size,
            QString::fromStdString(inst.operands.empty() ? inst.mnemonic
                                                         : inst.mnemonic + " " + inst.operands));
    } else if (picked == nopAct) {
        emit requestNop(inst.address, (int)inst.size);
    } else if (picked == codeInjAct) {
        emit requestInjection(inst.address, /*aob=*/false);
    } else if (picked == aobInjAct) {
        emit requestInjection(inst.address, /*aob=*/true);
    } else if (picked == saveAct) {
        emit requestSaveRegion(inst.address);
    }
}

void DisasmView::setAddress(uintptr_t addr) {
    address_ = addr;
    refresh();
}

int DisasmView::visibleRows() const {
    return viewport()->height() / charH_;
}

void DisasmView::resizeEvent(QResizeEvent* e) {
    QAbstractScrollArea::resizeEvent(e);
    refresh();
}

void DisasmView::refresh() {
    instructions_.clear();
    emptyReason_.clear();
    if (!proc_) { viewport()->update(); return; }

    int rows = visibleRows() + 5;
    std::vector<uint8_t> buf(rows * 15);
    auto r = proc_->read(address_, buf.data(), buf.size());
    if (!r || *r == 0) {
        // Explain the blank pane instead of leaving it empty. EPERM/EACCES means we
        // aren't allowed to ptrace this process (yama ptrace_scope) — the common
        // reason "browse memory" shows nothing for processes we didn't spawn.
        const bool denied = !r && (r.error() == std::errc::operation_not_permitted ||
                                   r.error() == std::errc::permission_denied);
        emptyReason_ = denied
            ? QStringLiteral("Cannot read this process's memory (permission denied).\n"
                             "Run Cheat Engine with ptrace rights: sudo setcap "
                             "cap_sys_ptrace+ep <cheatengine>, run as root, or set "
                             "kernel.yama.ptrace_scope=0.")
            : QStringLiteral("No readable memory at this address.");
        viewport()->update();
        return;
    }

    // emitDataBytes: undecodable bytes render as "db 0xXX" and disassembly
    // continues, so the pane never blanks out on data/obfuscated regions (CE-like).
    instructions_ = disasm_->disassemble(address_, {buf.data(), *r}, rows, /*emitDataBytes=*/true);
    viewport()->update();
}

// For an instruction with a RIP-relative operand ("[rip + 0x..]"), compute the
// effective address and annotate it with its symbol and the value it points at
// (as a string if printable, otherwise an int32) — CE-style inline comments.
// Effective address of an instruction's RIP-relative memory operand
// ("[rip + 0x..]"), or 0 if it has none.
static uintptr_t ripEffectiveAddress(const ce::Instruction& inst) {
    // The Disassembler now resolves RIP-relative operands and stores the absolute
    // effective address on the instruction (and rewrites the operand text to
    // "[0x<abs>]"), so read it directly rather than re-parsing "rip + disp".
    return inst.ripTarget;
}

static QString ripRefAnnotation(const ce::Instruction& inst,
                                ce::SymbolResolver* resolver,
                                ce::ProcessHandle* proc) {
    uintptr_t eff = ripEffectiveAddress(inst);
    if (!eff) return {};
    // The operand is already rewritten to "[0x<eff>]", so don't repeat the address;
    // annotate only with the extra info: the target symbol and the live value/string.
    QString a;
    if (resolver) {
        auto s = resolver->resolve(eff);
        if (!s.empty()) a += " " + QString::fromStdString(s);
    }
    if (proc) {
        uint8_t vb[24] = {};
        auto r = proc->read(eff, vb, sizeof(vb));
        if (r && *r >= 1) {
            size_t n = *r, printable = 0;
            for (size_t k = 0; k < n && vb[k]; ++k) {
                if (vb[k] >= 0x20 && vb[k] < 0x7f) ++printable; else break;
            }
            if (printable >= 3 && (printable == n || vb[printable] == 0)) {
                a += QString(" = \"%1\"").arg(QString::fromLatin1(
                    reinterpret_cast<const char*>(vb), static_cast<int>(printable)));
            } else if (n >= 8) {
                // If the target holds a pointer that resolves to a symbol (e.g. a
                // GOT slot holding a function pointer), follow it — CE-style.
                uintptr_t ptr; std::memcpy(&ptr, vb, 8);
                std::string ps = (resolver && ptr > 0x1000) ? resolver->resolve(ptr) : std::string();
                if (!ps.empty()) a += " -> " + QString::fromStdString(ps);
                else { int32_t iv; std::memcpy(&iv, vb, 4); a += QString(" = %1").arg(iv); }
            } else if (n >= 4) {
                int32_t iv; std::memcpy(&iv, vb, 4);
                a += QString(" = %1").arg(iv);
            }
        }
    }
    if (a.isEmpty()) return {};   // nothing beyond the address the operand already shows
    return " ;" + a;
}

void DisasmView::paintEvent(QPaintEvent*) {
    QPainter p(viewport());
    p.setFont(monoFont_);
    p.fillRect(viewport()->rect(), QColor(0x1e, 0x1e, 0x2e));

    // Nothing decoded: explain why rather than showing a blank pane.
    if (instructions_.empty()) {
        p.setPen(QColor(0xa6, 0xad, 0xc8));
        p.drawText(viewport()->rect().adjusted(24, 24, -24, -24),
                   Qt::AlignCenter | Qt::TextWordWrap,
                   emptyReason_.isEmpty() ? QStringLiteral("No data at this address.")
                                          : emptyReason_);
        return;
    }

    int arrowW = charW_ * 6;              // strip for jump/branch arrows
    int contentX = gutterW_ + arrowW;     // address/bytes/mnemonic start here
    int addrColW = charW_ * 18;
    int bytesColW = charW_ * 25;
    int mnemonicX = contentX + addrColW + bytesColW;

    // ── Jump/branch arrows ──
    // For each visible direct jmp/jcc whose target is also on screen, draw a
    // line in the arrow strip from the source row to the target row (with an
    // arrowhead at the target). Lanes are assigned greedily so nested/adjacent
    // arrows don't overlap. Unconditional jmp = blue, conditional = peach.
    {
        struct Arrow { int src, dst; bool cond; };
        std::vector<Arrow> arrows;
        int nvis = std::min((int)instructions_.size(), visibleRows());
        for (int i = 0; i < nvis; ++i) {
            const auto& in = instructions_[i];
            bool isJmp = in.mnemonic == "jmp";
            bool isCond = in.mnemonic.size() > 1 && in.mnemonic[0] == 'j' && !isJmp;
            if (!isJmp && !isCond) continue;
            uintptr_t t = parseImmediate(in.operands);
            if (!t) continue;
            int dst = -2;
            for (int d = 0; d < nvis; ++d)
                if (instructions_[d].address == t) { dst = d; break; }
            if (dst == -2 && nvis > 0) {
                // Target isn't an on-screen instruction: mark which edge it lies
                // beyond so we can draw an arrow running off the top/bottom (the
                // branch goes somewhere outside the visible window).
                if (t < instructions_[0].address)             dst = -1;    // off-top
                else if (t > instructions_[nvis - 1].address) dst = nvis;  // off-bottom
            }
            if (dst != -2)
                arrows.push_back({i, dst, isCond});
        }
        // Greedy lane assignment by ascending span.
        std::sort(arrows.begin(), arrows.end(), [](const Arrow& a, const Arrow& b) {
            return std::abs(a.src - a.dst) < std::abs(b.src - b.dst);
        });
        std::vector<std::vector<std::pair<int,int>>> lanes; // occupied [lo,hi] per lane
        auto laneOf = [&](int lo, int hi) {
            for (size_t L = 0; L < lanes.size(); ++L) {
                bool clash = false;
                for (auto& r : lanes[L]) if (!(hi < r.first || lo > r.second)) { clash = true; break; }
                if (!clash) { lanes[L].push_back({lo, hi}); return (int)L; }
            }
            lanes.push_back({{lo, hi}});
            return (int)lanes.size() - 1;
        };
        p.setRenderHint(QPainter::Antialiasing, true);
        for (auto& ar : arrows) {
            bool offTop = ar.dst < 0;
            bool offBottom = ar.dst >= nvis;
            int dstRow = offTop ? 0 : (offBottom ? nvis - 1 : ar.dst);
            int lo = std::min(ar.src, dstRow), hi = std::max(ar.src, dstRow);
            int lane = laneOf(lo, hi);
            int maxLane = std::max(0, arrowW / std::max(1, charW_) - 1);
            int laneX = contentX - 3 - std::min(lane, maxLane) * charW_;
            int ySrc = ar.src * charH_ + charH_ / 2;
            QColor col = ar.cond ? condJumpColor_ : jumpColor_;
            p.setPen(QPen(col, 1));
            p.drawLine(contentX - 2, ySrc, laneX, ySrc);   // out from source
            if (offTop || offBottom) {
                // Runs off the visible edge — arrowhead at the edge signals the
                // branch target lies beyond the window.
                int ay = offTop ? 0 : nvis * charH_;
                int wing = offTop ? 4 : -4;
                p.drawLine(laneX, ySrc, laneX, ay);            // vertical to the edge
                p.drawLine(laneX, ay, laneX - 3, ay + wing);
                p.drawLine(laneX, ay, laneX + 3, ay + wing);
            } else {
                int yDst = ar.dst * charH_ + charH_ / 2;
                p.drawLine(laneX, ySrc, laneX, yDst);          // vertical run
                p.drawLine(laneX, yDst, contentX - 2, yDst);   // in to target
                p.drawLine(contentX - 2, yDst, contentX - 6, yDst - 3);
                p.drawLine(contentX - 2, yDst, contentX - 6, yDst + 3);
            }
        }
        p.setRenderHint(QPainter::Antialiasing, false);
    }

    // If the selected instruction is a direct branch, find its on-screen target
    // row so we can tint it — shows where the selected jump/call lands (like CE).
    int targetRow = -1;
    if (selectedRow_ >= 0 && selectedRow_ < (int)instructions_.size()) {
        const auto& sel = instructions_[selectedRow_];
        bool selBranch = sel.mnemonic == "call" || sel.mnemonic == "jmp" ||
                         (sel.mnemonic.size() > 1 && sel.mnemonic[0] == 'j');
        uintptr_t t = selBranch ? parseImmediate(sel.operands) : 0;
        if (t)
            for (int d = 0; d < (int)instructions_.size() && d < visibleRows(); ++d)
                if (instructions_[d].address == t) { targetRow = d; break; }
    }

    std::string prevDwarfFunc;  // last DWARF function label drawn (once per function)
    for (int i = 0; i < (int)instructions_.size() && i < visibleRows(); ++i) {
        auto& inst = instructions_[i];
        int rowTop = i * charH_;
        int y = rowTop + charH_ - 2;  // text baseline

        // Selection highlight on this row (and a subtle tint on the selected
        // branch's target row so you can see where it goes).
        if (i == selectedRow_) {
            p.fillRect(0, rowTop, viewport()->width(), charH_, QColor(0x45, 0x47, 0x5a));
        } else if (i == targetRow) {
            p.fillRect(0, rowTop, viewport()->width(), charH_, QColor(0x2d, 0x40, 0x3a));
        }

        // Breakpoint glyph in the gutter.
        if (breakpoints_.count(inst.address)) {
            int margin = 3;
            p.setBrush(QColor(0xf3, 0x8b, 0xa8));
            p.setPen(Qt::NoPen);
            p.drawEllipse(margin, rowTop + margin, charH_ - 2 * margin, charH_ - 2 * margin);
        }

        // Symbol label (if this address has a symbol). Try the ELF symbol
        // table first; fall back to DWARF subprogram names for binaries
        // that were stripped of .symtab but still carry .debug_info.
        std::string rsym = resolver_ ? resolver_->resolve(inst.address) : std::string();
        if (!rsym.empty() && rsym.find('+') == std::string::npos) {
            p.setPen(QColor(0xf9, 0xe2, 0xaf));
            p.drawText(contentX, y, QString::fromStdString(rsym + ":"));
            continue;
        }
        // DWARF function label only when the resolver is clueless (stripped
        // module with debug info): functionName() returns the SAME name for every
        // address in the function, so guard on rsym-empty AND a name change to
        // emit one header per function — not one per instruction (which would
        // replace the whole disassembly with repeated "func:" lines).
        if (dwarf_ && rsym.empty()) {
            if (auto fn = dwarf_->functionName(inst.address); fn && !fn->empty()) {
                if (*fn != prevDwarfFunc) {
                    prevDwarfFunc = *fn;
                    p.setPen(QColor(0xf9, 0xe2, 0xaf));
                    p.drawText(contentX, y, QString::fromStdString(*fn + ":"));
                    continue;
                }
            }
        }

        // Address
        p.setPen(addrColor_);
        p.drawText(contentX, y, QString("%1").arg(inst.address, 16, 16, QChar('0')));

        // Bytes
        p.setPen(QColor(0x58, 0x5b, 0x70));
        QString bytes;
        for (auto b : inst.bytes) bytes += QString("%1 ").arg(b, 2, 16, QChar('0'));
        p.drawText(contentX + addrColW, y, bytes.left(24));

        // Mnemonic
        p.setPen(defaultColor_); // instruction text (Default color)
        p.drawText(mnemonicX, y, QString::fromStdString(inst.mnemonic));

        // Operands — try to annotate with symbol name
        auto operands = QString::fromStdString(inst.operands);
        QString annotation;
        if (resolver_ && (inst.mnemonic == "call" || inst.mnemonic == "jmp" || inst.mnemonic.substr(0, 1) == "j")) {
            uintptr_t target = parseImmediate(inst.operands);
            if (target) {
                auto sym = resolver_->resolve(target);
                if (!sym.empty()) annotation = " ; " + QString::fromStdString(sym);
            }
        }
        // RIP-relative data reference (mov/lea/cmp/…): show effective address,
        // symbol, and the value/string it points at.
        if (annotation.isEmpty())
            annotation = ripRefAnnotation(inst, resolver_, proc_);

        p.setPen(QColor(0xcd, 0xd6, 0xf4));
        int opX = mnemonicX + charW_ * 8;
        p.drawText(opX, y, operands);
        int endX = opX + p.fontMetrics().horizontalAdvance(operands);

        // User-defined comment first (green), immediately after the operands so
        // it's always visible even when an auto-annotation is long.
        if (auto cit = comments_.find(inst.address); cit != comments_.end()) {
            QString c = "  ; " + QString::fromStdString(cit->second);
            p.setPen(QColor(0xa6, 0xe3, 0xa1)); // Green for user comments
            p.drawText(endX, y, c);
            endX += p.fontMetrics().horizontalAdvance(c);
        }

        if (!annotation.isEmpty()) {
            p.setPen(QColor(0x6c, 0x70, 0x86)); // Dim for auto-annotations
            p.drawText(endX, y, annotation);
            endX += p.fontMetrics().horizontalAdvance(annotation);
        }

        // DWARF source-line annotation, appended after symbol annotation.
        if (dwarf_) {
            if (auto src = dwarf_->lookup(inst.address); src && src->line > 0) {
                QString srcAnno = QString("  ; %1:%2")
                    .arg(QString::fromStdString(src->file).section('/', -1))
                    .arg(src->line);
                p.setPen(QColor(0x94, 0xe2, 0xd5)); // Teal for source annotations
                p.drawText(endX, y, srcAnno);
                endX += p.fontMetrics().horizontalAdvance(srcAnno);
            }
        }
    }
}

// Try to find a valid instruction boundary `count` instructions before `addr`
uintptr_t DisasmView::scrollBack(uintptr_t addr, int count) {
    if (!proc_ || count <= 0) return addr;
    // Read a chunk before the address and disassemble forward to find boundaries.
    // x86 self-synchronises, so mid-section this aligns correctly.
    constexpr int LOOKBACK = 128;
    uintptr_t startAddr = (addr > LOOKBACK) ? addr - LOOKBACK : 0;
    size_t readSize = addr - startAddr;
    if (readSize > 0) {
        std::vector<uint8_t> buf(readSize);
        auto r = proc_->read(startAddr, buf.data(), readSize);
        if (r && *r > 0) {
            auto insns = disasm_->disassemble(startAddr, {buf.data(), *r}, 0);
            if (!insns.empty()) {
                int targetIdx = -1;
                for (int i = 0; i < (int)insns.size(); ++i)
                    if (insns[i].address >= addr) { targetIdx = i; break; }
                if (targetIdx < 0) targetIdx = insns.size();
                if (targetIdx > 0) {  // at least one instruction started before addr
                    int newIdx = targetIdx - count;
                    if (newIdx < 0) newIdx = 0;
                    return insns[newIdx].address;
                }
            }
        }
    }
    // Region boundary or unreadable lookback: step back one instruction at a time
    // with the bounded, region-safe previousInstruction (reads only each
    // candidate's own bytes, so it never touches unmapped memory before a section).
    uintptr_t a = addr;
    auto read = [&](uintptr_t p, uint8_t* b, size_t n) {
        auto rr = proc_->read(p, b, n);
        return rr && *rr >= n;
    };
    for (int i = 0; i < count && a > 0; ++i) {
        uintptr_t prev = disasm_->previousInstruction(a, read);
        if (prev >= a) break;
        a = prev;
    }
    return a;
}

void DisasmView::keyPressEvent(QKeyEvent* e) {
    if (e->key() == Qt::Key_Down && !instructions_.empty()) {
        // Move the selection cursor down (CE-style); scroll one instruction when
        // it's already at the bottom so the selection keeps advancing.
        int lastVisible = std::min((int)instructions_.size(), visibleRows()) - 1;
        if (selectedRow_ < 0) { selectedRow_ = 0; viewport()->update(); }
        else if (selectedRow_ < lastVisible) { selectedRow_++; viewport()->update(); }
        else { address_ = instructions_.size() > 1 ? instructions_[1].address : address_ + 1; refresh(); }
    } else if (e->key() == Qt::Key_Up) {
        if (selectedRow_ > 0) { selectedRow_--; viewport()->update(); }
        else if (selectedRow_ < 0) { selectedRow_ = 0; viewport()->update(); }
        else { address_ = scrollBack(address_, 1); refresh(); }  // at top: scroll, keep selection at row 0
    } else if (e->key() == Qt::Key_PageDown && !instructions_.empty()) {
        int rows = visibleRows();
        if ((int)instructions_.size() > rows)
            address_ = instructions_[rows - 1].address;
        refresh();
    } else if (e->key() == Qt::Key_PageUp) {
        address_ = scrollBack(address_, visibleRows());
        refresh();
    } else if (e->key() == Qt::Key_Return || e->key() == Qt::Key_Enter ||
               e->key() == Qt::Key_Space) {
        // Follow the selected instruction's branch/data target (CE keyboard nav).
        if (!followRow(selectedRow_)) QAbstractScrollArea::keyPressEvent(e);
    } else if (e->matches(QKeySequence::Copy) &&
               selectedRow_ >= 0 && selectedRow_ < (int)instructions_.size()) {
        // Ctrl+C copies the selected line ("addr - bytes - mnemonic ops"), the
        // same text the context menu's "Copy line" produces.
        const auto& inst = instructions_[selectedRow_];
        QString bytes;
        for (auto b : inst.bytes) bytes += QString("%1 ").arg(b, 2, 16, QChar('0'));
        QString text = QString::fromStdString(inst.operands.empty()
            ? inst.mnemonic : inst.mnemonic + " " + inst.operands);
        QApplication::clipboard()->setText(QString("%1 - %2 - %3")
            .arg(inst.address, 0, 16).arg(bytes.trimmed(), text));
    } else {
        QAbstractScrollArea::keyPressEvent(e);
    }
}

void DisasmView::wheelEvent(QWheelEvent* e) {
    int delta = e->angleDelta().y() / 120;
    if (delta > 0) {
        // Scroll up
        address_ = scrollBack(address_, delta * 3);
    } else if (delta < 0 && !instructions_.empty()) {
        // Scroll down
        int steps = std::min((int)instructions_.size() - 1, -delta * 3);
        if (steps > 0)
            address_ = instructions_[steps].address;
    }
    refresh();
}

// ═══════════════════════════════════════════════════════════════
// MemoryBrowser
// ═══════════════════════════════════════════════════════════════

MemoryBrowser::MemoryBrowser(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {

    setWindowTitle("Memory Browser");
    resize(900, 600);

    // Toolbar
    auto* toolbar = new QToolBar;
    backAct_ = toolbar->addAction("◀");
    backAct_->setToolTip("Back (Alt+Left)");
    backAct_->setEnabled(false);
    connect(backAct_, &QAction::triggered, this, &MemoryBrowser::goBack);
    fwdAct_ = toolbar->addAction("▶");
    fwdAct_->setToolTip("Forward (Alt+Right)");
    fwdAct_->setEnabled(false);
    connect(fwdAct_, &QAction::triggered, this, &MemoryBrowser::goForward);
    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(" Address: "));
    addressEdit_ = new QLineEdit;
    addressEdit_->setFont(QFont("Monospace", 10));
    addressEdit_->setFixedWidth(200);
    addressEdit_->setPlaceholderText("0x0000000000000000");
    connect(addressEdit_, &QLineEdit::returnPressed, this, &MemoryBrowser::onGotoAddress);
    toolbar->addWidget(addressEdit_);

    auto* goBtn = new QPushButton("Go");
    connect(goBtn, &QPushButton::clicked, this, &MemoryBrowser::onGotoAddress);
    toolbar->addWidget(goBtn);

    toolbar->addSeparator();
    auto* refreshBtn = new QPushButton("Refresh");
    connect(refreshBtn, &QPushButton::clicked, this, &MemoryBrowser::onRefresh);
    toolbar->addWidget(refreshBtn);

    toolbar->addSeparator();
    auto* bmToggleBtn = new QPushButton("★");
    bmToggleBtn->setToolTip("Toggle bookmark at current address (Ctrl+B)");
    connect(bmToggleBtn, &QPushButton::clicked, this, &MemoryBrowser::toggleBookmark);
    toolbar->addWidget(bmToggleBtn);
    auto* bmBtn = new QToolButton;
    bmBtn->setText("Bookmarks ▾");
    bmBtn->setPopupMode(QToolButton::InstantPopup);
    bookmarksMenu_ = new QMenu(bmBtn);
    bmBtn->setMenu(bookmarksMenu_);
    toolbar->addWidget(bmBtn);
    rebuildBookmarksMenu();  // eager: kept current on every bookmark change
    addToolBar(toolbar);

    // Debug toolbar (CE MemoryBrowserFormUnit.tbDebug): breakpoint + step controls
    // on their own row. Toggle-breakpoint uses the same setter as the disasm
    // context menu. Single-stepping needs a debug session hosted in the browser;
    // until that lands, the step/run buttons are present (matching CE's toolbar)
    // but disabled, pointing at the Debugger window.
    addToolBarBreak();
    auto* dbgBar = new QToolBar("Debug");
    auto* bpAct = dbgBar->addAction("Toggle BP");
    bpAct->setToolTip("Toggle breakpoint at the selected instruction (F5)");
    bpAct->setShortcut(QKeySequence("F5"));
    connect(bpAct, &QAction::triggered, this, [this]() {
        uintptr_t a = disasmView_->selectedAddress();
        if (!a) a = currentAddr_;
        if (a && bpSetter_) { bpSetter_(a, /*hardware=*/false); refreshBreakpoints(); }
    });
    dbgBar->addSeparator();
    auto stepStub = [dbgBar](const QString& text, const QString& tip) {
        auto* a = dbgBar->addAction(text);
        a->setEnabled(false);
        a->setToolTip(tip + " — use the Debugger window (Tools ▸ Debugger)");
        return a;
    };
    stepStub("Run", "Resume the target");
    stepStub("Step Into", "Single-step into");
    stepStub("Step Over", "Step over calls");
    stepStub("Step Out", "Run until return");
    dbgBar->addSeparator();
    stepStub("Run Till", "Run until the selected line");
    dbgBar->addSeparator();
    stepStub("Run Unhandled", "Run, passing exceptions to the target");
    dbgBar->addSeparator();
    // Disassembler Preferences (CE frmMemviewPreferencesUnit): font + colors.
    auto* prefsAct = dbgBar->addAction("Preferences");
    prefsAct->setToolTip("Disassembler Preferences — font and colors");
    connect(prefsAct, &QAction::triggered, this, [this]() {
        auto* dlg = new ce::gui::MemviewPreferences(this);
        connect(dlg, &ce::gui::MemviewPreferences::applied, this,
                [this]() { disasmView_->reloadPreferences(); });
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    addToolBar(dbgBar);

    // Load symbols + DWARF (if libdw is compiled in and modules have debug info).
    if (proc_) {
        resolver_.loadProcess(*proc_);
        dwarf_.loadFromProcess(*proc_);
    }

    disasmView_ = new DisasmView;
    disasmView_->setProcess(proc);
    disasmView_->setResolver(&resolver_);
    disasmView_->setDwarf(&dwarf_);
    // Disassemble in the target's code bitness (32-bit for a native-32 or WoW64
    // target, so registers read eax/ecx rather than rax/rcx).
    if (proc && proc->runs32BitCode())
        disasmView_->setArch(ce::Arch::X86_32);

    hexView_ = new HexView;
    hexView_->setProcess(proc);

    // Cheat-Engine layout: the disassembler with a register panel on its right,
    // and the hex view below (CE's memory viewer). The register panel lists the
    // target's registers; values populate from an active debug stop (updateRegisters).
    registerPanel_ = new QTableWidget;
    registerPanel_->setColumnCount(2);
    registerPanel_->horizontalHeader()->setVisible(false);
    registerPanel_->verticalHeader()->setVisible(false);
    registerPanel_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    registerPanel_->setSelectionMode(QAbstractItemView::NoSelection);
    registerPanel_->setFont(QFont("Monospace", 9));
    const bool is32 = proc && proc->runs32BitCode();
    const QStringList regs = is32
        ? QStringList{"EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP","EFLAGS"}
        : QStringList{"RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","RIP",
                      "R8","R9","R10","R11","R12","R13","R14","R15","RFLAGS"};
    registerPanel_->setRowCount(regs.size());
    for (int i = 0; i < regs.size(); ++i) {
        registerPanel_->setItem(i, 0, new QTableWidgetItem(regs[i]));
        registerPanel_->setItem(i, 1, new QTableWidgetItem(QStringLiteral("—")));
    }
    registerPanel_->resizeColumnsToContents();
    registerPanel_->setToolTip("Registers (populated at a debug breakpoint)");

    auto* topSplit = new QSplitter(Qt::Horizontal);
    topSplit->addWidget(disasmView_);
    topSplit->addWidget(registerPanel_);
    topSplit->setStretchFactor(0, 4);
    topSplit->setStretchFactor(1, 1);
    topSplit->setSizes({640, 200});

    auto* splitter = new QSplitter(Qt::Vertical);
    splitter->addWidget(topSplit);
    splitter->addWidget(hexView_);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 1);
    setCentralWidget(splitter);

    // Wire HexView signals.
    connect(hexView_, &HexView::requestFindWhatAccesses, this, [this](uintptr_t addr, bool writesOnly) {
        if (cfLauncher_) cfLauncher_(addr, writesOnly);
        else QMessageBox::information(this, "Code finder unavailable",
            "No code-finder launcher is wired to this memory browser instance.");
    });
    connect(hexView_, &HexView::requestGoto, this, [this](uintptr_t addr) {
        gotoAddress(addr);
    });
    // Data inspector: interpret the byte(s) at the hex cursor as scalar types.
    connect(hexView_, &HexView::cursorMoved, this, [this](uintptr_t addr) {
        if (!proc_) return;
        uint8_t b[8] = {};
        auto r = proc_->read(addr, b, sizeof(b));
        size_t got = r ? *r : 0;
        if (got < 1) { statusBar()->showMessage(QString("0x%1: <unreadable>").arg(addr, 0, 16)); return; }
        QString msg = QString("0x%1  ").arg(addr, 0, 16);
        int8_t i8; std::memcpy(&i8, b, 1);
        msg += QString("i8=%1  u8=%2").arg(i8).arg((unsigned)b[0]);
        if (got >= 2) { int16_t v; std::memcpy(&v, b, 2); msg += QString("  i16=%1").arg(v); }
        if (got >= 4) {
            int32_t v; std::memcpy(&v, b, 4);
            float f; std::memcpy(&f, b, 4);
            msg += QString("  i32=%1  float=%2").arg(v).arg((double)f, 0, 'g', 7);
        }
        if (got >= 8) {
            int64_t v; std::memcpy(&v, b, 8);
            double d; std::memcpy(&d, b, 8);
            msg += QString("  i64=%1  double=%2").arg(v).arg(d, 0, 'g', 10);
        }
        statusBar()->showMessage(msg);
    });

    // Wire DisasmView signals to MemoryBrowser actions.
    connect(disasmView_, &DisasmView::requestSetSoftBreakpoint, this, [this](uintptr_t addr) {
        if (bpSetter_) { bpSetter_(addr, /*hardware=*/false); refreshBreakpoints(); }
    });
    connect(disasmView_, &DisasmView::requestSetHwExecBreakpoint, this, [this](uintptr_t addr) {
        if (bpSetter_) { bpSetter_(addr, /*hardware=*/true); refreshBreakpoints(); }
    });
    connect(disasmView_, &DisasmView::requestRemoveBreakpoint, this, [this](uintptr_t addr) {
        if (bpRemover_) { bpRemover_(addr); refreshBreakpoints(); }
    });
    connect(disasmView_, &DisasmView::requestNop, this, [this](uintptr_t addr, int size) {
        writeNop(addr, size);
    });
    connect(disasmView_, &DisasmView::requestAssemble, this,
        [this](uintptr_t addr, int size, const QString& current) {
            assembleAt(addr, size, current);
        });
    connect(disasmView_, &DisasmView::requestXrefs, this,
        [this](uintptr_t addr) { showXrefs(addr); });
    connect(disasmView_, &DisasmView::requestSetComment, this, [this](uintptr_t addr) {
        bool ok = false;
        QString cur = QString::fromStdString(disasmView_->comment(addr));
        QString text = QInputDialog::getText(this, "Comment",
            QString("Comment for 0x%1 (blank to clear):").arg(addr, 0, 16),
            QLineEdit::Normal, cur, &ok);
        if (ok) { disasmView_->setComment(addr, text.trimmed().toStdString()); persistComments(); }
    });
    connect(disasmView_, &DisasmView::requestSetSymbol, this, [this](uintptr_t addr) {
        // Name (or clear the name of) an address. The label then shows in the
        // disassembler wherever this address is referenced.
        std::string existing = resolver_.resolve(addr);
        bool ok = false;
        QString name = QInputDialog::getText(this, "Label address",
            QString("Name for 0x%1 (blank to clear):").arg(addr, 0, 16),
            QLineEdit::Normal, QString::fromStdString(existing), &ok);
        if (!ok) return;
        if (name.trimmed().isEmpty()) resolver_.removeUserSymbol(addr);
        else                          resolver_.addUserSymbol(addr, name.trimmed().toStdString());
        persistComments();
        onRefresh();
    });
    connect(disasmView_, &DisasmView::requestSaveRegion, this, [this](uintptr_t addr) {
        saveRegionToFile(addr);
    });
    connect(disasmView_, &DisasmView::requestInjection, this, [this](uintptr_t addr, bool aob) {
        if (!proc_ || !autoAssembleOpener_) return;
        std::string err;
        std::string script = ce::generateInjectionScript(*proc_, addr, aob, err);
        if (script.empty()) {
            QMessageBox::warning(this, "Auto Assemble",
                QString::fromStdString(err.empty() ? "Could not generate a template here." : err));
            return;
        }
        // Hand the pre-filled script to MainWindow, which opens a script editor
        // with an AutoAssembler; the cave has a "// your code here" line to fill in.
        autoAssembleOpener_(QString::fromStdString(script));
    });
    connect(disasmView_, &DisasmView::addressChanged, this, [this](uintptr_t addr) {
        // A follow (double-click / "Follow operand") already moved the disasm;
        // record it in history and sync the rest.
        navigateTo(addr);
    });

    // Keyboard shortcuts
    auto* backSc = new QShortcut(QKeySequence("Alt+Left"), this);
    connect(backSc, &QShortcut::activated, this, &MemoryBrowser::goBack);
    auto* fwdSc = new QShortcut(QKeySequence("Alt+Right"), this);
    connect(fwdSc, &QShortcut::activated, this, &MemoryBrowser::goForward);
    auto* bmSc = new QShortcut(QKeySequence("Ctrl+B"), this);
    connect(bmSc, &QShortcut::activated, this, &MemoryBrowser::toggleBookmark);
    auto* findSc = new QShortcut(QKeySequence("Ctrl+F"), this);
    connect(findSc, &QShortcut::activated, this, [this]() { findInMemory(false); });
    auto* findNextSc = new QShortcut(QKeySequence("F3"), this);
    connect(findNextSc, &QShortcut::activated, this, [this]() { findInMemory(true); });
    auto* gotoShortcut = new QShortcut(QKeySequence("Ctrl+G"), this);
    connect(gotoShortcut, &QShortcut::activated, this, [this]() {
        bool ok;
        auto text = QInputDialog::getText(this, "Goto Address",
            "Address, symbol, or expression (e.g. worker, target2+0x100):",
            QLineEdit::Normal, addressEdit_->text(), &ok);
        if (ok && !text.isEmpty()) {
            addressEdit_->setText(text);
            onGotoAddress();
        }
    });

    // Auto-refresh
    refreshTimer_ = new QTimer(this);
    connect(refreshTimer_, &QTimer::timeout, this, &MemoryBrowser::onRefresh);
    refreshTimer_->start(QSettings().value("memview/refreshMs", 2000).toInt());

    // Navigate to first executable region
    if (proc_) {
        auto regions = proc_->queryRegions();
        for (auto& r : regions) {
            if (r.protection & ce::MemProt::Exec) {
                gotoAddress(r.base);
                break;
            }
        }
    }
}

void MemoryBrowser::syncViews(uintptr_t addr) {
    currentAddr_ = addr;
    addressEdit_->setText(QString("0x%1").arg(addr, 16, 16, QChar('0')));
    disasmView_->setAddress(addr);
    hexView_->setAddress(addr);
}

void MemoryBrowser::navigateTo(uintptr_t addr) {
    if (addr == currentAddr_) { syncViews(addr); return; }
    if (currentAddr_ != 0) {
        backStack_.push_back(currentAddr_);
        forwardStack_.clear();
    }
    syncViews(addr);
    updateNavActions();
}

void MemoryBrowser::goBack() {
    if (backStack_.empty()) return;
    forwardStack_.push_back(currentAddr_);
    uintptr_t a = backStack_.back();
    backStack_.pop_back();
    syncViews(a);
    updateNavActions();
}

void MemoryBrowser::goForward() {
    if (forwardStack_.empty()) return;
    backStack_.push_back(currentAddr_);
    uintptr_t a = forwardStack_.back();
    forwardStack_.pop_back();
    syncViews(a);
    updateNavActions();
}

void MemoryBrowser::updateNavActions() {
    if (backAct_) backAct_->setEnabled(!backStack_.empty());
    if (fwdAct_)  fwdAct_->setEnabled(!forwardStack_.empty());
}

void MemoryBrowser::gotoAddress(uintptr_t addr) {
    navigateTo(addr);
}

void MemoryBrowser::toggleBookmark() {
    // Bookmark the selected instruction if one is selected, else the current view.
    uintptr_t addr = disasmView_->selectedAddress();
    if (!addr) addr = currentAddr_;
    if (!addr) return;
    if (!bookmarks_.insert(addr).second) bookmarks_.erase(addr);
    rebuildBookmarksMenu();
}

void MemoryBrowser::rebuildBookmarksMenu() {
    bookmarksMenu_->clear();
    if (bookmarks_.empty()) {
        bookmarksMenu_->addAction("(no bookmarks — Ctrl+B to add)")->setEnabled(false);
        return;
    }
    for (uintptr_t a : bookmarks_) {
        QString label = QString("0x%1").arg(a, 0, 16);
        auto sym = resolver_.resolve(a);
        if (!sym.empty()) label += "  " + QString::fromStdString(sym);
        bookmarksMenu_->addAction(label, this, [this, a]() { navigateTo(a); });
    }
    bookmarksMenu_->addSeparator();
    bookmarksMenu_->addAction("Clear all bookmarks", this, [this]() {
        bookmarks_.clear();
        rebuildBookmarksMenu();
    });
}

void MemoryBrowser::onGotoAddress() {
    QString text = addressEdit_->text().trimmed();
    if (text.isEmpty()) return;
    // Accept full CE-style expressions: symbols ("worker"), module+offset
    // ("target2+0x100"), pointer derefs ("[rax+8]"), decimal ("#1234"), or hex.
    ce::ExpressionParser parser(proc_, &resolver_);
    if (auto addr = parser.parse(text.toStdString()); addr && *addr) {
        gotoAddress(*addr);
        return;
    }
    bool ok;
    uintptr_t addr = text.toULongLong(&ok, 16);
    if (ok) gotoAddress(addr);
    else QMessageBox::warning(this, "Goto", QString("Could not resolve \"%1\".").arg(text));
}

void MemoryBrowser::onRefresh() {
    disasmView_->refresh();
    hexView_->refresh();
    refreshBreakpoints();
}

void MemoryBrowser::refreshBreakpoints() {
    if (!bpQuery_) return;
    disasmView_->setActiveBreakpoints(bpQuery_());
}

bool MemoryBrowser::patchBytes(uintptr_t addr, const std::vector<uint8_t>& bytes) {
    if (!proc_ || bytes.empty()) return false;
    auto r = proc_->write(addr, bytes.data(), bytes.size());
    if (!r || *r < bytes.size()) {
        // Code lives on r-x pages that process_vm_writev can't touch; make the
        // page writable and retry (same approach as the auto-assembler).
        proc_->protect(addr, bytes.size(), ce::MemProt::All);
        r = proc_->write(addr, bytes.data(), bytes.size());
        if (!r || *r < bytes.size()) return false;
    }
    return true;
}

void MemoryBrowser::writeNop(uintptr_t addr, int size) {
    if (!proc_ || size <= 0) return;
    std::vector<uint8_t> nops(size, 0x90);
    if (!patchBytes(addr, nops)) {
        QMessageBox::warning(this, "NOP failed",
            QString("Could not write %1 NOP byte%2 to 0x%3.")
                .arg(size).arg(size == 1 ? "" : "s").arg(addr, 0, 16));
        return;
    }
    onRefresh();
}

void MemoryBrowser::assembleAt(uintptr_t addr, int origSize, const QString& current) {
    if (!proc_) return;
    bool ok = false;
    QString text = QInputDialog::getText(this, "Assemble",
        QString("Instruction to assemble at 0x%1:").arg(addr, 0, 16),
        QLineEdit::Normal, current, &ok);
    if (!ok || text.trimmed().isEmpty()) return;

    ce::Assembler asmr(proc_ && proc_->runs32BitCode() ? ce::AsmArch::X86_32
                                                        : ce::AsmArch::X86_64);
    auto res = asmr.assemble(text.toStdString(), addr);
    if (!res) {
        QMessageBox::warning(this, "Assemble failed",
            QString("Could not assemble \"%1\":\n%2").arg(text, QString::fromStdString(res.error())));
        return;
    }
    std::vector<uint8_t> bytes = *res;
    if (bytes.empty()) {
        QMessageBox::warning(this, "Assemble failed",
            QString("\"%1\" assembled to no bytes; not writing.").arg(text));
        return;
    }
    if ((int)bytes.size() > origSize) {
        auto ans = QMessageBox::question(this, "Longer instruction",
            QString("The new instruction is %1 bytes but the original was %2. Writing it will "
                    "overwrite the following instruction(s). Continue?")
                .arg(bytes.size()).arg(origSize),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (ans != QMessageBox::Yes) return;
    } else {
        // Pad the remainder of the original instruction with NOPs so the next
        // instruction boundary is preserved.
        while ((int)bytes.size() < origSize) bytes.push_back(0x90);
    }
    if (!patchBytes(addr, bytes)) {
        QMessageBox::warning(this, "Write failed",
            QString("Assembled %1 bytes but could not write to 0x%2.").arg(bytes.size()).arg(addr, 0, 16));
        return;
    }
    onRefresh();
}

uintptr_t MemoryBrowser::searchMemory(const std::vector<uint8_t>& pat, uintptr_t start,
                                      bool inclusive) {
    if (pat.empty() || !proc_) return 0;
    // Walk readable regions in order, searching each for the pattern from `start`.
    // A first Find is inclusive (a match sitting exactly at the cursor counts); a
    // Find-Next is exclusive so it advances past the current match.
    auto regions = proc_->queryRegions();
    // Read each region in bounded chunks rather than one giant buffer — a real
    // game can have multi-GB regions (a big heap or a mapped file), and
    // buf.resize(r.size) on those would OOM. Chunks overlap by pat.size()-1 so a
    // match straddling a chunk boundary is still found.
    constexpr size_t CHUNK = 16 * 1024 * 1024;
    const size_t overlap = pat.size() > 1 ? pat.size() - 1 : 0;
    std::vector<uint8_t> buf;
    for (auto& r : regions) {
        if (r.base + r.size <= start) continue;
        if (!(r.protection & ce::MemProt::Read)) continue;
        uintptr_t regionEnd = r.base + r.size;
        uintptr_t pos = r.base;
        while (pos < regionEnd) {
            size_t want = (size_t)std::min<uintptr_t>(CHUNK, regionEnd - pos);
            buf.resize(want);
            auto rr = proc_->read(pos, buf.data(), want);
            size_t got = rr ? *rr : 0;
            for (size_t off = 0; off + pat.size() <= got; ++off) {
                uintptr_t found = pos + off;
                bool pastStart = inclusive ? (found >= start) : (found > start);
                if (pastStart && std::memcmp(buf.data() + off, pat.data(), pat.size()) == 0)
                    return found;
            }
            if (got < want) break;               // short read → rest of region unreadable
            if (pos + want >= regionEnd) break;  // reached region end
            pos += (want > overlap) ? (want - overlap) : want;  // advance, keep overlap
        }
    }
    return 0;
}

void MemoryBrowser::findInMemory(bool findNext) {
    if (!proc_) return;
    std::vector<uint8_t> pat;
    if (findNext && !lastSearch_.empty()) {
        pat = lastSearch_;
    } else {
        bool ok = false;
        QString s = QInputDialog::getText(this, "Find in memory",
            "Bytes (e.g. 48 8B 05) or \"text\":", QLineEdit::Normal, "", &ok);
        if (!ok || s.trimmed().isEmpty()) return;
        s = s.trimmed();
        if (s.startsWith('"') && s.endsWith('"') && s.size() >= 2) {
            QByteArray ba = s.mid(1, s.size() - 2).toUtf8();
            pat.assign(ba.begin(), ba.end());
        } else {
            QString hex = s; hex.remove(' ');
            bool okh = true;
            if (hex.isEmpty() || hex.size() % 2 != 0) okh = false;
            for (int i = 0; okh && i < hex.size(); i += 2) {
                pat.push_back((uint8_t)hex.mid(i, 2).toInt(&okh, 16));
            }
            if (!okh) {
                QMessageBox::warning(this, "Find",
                    "Enter whitespace-separated hex byte pairs (48 8B 05) or a quoted \"string\".");
                return;
            }
        }
        lastSearch_ = pat;
    }
    // First Find is inclusive of the current address; Find Next advances past it.
    uintptr_t hit = searchMemory(pat, currentAddr_, /*inclusive=*/!findNext);
    if (hit) {
        navigateTo(hit);
    } else {
        QMessageBox::information(this, "Find",
            "Not found searching forward from the current address.");
    }
}

void MemoryBrowser::showXrefs(uintptr_t addr) {
    if (!proc_) return;
    // Find the module containing this address.
    ce::ModuleInfo mod{};
    bool found = false;
    for (const auto& m : proc_->modules()) {
        if (addr >= m.base && addr < m.base + m.size) { mod = m; found = true; break; }
    }
    if (!found) {
        QMessageBox::information(this, "References",
            "This address is not inside a known module, so its references can't be scanned.");
        return;
    }

    QApplication::setOverrideCursor(Qt::WaitCursor);
    ce::CodeAnalyzer analyzer;
    auto refs = analyzer.findReferencesTo(*proc_, mod, addr);
    QApplication::restoreOverrideCursor();

    auto* dlg = new QDialog(this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setWindowTitle(QString("References to 0x%1 — %2 found").arg(addr, 0, 16).arg(refs.size()));
    dlg->resize(640, 360);
    auto* lay = new QVBoxLayout(dlg);
    auto* table = new QTableWidget(dlg);
    table->setColumnCount(3);
    table->setHorizontalHeaderLabels({"From", "Type", "Instruction"});
    table->horizontalHeader()->setStretchLastSection(true);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setRowCount((int)refs.size());
    auto typeName = [](ce::RefType t) -> QString {
        switch (t) {
            case ce::RefType::Call: return "call";
            case ce::RefType::Jump: return "jump";
            case ce::RefType::String: return "string";
            case ce::RefType::RipRelative: return "data";
            default: return "ref";
        }
    };
    for (int i = 0; i < (int)refs.size(); ++i) {
        const auto& r = refs[i];
        auto* a = new QTableWidgetItem(QString("0x%1").arg(r.address, 0, 16));
        a->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(r.address));
        table->setItem(i, 0, a);
        table->setItem(i, 1, new QTableWidgetItem(typeName(r.type)));
        table->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(r.text)));
    }
    table->setFont(QFont("Monospace", 9));
    lay->addWidget(table);
    // Double-click a reference to navigate the disassembler there.
    connect(table, &QTableWidget::cellDoubleClicked, this, [this, table, dlg](int row, int) {
        auto* it = table->item(row, 0);
        if (!it) return;
        uintptr_t a = it->data(Qt::UserRole).toULongLong();
        disasmView_->setAddress(a);
        addressEdit_->setText(QString("0x%1").arg(a, 16, 16, QChar('0')));
        hexView_->setAddress(a);
        dlg->raise();
    });
    dlg->show();
}

void MemoryBrowser::saveRegionToFile(uintptr_t addr) {
    if (!proc_) return;
    bool ok = false;
    int size = QInputDialog::getInt(this, "Save region", "Bytes to save:", 4096, 1, 1 << 28, 1, &ok);
    if (!ok) return;
    auto path = QFileDialog::getSaveFileName(this, "Save region",
        QString("region_%1_%2.bin").arg(addr, 0, 16).arg(size), "Binary (*.bin);;All (*)");
    if (path.isEmpty()) return;

    std::vector<uint8_t> buf(size);
    auto r = proc_->read(addr, buf.data(), size);
    if (!r) {
        QMessageBox::warning(this, "Read failed",
            QString("Could not read %1 bytes at 0x%2.").arg(size).arg(addr, 0, 16));
        return;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Save failed", f.errorString());
        return;
    }
    f.write(reinterpret_cast<const char*>(buf.data()), (qint64)*r);
}

std::string MemoryBrowser::addrToExpr(uintptr_t addr) const {
    // Prefer a module-relative expression ("libgame.so+0x1234") so the comment
    // survives ASLR; fall back to an absolute hex address outside any module.
    if (proc_) {
        for (const auto& m : proc_->modules()) {
            if (addr >= m.base && addr < m.base + m.size) {
                char buf[64];
                snprintf(buf, sizeof(buf), "+0x%lx", (unsigned long)(addr - m.base));
                return m.name + buf;
            }
        }
    }
    char buf[32]; snprintf(buf, sizeof(buf), "0x%lx", (unsigned long)addr);
    return buf;
}

uintptr_t MemoryBrowser::exprToAddr(const std::string& expr) const {
    // "module+0xoff" -> module base + off; "0x..." -> absolute. Returns 0 if the
    // module is not loaded (comment simply not shown until it is).
    auto plus = expr.rfind('+');
    if (plus != std::string::npos && proc_) {
        std::string name = expr.substr(0, plus);
        uintptr_t off = strtoull(expr.c_str() + plus + 1, nullptr, 0);
        for (const auto& m : proc_->modules())
            if (m.name == name) return m.base + off;
        return 0;
    }
    return (uintptr_t)strtoull(expr.c_str(), nullptr, 0);
}

void MemoryBrowser::persistComments() {
    if (!annotationSaver_) return;
    // Merge inline comments and user labels by module-relative address expression:
    // an address may carry a comment, a label, or both.
    std::map<std::string, ce::DisassemblerComment> byExpr;
    for (const auto& [addr, text] : disasmView_->comments()) {
        auto e = addrToExpr(addr);
        byExpr[e].address = e;
        byExpr[e].comment = text;
    }
    for (const auto& [addr, name] : resolver_.userSymbols()) {
        auto e = addrToExpr(addr);
        byExpr[e].address = e;
        byExpr[e].label = name;
    }
    std::vector<ce::DisassemblerComment> out;
    out.reserve(byExpr.size());
    for (auto& [e, c] : byExpr) out.push_back(std::move(c));
    annotationSaver_(std::move(out));
}

void MemoryBrowser::setAnnotationStore(
    std::vector<ce::DisassemblerComment> initial,
    std::function<void(std::vector<ce::DisassemblerComment>)> saver) {
    annotationSaver_ = std::move(saver);
    for (const auto& c : initial) {
        uintptr_t addr = exprToAddr(c.address);
        if (!addr) continue;
        if (!c.comment.empty()) disasmView_->setComment(addr, c.comment);
        if (!c.label.empty())   resolver_.addUserSymbol(addr, c.label);
    }
}

} // namespace ce::gui
