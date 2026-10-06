// Included by the existing GUI lifecycle driver to reuse its Qt implementation
// objects instead of compiling a second complete GUI on limited machines.
#include "gui/gdbconnectiondialog.hpp"
#include "gui/registereditor.hpp"
#include "gui/luaconsole.hpp"
#include "gui/branchmapper.hpp"
#include <QDir>
#include <QSpinBox>
#include <QElapsedTimer>
#include <limits>

static int gdbGuiChecks(const QString& mode, const QString& host, int port) {
    unsigned failures=0;
    auto check=[&](bool ok,const char* text) {
        std::printf("%s: %s\n",ok ? "OK" : "FAILED",text);std::fflush(stdout);failures+=!ok;
    };
    const bool qemu=mode=="qemu-gui", cancel=mode=="gdb-cancel", fail=mode=="gdb-fail";
    const bool unknown=mode=="gdb-unknown", unavailable=mode=="gdb-unavailable";
    const uintptr_t base=qemu ? 0x40000000 : 0x1000;
    QString screenshots=QString::fromLocal8Bit(qgetenv("CE_GDB_SCREENSHOT_DIR"));
    auto screenshot=[&](QWidget* widget,const QString& name) {
        if (screenshots.isEmpty() || !widget) return;
        QDir().mkpath(screenshots);widget->show();QApplication::processEvents();
        check(widget->grab().save(screenshots+"/"+name+".png"),"actual GUI screenshot saved");
    };
    ce::gui::MainWindow main;main.show();
    auto* scanTo=main.findChild<QLineEdit*>("scanTo");bool fullRange=false;
    const auto lastAddress=scanTo ? scanTo->text().toULongLong(&fullRange,16) : 0;
    check(fullRange && lastAddress==UINTPTR_MAX,"the GUI defaults to the full representable inclusive scan range");
    main.attachToPid(getpid(),"GUI fixture");
    auto* label=main.findChild<QLabel*>("processLabel");
    const auto oldLabel=label ? label->text() : QString{};
    QPointer<ce::gui::MemoryBrowser> oldViewer=main.openMemoryView(reinterpret_cast<uintptr_t>(&watched));
    bool started=false,canceled=false,sawError=false;unsigned pulses=0;
    QElapsedTimer elapsed;
    QTimer timer;timer.setInterval(5);
    QObject::connect(&timer,&QTimer::timeout,[&] {
        ++pulses;
        auto* dialog=dynamic_cast<ce::gui::GdbConnectionDialog*>(QApplication::activeModalWidget());
        if (!dialog) return;
        if (!started) {
            started=true;elapsed.start();
            dialog->findChild<QLineEdit*>("gdbHost")->setText(host);
            dialog->findChild<QSpinBox*>("gdbPort")->setValue(port);
            dialog->findChild<QComboBox*>("gdbByteOrder")->setCurrentIndex(unknown ? 0 : qemu ? 1 : 2);
            dialog->findChild<QComboBox*>("gdbPointerWidth")->setCurrentIndex(qemu ? 0 : 1);
            dialog->findChild<QLineEdit*>("gdbRangeStart")->setText(QString("0x%1").arg(base,0,16));
            dialog->findChild<QLineEdit*>("gdbRangeSize")->setText("0x1000");
            if (qemu) screenshot(dialog,"connection");
            dialog->findChild<QPushButton*>("gdbConnect")->click();return;
        }
        if (cancel && !canceled && elapsed.elapsed()>=100) {canceled=true;dialog->reject();}
        if (fail && dialog->findChild<QPushButton*>("gdbConnect")->isEnabled()) {
            sawError=!dialog->findChild<QLabel*>("gdbConnectionStatus")->text().isEmpty();dialog->reject();
        }
        if (elapsed.elapsed()>5000) dialog->reject();
    });
    timer.start();check(trigger(main,"Connect to GDB / QEMU..."),"the actual File menu launches the connection dialog");timer.stop();
    if (cancel || fail) {
        check(started && label && label->text()==oldLabel && oldViewer &&
              !oldViewer->windowTitle().contains("target exited"),"failed or canceled connection preserves the original target and viewer");
        if (cancel) check(canceled && elapsed.elapsed()<600 && pulses>10,"cancel interrupts a stalled peer while the dialog continues processing events");
        if (fail) check(sawError,"invalid XML is reported in the connection dialog");
        std::printf("GDB_GUI_RESULT=%s mode=%s\n",failures ? "FAILED" : "PASSED",mode.toUtf8().constData());return failures ? 1 : 0;
    }
    check(started && label && label->text().startsWith("GDB:") && label->text().contains("aarch64"),"the GUI displays the guest endpoint and architecture without a local PID");
    if (!label || !label->text().startsWith("GDB:")) return 1;
    check(label->text().contains(unknown ? "data order unknown" : qemu ? "little-endian data" : "big-endian data") &&
          label->text().contains(qemu ? "64-bit pointers" : "32-bit pointers"),"visible guest label distinguishes CPU architecture, data order and program pointer width");
    check(oldViewer && oldViewer->windowTitle().contains("target exited"),"target switching freezes the previous memory viewer before releasing its process");
    auto* viewer=main.openMemoryView(base);auto* hex=viewer ? viewer->findChild<ce::gui::HexView*>() : nullptr;
    check(hex!=nullptr,"the ordinary memory viewer opens on guest RAM");
    if (!hex || !viewer) return 1;
    if (!qemu) {
        if (unknown) check(!hex->pointerValueAt(base),"unknown guest data order never becomes a guessed host pointer");
        else {
            check(hex->pointerValueAt(base)==std::optional<uintptr_t>{0x11223344},"follow-pointer uses four-byte big-endian program pointers on an ARM64 CPU");
            check(hex->pointerValueAt(base+4092)==std::optional<uintptr_t>{0},"a valid guest zero pointer remains distinguishable from an unreadable pointer");
            check(!hex->pointerValueAt(base+4094),"a short pointer read cannot consume invented bytes");
        }
    }
    check(trigger(*viewer,"Registers"),"the Memory Viewer opens its register editor for the GDB target");
    QPointer<ce::gui::RegisterEditorWindow> editor=main.findChild<ce::gui::RegisterEditorWindow*>();
    auto* table=editor ? editor->findChild<QTableWidget*>("registerEditorGeneral") : nullptr;
    check(table && editor->windowTitle()=="GDB Register Editor","the editor uses guest XML registers without local thread inspection");
    if (unavailable && table) check(table->item(0,1)->text().startsWith("Unavailable:") &&
        !(table->item(0,1)->flags() & Qt::ItemIsEditable),"unavailable guest registers remain unavailable and cannot be edited as zero");
    auto* console=qobject_cast<ce::gui::LuaConsole*>(main.openPanelByName("Lua Engine"));
    check(console!=nullptr,"the existing Lua console shares the GUI target");
    auto lua=[&](const QString& code) {
        if (!console) return false;
        auto* output=console->findChild<QPlainTextEdit*>();if (!output) return false;
        output->clear();console->runForTest(code);
        const auto text=output->toPlainText();const bool ok=!text.contains("ERROR:");
        if (!ok) std::fprintf(stderr,"%s\n",text.toUtf8().constData());
        return ok;
    };
    check(lua("assert(getTargetInfo().transport=='gdb' and getOpenedProcessID()==0); print('Shared guest target verified')"),"GUI Lua reads the actual GDB target metadata");
    if (mode=="gdb-bank" && table && console) {
        check(lua("bankOriginalX0=assert(readGdbRegister('x0')); bankOriginalVector=assert(readGdbRegister('v0')); bankOriginalNarrow=assert(readGdbRegister('narrow'))"),
              "save all edited register bytes from the bank-only peer");
        int vectorRow=-1,x0Row=-1;
        for (int row=0;row<table->rowCount();++row) {
            if (table->item(row,0)->text()=="v0") vectorRow=row;
            if (table->item(row,0)->text()=="x0") x0Row=row;
        }
        check(vectorRow>=0 && x0Row>=0,"the GUI exposes sparse XML registers in their declared display order");
        if (vectorRow>=0 && x0Row>=0) {
            table->selectRow(x0Row);editor->findChild<QPushButton*>("registerEditorRefresh")->click();
            table->item(x0Row,1)->setText("0102030405060708");editor->findChild<QPushButton*>("registerEditorApply")->click();
            check(lua("assert(readGdbRegister('x0')==string.char(1,2,3,4,5,6,7,8)); bankLivePC=assert(readGdbRegister('pc')); assert(bankLivePC==string.char(0xef,0xcd,0xab,0x89,0,0,0,0x40))"),
                  "the actual Apply action edits a bank-only scalar and observes the peer's later PC change");
            table->item(vectorRow,1)->setText("202122232425262728292a2b2c2d2e2f");editor->findChild<QPushButton*>("registerEditorApply")->click();
            check(lua("assert(readGdbRegister('v0')==string.char(0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f)); assert(readGdbRegister('pc')==bankLivePC and readGdbRegister('narrow')==bankOriginalNarrow)"),
                  "GUI vector Apply rereads the bank and preserves unedited PC and narrow register bytes");
            screenshot(editor,"bank-registers");
        }
        check(lua("assert(writeGdbRegister('x0',bankOriginalX0)); assert(writeGdbRegister('v0',bankOriginalVector)); assert(readGdbRegister('x0')==bankOriginalX0 and readGdbRegister('v0')==bankOriginalVector and readGdbRegister('pc')==bankLivePC and readGdbRegister('narrow')==bankOriginalNarrow)"),
              "restore both GUI-edited bank fields and preserve unrelated live register state");
    }
    check(lua("assert(pause()==false and unpause()==false and getProcessDir()==''); local result,err=branchMap(0); assert(result==nil and err:find('local'))"),"guest Lua identifiers cannot select host signals, proc paths or branch sampling");
    check(trigger(*viewer,"Branch mapper (LBR)"),"the actual Branch Mapper opens with a clear guest limitation");
    QPointer<ce::gui::BranchMapper> mapper=main.findChild<ce::gui::BranchMapper*>();
    auto* threadChoice=mapper ? mapper->findChild<QSpinBox*>("branchMapperThread") : nullptr;
    check(threadChoice && threadChoice->minimum()==1 && threadChoice->maximum()==std::numeric_limits<pid_t>::max(),
          "the branch thread selector accepts the kernel PID range and excludes the frontend-thread sentinel");
    check(mapper && !mapper->findChild<QPushButton*>("branchMapperStart")->isEnabled() &&
          !mapper->findChild<QSpinBox*>("branchMapperThread")->isEnabled() &&
          mapper->findChild<QLabel*>("branchMapperStatus")->text().contains("local process"),
          "guest branch sampling is disabled before reaching the host perf backend");
    for (auto* action:main.findChildren<QAction*>()) if (action->text()=="Pause the process") {
        action->setChecked(true);check(!action->isChecked(),"the GUI refuses host signal pause for a guest target");
    }
    auto encodedPointerScan = [&] {
        const uintptr_t data = base + 384;
        check(lua(QString("encodedData=%1; encodedOriginal=assert(readBytes(encodedData,8,true)); writeBytes(encodedData,{0x12,0x34,0x56,0x78})").arg(data)),
              "seed independent BE32 encoded pointers without changing guest CPU metadata");
        auto* type = main.findChild<QComboBox*>("scanValueType");
        auto* value = main.findChild<QLineEdit*>("scanValue");
        auto* primary = main.findChild<QPushButton*>("primaryButton");
        auto* order = main.findChild<QComboBox*>("scanByteOrder");
        auto* width = main.findChild<QComboBox*>("scanPointerWidth");
        if (primary->text() == "New Scan") primary->click();
        main.findChild<QLineEdit*>("scanFrom")->setText(QString("0x%1").arg(data,0,16));
        main.findChild<QLineEdit*>("scanTo")->setText(QString("0x%1").arg(data+3,0,16));
        type->setCurrentIndex(11);value->setText("0x12345678");
        order->setCurrentIndex(order->findData(int(ce::ByteOrder::Big)));width->setCurrentIndex(width->findData(4));
        primary->click();auto* results=main.findChild<ce::gui::ScanResultsModel*>();
        check(results && results->rowCount()==1 && results->displayValueAt(0,1)=="0x12345678" && results->displayValueAt(0,2)=="0x12345678",
              "explicit GUI data controls scan BE32 pointers independently of unknown or LE64 guest metadata");
        auto* records=main.findChild<ce::gui::AddressListModel*>();
        bool added=results && results->rowCount()==1 && QMetaObject::invokeMethod(&main,"onResultDoubleClicked",Qt::DirectConnection,Q_ARG(QModelIndex,results->index(0,0)));
        int row=records->rowCount()-1;
        check(added && row>=0 && records->entries()[row].pointerWidth==4 && records->entries()[row].dataByteOrder==ce::ByteOrder::Big &&
              records->setData(records->index(row,4),"0x12345679",Qt::EditRole),
              "a transferred encoded guest pointer retains its format for actual address-list edits");
        check(lua("local now=assert(readBytes(encodedData,8,true)); assert(now[1]==0x12 and now[2]==0x34 and now[3]==0x56 and now[4]==0x79); for i=5,8 do assert(now[i]==encodedOriginal[i]) end"),
              "the actual guest observes exactly four big-endian edit bytes and unchanged neighbors");
        if (qemu) screenshot(&main,"encoded-pointer");
        check(lua("writeBytes(encodedData,encodedOriginal); local now=assert(readBytes(encodedData,8,true)); for i=1,8 do assert(now[i]==encodedOriginal[i]) end"),
              "restore every guest byte changed by explicit pointer scan and record editing");
    };
    if (unknown && console) encodedPointerScan();
    if (!qemu && !unknown && console) {
        check(lua("formatOriginalRAM=assert(readBytes(0x1000,4096,true)); assert(writeInteger(0x1100,0x12345678))"),"seed independent big-endian guest numeric data");
        auto* type=main.findChild<QComboBox*>("scanValueType");
        auto* value=main.findChild<QLineEdit*>("scanValue");
        auto* primary=main.findChild<QPushButton*>("primaryButton");
        type->setCurrentIndex(2);value->setText("305419896");primary->click();
        auto* results=main.findChild<ce::gui::ScanResultsModel*>();
        check(results && results->rowCount()==1 && results->displayValueAt(0,1)=="305419896" && results->displayValueAt(0,2)=="305419896",
              "ordinary GUI numeric scan displays big-endian live and captured values correctly");
        check(lua("assert(writeInteger(0x1100,0x12345679))"),"change actual guest numeric data through the shared Lua target");
        if (results) results->refreshRange(0,0);
        check(results && results->displayValueAt(0,1)=="305419897" && results->displayValueAt(0,2)=="305419896",
              "live numeric refresh uses the sample byte order while Previous retains its captured bytes");
        if (mode=="gdb-pointer") screenshot(&main,"big-endian-numeric");
        value->setText("305419897");main.findChild<QPushButton*>("nextScanButton")->click();
        check(results && results->rowCount()==1 && results->displayValueAt(0,2)=="305419897","GUI next scan compares and saves big-endian numeric samples");
        primary->click();type->setCurrentIndex(11);value->setText("0x12345679");primary->click();
        check(results && results->rowCount()==1 && results->displayValueAt(0,1)=="0x12345679" && results->displayValueAt(0,2)=="0x12345679",
              "GUI pointer scans use four-byte program pointers on the eight-byte ARM64 CPU");
        if (mode=="gdb-pointer") screenshot(&main,"big-endian-pointer");
        check(lua("writeBytes(0x1000,formatOriginalRAM); local current=assert(readBytes(0x1000,4096,true)); for i=1,4096 do assert(current[i]==formatOriginalRAM[i]) end"),"restore every guest RAM byte after numeric and pointer GUI scans");
    }
    if (qemu && table && console) {
        check(lua(R"lua(guestBase=0x40000000; guestOriginalRAM=assert(readBytes(guestBase,4096,true)); guestOriginalX0=assert(readGdbRegister('x0')); guestOriginalPC=assert(readGdbRegister('pc')); guestOriginalV0=assert(readGdbRegister('v0')); assert(#guestOriginalV0==16); writeBytes(guestBase,{0xe0,0,0x80,0xd2,0,0x14,0,0x91,0x1f,0x20,3,0xd5}); assert(readBytes(guestBase,1)==0xe0); writeBytes(guestBase+256,{0xe0,0x12,0x34,0x56,0x78,0x90,0xab,0xcd}); assert(byteTableToString(readBytes(guestBase+256,8,true))==string.char(0xe0,0x12,0x34,0x56,0x78,0x90,0xab,0xcd)); assert(writeGdbRegister('v0',string.char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16))); print('Saved guest RAM and CPU state; seeded ARM64 instructions and a unique byte pattern'))lua"),"shared GUI Lua edits actual QEMU RAM and its full 128-bit vector register");
        hex->setAddress(base+128);check(hex->pasteBytes("78 56 34 12")==4,"the Hex View edits actual guest bytes");
        check(lua("assert(readInteger(guestBase+128)==0x12345678)"),"Lua confirms the actual Hex View edit with guest-order typed reads");
        int vectorRow=-1,x0Row=-1;
        for (int row=0;row<table->rowCount();++row) {
            if (table->item(row,0)->text()=="v0") vectorRow=row;
            if (table->item(row,0)->text()=="x0") x0Row=row;
        }
        check(vectorRow>=0 && x0Row>=0,"the XML editor exposes actual scalar and vector registers");
        if (vectorRow>=0 && x0Row>=0) {
            table->selectRow(vectorRow);editor->findChild<QPushButton*>("registerEditorRefresh")->click();
            check(table->item(vectorRow,1)->text()=="0102030405060708090a0b0c0d0e0f10","Refresh reads all actual vector bytes in target order");
            const auto x0Text=table->item(x0Row,1)->text();
            table->item(x0Row,1)->setText("0102030405060708");table->item(vectorRow,1)->setText("ff");
            editor->findChild<QPushButton*>("registerEditorApply")->click();
            check(lua("assert(readGdbRegister('x0')==guestOriginalX0); assert(readGdbRegister('v0')==string.char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16))"),"invalid wide edits reject the entire edit set before writing any register");
            table->item(x0Row,1)->setText(x0Text);
            check(lua("assert(writeGdbRegister('x0',string.char(9,8,7,6,5,4,3,2)))"),"a live register can change after the editor's earlier snapshot");
            table->item(vectorRow,1)->setText("100f0e0d0c0b0a090807060504030201");editor->findChild<QPushButton*>("registerEditorApply")->click();
            check(lua("assert(readGdbRegister('v0')==string.char(16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1)); assert(readGdbRegister('x0')==string.char(9,8,7,6,5,4,3,2)); assert(readGdbRegister('pc')==guestOriginalPC); print('XML vector edit applied; unedited live registers preserved')"),"Apply edits the guest vector while preserving unedited live scalar and PC state");
        }
        main.findChild<QLineEdit*>("scanValue")->setText("E0 12 34 56 78 90 AB CD");
        main.findChild<QPushButton*>("primaryButton")->click();
        auto* results=main.findChild<ce::gui::ScanResultsModel*>();
        check(results && results->rowCount()==1 && results->data(results->index(0,0),Qt::DisplayRole).toString().toULongLong(nullptr,16)==base+256,
              "the ordinary GUI scanner finds the exact pattern in actual guest RAM");
        hex->setAddress(base);if (auto* disasm=viewer->findChild<ce::gui::DisasmView*>()) disasm->setAddress(base);viewer->show();QApplication::processEvents();
        screenshot(&main,"main-scan");screenshot(viewer,"memory-viewer");screenshot(editor,"xml-registers");screenshot(console,"lua-console");screenshot(mapper,"branch-mapper");
        encodedPointerScan();
        check(lua(R"lua(writeBytes(guestBase,guestOriginalRAM); assert(writeGdbRegister('x0',guestOriginalX0)); assert(writeGdbRegister('pc',guestOriginalPC)); assert(writeGdbRegister('v0',guestOriginalV0)); local ram=assert(readBytes(guestBase,4096,true)); for i=1,4096 do assert(ram[i]==guestOriginalRAM[i],'RAM restore mismatch') end; assert(readGdbRegister('x0')==guestOriginalX0 and readGdbRegister('pc')==guestOriginalPC and readGdbRegister('v0')==guestOriginalV0); print('Every modified guest RAM byte and captured register restored'))lua"),"the GUI and Lua restore every modified guest RAM byte and captured register exactly");
    }
    check(trigger(main,"Disconnect target"),"the actual File menu disconnects the guest");
    check(!editor && !mapper && viewer->windowTitle().contains("target exited") && label->text()=="No process selected","disconnect releases target-bound editors and freezes its memory viewer");
    check(lua("assert(getTargetInfo()==nil and readInteger(0x40000000)==nil and readGdbRegister('x0')==nil)"),"the shared console rejects stale reads after GUI disconnect");
    main.attachToPid(getpid(),"native again");
    check(label->text().startsWith("PID:"),"the GUI can return to a native target after a guest disconnect");
    std::printf("GDB_GUI_RESULT=%s mode=%s\n",failures ? "FAILED" : "PASSED",mode.toUtf8().constData());return failures ? 1 : 0;
}
