#include <QFileDialog>
#include <QEventLoop>
#include <QJsonArray>
#include <QFileInfo>
#include "core/ct_file.hpp"

static bool guiScanFormatChecks(const QString& screenshot = {}) {
    std::printf("GUI scan-format stage: attach\n");
    alignas(16) std::array<uint8_t,16> memory{};
    const uintptr_t address=reinterpret_cast<uintptr_t>(memory.data());
    ce::gui::MainWindow main;main.attachToPid(getpid(),"encoded data fixture");
    auto* type=main.findChild<QComboBox*>("scanValueType");
    auto* value=main.findChild<QLineEdit*>("scanValue");
    auto* from=main.findChild<QLineEdit*>("scanFrom");auto* to=main.findChild<QLineEdit*>("scanTo");
    auto* order=main.findChild<QComboBox*>("scanByteOrder");auto* width=main.findChild<QComboBox*>("scanPointerWidth");
    auto* first=main.findChild<QPushButton*>("primaryButton");auto* next=main.findChild<QPushButton*>("nextScanButton");
    auto* results=main.findChild<ce::gui::ScanResultsModel*>();auto* records=main.findChild<ce::gui::AddressListModel*>();
    if(!type||!value||!from||!to||!order||!width||!first||!next||!results||!records)return false;
    from->setText(QString("0x%1").arg(address,0,16));to->setText(QString("0x%1").arg(address+3,0,16));
    auto seed=[&](bool big,uint32_t number) {
        memory.fill(0xee);
        for(size_t i=0;i<4;++i)memory[i]=uint8_t(number>>(8*(big ? 3-i : i)));
    };
    auto addResult=[&] {
        return QMetaObject::invokeMethod(&main,"onResultDoubleClicked",Qt::DirectConnection,Q_ARG(QModelIndex,results->index(0,0)));
    };
    auto awaitEditVerification=[] {
        // A wall-clock polling deadline can expire while the host is busy,
        // leaving the earlier verification timer unprocessed when bytes are
        // reused. Exit through a later Qt timer so overdue callbacks run first.
        QEventLoop loop;
        QTimer::singleShot(300,&loop,&QEventLoop::quit);
        loop.exec();
    };
    bool numeric=true, transfers=true;
    for(bool big:{false,true}) {
        std::printf("GUI scan-format stage: numeric %s\n",big ? "big" : "little");
        if(first->text()=="New Scan")first->click();
        type->setCurrentIndex(2);order->setCurrentIndex(order->findData(int(big ? ce::ByteOrder::Big : ce::ByteOrder::Little)));
        seed(big,0x12345678);value->setText("305419896");first->click();
        numeric=numeric && results->rowCount()==1 && results->displayValueAt(0,1)=="305419896" && results->displayValueAt(0,2)=="305419896";
        seed(big,0x12345679);results->refreshRange(0,0);
        numeric=numeric && results->displayValueAt(0,1)=="305419897" && results->displayValueAt(0,2)=="305419896";
        value->setText("305419897");next->click();
        const int row=records->rowCount();transfers=addResult() && transfers;
        ce::os::LinuxProcessHandle process(getpid());records->updateValues(&process);
        transfers=transfers && records->rowCount()==row+1 && records->data(records->index(row,4),Qt::DisplayRole).toString()=="305419897";
        transfers=records->setData(records->index(row,4),"305419898",Qt::EditRole) && transfers;
        transfers=transfers && memory[big ? 3 : 0]==0x7a && memory[4]==0xee;
        // Let the real verification timer observe this edit before intentionally
        // reusing the same fixture bytes with another encoding.
        awaitEditVerification();
    }
    first->click();type->setCurrentIndex(11);order->setCurrentIndex(order->findData(int(ce::ByteOrder::Big)));width->setCurrentIndex(width->findData(4));
    std::printf("GUI scan-format stage: pointer\n");
    seed(true,0x12345678);value->setText("0x12345678");first->click();
    bool pointers=results->rowCount()==1 && results->displayValueAt(0,1)=="0x12345678" && results->displayValueAt(0,2)=="0x12345678";
    const int row=records->rowCount();pointers=addResult() && pointers;
    pointers=records->setData(records->index(row,4),"0x12345679",Qt::EditRole) && pointers;
    pointers=pointers && memory[3]==0x79 && memory[4]==0xee && records->entries()[row].pointerWidth==4;
    awaitEditVerification();
    bool preserved=true;int errors=0;QTimer dismiss;dismiss.setInterval(5);
    QObject::connect(&dismiss,&QTimer::timeout,[&] {if(auto* box=qobject_cast<QMessageBox*>(QApplication::activeModalWidget())){++errors;box->accept();}});
    width->setCurrentIndex(width->findData(8));dismiss.start();next->click();dismiss.stop();
    std::printf("GUI scan-format stage: freeze\n");
    preserved=errors==1 && results->rowCount()==1 && results->displayValueAt(0,2)=="0x12345678";
    width->setCurrentIndex(width->findData(4));value->setText("0x12345679");next->click();
    preserved=preserved && results->rowCount()==1 && results->displayValueAt(0,2)=="0x12345679";
    records->setActive(records->entries()[row].id,true);memory[3]=0x22;
    ce::os::LinuxProcessHandle process(getpid());records->freezeWrite(&process);
    bool freeze=memory[3]==0x79 && memory[4]==0xee;
    records->setActive(records->entries()[row].id,false);
    auto json=records->toJson();ce::gui::AddressListModel loaded;loaded.setProcess(&process);loaded.fromJson(json);loaded.updateValues(&process);
    bool persistence=loaded.entries()[row].pointerWidth==4 && loaded.entries()[row].dataByteOrder==ce::ByteOrder::Big && loaded.liveValue(loaded.entries()[row].id)=="0x12345679";
    QTemporaryDir directory;
    for(const auto& extension:{"ct","json"}) {
        std::printf("GUI scan-format stage: save %s\n",extension);
        const auto path=directory.filePath(QString("encoded.%1").arg(extension));bool dialogUsed=false,unexpectedError=false;
        bool prepared=false;
        QTimer choose;choose.setInterval(5);int chooserTicks=0;
        QObject::connect(&choose,&QTimer::timeout,[&] {
            if(++chooserTicks%200==0) {
                auto* active=QApplication::activeModalWidget();
                auto* dialog=qobject_cast<QFileDialog*>(active);
                std::printf("GUI save chooser: active=%s directory=%s selected=%s filter=%s\n",
                    active ? active->metaObject()->className():"none",
                    dialog ? dialog->directory().absolutePath().toUtf8().constData():"",
                    dialog ? dialog->selectedFiles().join(";").toUtf8().constData():"",
                    dialog ? dialog->selectedNameFilter().toUtf8().constData():"");
                const auto diagnostic=qgetenv("CE_GUI_SAVE_DIAGNOSTIC_IMAGE");
                if(active && !diagnostic.isEmpty())active->grab().save(QString::fromUtf8(diagnostic));
            }
            if(auto* dialog=qobject_cast<QFileDialog*>(QApplication::activeModalWidget())) {
                dialogUsed=true;
                if (!prepared) {
                    dialog->setDirectory(directory.path());
                    dialog->selectNameFilter(QString(extension)=="json" ? "JSON Tables (*.json)":"Cheat Tables (*.ct)");
                    prepared=true;
                }
                // selectFile() intentionally leaves a visible, focused filename
                // edit unchanged. Exercise that state deterministically, then
                // enter the name as a user would instead of repeatedly selecting.
                if (auto* edit=dialog->findChild<QLineEdit*>("fileNameEdit")) {
                    edit->setFocus();edit->setText(QFileInfo(path).fileName());
                } else dialog->selectFile(path);
                if (dialog->selectedFiles()==QStringList{path})
                    QMetaObject::invokeMethod(dialog,"accept",Qt::QueuedConnection);
            } else if(auto* box=qobject_cast<QMessageBox*>(QApplication::activeModalWidget())) {
                unexpectedError=true;
                std::printf("GUI scan-format save error: %s\n",box->text().toUtf8().constData());
                box->accept();
            }
        });
        choose.start();QMetaObject::invokeMethod(&main,"onSaveTable",Qt::DirectConnection);choose.stop();
        std::printf("GUI scan-format stage: save %s action returned\n",extension);
        ce::CheatTable table;bool read=table.loadAuto(path.toStdString());
        std::printf("GUI scan-format stage: load saved %s returned\n",extension);
        persistence=persistence && dialogUsed && !unexpectedError && read && table.entries.size()==size_t(records->rowCount()) &&
            table.entries[row].dataByteOrder==ce::ByteOrder::Big && table.entries[row].pointerWidth==4;
    }
    std::printf("GUI scan-format stage: final next scan\n");
    value->setText("0x12345679");next->click();
    bool rendered=true;
    if(!screenshot.isEmpty()) {main.resize(1200,800);main.show();QApplication::processEvents();rendered=main.grab().save(screenshot);}
    std::printf("GUI scan data formats: %s (numeric=%d transfer=%d pointers=%d invalid-width=%d freeze=%d persistence=%d screenshot=%d)\n",
        numeric&&transfers&&pointers&&preserved&&freeze&&persistence&&rendered ? "OK":"FAILED",numeric,transfers,pointers,preserved,freeze,persistence,rendered);
    return numeric&&transfers&&pointers&&preserved&&freeze&&persistence&&rendered;
}
