#include <sys/resource.h>
#include <QDir>
#include <QFile>
#include <QSettings>
#include <QJsonObject>
#include <limits>
#include <unordered_set>
static bool guiTableSaveChecks() {
    QTemporaryDir directory;
    const auto native=directory.filePath("source.json");
    alignas(8) std::array<uint8_t,8> memory{0x12,0x34,0x56,0x78,0xee,0xee,0xee,0xee};
    ce::CheatTable source;source.gameName="Imported game";source.gameVersion="2.5";source.author="fixture author";
    source.comment="metadata \xc3\xa9";source.luaScript="error('must not run without consent')";
    source.rawFormsXml="<Form Name=\"Kept\"/>";
    ce::StructureDefinition structure;structure.name="Object";structure.size=16;
    source.structures.push_back(structure);
    ce::CheatEntry group;group.id=0;group.isGroup=true;group.description="Root";
    group.activateChildren=false;group.deactivateChildren=false;
    ce::CheatEntry pointer;pointer.id=42;pointer.parentId=0;pointer.description="Pointer";
    pointer.address=reinterpret_cast<uintptr_t>(memory.data());pointer.type=ce::ValueType::Pointer;
    pointer.pointerWidth=4;pointer.dataByteOrder=ce::ByteOrder::Big;
    source.entries={group,pointer};
    if(!source.saveJson(native.toStdString()))return false;
    // Exercise shared metadata decoding, rather than only unescaped UTF-8.
    QFile escaped(native);
    if(!escaped.open(QIODevice::ReadOnly))return false;
    auto sourceBytes=escaped.readAll();escaped.close();
    sourceBytes.replace("\xc3\xa9","\\u00e9");
    if(!escaped.open(QIODevice::WriteOnly|QIODevice::Truncate) || escaped.write(sourceBytes)!=sourceBytes.size())return false;
    escaped.close();
    ce::gui::MainWindow main;main.attachToPid(getpid(),"table fixture");
    QStringList errors;int prompts=0;
    QTimer dismiss;dismiss.setInterval(5);
    QObject::connect(&dismiss,&QTimer::timeout,[&] {
        if(auto* box=qobject_cast<QMessageBox*>(QApplication::activeModalWidget())) {
            if(box->standardButtons()&QMessageBox::No){++prompts;box->done(QMessageBox::No);}
            else {errors.push_back(box->text());box->accept();}
        }
    });
    dismiss.start();main.loadTableFromPath(native);dismiss.stop();
    auto* model=main.findChild<ce::gui::AddressListModel*>();
    bool loaded=model && model->entries().size()==2 && model->entries()[0].id==0 && model->entries()[1].id==42 &&
        model->entries()[1].indent==1 && model->entries()[1].address==pointer.address &&
        model->entries()[1].type==ce::ValueType::Pointer && model->entries()[1].pointerWidth==4;
    if(!loaded)return false;
    const auto fixtureCodec=ce::ValueCodec::parse("xor:0x5a");
    if(!fixtureCodec)return false;
    model->setEntryCodec(1,*fixtureCodec);
    auto xml=directory.filePath("saved.CT"),json=directory.filePath("saved.json");
    bool written=main.saveTableToPath(xml) && main.saveTableToPath(json);
    ce::CheatTable savedXml,savedJson;
    auto metadata=[&](const ce::CheatTable& table) {
        return table.gameName==source.gameName && table.gameVersion==source.gameVersion && table.author==source.author &&
            table.comment==source.comment && table.luaScript==source.luaScript && table.rawFormsXml==source.rawFormsXml &&
            table.structures.size()==1 && table.entries.size()==2 && !table.entries[0].activateChildren && !table.entries[0].deactivateChildren && table.entries[1].id==42 && table.entries[1].parentId==0 &&
            table.entries[1].address==pointer.address && table.entries[1].type==ce::ValueType::Pointer &&
            table.entries[1].pointerWidth==4 && table.entries[1].dataByteOrder==ce::ByteOrder::Big;
    };
    bool preserved=written && savedXml.loadAuto(xml.toStdString()) && savedJson.loadAuto(json.toStdString()) && metadata(savedXml) && metadata(savedJson);
    ce::gui::MainWindow reloaded;dismiss.start();reloaded.loadTableFromPath(json);dismiss.stop();
    auto* other=reloaded.findChild<ce::gui::AddressListModel*>();
    bool codec=other && other->entries().size()==2 && other->entries()[1].codec.describe()==model->entries()[1].codec.describe();
    QFile originalXml(xml),originalJson(json);
    if(!originalXml.open(QIODevice::ReadOnly) || !originalJson.open(QIODevice::ReadOnly))return false;
    auto xmlBytes=originalXml.readAll(),jsonBytes=originalJson.readAll();originalXml.close();originalJson.close();
    QSettings settings;
    // Flush successful-save settings before imposing a process-wide file-size
    // limit: nested error-dialog event loops must not flush unrelated writes.
    settings.sync();
    const bool settingsReady=settings.status()==QSettings::NoError;
    const auto recent=settings.value("recentTables");
    rlimit previous{};struct sigaction ignored{},oldAction{};ignored.sa_handler=SIG_IGN;sigemptyset(&ignored.sa_mask);
    const bool haveLimit=getrlimit(RLIMIT_FSIZE,&previous)==0;
    const bool haveSignal=sigaction(SIGXFSZ,&ignored,&oldAction)==0;
    bool limited=haveLimit && haveSignal;
    rlimit cap=previous;cap.rlim_cur=64;limited=limited && setrlimit(RLIMIT_FSIZE,&cap)==0;
    const int errorsBefore=errors.size();dismiss.start();
    bool failedXml=limited && !main.saveTableToPath(xml),failedJson=limited && !main.saveTableToPath(json);
    dismiss.stop();bool restored=haveLimit && setrlimit(RLIMIT_FSIZE,&previous)==0;
    if(haveSignal)sigaction(SIGXFSZ,&oldAction,nullptr);
    clearerr(stdout);clearerr(stderr);
    if(!originalXml.open(QIODevice::ReadOnly) || !originalJson.open(QIODevice::ReadOnly))return false;
    const bool xmlUnchanged=originalXml.readAll()==xmlBytes,jsonUnchanged=originalJson.readAll()==jsonBytes;
    const bool recentUnchanged=QSettings().value("recentTables")==recent;
    bool rollback=settingsReady && failedXml && failedJson && errors.size()==errorsBefore+2 && xmlUnchanged && jsonUnchanged &&
        recentUnchanged && restored;
    if (!rollback)
        printf("GUI_TABLE_SAVE_DIAGNOSTIC limited=%d settings=%d xmlRejected=%d jsonRejected=%d errors=%lld expectedErrors=2 xmlUnchanged=%d jsonUnchanged=%d recentUnchanged=%d restored=%d\n",
            limited,settingsReady,failedXml,failedJson,static_cast<long long>(errors.size()-errorsBefore),
            xmlUnchanged,jsonUnchanged,recentUnchanged,restored);
    bool tempClean=QDir(directory.path()).entryList(QDir::Files|QDir::Hidden).size()==3;
    auto title=reloaded.windowTitle();auto rowCount=other ? other->rowCount():0;
    QFile bad(directory.filePath("invalid.json"));
    if(!bad.open(QIODevice::WriteOnly) || bad.write("{\"entries\":[{\"pointerWidth\":3}]}\n")<=0)return false;
    bad.close();
    dismiss.start();reloaded.loadTableFromPath(bad.fileName());dismiss.stop();
    bool rejected=other && other->rowCount()==rowCount && reloaded.windowTitle()==title;
    if(!bad.open(QIODevice::WriteOnly|QIODevice::Truncate) || bad.write("{\"process\":\"fixture\",\"entries\":[{\"byteCount\":-1}]}\n")<=0)return false;
    bad.close();dismiss.start();reloaded.loadTableFromPath(bad.fileName());dismiss.stop();
    rejected=rejected && other->rowCount()==rowCount && reloaded.windowTitle()==title;
    ce::gui::AddressListModel ids;
    QJsonArray imported;
    for(int id:{std::numeric_limits<int>::max(),0,1,1}) {QJsonObject object;object["id"]=id;object["description"]="ID fixture";imported.append(object);}
    imported.append(QJsonObject{{"description","missing ID"}});
    ids.fromJson(imported);const int added=ids.addEntry(0,ce::ValueType::Int32,"added");
    std::unordered_set<int> unique;bool stable=ids.entries()[0].id==std::numeric_limits<int>::max() && ids.entries()[1].id==0;
    for(const auto& entry:ids.entries())stable=stable && entry.id>=0 && unique.insert(entry.id).second;
    stable=stable && unique.size()==6 && added>0 && ids.rowOfId(added)==5;
    QFile numeric(directory.filePath("numeric.json"));
    const auto maximum=std::numeric_limits<uintptr_t>::max();
    const auto fixture=QByteArray("{\"process\":\"mixed schema\",\"entries\":[{\"id\":7,\"description\":\"numeric pointer\",\"address\":")+QByteArray::number(qulonglong(maximum))+",\"type\":\"pointer\"}]}";
    if(!numeric.open(QIODevice::WriteOnly) || numeric.write(fixture)!=fixture.size())return false;
    numeric.close();ce::gui::MainWindow exact;dismiss.start();exact.loadTableFromPath(numeric.fileName());dismiss.stop();
    auto* exactModel=exact.findChild<ce::gui::AddressListModel*>();
    bool exactAddress=exactModel && exactModel->entries().size()==1 && exactModel->entries()[0].address==maximum;
    bool ok=loaded && preserved && codec && rollback && tempClean && rejected && prompts==2 && stable && exactAddress;
    printf("GUI table save: %s (load=%d metadata=%d codec=%d write-failure=%d cleanup=%d reject=%d consent=%d stable-IDs=%d exact-address=%d)\n",
        ok ? "OK":"FAILED",loaded,preserved,codec,rollback,tempClean,rejected,prompts==2,stable,exactAddress);
    return ok;
}
