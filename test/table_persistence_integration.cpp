#include "core/ct_file.hpp"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <signal.h>
#include <sys/resource.h>
#include <unistd.h>
using namespace ce;
static unsigned checks,failures;
static void check(bool good,const char* label) {++checks;failures+=!good;printf("%s: %s\n",good ? "OK":"FAILED",label);fflush(stdout);}
int main() {
    alarm(20);
    auto directory=std::filesystem::temp_directory_path()/std::string("ce-table-save-XXXXXX");
    auto name=directory.string();if(!mkdtemp(name.data()))return 2;directory=name;
    CheatTable table;table.gameName="format fixture";table.comment="UTF-8 \xc3\xa9";
    table.rawFormsXml="<Form Name=\"Preserved\"/>";
    CheatEntry root;root.id=0;root.isGroup=true;root.description="root";
    CheatEntry record;record.id=42;record.parentId=0;record.address=0x12345678;
    record.description="four-byte pointer";record.type=ValueType::Pointer;
    record.dataByteOrder=ByteOrder::Big;record.pointerWidth=4;
    table.entries={root,record};
    CheatTable xml,json,protectedTable;
    check(table.save((directory/"table.ct").string()) && xml.load((directory/"table.ct").string()) &&
        xml.entries.size()==2 && xml.entries[1].parentId==0,"XML preserves a valid group ID zero and its child's stable parent");
    check(table.saveJson((directory/"table.json").string()) && json.loadJson((directory/"table.json").string()) &&
        json.rawFormsXml==table.rawFormsXml,"native JSON preserves imported raw form metadata");
    check(table.saveProtected((directory/"table.cetrainer").string(),"pw") && protectedTable.loadProtected((directory/"table.cetrainer").string(),"pw") &&
        protectedTable.rawFormsXml==table.rawFormsXml,"protected tables preserve form metadata through their JSON payload");
    auto same=[&](const CheatTable& t){return t.entries.size()==2 && t.entries[1].id==42 && t.entries[1].address==record.address && t.entries[1].type==ValueType::Pointer && t.entries[1].dataByteOrder==ByteOrder::Big && t.entries[1].pointerWidth==4;};
    check(same(xml)&&same(json)&&same(protectedTable),"all table formats preserve pointer addresses, types, widths, data order and stable IDs");
    {
        std::ofstream f(directory/"gui.json");
        f<<R"({"process":"GUI fixture","entries":[{"id":10,"description":"group","group":true},{"id":42,"description":"pointer","address":"0x12345678","type":"pointer","pointerWidth":4,"dataByteOrder":"big","parent":0,"addressExpr":"[game+10]","byteCount":12}]})";
    }
    CheatTable gui;check(gui.loadJson((directory/"gui.json").string()) && gui.entries.size()==2 &&
        gui.entries[1].address==0x12345678 && gui.entries[1].description=="pointer" && gui.entries[1].type==ValueType::Pointer &&
        gui.entries[1].length==12 && gui.entries[1].addressString=="[game+10]",
        "the core reads GUI JSON addresses, pointer types, descriptions, expressions and lengths");
    check(gui.gameName=="GUI fixture" && gui.entries[1].parentId==10,"GUI parent rows become the correct stable parent IDs in the core model");
    rlimit previous{};struct sigaction ignored{},oldAction{};ignored.sa_handler=SIG_IGN;sigemptyset(&ignored.sa_mask);
    const bool haveLimit=getrlimit(RLIMIT_FSIZE,&previous)==0;
    const bool haveSignal=sigaction(SIGXFSZ,&ignored,&oldAction)==0;
    bool limitReady=haveLimit && haveSignal;
    rlimit limited=previous;limited.rlim_cur=64;
    limitReady=limitReady && setrlimit(RLIMIT_FSIZE,&limited)==0;
    const auto serializedSize=std::filesystem::file_size(directory/"table.json");
    bool failedXml=false,failedJson=false,failedProtected=false;
    if(limitReady) {
        failedXml=!table.save((directory/"failure.ct").string());
        failedJson=!table.saveJson((directory/"failure.json").string());
        // Let the JSON staging file succeed, then reject the larger encrypted
        // payload plus header. This exercises the protected output's own flush.
        limited.rlim_cur=serializedSize;
        if(setrlimit(RLIMIT_FSIZE,&limited)==0)
            failedProtected=!table.saveProtected((directory/"failure.cetrainer").string(),"pw");
    }
    bool restored=haveLimit && setrlimit(RLIMIT_FSIZE,&previous)==0;
    if(haveSignal)sigaction(SIGXFSZ,&oldAction,nullptr);
    clearerr(stdout);clearerr(stderr);
    check(limitReady && failedXml,"XML reports actual buffered-write failure rather than successful serialization");
    check(limitReady && failedJson,"JSON reports actual buffered-write failure rather than successful serialization");
    check(limitReady && failedProtected,"protected-table saves report actual buffered-write failure");
    check(restored,"the owned integration process restores its original file-size limit");
    std::filesystem::remove_all(directory);
    printf("TABLE_PERSISTENCE_RESULT=%s checks=%u failures=%u\n",failures ? "FAILED":"PASSED",checks,failures);
    return failures ? 1:0;
}
