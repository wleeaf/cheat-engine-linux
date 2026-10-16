#include "core/ct_file.hpp"
#include "core/simple_address_list.hpp"
#include "scripting/lua_engine.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
using namespace ce;
static unsigned checks,failures;
static void check(bool good,const char* label) {++checks;failures+=!good;printf("%s: %s\n",good ? "OK":"FAILED",label);fflush(stdout);}
static std::string readFile(const std::filesystem::path& path) {std::ifstream f(path);return {std::istreambuf_iterator<char>(f),std::istreambuf_iterator<char>()};}
static bool has(const std::string& text,const char* part) {return text.find(part)!=std::string::npos;}
// One Cheat Engine record inside a whole table.
static std::string ceTable(const std::string& records) {return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<CheatTable CheatEngineTableVersion=\"45\">\n<CheatEntries>\n"+records+"</CheatEntries>\n</CheatTable>\n";}
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
    // Cheat Engine format fidelity: what CE writes loads, and a save writes it back.
    auto saveAndRead=[&](const CheatTable& t,const char* name) {
        const auto path=directory/name;
        return t.save(path.string()) ? readFile(path) : std::string();
    };
    {
        CheatTable t;
        const bool loaded=t.loadFromString(ceTable(
            "<CheatEntry><ID>1</ID><Description>\"hp\"</Description><VariableType>4 Bytes</VariableType><Address>400000</Address>"
            "<Hotkeys>"
            "<Hotkey><Action>Toggle Activation</Action><Keys><Key>17</Key><Key>72</Key></Keys><ID>0</ID></Hotkey>"
            "<Hotkey><Action>Set Value</Action><Keys><Key>116</Key></Keys><Value>100</Value><ID>1</ID></Hotkey>"
            "<Hotkey><Action>Activate</Action><Keys><Key>117</Key></Keys><ID>2</ID></Hotkey>"
            "<Hotkey Active=\"0\"><Action>Toggle Activation</Action><Keys><Key>118</Key></Keys><Description>off</Description><ID>3</ID></Hotkey>"
            "<Hotkey><Action>Decrease Value</Action><Keys><Key>119</Key></Keys><Value>5</Value><ID>4</ID></Hotkey>"
            "</Hotkeys></CheatEntry>\n"
            "<CheatEntry><ID>2</ID><Description>\"old\"</Description><VariableType>4 Bytes</VariableType><Address>400004</Address>"
            "<Hotkeys><Hotkey><Action>6</Action><Keys><Key>120</Key></Keys><Value>2</Value></Hotkey></Hotkeys></CheatEntry>\n"));
        const auto disk=saveAndRead(t,"hotkeys.CT");
        CheatTable back;back.loadFromString(disk);
        const auto& e=t.entries[0];
        check(loaded && t.entries.size()==2 && e.hotkeyKeys=="Ctrl+H" && e.setValueHotkeyKeys=="F5" && e.setValueHotkeyValue=="100" &&
            e.decreaseHotkeyKeys=="F8" && e.hotkeyStep=="5" && has(e.extraHotkeysXml,"<Action>Activate</Action>") &&
            has(e.extraHotkeysXml,"<Description>off</Description>") && t.entries[1].increaseHotkeyKeys=="F9" &&
            has(disk,"<Action>Set Value</Action>") && has(disk,"<Action>Decrease Value</Action>") && !has(disk,"<Action>5</Action>") &&
            has(disk,"<Hotkey Active=\"0\">") && back.entries.size()==2 && back.entries[0].hotkeyKeys=="Ctrl+H" &&
            back.entries[0].setValueHotkeyKeys=="F5" && back.entries[0].extraHotkeysXml==e.extraHotkeysXml,
            "CE hotkey action texts load, and every hotkey is written back with CE's action text");
    }
    {
        CheatTable t;
        t.loadFromString(ceTable("<CheatEntry><ID>1</ID><Description>\"mode\"</Description><VariableType>4 Bytes</VariableType><Address>400000</Address>"
            "<DropDownList DescriptionOnly=\"1\" DisplayValueAsItem=\"1\">0:Off\r\n1:On\r\n</DropDownList></CheatEntry>\n"));
        const auto disk=saveAndRead(t,"dropdown.CT");
        check(t.entries.size()==1 && t.entries[0].dropdownList=="0:Off\n1:On\n" &&
            t.entries[0].dropdownAttributes=="DescriptionOnly=\"1\" DisplayValueAsItem=\"1\"" &&
            has(disk,"<DropDownList DescriptionOnly=\"1\" DisplayValueAsItem=\"1\">0:Off\n1:On\n</DropDownList>"),
            "a CE dropdown list with attributes loads one choice per line and saves with its attributes");
    }
    {
        CheatTable t;
        t.loadFromString(ceTable("<CheatEntry><ID>1</ID><Description>\"p\"</Description><VariableType>4 Bytes</VariableType>"
            "<Address>\"game.exe\"+10</Address><Offsets><Offset>player_ofs</Offset><Offset Interval=\"100\">8</Offset></Offsets></CheatEntry>\n"
            "<CheatEntry><ID>2</ID><Description>\"q\"</Description><VariableType>4 Bytes</VariableType>"
            "<Address>game.exe+20</Address><Offsets><Offset>4</Offset><Offset Interval=\"100\">8</Offset></Offsets></CheatEntry>\n"));
        const auto disk=saveAndRead(t,"offsets.CT");
        check(t.entries.size()==2 && t.entries[0].address==0 && t.entries[0].offsets.empty() &&
            t.entries[0].unparsedOffsets==std::vector<std::string>{"player_ofs","8"} &&
            has(disk,"<Address>\"game.exe\"+10</Address>") && has(disk,"<Offset>player_ofs</Offset>") &&
            t.entries[1].offsets==std::vector<int64_t>{4,8},
            "a symbolic offset keeps the record's base and offsets for the save, and an offset with attributes is read");
    }
    {
        CheatTable t;
        t.loadFromString(ceTable("<CheatEntry><ID>1</ID><Description>\"god\"</Description><VariableType>Auto Assembler Script</VariableType>"
            "<AssemblerScript Async=\"1\">[ENABLE]\nnop\n[DISABLE]\nnop\n</AssemblerScript></CheatEntry>\n"));
        const auto disk=saveAndRead(t,"async.CT");
        check(t.entries.size()==1 && t.entries[0].autoAsmScript=="[ENABLE]\nnop\n[DISABLE]\nnop\n" && t.entries[0].asyncScript &&
            has(disk,"<AssemblerScript Async=\"1\">[ENABLE]") && has(disk,"<VariableType>Auto Assembler Script</VariableType>"),
            "an Async Auto Assembler script loads as a script record and keeps Async on save");
    }
    {
        CheatTable t;
        t.loadFromString(ceTable(
            "<CheatEntry><ID>1</ID><Description>\"sig\"</Description><VariableType>Array of byte</VariableType><ByteLength>6</ByteLength><Address>400000</Address></CheatEntry>\n"
            "<CheatEntry><ID>2</ID><Description>\"old\"</Description><VariableType>Array of byte</VariableType><Length>4</Length><Address>400010</Address></CheatEntry>\n"
            "<CheatEntry><ID>3</ID><Description>\"c\"</Description><VariableType>Custom</VariableType><CustomType>Float Big Endian</CustomType><Address>400020</Address></CheatEntry>\n"
            "<CheatEntry><ID>4</ID><Description>\"b\"</Description><VariableType>Binary</VariableType><BitStart>3</BitStart><BitLength>2</BitLength><ShowAsBinary>1</ShowAsBinary><Address>400030</Address></CheatEntry>\n"
            "<CheatEntry><ID>5</ID><Description>\"s\"</Description><VariableType>String</VariableType><Length>8</Length><Unicode>0</Unicode><CodePage>1</CodePage><ZeroTerminate>1</ZeroTerminate><Address>400040</Address></CheatEntry>\n"));
        const auto disk=saveAndRead(t,"lengths.CT");
        check(t.entries.size()==5 && t.entries[0].length==6 && t.entries[1].length==4 && t.entries[2].customTypeName=="Float Big Endian" &&
            has(disk,"<ByteLength>6</ByteLength>") && has(disk,"<ByteLength>4</ByteLength>") &&
            has(disk,"<CustomType>Float Big Endian</CustomType>") && has(disk,"<BitStart>3</BitStart>") &&
            has(disk,"<ShowAsBinary>1</ShowAsBinary>") && has(disk,"<CodePage>1</CodePage>") && has(disk,"<ZeroTerminate>1</ZeroTerminate>"),
            "ByteLength, CustomType and record elements we do not model survive a load and save");
    }
    {
        CheatTable t;
        t.loadFromString(ceTable("<CheatEntry><ID>1</ID><Description>\"player\"</Description><GroupHeader>1</GroupHeader>"
            "<Address>game.exe+100</Address><Offsets><Offset>18</Offset></Offsets><CheatEntries>"
            "<CheatEntry><ID>2</ID><Description>\"hp\"</Description><VariableType>4 Bytes</VariableType><Address>+10</Address></CheatEntry>"
            "</CheatEntries></CheatEntry>\n"));
        const auto disk=saveAndRead(t,"group.CT");
        CheatTable back;back.loadFromString(disk);
        check(t.entries.size()==2 && t.entries[0].isGroup && t.entries[0].addressString=="game.exe+100" &&
            t.entries[0].offsets==std::vector<int64_t>{0x18} && t.entries[1].addressString=="+10" &&
            back.entries.size()==2 && back.entries[0].addressString=="game.exe+100" && back.entries[0].offsets==t.entries[0].offsets &&
            back.entries[1].parentId==back.entries[0].id && back.entries[1].addressString=="+10",
            "an address group header keeps its address and offsets, and its child its relative address");
    }
    {
        std::string records;
        for (int i=0;i<20000;++i)
            records+="<CheatEntry><ID>"+std::to_string(i)+"</ID><Description>\"r\"</Description><VariableType>4 Bytes</VariableType><Address>"+std::to_string(400000+i)+"</Address></CheatEntry>\n";
        CheatTable t;
        const auto start=std::chrono::steady_clock::now();
        const bool loaded=t.loadFromString(ceTable(records));
        const auto seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
        check(loaded && t.entries.size()==20000 && seconds<5,"a table of 20000 flat records loads in linear time");
    }
    {
        CheatTable t;CheatEntry e;e.id=1;e.type=ValueType::Int32;e.addressString="[[game.exe+1C]+8]+10";t.entries={e};
        CheatTable back;back.loadFromString(saveAndRead(t,"chain.CT"));
        check(back.entries.size()==1 && back.entries[0].addressString=="game.exe+1C" && back.entries[0].offsets==std::vector<int64_t>{0x10,0x8},
            "a pointer path kept as one expression is saved as CE's base and offsets");
    }
    {
        CheatTable t;
        t.loadFromString(ceTable(
            "<CheatEntry><ID>1</ID><Description>\"red\"</Description><Color>0000FF</Color><VariableType>4 Bytes</VariableType><Address>400000</Address></CheatEntry>\n"
            "<CheatEntry><ID>2</ID><Description>\"sys\"</Description><Color>80000008</Color><VariableType>4 Bytes</VariableType><Address>400004</Address></CheatEntry>\n"));
        CheatTable mine;CheatEntry e;e.id=1;e.type=ValueType::Int32;e.address=0x1000;e.color="#3366cc";mine.entries={e};
        const auto disk=saveAndRead(mine,"color.CT");
        check(t.entries.size()==2 && t.entries[0].color=="FF0000" && t.entries[1].color.empty() && has(disk,"<Color>CC6633</Color>"),
            "CE colors convert from and to Delphi BGR, and system colors mean the default");
    }
    {
        {std::ofstream f(directory/"mentions.json");f<<R"({"comment":"pasted <CheatTable> text","entries":[]})";}
        check(detectTableFormat((directory/"mentions.json").string())==TableFormat::Json,"a JSON table that mentions <CheatTable> is still JSON");
    }
    {
        CheatTable t;
        t.loadFromString(ceTable("<CheatEntry><ID>1</ID><Description>\"a&#x27;b&#10;c\"</Description><VariableType>Auto Assembler Script</VariableType>"
            "<AssemblerScript><![CDATA[[ENABLE]\nmov eax,[rbx+4] // a<b & c\n[DISABLE]\n]]></AssemblerScript></CheatEntry>\n"));
        check(t.entries.size()==1 && t.entries[0].description=="a'b\nc" && t.entries[0].autoAsmScript=="[ENABLE]\nmov eax,[rbx+4] // a<b & c\n[DISABLE]\n",
            "numeric character references and CDATA sections read as text");
    }
    {
        CheatTable t;StructureDefinition s;s.name="S";s.size=16;s.fields.push_back({"name",0,ValueType::UnicodeString,16,"",""});t.structures={s};
        CheatTable back;back.loadFromString(saveAndRead(t,"structure.CT"));
        check(back.structures.size()==1 && back.structures[0].fields.size()==1 && back.structures[0].fields[0].type==ValueType::UnicodeString,
            "a Unicode string structure field stays Unicode");
    }
    {
        {std::ofstream f(directory/"options.json");f<<R"({"entries":[{"id":1,"desc":"g","group":true,"options":"<Options/></CheatEntry><CheatEntry>","extraXml":"</CheatEntries>"}]})";}
        CheatTable t;
        const bool loaded=t.loadJson((directory/"options.json").string());
        const auto disk=saveAndRead(t,"options.CT");
        CheatTable back;
        check(loaded && back.loadFromString(disk) && back.entries.size()==1 && !has(disk,"<Options/></CheatEntry>") && !has(disk,"\n      </CheatEntries>"),
            "raw XML from a JSON table cannot open or close records in the .CT");
    }
    {
        setenv("CECORE_LUA_ALLOW_UNSAFE","1",1);   // saveTable writes a file
        SimpleAddressList list;LuaEngine lua;lua.setAddressList(&list);
        const auto path=(directory/"lua.CT").string();
        const auto error=lua.execute("local r=createMemoryRecord(); r.Description='hp'; r.Address=0x1000; r.Type=2\n"
            "assert(saveTable('"+path+"'))\n");
        CheatTable back;
        check(error.empty() && detectTableFormat(path)==TableFormat::Xml && back.load(path) && back.entries.size()==1,
            "Lua saveTable writes Cheat Engine XML to a .CT name");
    }
    {
        CheatTable t;
        t.loadFromString(ceTable(
            "<CheatEntry><ID>1</ID><Description>\"a\"</Description><VariableType>4 Bytes</VariableType><Address>400000</Address>"
            "<Hotkeys><Hotkey><Action>Activate</Action><Keys><Key>117</Key></Keys><ID>0</ID></Hotkey>"
            "<Hotkey><Action>Deactivate</Action><Keys><Key>118</Key></Keys><ID>1</ID></Hotkey></Hotkeys></CheatEntry>\n"
            "<CheatEntry><ID>2</ID><Description>\"b\"</Description><VariableType>4 Bytes</VariableType><Address>400004</Address>"
            "<Hotkeys><Hotkey><Action>Activate</Action><Keys><Key>117</Key></Keys><ID>0</ID></Hotkey>"
            "<Hotkey><Action>Toggle Activation</Action><Keys><Key>17</Key><Key>72</Key></Keys><ID>1</ID></Hotkey></Hotkeys></CheatEntry>\n"
            "<CheatEntry><ID>3</ID><Description>\"c\"</Description><VariableType>4 Bytes</VariableType><Address>400008</Address>"
            "<Hotkeys><Hotkey><Action>Increase Value</Action><Keys><Key>120</Key></Keys><Value>2</Value><ID>0</ID></Hotkey>"
            "<Hotkey><Action>Decrease Value</Action><Keys><Key>119</Key></Keys><Value>5</Value><ID>1</ID></Hotkey></Hotkeys></CheatEntry>\n"));
        check(t.entries.size()==3 && t.entries[0].hotkeyKeys=="F6" && has(t.entries[0].extraHotkeysXml,"<Action>Deactivate</Action>") &&
            t.entries[1].hotkeyKeys=="Ctrl+H" && has(t.entries[1].extraHotkeysXml,"<Action>Activate</Action>"),
            "an Activate hotkey fills the toggle slot when no plain toggle does");
        check(t.entries.size()==3 && t.entries[2].increaseHotkeyKeys=="F9" && t.entries[2].decreaseHotkeyKeys=="F8" &&
            t.entries[2].hotkeyStep=="2",
            "increase and decrease hotkeys with different steps both bind, with the first step");
        // A save writes the hotkeys a slot borrowed as they were: the Activate
        // stays Activate, and each step stays its own.
        auto hotkeys=[](const std::string& disk,int record) {
            size_t at=0;
            for (int i=0;i<=record;++i) at=disk.find("<CheatEntry>",at+1);
            const size_t end=disk.find("</CheatEntry>",at);
            return disk.substr(at,end-at);
        };
        const auto disk=saveAndRead(t,"borrowed.CT");
        CheatTable back;back.loadFromString(disk);
        const auto first=hotkeys(disk,0),third=hotkeys(disk,2);
        auto count=[](const std::string& text,const std::string& part) {
            size_t n=0;for (size_t at=text.find(part);at!=std::string::npos;at=text.find(part,at+1)) ++n;return n;
        };
        check(!has(first,"Toggle Activation") && count(first,"<Action>Activate</Action>")==1 && count(first,"<Hotkey>")==2 &&
            has(third,"<Action>Increase Value</Action>") && has(third,"<Value>2</Value>") &&
            has(third,"<Action>Decrease Value</Action><Keys><Key>119</Key></Keys><Value>5</Value>") && count(third,"<Hotkey>")==2 &&
            back.entries.size()==3 && back.entries[0].hotkeyKeys=="F6" && back.entries[2].decreaseHotkeyKeys=="F8" &&
            back.entries[2].hotkeyStep=="2" && saveAndRead(back,"borrowed-again.CT")==disk,
            "a save writes borrowed hotkeys with their own actions and steps, and a reload binds them the same way");
        // A plain toggle and an Activate on the same keys both survive.
        CheatTable same;
        same.loadFromString(ceTable("<CheatEntry><ID>1</ID><Description>\"d\"</Description><VariableType>4 Bytes</VariableType><Address>400000</Address>"
            "<Hotkeys><Hotkey><Action>Toggle Activation</Action><Keys><Key>117</Key></Keys><ID>0</ID></Hotkey>"
            "<Hotkey><Action>Activate</Action><Keys><Key>117</Key></Keys><ID>1</ID></Hotkey></Hotkeys></CheatEntry>\n"));
        const auto sameDisk=saveAndRead(same,"same-keys.CT");
        check(same.entries.size()==1 && same.entries[0].hotkeyKeys=="F6" && count(sameDisk,"<Action>Toggle Activation</Action>")==1 &&
            count(sameDisk,"<Action>Activate</Action>")==1 && count(sameDisk,"<Hotkey>")==2,
            "a toggle and an Activate on the same keys are each written once");
        // A key changed after loading is written as the slot's own action.
        CheatTable edited=t;edited.entries[0].hotkeyKeys="F2";
        const auto editedDisk=hotkeys(saveAndRead(edited,"edited.CT"),0);
        check(has(editedDisk,"<Action>Toggle Activation</Action>") && has(editedDisk,"<Key>113</Key>") &&
            !has(editedDisk,"<Action>Activate</Action>") && !has(editedDisk,"<Key>117</Key>") &&
            has(editedDisk,"<Action>Deactivate</Action>") && count(editedDisk,"<Hotkey>")==2,
            "a borrowed hotkey changed after loading is saved as the slot's own, without the old key");
        // A cleared slot drops the element it borrowed; other kept hotkeys stay.
        CheatTable cleared=t;cleared.entries[0].hotkeyKeys.clear();
        const auto clearedDisk=saveAndRead(cleared,"cleared.CT");
        CheatTable clearedBack;clearedBack.loadFromString(clearedDisk);
        const auto clearedFirst=hotkeys(clearedDisk,0);
        check(!has(clearedFirst,"<Action>Activate</Action>") && !has(clearedFirst,"<Key>117</Key>") &&
            has(clearedFirst,"<Action>Deactivate</Action>") && count(clearedFirst,"<Hotkey>")==1 &&
            clearedBack.entries.size()==3 && clearedBack.entries[0].hotkeyKeys=="F7",
            "a cleared slot drops the hotkey it borrowed, so the old key does not come back");
        // A changed step drops a decrease hotkey kept for its own step.
        CheatTable stepped=t;stepped.entries[2].hotkeyStep="3";
        const auto steppedThird=hotkeys(saveAndRead(stepped,"stepped.CT"),2);
        check(has(steppedThird,"<Action>Decrease Value</Action>") && has(steppedThird,"<Key>119</Key>") &&
            count(steppedThird,"<Value>3</Value>")==2 && !has(steppedThird,"<Value>5</Value>") && count(steppedThird,"<Hotkey>")==2,
            "a changed step writes the decrease hotkey with the new step only");
        // The marks survive the JSON form and never reach a .CT.
        CheatTable viaJson;
        const bool jsonOk=t.saveJson((directory/"borrowed.json").string()) && viaJson.loadJson((directory/"borrowed.json").string());
        viaJson.entries[0].hotkeyKeys.clear();
        const auto viaJsonDisk=jsonOk ? saveAndRead(viaJson,"borrowed-json.CT") : std::string();
        check(jsonOk && !has(hotkeys(viaJsonDisk,0),"<Action>Activate</Action>") && !has(viaJsonDisk,"LinuxSlot") &&
            !has(disk,"LinuxSlot") && !has(clearedDisk,"LinuxSlot"),
            "a slot cleared after a JSON round trip drops its borrowed hotkey, and no .CT carries the marks");
    }
    {
        // Saving keeps what an ordinary save keeps: a read-only table stays
        // untouched, links and hard links stay, and an unwritable directory
        // still lets a writable table be saved.
        const bool root=geteuid()==0;
        const auto readOnly=directory/"readonly.ct";
        table.save(readOnly.string());
        const auto before=readFile(readOnly);
        chmod(readOnly.c_str(),0444);
        CheatTable changed=table;changed.gameName="changed";
        check(root || (!changed.save(readOnly.string()) && readFile(readOnly)==before),"a read-only table is not replaced");
        chmod(readOnly.c_str(),0644);

        const auto linked=directory/"linked.ct",second=directory/"second-name.ct";
        table.save(linked.string());
        std::filesystem::create_hard_link(linked,second);
        struct stat a{},b{};
        check(changed.save(linked.string()) && has(readFile(second),"changed") && stat(linked.c_str(),&a)==0 &&
            stat(second.c_str(),&b)==0 && a.st_ino==b.st_ino,"a save keeps a table's hard links");

        const auto real=directory/"real.ct",link=directory/"link.ct",dangling=directory/"dangling.ct";
        table.save(real.string());
        std::filesystem::create_symlink("real.ct",link);
        std::filesystem::create_symlink("missing/none.ct",dangling);
        check(changed.save(link.string()) && std::filesystem::is_symlink(link) && has(readFile(real),"changed") &&
            !changed.save(dangling.string()) && std::filesystem::is_symlink(dangling),
            "a save writes through a symlink that resolves and refuses a dangling one");

        const auto locked=directory/"locked";
        std::filesystem::create_directory(locked);
        table.save((locked/"t.ct").string());
        chmod(locked.c_str(),0555);
        bool savedLocked=changed.save((locked/"t.ct").string()) && has(readFile(locked/"t.ct"),"changed");
        size_t names=0;for (const auto& entry:std::filesystem::directory_iterator(locked)) {(void)entry;++names;}
        chmod(locked.c_str(),0755);
        check(savedLocked && names==1,"a writable table in an unwritable directory is saved in place");
        std::filesystem::remove_all(locked);
        for (const auto& path:{readOnly,linked,second,real,link,dangling}) std::filesystem::remove(path);
    }
    table.save((directory/"keep.ct").string());
    // A hard-linked table is rewritten in place.
    const auto inPlace=directory/"inplace.ct",inPlaceLink=directory/"inplace-link.ct";
    table.save(inPlace.string());
    std::filesystem::create_hard_link(inPlace,inPlaceLink);
    const auto inPlaceBefore=readFile(inPlace);
    CheatTable bigger=table;bigger.comment=std::string(65536,'x');
    rlimit previous{};struct sigaction ignored{},oldAction{};ignored.sa_handler=SIG_IGN;sigemptyset(&ignored.sa_mask);
    const bool haveLimit=getrlimit(RLIMIT_FSIZE,&previous)==0;
    const bool haveSignal=sigaction(SIGXFSZ,&ignored,&oldAction)==0;
    bool limitReady=haveLimit && haveSignal;
    rlimit limited=previous;limited.rlim_cur=64;
    limitReady=limitReady && setrlimit(RLIMIT_FSIZE,&limited)==0;
    const auto serializedSize=std::filesystem::file_size(directory/"table.json");
    bool failedXml=false,failedJson=false,failedProtected=false,failedInPlace=false;
    if(limitReady) {
        failedXml=!table.save((directory/"failure.ct").string()) && !table.save((directory/"keep.ct").string());
        failedJson=!table.saveJson((directory/"failure.json").string());
        // Too little room for the new table: the old one stays whole.
        limited.rlim_cur=inPlaceBefore.size()+16;
        if(setrlimit(RLIMIT_FSIZE,&limited)==0)
            failedInPlace=!bigger.save(inPlace.string()) && readFile(inPlace)==inPlaceBefore &&
                std::filesystem::file_size(inPlace)==inPlaceBefore.size();
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
    check(limitReady && failedInPlace,"a failed in-place save leaves the previous table whole");
    check(bigger.save(inPlace.string()) && readFile(inPlaceLink)==readFile(inPlace) && has(readFile(inPlace),"xxxx") &&
        table.save(inPlace.string()) && readFile(inPlaceLink)==inPlaceBefore,
        "an in-place save grows and shrinks the table through its hard link");
    check(restored,"the owned integration process restores its original file-size limit");
    {
        CheatTable kept;bool leftovers=false;
        for (const auto& entry:std::filesystem::directory_iterator(directory)) leftovers|=entry.path().filename().string().rfind(".",0)==0;
        check(limitReady && kept.load((directory/"keep.ct").string()) && kept.entries.size()==2 && !leftovers,
            "a failed save leaves the previous table whole and no temporary file behind");
    }
    std::filesystem::remove_all(directory);
    printf("TABLE_PERSISTENCE_RESULT=%s checks=%u failures=%u\n",failures ? "FAILED":"PASSED",checks,failures);
    return failures ? 1:0;
}
