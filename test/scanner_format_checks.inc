// Independent byte fixtures exercise scans against a host/program ABI mismatch.
#include "scanner/memory_scanner.hpp"
#include <fstream>
#include <sys/stat.h>

static void scannerFormatTests() {
    TargetBuffer p;
    p.bytes=std::vector<uint8_t>(64,0xcc);
    p.description.host=*parseElfTarget(elf(EM_X86_64,true));
    p.description.program=*parseElfTarget(elf(EM_PPC,false,true));
    MemoryScanner scanner(1);
    std::vector<std::filesystem::path> directories;
    auto first=[&](const ScanConfig& config) {
        auto result=scanner.firstScan(p,config);directories.push_back(result.directory().parent_path());return result;
    };
    auto next=[&](const ScanConfig& config,const ScanResult& previous) {
        auto result=scanner.nextScan(p,config,previous);directories.push_back(result.directory().parent_path());return result;
    };
    auto put=[&](size_t offset,uint64_t bits,size_t width,ByteOrder order) {
        for (size_t i=0;i<width;++i) p.bytes[offset+i]=static_cast<uint8_t>(bits>>(8*(order==ByteOrder::Big ? width-1-i : i)));
    };
    auto config=[&](ValueType type,size_t size=64) {
        ScanConfig c;c.valueType=type;c.startAddress=p.base;c.stopAddress=p.base+size-1;c.alignment=1;return c;
    };
    auto throws=[&](auto operation) {try {operation();return false;} catch (const std::invalid_argument&) {return true;}};
    bool integers=true,pointers=true,floating=true,strings=true,formats=true;
    for (auto order:{ByteOrder::Little,ByteOrder::Big}) {
        p.description.program.byteOrder=order;
        for (auto [type,width]:{std::pair{ValueType::Int16,2},std::pair{ValueType::Int32,4},std::pair{ValueType::Int64,8}}) {
            for (size_t alignment:{size_t(1),size_t(4)}) {
                std::fill(p.bytes.begin(),p.bytes.end(),0xcc);
                put(12,static_cast<uint64_t>(-1234),width,order);
                auto c=config(type);c.intValue=-1234;c.alignment=alignment;
                auto result=first(c);
                integers=integers && !result.hasWriteError() && result.count()==1 && result.address(0)==p.base+12 && result.valueSize()==size_t(width);
                std::array<uint8_t,8> raw{};result.value(0,raw.data(),width);
                integers=integers && std::equal(raw.begin(),raw.begin()+width,p.bytes.begin()+12);
                ValueIoOptions display;display.byteOrder=result.byteOrder();
                integers=integers && decodeTypedValue(type,{raw.data(),size_t(width)},display)=="-1234";
                put(12,static_cast<uint64_t>(-1200),width,order);c.compareType=ScanCompare::IncreasedBy;c.intValue=34;
                auto changed=next(c,result);integers=integers && changed.count()==1;
                changed.firstValue(0,raw.data(),width);put(12,static_cast<uint64_t>(-1234),width,order);
                integers=integers && std::equal(raw.begin(),raw.begin()+width,p.bytes.begin()+12);
                c.compareType=ScanCompare::SameAsFirst;
                integers=integers && next(c,changed).count()==1;
                c.compareType=ScanCompare::Between;c.intValue=-1300;c.intValue2=-1200;
                integers=integers && first(c).count()==1;
            }
        }
        for (uint8_t width:{4,8}) {
            std::fill(p.bytes.begin(),p.bytes.end(),0xcc);p.description.program.pointerWidth=width;
            const uint64_t value=width==4 ? 0xf1234567ull : 0xf123456789abcdefull;
            put(8,value,width,order);auto c=config(ValueType::Pointer);c.intValue=static_cast<int64_t>(value);
            auto result=first(c);pointers=pointers && result.count()==1 && result.valueSize()==width && result.pointerWidth()==width;
            put(8,value+3,width,order);c.compareType=ScanCompare::IncreasedBy;c.intValue=3;
            pointers=pointers && next(c,result).count()==1;
        }
        for (auto [type,width]:{std::pair{ValueType::Float,4},std::pair{ValueType::Double,8}}) {
            std::fill(p.bytes.begin(),p.bytes.end(),0xcc);
            put(8,width==4 ? 0x40200000ull : 0x4004000000000000ull,width,order); // IEEE 2.5
            auto c=config(type);c.floatValue=2.5;auto result=first(c);
            std::array<uint8_t,8> raw{};result.value(0,raw.data(),width);
            ValueIoOptions display;display.byteOrder=result.byteOrder();
            floating=floating && result.count()==1 && decodeTypedValue(type,{raw.data(),size_t(width)},display)=="2.5";
            put(8,width==4 ? 0x40600000ull : 0x400c000000000000ull,width,order); // IEEE 3.5
            c.compareType=ScanCompare::IncreasedBy;c.floatValue=1;
            floating=floating && next(c,result).count()==1;
            c.percentageScan=true;c.compareType=ScanCompare::Increased;c.percentageValue=40;
            floating=floating && next(c,result).count()==1;
            std::fill(p.bytes.begin(),p.bytes.end(),0xcc);
            put(8,width==4 ? 0x80000000ull : 0x8000000000000000ull,width,order); // negative zero
            c.compareType=ScanCompare::Exact;c.percentageScan=false;c.floatValue=0;
            floating=floating && first(c).count()==1;
        }
        std::fill(p.bytes.begin(),p.bytes.end(),0xcc);p.description.program.pointerWidth=4;
        put(8,0x0041,2,order);put(10,0x03a9,2,order);put(12,0xd83d,2,order);put(14,0xde00,2,order);
        auto c=config(ValueType::UnicodeString);c.stringValue="aΩ😀";c.caseSensitive=false;
        auto result=first(c);strings=strings && result.count()==1 && result.valueSize()==8;
        c.compareType=ScanCompare::Exact;strings=strings && next(c,result).count()==1;
        std::array<uint8_t,8> raw{};result.value(0,raw.data(),8);ValueIoOptions display;display.byteOrder=order;
        strings=strings && decodeTypedValue(ValueType::UnicodeString,raw,display)=="AΩ😀";
        put(0,0x10203040,4,order);p.bytes[4]=0x7a;
        c=config(ValueType::Grouped);std::string error;
        strings=strings && c.parseGrouped("pointer:0x10203040@0;byte:122@4;unicode:aΩ😀@8",&error);
        c.caseSensitive=false;auto grouped=first(c);
        strings=strings && grouped.count()==1 && grouped.address(0)==p.base && grouped.valueSize()==16;
        auto groupedChanged=next(c,grouped);strings=strings && groupedChanged.count()==1;
        c=config(ValueType::Int32);c.intValue=0x10203040;
        auto snapshot=first(c);ScanResult reopened(snapshot.directory());
        formats=formats && reopened.hasDataFormat() && reopened.byteOrder()==order && reopened.pointerWidth()==4 && !reopened.hasWriteError();
        auto pruned=pruneScanResult(reopened,4,std::vector<bool>(reopened.count(),false));
        directories.push_back(pruned->directory().parent_path());
        formats=formats && pruned->hasDataFormat() && pruned->byteOrder()==order && pruned->pointerWidth()==4 && pruned->count()==1;
        p.description.program.byteOrder=order==ByteOrder::Big ? ByteOrder::Little : ByteOrder::Big;
        formats=formats && throws([&]{next(c,reopened);});
        c.byteOrder=order;formats=formats && next(c,reopened).count()==1;
        p.description.program.byteOrder=order;
    }
    check(integers,"numeric scans preserve target-order bytes through exact, relational, delta and first-value comparisons");
    check(pointers,"four- and eight-byte unsigned pointers scan and narrow independently of frontend width");
    check(floating,"both floating widths scan target IEEE bytes, deltas, percentages and signed zero");
    check(strings,"UTF-16 case folding, BMP, surrogate pairs and mixed grouped terms follow target order");
    check(formats,"persisted, reloaded and pruned scan formats prevent accidental byte-order changes");

    p.description.program.byteOrder=ByteOrder::Big;p.description.program.pointerWidth=4;
    std::fill(p.bytes.begin(),p.bytes.end(),0xcc);put(60,0x12345678,4,ByteOrder::Big);
    auto boundary=config(ValueType::Int32);boundary.intValue=0x12345678;
    auto tail=first(boundary);check(tail.count()==1 && tail.address(0)==p.base+60,"inclusive To address admits a complete scalar ending at the last byte");
    boundary=config(ValueType::Byte);boundary.startAddress=boundary.stopAddress=p.base+63;boundary.intValue=0x78;
    check(first(boundary).count()==1,"a one-byte From/To scan includes its sole address");
    boundary=config(ValueType::Int32,63);boundary.intValue=0x12345678;
    check(first(boundary).count()==0,"a scalar cannot read past the inclusive To boundary");
    auto unknown=config(ValueType::Int32);p.description.program={};auto reads=p.reads.load();
    check(throws([&]{first(unknown);}) && p.reads==reads,"unknown data order rejects numeric scanning before memory reads");
    unknown.byteOrder=ByteOrder::Big;unknown.intValue=0x12345678;
    check(first(unknown).count()==1,"an explicit scan order permits numeric data inspection with unknown ISA");
    unknown=config(ValueType::ByteArray);unknown.parseAOB("12 34 56 78");
    check(first(unknown).count()==1,"unknown architecture and byte order preserve raw byte scanning");
    unknown=config(ValueType::Pointer);unknown.byteOrder=ByteOrder::Big;reads=p.reads;
    check(throws([&]{first(unknown);}) && p.reads==reads,"unknown program pointer width cannot silently become host width");
    unknown.pointerWidth=4;unknown.intValue=0x12345678;
    auto narrow=first(unknown);check(narrow.count()==1 && narrow.valueSize()==4,"an explicit pointer width permits narrow encoded data scanning");
    p.description.program.byteOrder=ByteOrder::Big;p.description.program.pointerWidth=8;unknown.pointerWidth=0;
    check(throws([&]{next(unknown,narrow);}),"a next scan cannot reinterpret a four-byte pointer stream as eight-byte pointers");

    std::fill(p.bytes.begin(),p.bytes.end(),0xcc);put(8,0x8000000000000000ull,8,ByteOrder::Big);
    auto extreme=config(ValueType::Int64);extreme.intValue=INT64_MIN;auto minimum=first(extreme);
    put(8,0x7fffffffffffffffull,8,ByteOrder::Big);extreme.compareType=ScanCompare::IncreasedBy;extreme.intValue=-1;
    bool extremeDelta=next(extreme,minimum).count()==0;
    extreme.intValue=1;extremeDelta=extremeDelta && next(extreme,minimum).count()==0;
    check(extremeDelta,"signed delta subtraction across INT64 extremes neither overflows nor accepts a negative distance");

    const auto formatFile=minimum.directory()/"format.txt";
    bool malformed=true;
    for (const char* text:{"", "CE_SCAN_FORMAT 2 2 8\n", "CE_SCAN_FORMAT 1 99 8\n", "CE_SCAN_FORMAT 1 2 3\n", "CE_SCAN_FORMAT 1 2\n", "CE_SCAN_FORMAT 1 2 8 extra\n", "CE_SCAN_FORMAT -4294967295 -4294967294 -4294967288\n", "CE_SCAN_FORMAT 1 2 4294967300\n"}) {
        {std::ofstream file(formatFile);file<<text;}
        ScanResult loaded(minimum.directory());malformed=malformed && loaded.hasWriteError() && throws([&]{next(extreme,loaded);});
    }
    std::filesystem::remove(formatFile);std::filesystem::create_symlink("values.bin",formatFile);
    {ScanResult loaded(minimum.directory());malformed=malformed && loaded.hasWriteError();}
    std::filesystem::remove(formatFile);mkfifo(formatFile.c_str(),0600);
    {ScanResult loaded(minimum.directory());malformed=malformed && loaded.hasWriteError();}
    std::filesystem::remove(formatFile);
    {ScanResult legacy(minimum.directory());malformed=malformed && !legacy.hasDataFormat() && !legacy.hasWriteError();}
    check(malformed,"invalid versions, fields, truncation, symlinks and FIFOs fail safely while legacy snapshots remain loadable");
    ValueIoOptions display;display.byteOrder=ByteOrder::Big;display.pointerWidth=4;
    const std::array<uint8_t,4> raw{0x12,0x34,0x56,0x78};
    check(decodeTypedValue(ValueType::Int32,raw,display)=="305419896" &&
          decodeTypedValue(ValueType::Pointer,raw,display)=="0x12345678" &&
          !decodeTypedValue(ValueType::Int64,raw,display),"captured scalar display validates width and uses target encoding");
    display.byteOrder=ByteOrder::Unknown;
    check(!decodeTypedValue(ValueType::Int32,raw,display) && decodeTypedValue(ValueType::ByteArray,raw,display)=="12 34 56 78",
          "unknown sample order never becomes a guessed numeric display");
    for (const auto& directory:directories) {std::error_code error;std::filesystem::remove_all(directory,error);}
}


static void highAddressScanTests() {
    TargetBuffer p;p.bytes=std::vector<uint8_t>(64,0xcc);
    p.description.host=p.description.program=nativeTargetMachine();
    MemoryScanner scanner(1);std::vector<std::filesystem::path> directories;
    auto first=[&](const ScanConfig& c) {auto r=scanner.firstScan(p,c);directories.push_back(r.directory().parent_path());return r;};
    auto next=[&](const ScanConfig& c,const ScanResult& old) {auto r=scanner.nextScan(p,c,old);directories.push_back(r.directory().parent_path());return r;};
    if constexpr (sizeof(uintptr_t)>=8) {
        p.memoryBase=static_cast<uintptr_t>(uint64_t(1)<<52);p.bytes[8]=0x7f;
        ScanConfig c;c.valueType=ValueType::Byte;c.intValue=0x7f;c.alignment=1;
        auto r=first(c);check(r.count()==1 && r.address(0)==p.memoryBase+8,"default scans include known memory above the old 47-bit ceiling");
    }
    p.memoryBase=UINTPTR_MAX-63;std::fill(p.bytes.begin(),p.bytes.end(),0xcc);
    p.bytes[63]=0x7f;
    ScanConfig c;c.valueType=ValueType::Byte;c.intValue=0x7f;c.alignment=1;
    auto r=first(c);check(r.count()==1 && r.address(0)==UINTPTR_MAX && next(c,r).count()==1,
        "first and next scans can read the inclusive final address without wrapping an end pointer");
    const std::array<uint8_t,4> word{0x12,0x34,0x56,0x78};
    std::copy(word.begin(),word.end(),p.bytes.begin());std::copy(word.begin(),word.end(),p.bytes.begin()+60);
    c.valueType=ValueType::Int32;c.byteOrder=ByteOrder::Big;c.intValue=0x12345678;
    auto two=first(c);check(two.count()==2 && two.address(1)==UINTPTR_MAX-3,"a complete scalar can end at UINTPTR_MAX");
    c.startAddress=UINTPTR_MAX-3;int before=p.reads;auto one=next(c,two);
    check(one.count()==1 && one.address(0)==UINTPTR_MAX-3 && p.reads==before+1,"next-scan range narrowing avoids reads of excluded old addresses");
    c.startAddress=UINTPTR_MAX-2;before=p.reads;
    check(next(c,two).count()==0 && p.reads==before,"next scans cannot read a scalar crossing their inclusive bounds");
    c.startAddress=UINTPTR_MAX;c.stopAddress=0;before=p.reads;bool rejected=false;
    try {(void)first(c);} catch (const std::invalid_argument&) {rejected=true;}
    check(rejected && p.reads==before,"reversed scanner ranges fail before any target memory read");
    p.bytes[8]=0x7f;ce::LuaEngine lua;lua.setProcess(&p);
    check(lua.execute("local m=createMemScan(); assert(m:firstScan(0,0,'127')); assert(m:getFoundCount()==1)").empty(),
          "Lua scans retain a full-width default To address");
    for (const auto& directory:directories) {std::error_code error;std::filesystem::remove_all(directory,error);}
}
