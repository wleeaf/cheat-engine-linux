// Independent numeric representations and mutable readable spans, not host ABI guesses.
static void allTypeScanTests() {
    TargetBuffer p;p.description.program=nativeTargetMachine();
    MemoryScanner scanner(2);std::vector<std::filesystem::path> directories;
    auto first=[&](const ScanConfig& c) {auto r=scanner.firstScan(p,c);directories.push_back(r.directory().parent_path());return r;};
    auto next=[&](const ScanConfig& c,const ScanResult& old) {auto r=scanner.nextScan(p,c,old);directories.push_back(r.directory().parent_path());return r;};
    auto put=[&](uint64_t bits,size_t width,ByteOrder order) {
        for (size_t i=0;i<width;++i) p.bytes[16+i]=static_cast<uint8_t>(bits>>(8*(order==ByteOrder::Big ? width-1-i : i)));
    };
    bool integers=true,floats=true,candidates=true,tails=true,persistence=true,selection=true;
    for (ByteOrder order:{ByteOrder::Little,ByteOrder::Big}) {
        p.description.program.byteOrder=order;
        ScanConfig c;c.valueType=ValueType::All;c.startAddress=p.base+16;c.stopAddress=p.base+23;c.alignment=16;c.intValue=42;c.floatValue=42;
        p.bytes.assign(64,0xcc);p.bytes[16]=42;
        auto bytes=first(c);
        integers=integers && bytes.count()==1 && bytes.allTypeCandidates(0)==1;
        p.bytes[17]=0xdd;
        auto unchanged=next(c,bytes);integers=integers && unchanged.count()==1 && unchanged.allTypeCandidates(0)==1;
        c.compareType=ScanCompare::Changed;integers=integers && next(c,bytes).empty();
        p.bytes[16]=43;c.compareType=ScanCompare::Increased;
        auto increased=next(c,bytes);integers=integers && increased.count()==1;
        p.bytes[16]=42;c.compareType=ScanCompare::SameAsFirst;
        integers=integers && next(c,increased).count()==1;
        c.compareType=ScanCompare::Exact;c.intValue=298;c.floatValue=298;
        integers=integers && first(c).empty() && next(c,bytes).empty();
        c.compareType=ScanCompare::Between;c.intValue=40;c.intValue2=44;c.floatValue=40;c.floatValue2=44;
        integers=integers && first(c).count()==1 && next(c,bytes).count()==1;
        p.bytes[16]=84;c.compareType=ScanCompare::Increased;c.percentageScan=true;c.percentageValue=100;
        integers=integers && next(c,bytes).count()==1;c.percentageScan=false;
        for (auto [width,mask]:{std::pair{2,2},std::pair{4,4},std::pair{8,8}}) {
            p.bytes.assign(64,0xcc);put(static_cast<uint64_t>(-1234),width,order);
            c.compareType=ScanCompare::Exact;c.intValue=-1234;c.floatValue=-1234;
            auto original=first(c);integers=integers && original.count()==1 && (original.allTypeCandidates(0)&mask);
            put(static_cast<uint64_t>(-1200),width,order);c.compareType=ScanCompare::IncreasedBy;c.intValue=34;c.floatValue=34;
            auto changed=next(c,original);integers=integers && changed.count()==1 && (changed.allTypeCandidates(0)&mask);
        }
        for (auto [width,mask,bits,nextBits]:{std::tuple{4,16,UINT64_C(0x40200000),UINT64_C(0x40600000)},std::tuple{8,32,UINT64_C(0x4004000000000000),UINT64_C(0x400c000000000000)}}) {
            p.bytes.assign(64,0xcc);put(bits,width,order);
            c.compareType=ScanCompare::Exact;c.intValue=-999999;c.floatValue=2.5;
            auto original=first(c);floats=floats && original.count()==1 && original.allTypeCandidates(0)==mask;
            put(nextBits,width,order);c.compareType=ScanCompare::IncreasedBy;c.intValue=1;c.floatValue=1;
            auto changed=next(c,original);floats=floats && changed.count()==1 && changed.allTypeCandidates(0)==mask;
            c.compareType=ScanCompare::Exact;c.intValue=0;c.floatValue=99;put(0,width,order);
            candidates=candidates && next(c,original).empty(); // Matching integer bits cannot invent a formerly unmatched type.
            put(bits,width,order);c.valueType=width==4 ? ValueType::Float : ValueType::Double;c.floatValue=2.5;
            auto typed=next(c,original);selection=selection && typed.count()==1 && typed.valueSize()==size_t(width) && !typed.hasAllTypeCandidates();
            c.valueType=ValueType::All;
        }
        p.bytes.assign(64,0);put(42,8,order);c.compareType=ScanCompare::Exact;c.intValue=42;c.floatValue=42;
        auto wide=first(c);const uint8_t originalMask=order==ByteOrder::Little ? 15 : 8;
        candidates=candidates && wide.count()==1 && wide.allTypeCandidates(0)==originalMask;
        // The readable address space shrinks after capture. Preserve whichever
        // original candidate types still fit, without reading padding as data.
        if (order==ByteOrder::Little) {
            p.bytes.resize(17);auto narrow=next(c,wide);
            tails=tails && narrow.count()==1 && narrow.allTypeCandidates(0)==1;
            c.stopAddress=p.base+16;tails=tails && next(c,wide).count()==1;
        }
        p.bytes.assign(17,0xcc);p.bytes.back()=255;c.stopAddress=p.base+16;c.intValue=255;c.floatValue=255;
        auto tail=first(c);tails=tails && tail.count()==1 && tail.allTypeCandidates(0)==1 && next(c,tail).count()==1;
        ScanResult loaded(tail.directory());auto pruned=pruneScanResult(loaded,8,{false});directories.push_back(pruned->directory().parent_path());
        persistence=persistence && loaded.hasAllTypeCandidates() && pruned->hasAllTypeCandidates() && pruned->allTypeCandidates(0)==1;
        ScanResult moved(std::move(loaded));persistence=persistence && moved.allTypeCandidates(0)==1;
    }
    check(integers,"All-type scans use full integer bounds, typed deltas/percentages and first values without truncating search values");
    check(floats,"All-type float/double candidates narrow by numerical comparisons in both data orders");
    check(candidates,"All-type narrowing preserves type identity and cannot introduce candidates that failed earlier scans");
    check(tails,"All-type narrow tails and surviving narrow fields remain readable after wider memory becomes unavailable");
    check(persistence,"All-type candidates survive reload, move and pruning alongside original samples");
    check(selection,"All-type results can select a surviving concrete numeric type with the correct new record stride");
    p.description.program.byteOrder=ByteOrder::Little;p.bytes.assign(17,0xcc);p.bytes[16]=42;
    LuaEngine lua;lua.setProcess(&p);
    check(lua.execute(R"lua(
        local s=createMemScan()
        assert(s:firstScan(0,10,"42",0x10010,0x10010,1))
        assert(s:getFoundCount()==1 and s:getValueTypes(0)[1]==0 and #s:getValueTypes(0)==1)
        assert(s:getValue(0)=="2A" and s:getValue(0,false,0)=="42" and s:getValue(0,true,0)=="42")
        local bad,err=s:getValue(0,false,1);assert(bad==nil and err:find('candidate'))
        assert(s:nextScan(0,0,"42",0x10010,0x10010,1) and s:getValue(0)=="42")
    )lua").empty(),"Lua exposes surviving All-type candidates and decodes selected numeric samples without padding or rereads");
    p.description.program.byteOrder=ByteOrder::Little;p.bytes.assign(70008,0xcc);p.concurrentReads=true;
    ScanConfig c;c.valueType=ValueType::All;c.compareType=ScanCompare::Unknown;c.startAddress=p.base;c.stopAddress=p.base+p.bytes.size()-1;c.alignment=1;
    const char* oldChunk=getenv("CE_SCAN_CHUNK_KB");std::optional<std::string> savedChunk=oldChunk ? std::optional<std::string>(oldChunk) : std::nullopt;
    setenv("CE_SCAN_CHUNK_KB","1",1);auto dense=first(c);
    if (savedChunk) setenv("CE_SCAN_CHUNK_KB",savedChunk->c_str(),1);else unsetenv("CE_SCAN_CHUNK_KB");
    auto denseNext=next(c,dense);
    bool sharded=dense.count()==p.bytes.size() && dense.shardLayout().size()==2 && denseNext.count()==dense.count() && denseNext.shardLayout().size()==2;
    for (size_t i:{size_t(0),size_t(35000),size_t(69999),size_t(70007)})
        sharded=sharded && denseNext.address(i)==p.base+i && denseNext.allTypeCandidates(i)==dense.allTypeCandidates(i);
    check(sharded,"All-type masks and raw sample strides remain aligned across chunks, shards and parallel next-scan batches");
    p.concurrentReads=false;
    bool malformed=true;
    auto shard=dense.shardLayout().front();auto path=shard.dir/"all_types.bin";
    {
        std::fstream file(path,std::ios::in|std::ios::out|std::ios::binary);char zero=0;file.write(&zero,1);
    }
    ScanResult corrupt(dense.directory());malformed=malformed && corrupt.hasWriteError();
    bool rejected=false;try {next(c,corrupt);} catch (const std::invalid_argument&) {rejected=true;}
    malformed=malformed && rejected;
    std::filesystem::remove(path);std::filesystem::create_directory(path);ScanResult directory(dense.directory());malformed=malformed && directory.hasWriteError();
    std::filesystem::remove(path);std::filesystem::create_symlink(shard.dir/"values.bin",path);ScanResult link(dense.directory());malformed=malformed && link.hasWriteError();
    check(malformed,"invalid All-type masks, nonregular streams and links are rejected instead of guessing candidate types");
    for (const auto& dir:directories) {std::error_code ignored;std::filesystem::remove_all(dir,ignored);}
}
