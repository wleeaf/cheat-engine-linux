namespace ce {extern std::atomic<int> g_scanSimdOverride;}
static void floatingRoundingTests() {
    TargetBuffer p; p.description.program=nativeTargetMachine(); MemoryScanner scanner(1);
    ScanConfig c;c.startAddress=p.base+16;c.stopAddress=p.base+23;c.alignment=16;
    std::vector<std::filesystem::path> directories;
    auto first=[&] {auto r=scanner.firstScan(p,c);directories.push_back(r.directory().parent_path());return r;};
    auto next=[&](const ScanResult& r) {auto n=scanner.nextScan(p,c,r);directories.push_back(n.directory().parent_path());return n;};
    auto parse=[&](std::string_view value) {return c.valueType==ValueType::All ? c.parseAllValues(value) : c.parseFloatingValues(value);};
    auto put=[&](uint64_t bits,size_t width,ByteOrder order) {
        p.bytes.assign(64,0xcc);for(size_t i=0;i<width;++i)p.bytes[16+i]=static_cast<uint8_t>(bits>>(8*(order==ByteOrder::Big ? width-1-i : i)));
    };
    bool rounded=true,truncated=true,extreme=true,relational=true,grouped=true;
    for(auto order:{ByteOrder::Little,ByteOrder::Big}) {
        p.description.program.byteOrder=order;
        for(auto type:{ValueType::Float,ValueType::All}) {
            c.valueType=type;c.compareType=ScanCompare::Exact;c.roundingType=1;c.floatTolerance=0;
            put(UINT64_C(0x3d4ccccd),4,order); // Float 0.05 is just above the lower 0.1 rounded boundary.
            rounded=rounded && parse("0.1") && first().count()==1;
            auto captured=first();rounded=rounded && next(captured).count()==1;
            c.roundingType=2;put(UINT64_C(0x4b800000),4,order);
            truncated=truncated && parse("16777217") && first().empty();
            put(UINT64_C(0x40000000),4,order);truncated=truncated && parse("1.99999999") && first().empty();
            c.roundingType=3;c.floatTolerance=1e-6;put(UINT64_C(0x4b800000),4,order);
            extreme=extreme && parse("16777217") && first().empty();
            c.floatTolerance=1e308;put(UINT64_C(0x7f7fffff),4,order);
            extreme=extreme && parse("1e308") && first().count()==1;
            put(UINT64_C(0x7f800000),4,order);auto infinite=first();
            extreme=extreme && (type==ValueType::All ? !(infinite.allTypeCandidates(0)&16) : infinite.empty());
        }
        c.valueType=ValueType::Float;c.roundingType=0;c.floatTolerance=0;put(UINT64_C(0x40200000),4,order);
        c.compareType=ScanCompare::Unknown;auto captured=first();c.compareType=ScanCompare::Less;
        relational=relational && c.parseFloatingValues("2.50000001") && first().count()==1 && next(captured).count()==1;
        c.compareType=ScanCompare::Between;
        relational=relational && c.parseFloatingValues("2.49999999","2.50000001") && first().count()==1;
        c.valueType=ValueType::Grouped;c.compareType=ScanCompare::Exact;c.roundingType=1;c.floatDecimals=1;
        put(UINT64_C(0x3d4ccccd),4,order);c.parseGrouped("float:0.1@0");grouped=grouped && first().count()==1;
    }
    check(rounded,"Rounded float and All first/next scans retain the full requested decimal boundary in both byte orders");
    check(truncated,"Truncated float and All scans cannot invent matches by rounding requested integers or fractions to float");
    check(extreme,"Extreme float and All scans preserve the full center/tolerance, including wide finite ranges without infinity matches");
    check(relational,"Typed float relational and Between scans retain requested double precision through first and next scans");
    check(grouped,"Grouped float terms use their full requested value for rounded comparisons");
    c=ScanConfig{};c.valueType=ValueType::Float;c.floatValue=17;
    bool parsing=c.parseFloatingValues("3e-2") && c.floatValue==0.03 && c.floatDecimals==2 &&
        !c.parseFloatingValues("3e-2oops") && c.floatValue==0.03 && !c.parseFloatingValues(std::string("3\0bad",5));
    c.compareType=ScanCompare::Between;parsing=parsing && !c.parseFloatingValues("1") && c.parseFloatingValues("1,5","2,5");
    check(parsing,"Floating number parsing retains scientific precision and rejects malformed or missing bounds atomically");
    p.description.program.byteOrder=ByteOrder::Little;put(UINT64_C(0x3d4ccccd),4,ByteOrder::Little);
    LuaEngine lua;lua.setProcess(&p);
    check(lua.execute(R"lua(
        local s=createMemScan();local f={rounding='rounded'}
        assert(s:firstScan(0,4,'1e-1',0x10010,0x10013,4,nil,f) and s:getFoundCount()==1)
        assert(s:nextScan(0,4,'0.1',0x10010,0x10013,4,nil,f) and s:getValue(0)=='0.05')
        for _,opts in ipairs({{rounding='wrong'},{rounding=1},{tolerance=-1},{tolerance=math.huge},
                              {tolerance='oops'},setmetatable({}, {__index=function()error('bad getter')end})}) do
            local ok,err=s:firstScan(0,4,'0.1',0x10010,0x10013,4,nil,opts)
            assert(ok==false and type(err)=='string' and s:getValue(0)=='0.05')
        end
        local ok,err=s:firstScan(0,4,'0.1\0suffix',0x10010,0x10013,4,nil,f)
        assert(ok==false and err:find('floating') and s:getValue(0)=='0.05')
        assert(s:firstScan(1,4,'0.01',0x10010,0x10013,4,nil,{value2='0.09'}) and s:getFoundCount()==1)
        assert(s:firstScan(0,10,'0.1',0x10010,0x10013,4,nil,{rounding='rounded'}) and s:getFoundCount()==1)
        assert(s:getValue(0,false,4)=='0.05')
    )lua").empty(),"Lua exposes float/All rounding and tolerance controls, floating Between bounds and invalid-input recovery");
    put(42,4,ByteOrder::Little);
    check(lua.execute(R"lua(
        local s=createMemScan()
        assert(s:firstScan(1,2,'41',0x10010,0x10013,4,nil,{value2='43'}) and s:getValue(0)=='42')
        local ok,err=s:nextScan(1,2,'41',0x10010,0x10013,4)
        assert(ok==false and err:find('value2') and s:getValue(0)=='42')
        assert(s:nextScan(1,2,'43',0x10010,0x10013,4,nil,{value2='41'}) and s:getValue(0)=='42')
    )lua").empty(),"Lua ordinary integer Between scans support explicit reversed upper bounds and preserve results when absent");
    bool lanes=true;const int previousMode=g_scanSimdOverride.load();std::vector<int> modes{0};
#if defined(__x86_64__)
    modes.push_back(1);if(__builtin_cpu_supports("avx2"))modes.push_back(2);
#endif
    for(auto order:{ByteOrder::Little,ByteOrder::Big})for(size_t width:{size_t(4),size_t(8)})for(int mode:modes) {
        p.description.program.byteOrder=order;p.bytes.resize(64*width);
        const std::array<uint64_t,4> bits=width==4 ?
            std::array<uint64_t,4>{0x3d4ccccd,0x3e19999a,0,0x3dcccccd} :
            std::array<uint64_t,4>{UINT64_C(0x3fa999999999999a),UINT64_C(0x3fc3333333333333),0,UINT64_C(0x3fb999999999999a)};
        std::vector<uintptr_t> expected;
        for(size_t i=0;i<64;++i) {
            for(size_t b=0;b<width;++b)p.bytes[i*width+b]=static_cast<uint8_t>(bits[i%4]>>(8*(order==ByteOrder::Big ? width-1-b : b)));
            if(i%4==0 || i%4==3 || (width==8 && i%4==1))expected.push_back(p.base+i*width);
        }
        c=ScanConfig{};c.valueType=width==4 ? ValueType::Float : ValueType::Double;c.alignment=width;c.roundingType=1;
        c.startAddress=p.base;c.stopAddress=p.base+p.bytes.size()-1;c.parseFloatingValues("0.1");g_scanSimdOverride.store(mode);
        auto result=first();lanes=lanes && result.count()==expected.size();
        for(size_t i=0;i<std::min(result.count(),expected.size());++i)lanes=lanes && result.address(i)==expected[i];
    }
    g_scanSimdOverride.store(previousMode);
    check(lanes,"Independent float/double rounded boundary addresses agree across scalar, supported SIMD modes and both data orders");
    for(const auto& dir:directories){std::error_code ignored;std::filesystem::remove_all(dir,ignored);}
}
