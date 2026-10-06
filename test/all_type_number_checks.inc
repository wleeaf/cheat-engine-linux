static void allTypeNumberTests() {
    TargetBuffer p; p.description.program=nativeTargetMachine();
    MemoryScanner scanner(1); std::vector<std::filesystem::path> directories;
    ScanConfig c; c.valueType=ValueType::All; c.startAddress=p.base+16; c.stopAddress=p.base+23; c.alignment=16;
    auto first=[&] {auto r=scanner.firstScan(p,c);directories.push_back(r.directory().parent_path());return r;};
    auto next=[&](const ScanResult& r) {auto n=scanner.nextScan(p,c,r);directories.push_back(n.directory().parent_path());return n;};
    auto put=[&](uint64_t bits,size_t width,ByteOrder order) {
        p.bytes.assign(64,0xcc);
        for(size_t i=0;i<width;++i) p.bytes[16+i]=static_cast<uint8_t>(bits>>(8*(order==ByteOrder::Big ? width-1-i : i)));
    };
    bool fraction=true, scientific=true, limits=true, deltas=true, floatSpecial=true, floatBounds=true, percentages=true;
    for(auto order:{ByteOrder::Little,ByteOrder::Big}) {
        p.description.program.byteOrder=order;
        put(2,1,order); c.compareType=ScanCompare::Exact;
        fraction=fraction && c.parseAllValues("2.5") && first().empty();
        c.compareType=ScanCompare::Less;
        fraction=fraction && c.parseAllValues("2,5") && (first().allTypeCandidates(0)&1);
        put(3,1,order); c.compareType=ScanCompare::Greater;
        fraction=fraction && c.parseAllValues("+2.5") && (first().allTypeCandidates(0)&1);
        c.compareType=ScanCompare::Between;
        fraction=fraction && c.parseAllValues("4.5","1.5") && (first().allTypeCandidates(0)&1);
        put(static_cast<uint64_t>(-2),2,order); c.compareType=ScanCompare::Greater;
        fraction=fraction && c.parseAllValues("-2.5") && (first().allTypeCandidates(0)&2);
        c.compareType=ScanCompare::Less;
        fraction=fraction && c.parseAllValues("-1.5") && (first().allTypeCandidates(0)&2);
        put(30,1,order); c.compareType=ScanCompare::Exact;
        scientific=scientific && c.parseAllValues("3e1") && (first().allTypeCandidates(0)&1);
        put(3,1,order); scientific=scientific && first().empty();
        put(42,1,order); scientific=scientific && c.parseAllValues("  +0x2A \n") && (first().allTypeCandidates(0)&1);
        scientific=scientific && c.parseAllValues("2A",{},true) && (first().allTypeCandidates(0)&1);
        put(1,1,order); scientific=scientific && c.parseAllValues("00001000e-3") && (first().allTypeCandidates(0)&1);
        scientific=scientific && c.parseAllValues("3e-2") && c.floatDecimals==2 && c.parseAllValues("3.00e1") && c.floatDecimals==1;
        put(UINT64_C(0x7fffffffffffffff),8,order);
        limits=limits && c.parseAllValues("9223372036854775807") && (first().allTypeCandidates(0)&8);
        limits=limits && c.parseAllValues("9.223372036854775807e18") && (first().allTypeCandidates(0)&8);
        limits=limits && c.parseAllValues("9223372036854775806") && !(first().allTypeCandidates(0)&8);
        limits=limits && c.parseAllValues("9223372036854775807.1") && !(first().allTypeCandidates(0)&8);
        c.compareType=ScanCompare::Less;
        limits=limits && c.parseAllValues("9223372036854775807.1") && (first().allTypeCandidates(0)&8);
        put(UINT64_C(0x8000000000000000),8,order); c.compareType=ScanCompare::Greater;
        limits=limits && c.parseAllValues("-9223372036854775808.1") && (first().allTypeCandidates(0)&8);
        c.compareType=ScanCompare::Exact; c.parseAllValues("-9223372036854775808"); auto minimum=first();
        put(UINT64_C(0x7fffffffffffffff),8,order); c.compareType=ScanCompare::IncreasedBy;
        deltas=deltas && c.parseAllValues("18446744073709551615") && (next(minimum).allTypeCandidates(0)&8);
        deltas=deltas && c.parseAllValues("18446744073709551614") && next(minimum).empty();
        deltas=deltas && c.parseAllValues("18446744073709551615.1") && next(minimum).empty();
        put(2,1,order); c.compareType=ScanCompare::Exact; c.parseAllValues("2"); auto byte=first();
        put(4,1,order); c.compareType=ScanCompare::IncreasedBy;
        deltas=deltas && c.parseAllValues("2.5") && next(byte).empty();
        deltas=deltas && c.parseAllValues("2e0") && (next(byte).allTypeCandidates(0)&1);
        c.compareType=ScanCompare::Changed; deltas=deltas && (next(byte).allTypeCandidates(0)&1);
        c.compareType=ScanCompare::Between; c.percentageScan=true; c.percentageValue=100; c.percentageValue2=100;
        percentages=percentages && c.parseAllValues("") && (next(byte).allTypeCandidates(0)&1);
        c.percentageScan=false;
        put(UINT64_C(0x7f800000),4,order); c.compareType=ScanCompare::Exact;
        floatSpecial=floatSpecial && c.parseAllValues("inf") && (first().allTypeCandidates(0)&16);
        floatSpecial=floatSpecial && c.parseAllValues("1e308") && !(first().allTypeCandidates(0)&16);
        c.valueType=ValueType::Float;
        floatSpecial=floatSpecial && first().empty();
        c.parseAllValues("inf");floatSpecial=floatSpecial && first().count()==1;c.valueType=ValueType::All;
        floatSpecial=floatSpecial && c.parseAllValues("nan") && first().empty();
        put(UINT64_C(0x40200000),4,order); c.compareType=ScanCompare::Unknown;auto original=first();
        c.compareType=ScanCompare::Less;
        floatBounds=floatBounds && c.parseAllValues("2.50000001") && (first().allTypeCandidates(0)&16) &&
            (next(original).allTypeCandidates(0)&16);
        c.compareType=ScanCompare::Greater;
        floatBounds=floatBounds && c.parseAllValues("2.49999999") && (first().allTypeCandidates(0)&16) &&
            (next(original).allTypeCandidates(0)&16);
        c.compareType=ScanCompare::Unknown; floatSpecial=floatSpecial && c.parseAllValues("") && first().allTypeCandidates(0)==63;
    }
    check(fraction,"All numeric literals preserve fractional and negative integer comparison boundaries in both byte orders");
    check(scientific,"All numeric literals accept scientific/hex/comma forms and retain exponent-adjusted decimal precision");
    check(limits,"All numeric literals retain exact signed 64-bit boundaries independently of double rounding");
    check(deltas,"All delta literals reject fractional integer changes and preserve the complete unsigned distance across signed endpoints");
    check(floatSpecial,"All infinity searches and unknown nonfinite candidates never invent integer zero matches");
    check(floatBounds,"All floating relational bounds retain double input precision rather than rounding to the candidate's width");
    check(percentages,"All percentage comparisons use their own thresholds without requiring unrelated numeric search values");
    c.compareType=ScanCompare::Exact; c.parseAllValues("42");
    bool malformed=true;
    for(const auto& token:{std::string{},std::string("42oops"),std::string("2.5oops"),std::string("1e"),std::string("1e9999"),
        std::string("+"),std::string("1 2"),std::string("0xZZ"),std::string("42\0bad",6),std::string(4097,'0')})
        malformed=malformed && !c.parseAllValues(token) && c.floatValue==42 && c.allIntegerValue->compare(42)==0;
    c.compareType=ScanCompare::Between;
    malformed=malformed && !c.parseAllValues("1") && !c.parseAllValues("1","2bad") && c.floatValue==42;
    check(malformed,"Malformed All numeric literals and missing upper bounds fail atomically rather than scanning zero or a prefix");
    bool ordered=true; c.compareType=ScanCompare::Exact;
    for(int numerator=-250;numerator<=250;++numerator) {
        const int absolute=std::abs(numerator);
        const std::string decimal=(numerator<0 ? "-" : "")+std::to_string(absolute/10)+"."+std::to_string(absolute%10);
        for(const auto& text:{decimal,std::to_string(numerator)+"e-1"}) {
            const bool parsed=c.parseAllValues(text); ordered=ordered && parsed;
            if(!parsed) continue;
            for(int current=-25;current<=25;++current) {
                const int expected=current*10<numerator ? -1 : current*10>numerator ? 1 : 0;
                ordered=ordered && c.allIntegerValue->compare(current)==expected;
            }
        }
    }
    check(ordered,"Decimal and scientific All boundaries agree with 51102 independent exact rational integer comparisons");
    p.description.program.byteOrder=ByteOrder::Little; put(2,1,ByteOrder::Little);
    LuaEngine lua; lua.setProcess(&p);
    check(lua.execute(R"lua(
        local s=createMemScan()
        assert(s:firstScan(0,10,'2',0x10010,0x10010,1))
        for _,bad in ipairs({'2oops','2.5oops','1e','1e9999','2\0suffix'}) do
            local ok,err=s:firstScan(0,10,bad,0x10010,0x10010,1)
            assert(ok==false and err:find('All scan') and s:getValue(0,false,0)=='2')
        end
        local ok,err=s:nextScan(1,10,'1.5',0x10010,0x10010,1)
        assert(ok==false and err:find('value2') and s:getFoundCount()==1)
        assert(s:nextScan(1,10,'1.5',0x10010,0x10010,1,nil,{value2='2.5'}))
        assert(s:getValue(0,false,0)=='2')
        assert(s:firstScan(0,10,'2.5',0x10010,0x10010,1) and s:getFoundCount()==0)
    )lua").empty(),"Lua All scans use strict numeric boundaries, explicit Between upper values and preserve results on malformed input");
    for(const auto& dir:directories) {std::error_code ignored;std::filesystem::remove_all(dir,ignored);}
}
