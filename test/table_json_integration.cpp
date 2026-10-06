#include "core/ct_file.hpp"
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string_view>
#include <unistd.h>

static unsigned checks,failures;
static void check(bool good,const char* label) {
    ++checks;failures+=!good;std::printf("%s: %s\n",good ? "OK":"FAILED",label);
}
int main(int argc,char** argv) {
    alarm(20);
    if(argc==2 && std::string_view(argv[1])=="--integer-limits") {
        printf("{\"pointerBits\":%d,\"sizeBits\":%d,\"offsetBits\":%d}\n",std::numeric_limits<uintptr_t>::digits,
            std::numeric_limits<size_t>::digits,std::numeric_limits<int64_t>::digits+1);
        return 0;
    }
    if(argc==4 && std::string_view(argv[1])=="--round-trip") {
        ce::CheatTable table;
        return table.loadJson(argv[2]) && table.saveJson(argv[3]) ? 0:1;
    }
    auto name=(std::filesystem::temp_directory_path()/"ce-table-json-XXXXXX").string();
    if(!mkdtemp(name.data()))return 2;
    const std::filesystem::path directory=name,path=directory/"table.json";
    auto load=[&](ce::CheatTable& table,const std::string& text) {
        {std::ofstream output(path,std::ios::binary);output<<text;}
        return table.loadJson(path.string());
    };
    ce::CheatTable table;
    check(load(table,R"({"game":"caf\u00e9 \u4e2d \ud83d\ude80","entries":[{"desc":"\u03a9"}]})") &&
        table.gameName=="caf\xc3\xa9 \xe4\xb8\xad \xf0\x9f\x9a\x80" && table.entries[0].description=="\xce\xa9",
        "escaped BMP and supplementary Unicode become exact UTF-8");
    const auto address=std::numeric_limits<uintptr_t>::max();
    check(load(table,"{\"entries\":[{\"addr\":"+std::to_string(address)+"}]}") && table.entries[0].address==address,
        "maximum address JSON numbers retain every integer bit");
    check(load(table,R"({"entries":[{"offsets":[-9223372036854775808,9223372036854775807]}]})") &&
        table.entries[0].offsets==std::vector<int64_t>{INT64_MIN,INT64_MAX},"signed pointer offsets preserve both 64-bit endpoints");
    check(load(table,R"({"entries":[{"id":4.0,"length":12e0,"addr":123e2,"offsets":[1.2e1,-1.28e2]}]})") &&
        table.entries[0].id==4 && table.entries[0].length==12 && table.entries[0].address==12300 &&
        table.entries[0].offsets==std::vector<int64_t>{12,-128},"integral decimal/exponent syntax remains supported");
    const auto exponentFixture=sizeof(uintptr_t)==8 ? R"({"entries":[{"addr":1.234567890123456789e19}]})" : R"({"entries":[{"addr":1.23456789e8}]})";
    check(load(table,exponentFixture) && table.entries[0].address==(sizeof(uintptr_t)==8 ? static_cast<uintptr_t>(12345678901234567890ULL):uintptr_t{123456789}),
        "decimal/exponent integers are converted without floating-point rounding");
    check(load(table,R"({"entries":[{"id":"0x2a","addr":"0x1234","offsets":["-0x8000000000000000","+0x10"]}],"structures":[{"size":"020"}]})") &&
        table.entries[0].id==42 && table.entries[0].address==0x1234 && table.entries[0].offsets==std::vector<int64_t>{INT64_MIN,16} &&
        table.structures[0].size==16,"legacy integer strings retain hex/octal bases and signed offsets");
    check(load(table,R"({"game":"first","game":"second","entries":[{"id":1,"id":2}]})") &&
        table.gameName=="second" && table.entries[0].id==2,"duplicate fields follow the same last-value semantics as Qt JSON");
    std::string controls;for(int value=0;value<32;++value)controls.push_back(static_cast<char>(value));
    table={};ce::CheatEntry entry;entry.description=controls;table.entries.push_back(entry);table.comment=controls;
    bool saved=table.saveJson(path.string());std::ifstream input(path,std::ios::binary);
    std::string serialized{std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>()};ce::CheatTable restored;
    check(saved && serialized.find("\\u0000")!=std::string::npos && serialized.find("\\u001f")!=std::string::npos &&
        serialized.find("\\b")!=std::string::npos && serialized.find("\\f")!=std::string::npos && restored.loadJson(path.string()) &&
        restored.entries[0].description==controls && restored.comment==controls,"serialization escapes every control byte and preserves it on reload");
    ce::CheatTable sentinel;sentinel.gameName="preserved";sentinel.rawFormsXml="preserved forms";
    entry={};entry.id=17;entry.description="preserved record";sentinel.entries={entry};
    const std::vector<std::pair<std::string,const char*>> malformed={
        {R"({"entries":[{"id":2147483648}]})","out-of-range record ID"},
        {R"({"entries":[{"id":1.5}]})","fractional record ID"},
        {R"({"entries":[{"id":true}]})","boolean record ID"},
        {R"({"entries":[{"addr":-1}]})","negative address"},
        {R"({"entries":[{"addr":18446744073709551616}]})","overflowing address"},
        {R"({"entries":[{"addr":1.5}]})","fractional address"},
        {R"({"entries":[{"addr":"0x123garbage"}]})","partially parsed address string"},
        {R"({"entries":[{"length":-1}]})","negative record length"},
        {R"({"structures":[{"size":-1}]})","negative structure size"},
        {R"({"structures":[{"size":18446744073709551616}]})","overflowing structure size"},
        {R"({"entries":[{"offsets":[9223372036854775808]}]})","overflowing pointer offset"},
        {R"({"entries":[{"offsets":[0.5]}]})","fractional pointer offset"},
        {R"({"entries":[{"type":999}]})","unknown numeric value type"},
        {R"({"entries":[{"type":"unknown"}]})","unknown named value type"},
        {R"({"entries":[{"freezeMode":5}]})","unknown freeze mode"},
        {R"({"entries":[{"id":01}]})","leading-zero JSON number"},
        {R"({"entries":[{"id":1.}]})","JSON number missing fractional digits"},
        {R"({"game":"\ud800","entries":[]})","unpaired high surrogate"},
        {R"({"game":"\udfff","entries":[]})","unpaired low surrogate"},
        {R"({"game":"\ud800\u0041","entries":[]})","invalid surrogate pair"},
        {R"({"game":"\u+041","entries":[]})","non-hexadecimal Unicode escape"},
        {"{\"game\":\"raw\nnewline\",\"entries\":[]}","unescaped string control byte"},
        {R"({"entries":{}})","non-array entry collection"},
        {R"({"entries":[1]})","non-object record"},
        {R"({"game":"changed","entries":[{"id":2},{"pointerWidth":3}]})","invalid later record after valid metadata/record"},
    };
    for(const auto& [text,label]:malformed) {
        auto candidate=sentinel;
        bool rejected=!load(candidate,text);
        bool preserved=candidate.gameName==sentinel.gameName && candidate.rawFormsXml==sentinel.rawFormsXml &&
            candidate.entries.size()==1 && candidate.entries[0].id==17 && candidate.entries[0].description==entry.description;
        check(rejected && preserved,label);
    }
    std::filesystem::remove_all(directory);
    std::printf("TABLE_JSON_RESULT=%s checks=%u failures=%u\n",failures ? "FAILED":"PASSED",checks,failures);
    return failures ? 1:0;
}
