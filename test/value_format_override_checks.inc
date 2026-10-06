#include "core/ct_file.hpp"

static void valueFormatOverrideTests() {
    TargetBuffer process; process.description.program = {}; process.bytes.assign(64, 0xee);
    bool pointers = true, rejected = true;
    for (ByteOrder order : {ByteOrder::Little, ByteOrder::Big}) for (int width : {4,8}) {
        ValueIoOptions options; options.byteOrder = order; options.pointerWidthOverride = width;
        const uint64_t value = width == 4 ? 0x12345678ULL : 0x0102030405060708ULL;
        const auto text = width == 4 ? "0x12345678" : "0x0102030405060708";
        process.bytes.assign(64, 0xee);
        auto encoded = encodeTypedValue(ValueType::Pointer, text, options);
        auto written = writeTypedValue(process, process.base+16, ValueType::Pointer, text, options);
        auto current = readTypedValue(process, process.base+16, ValueType::Pointer, options);
        pointers = pointers && encoded && encoded->size() == size_t(width) && written && *written == size_t(width) && current;
        for (int i=0; i<width; ++i) pointers = pointers && process.bytes[16+i] == uint8_t(value >> (8*(order == ByteOrder::Big ? width-1-i : i)));
        pointers = pointers && process.bytes[15] == 0xee && process.bytes[16+width] == 0xee;
        if (encoded) pointers = pointers && decodeTypedValue(ValueType::Pointer, *encoded, options) == current;
        const auto original = process.bytes;
        options.pointerWidthOverride = 3;
        rejected = rejected && !encodeTypedValue(ValueType::Pointer, text, options);
        rejected = rejected && !readTypedValue(process, process.base+16, ValueType::Pointer, options) &&
            !writeTypedValue(process, process.base+16, ValueType::Pointer, text, options) && process.bytes == original;
        options.pointerWidthOverride = width; options.byteOrder = static_cast<ByteOrder>(99);
        rejected = rejected && !encodeTypedValue(ValueType::Pointer, text, options) &&
            !decodeTypedValue(ValueType::Pointer, std::span<const uint8_t>(process.bytes.data()+16,width), options);
        rejected = rejected && !writeTypedValue(process, process.base+16, ValueType::Pointer, text, options) && process.bytes == original;
    }
    check(pointers,"Explicit pointer width and byte order support encoded reads/writes on unknown targets and preserve neighboring fields");
    check(rejected,"Invalid encoded pointer widths and byte orders fail before target mutation");
    process.description.program = nativeTargetMachine(); process.description.program.pointerWidth = 4;
    ValueIoOptions options; options.byteOrder = ByteOrder::Little; process.bytes.assign(64, 0xee);
    auto automatic = writeTypedValue(process, process.base+16, ValueType::Pointer, "0x12345678", options);
    options.pointerWidthOverride = 8;
    auto explicitWidth = writeTypedValue(process, process.base+16, ValueType::Pointer, "0x0102030405060708", options);
    check(automatic && *automatic == 4 && explicitWidth && *explicitWidth == 8 && process.description.program.pointerWidth == 4,
          "Automatic pointer I/O still uses target width while explicit data overrides leave CPU metadata unchanged");
    std::string pattern=(std::filesystem::temp_directory_path()/"value-format-check-XXXXXX").string();
    if (!mkdtemp(pattern.data())) {check(false,"Create format persistence fixture");return;}
    const std::filesystem::path directory=pattern;
    CheatTable table; CheatEntry entry; entry.type=ValueType::Pointer; entry.address=process.base+16;
    entry.dataByteOrder=ByteOrder::Big; entry.pointerWidth=4; table.entries.push_back(entry);
    bool persisted=true;
    for (const auto& extension : {"ct","json","CETRAINER"}) {
        const auto file=(directory/(std::string("data.")+extension)).string(); CheatTable loaded;
        const bool protectedTable=std::string(extension)=="CETRAINER";
        bool saved=protectedTable ? table.saveProtected(file,"fixture") : std::string(extension)=="ct" ? table.save(file) : table.saveJson(file);
        bool read=saved && (protectedTable ? loaded.loadProtected(file,"fixture") : loaded.loadAuto(file));
        persisted=persisted && read && loaded.entries.size()==1 && loaded.entries[0].dataByteOrder==ByteOrder::Big && loaded.entries[0].pointerWidth==4;
    }
    check(persisted,"XML, JSON and protected cheat tables retain explicit data byte order and encoded pointer width");
    bool malformed=true;
    for (const auto& fields : {"<LinuxDataByteOrder>sideways</LinuxDataByteOrder>","<LinuxPointerWidth>4oops</LinuxPointerWidth>","<LinuxPointerWidth>16</LinuxPointerWidth>"}) {
        CheatTable invalid;
        malformed=malformed && !invalid.loadFromString(std::string("<CheatTable><CheatEntries><CheatEntry><ID>0</ID>")+fields+"</CheatEntry></CheatEntries></CheatTable>");
    }
    for (const auto& fields : {"\"dataByteOrder\":9","\"dataByteOrder\":\"sideways\"","\"pointerWidth\":4.5","\"pointerWidth\":\"4\""}) {
        const auto file=(directory/"bad.json").string(); {std::ofstream output(file);output<<"{\"entries\":[{"<<fields<<"}]}";}
        CheatTable invalid;malformed=malformed && !invalid.loadJson(file);
    }
    table.entries[0].pointerWidth=3;
    malformed=malformed && !table.save((directory/"invalid.ct").string()) && !table.saveJson((directory/"invalid.json").string());
    check(malformed,"Malformed record format metadata is rejected on table load/save instead of silently using the target format");
    std::error_code ignored;std::filesystem::remove_all(directory,ignored);
}
