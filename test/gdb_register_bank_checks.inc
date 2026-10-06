// Live, independent RSP peers verify whole-register fallback through the shared
// process API, including layout validation and preservation of unrelated state.
static int registerBankChecks(const std::string& mode,const std::string& host,uint16_t port) {
    ce::GdbProcessOptions options;options.timeout=std::chrono::milliseconds(250);
    if (mode=="bank-stall") options.timeout=std::chrono::milliseconds(75);
    auto opened=ce::GdbProcessHandle::connect(host,port,options);
    check(bool(opened),"whole-register stub connects using its actual sparse XML layout");
    if (!opened) return 1;
    auto& process=**opened;
    if (mode=="bank-disconnect" || mode=="bank-stall") {
        const auto started=std::chrono::steady_clock::now();
        auto read=process.readRegister("x0");
        check(!read && !process.targetDescription().live && process.queryRegions().empty(),
              "a disconnect or incomplete bank retires the actual transport without stale mappings or register values");
        check(std::chrono::steady_clock::now()-started<std::chrono::milliseconds(350),
              "a trickling bank reply cannot extend the original transaction deadline");
        check(!process.writeRegister("x0",std::array<uint8_t,8>{}) && process.detach().has_value(),
              "a retired bank owner rejects stale writes and detach does not resume a disconnected guest");
        std::printf("GDB_REGISTER_BANK_RESULT=%s mode=%s\n",failures ? "FAILED" : "PASSED",mode.c_str());
        return failures ? 1 : 0;
    }
    const std::vector<uint8_t> originalX0={0xe0,0x12,0x34,0x12,0x34,0x56,0x78,0x90};
    const std::vector<uint8_t> originalPc={0x78,0x56,0x34,0x12,0,0,0,0x40};
    const std::array<uint8_t,8> edit={1,2,3,4,5,6,7,8};
    const bool bad=mode=="bank-misaligned" || mode=="bank-oversized" || mode=="bank-invalid" ||
        mode=="bank-p-error" || mode=="bank-p-malformed" || mode=="bank-g-error";
    auto first=process.readRegister("x0");
    check(bad ? !first : first && *first==originalX0,
          "bank reads preserve raw bytes and reject malformed/error responses without guessing an offset");
    if (bad) {
        check(!process.writeRegister("x0",edit),"invalid bank or individual packet errors cannot trigger an unsafe G write");
    } else if (mode=="bank-too-large") {
        check(!process.writeRegister("x0",edit),"an indivisible G write must fit the negotiated packet size");
        auto fresh=process.readRegister("x0");check(fresh && *fresh==originalX0,"rejected oversized edits leave the stopped target unchanged");
    } else if (mode=="bank-unavailable") {
        check(!process.readRegister("v0"),"unavailable bank bytes never turn into a fabricated vector value");
        check(!process.writeRegister("x0",edit),"unknown unrelated bank fields cannot be zeroed by a scalar edit");
        auto fresh=process.readRegister("x0");check(fresh && *fresh==originalX0,"an unsafe edit is rejected before target mutation");
        const std::array<uint8_t,16> vector={0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f};
        check(process.writeRegister("v0",vector).has_value(),"an explicitly replaced unavailable field can be written when every other bank byte is known");
        auto value=process.readRegister("v0");fresh=process.readRegister("x0");
        check(value && std::equal(vector.begin(),vector.end(),value->begin(),value->end()) && fresh && *fresh==originalX0,
              "replacing an unavailable vector preserves all known neighboring registers");
    } else if (mode=="bank-G-error") {
        check(!process.writeRegister("x0",edit),"an error from G remains an unconfirmed edit");
        auto fresh=process.readRegister("x0");check(fresh && *fresh==originalX0,"a peer-rejected bank write preserves original state");
    } else {
        auto written=process.writeRegister("x0",edit);auto fresh=process.readRegister("x0");
        check(written && fresh && std::equal(edit.begin(),edit.end(),fresh->begin(),fresh->end()),
              "scalar fallback edits reach the actual stopped stub and read back exactly");
        if (mode=="bank-truncated") {
            check(!process.readRegister("pc") && !process.writeRegister("pc",edit),
                  "a complete returned prefix stays usable while omitted trailing registers remain unavailable");
        } else {
            const std::array<uint8_t,16> vector={0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f};
            auto vectorEdit=process.writeRegister("v0",vector);auto vectorRead=process.readRegister("v0");
            const std::array<uint8_t,3> narrow={0xfe,0xff,1};
            auto narrowEdit=process.writeRegister("narrow",narrow);auto narrowRead=process.readRegister("narrow");
            auto pc=process.readRegister("pc");
            const std::vector<uint8_t> expectedPc=mode=="bank-only" ? std::vector<uint8_t>{0xef,0xcd,0xab,0x89,0,0,0,0x40} : originalPc;
            check(vectorEdit && vectorRead && std::equal(vector.begin(),vector.end(),vectorRead->begin(),vectorRead->end()) &&
                  narrowEdit && narrowRead && std::equal(narrow.begin(),narrow.end(),narrowRead->begin(),narrowRead->end()) && pc && *pc==expectedPc,
                  "mixed-width sparse/out-of-order registers use numeric wire order and each write preserves fresh unrelated values");
        }
    }
    check(process.detach().has_value(),"bank-only session detaches normally after success or recoverable register errors");
    std::printf("GDB_REGISTER_BANK_RESULT=%s mode=%s\n",failures ? "FAILED" : "PASSED",mode.c_str());
    return failures ? 1 : 0;
}
