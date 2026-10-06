#include "debug/patch.hpp"

static void codeWriteTests() {
    TargetBuffer unknown;
    const auto saved=unknown.bytes;
    const std::array<uint8_t,4> nop{0x1f,0x20,0x03,0xd5};
    auto rejected=patchInstructionBytes(unknown,unknown.base,nop);
    check(!rejected && unknown.writes==0 && unknown.bytes==saved,
          "Unknown instruction architectures cannot patch code or attempt an unverified undo write");
    TargetBuffer arm;
    arm.description.host=arm.description.program=*parseElfTarget(elf(EM_AARCH64,true,true));
    arm.protection=MemProt::Read|MemProt::Exec;
    auto bytes=nopBytesFor(arm,arm.base,8);
    check(bytes && *bytes==std::vector<uint8_t>{0x1f,0x20,0x03,0xd5,0x1f,0x20,0x03,0xd5} && arm.writes==0,
          "AArch64 NOP bytes remain little endian even when target data uses big endian");
    check(!nopBytesFor(arm,arm.base+1,4) && !nopBytesFor(arm,arm.base,5) &&
          !nopBytesFor(arm,arm.base,0) && !nopBytesFor(arm,UINTPTR_MAX-3,8) && arm.writes==0,
          "Unaligned, fractional, empty and overflowing AArch64 NOP patches fail before mutation");
    AutoAssembler assembler;
    const auto before=arm.bytes;
    auto enable=assembler.execute(arm,"[ENABLE]\n0x10000:\nnop\n");
    check(!enable.success && arm.bytes==before && arm.writes==0 && arm.protection==(MemProt::Read|MemProt::Exec),
          "AutoAssembler refuses an ARM64 RX target without a cache adapter without promoting protection");
    struct ArmCode final : TargetBuffer {
        unsigned codeWrites=0;
        Result<size_t> writeCode(uintptr_t address,const void* data,size_t size) override {
            ++codeWrites;return write(address,data,size);
        }
    } explicitArm;
    explicitArm.description=arm.description;explicitArm.protection=arm.protection;
    const auto explicitBefore=explicitArm.bytes;AutoAssembler supported;
    auto enabled=supported.execute(explicitArm,"[ENABLE]\n0x10000:\nnop\n");
    bool installed=enabled.success && explicitArm.codeWrites==1 && std::equal(nop.begin(),nop.end(),explicitArm.bytes.begin()) && explicitArm.protection==arm.protection;
    auto disabled=supported.disable(explicitArm,"[DISABLE]",enabled.disableInfo);
    check(installed && disabled.success && explicitArm.codeWrites==2 && explicitArm.bytes==explicitBefore && explicitArm.protection==arm.protection,
          "AutoAssembler enable and disable both use an explicit ARM64 code adapter and retain RX protection");
    auto counted=supported.execute(explicitArm,"[ENABLE]\nlabel(after)\n0x10000:\ndd after\nnop 3\nafter:\ndb AB CD\n");
    bool layout=counted.success && std::equal(explicitArm.bytes.begin(),explicitArm.bytes.begin()+4,std::array<uint8_t,4>{0,1,0,0x10}.begin()) && explicitArm.bytes[16]==0xab && explicitArm.bytes[17]==0xcd;
    for (size_t at=4;at<16;at+=4) layout &= std::equal(nop.begin(),nop.end(),explicitArm.bytes.begin()+at);
    auto countedUndo=supported.disable(explicitArm,"[DISABLE]",counted.disableInfo);
    check(layout && countedUndo.success && explicitArm.bytes==explicitBefore,
          "Counted ARM64 NOP directives size forward labels by complete instructions and restore every byte");
    bool malformed=true;
    for (const char* count:{"-1","2junk","0","268435457","4294967297"}) {
        auto invalid=supported.execute(explicitArm,std::string("[ENABLE]\n0x10000:\nnop ")+count+"\n");
        malformed &= !invalid.success && explicitArm.bytes==explicitBefore;
    }
    check(malformed,"Negative, trailing, zero and excessive NOP counts fail before allocating a patch buffer");
    auto unaligned=supported.execute(explicitArm,"[ENABLE]\n0x10001:\nnop\n");
    auto overflowing=supported.execute(explicitArm,"[ENABLE]\n0xfffffffffffffffc:\nnop 2\n");
    check(!unaligned.success && !overflowing.success && explicitArm.bytes==explicitBefore,
          "AutoAssembler rejects unaligned ARM64 NOPs and overflowing instruction ranges during label sizing");
    TargetBuffer x86;x86.description.host=x86.description.program=*parseElfTarget(elf(EM_X86_64,true));
    x86.protection=MemProt::Read|MemProt::Exec;
    const auto x86Before=x86.bytes;
    x86.shortWrites=true;auto shortPatch=patchInstructionBytes(x86,x86.base,nop);
    check(!shortPatch && x86.bytes==x86Before && x86.protection==(MemProt::Read|MemProt::Exec),
          "Shared patch helpers reject a short x86 write and restore actual original bytes without changing protection");
    struct Retired final : TargetBuffer {
        unsigned attempts=0;
        Result<size_t> writeCode(uintptr_t,const void*,size_t) override {
            ++attempts;bytes[0]=0xab;
            return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        }
    } retired;
    retired.description=x86.description;
    auto stale=patchInstructionBytes(retired,retired.base,nop);
    check(!stale && retired.attempts==1 && retired.bytes[0]==0xab && stale.error().find("no undo bytes were replayed")!=std::string::npos,
          "A retired code transaction cannot trigger a second undo write into a replacement process image");
}
