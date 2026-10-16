#include "arch/aarch64_relocator.hpp"

static std::vector<uint8_t> relocationWords(std::initializer_list<uint32_t> words) {
    std::vector<uint8_t> bytes;
    for (auto word:words) for (unsigned i=0;i<4;++i) bytes.push_back(static_cast<uint8_t>(word>>(8*i)));
    return bytes;
}
static uint32_t relocationWord(const std::vector<uint8_t>& bytes,size_t offset) {
    if (offset+4>bytes.size()) return 0;
    return uint32_t(bytes[offset])|(uint32_t(bytes[offset+1])<<8)|(uint32_t(bytes[offset+2])<<16)|(uint32_t(bytes[offset+3])<<24);
}
static void aarch64RelocationTests() {
    const auto original=relocationWords({0x14000002,0xd503201f,0xd65f03c0});
    auto copy=relocateAarch64(original,0x1000,0x1000);
    check(copy && copy->bytes==original && copy->instructionOffsets==std::vector<size_t>{0,4,8},
          "AArch64 reassembly at the same address preserves every original byte and instruction boundary");
    auto branch=relocateAarch64(original,0x1000,0x2000);
    check(branch && branch->bytes.size()==28 && branch->instructionOffsets==std::vector<size_t>{0,20,24} &&
          relocationWord(branch->bytes,0)==0x14000006 && relocationWord(branch->bytes,24)==0xd65f03c0,
          "AArch64 static branches follow relocated internal instructions without padding absent source instructions");
    bool conditions=true;
    for (unsigned condition=0;condition<16;++condition) {
        auto block=relocateAarch64(relocationWords({0x54000040u|condition,0xd503201f,0xd65f03c0}),0x1000,0x2000);
        conditions &= block && block->bytes.size()==32 &&
            relocationWord(block->bytes,0)==(condition<14 ? (0x540000c0u|(condition^1)) : 0x14000007u) &&
            (condition>=14 || relocationWord(block->bytes,4)==0x14000006u);
    }
    check(conditions,"AArch64 conditional veneers invert only real predicates; AL and NV both retain unconditional behavior");
    auto compare=relocateAarch64(relocationWords({0xb4000040,0xd503201f,0xd65f03c0}),0x1000,0x2000);
    auto test=relocateAarch64(relocationWords({0xb6080043,0xd503201f,0xd65f03c0}),0x1000,0x2000);
    check(compare && test && relocationWord(compare->bytes,0)==0xb50000c0 && relocationWord(test->bytes,0)==0xb70800c3 &&
          relocationWord(compare->bytes,4)==0x14000006 && relocationWord(test->bytes,4)==0x14000006,
          "AArch64 CBZ and TBZ relocation retains register width and high tested bits while extending branch reach");
    auto page=relocateAarch64(relocationWords({0x90000000}),0x1ffc,0x400000000);
    auto address=relocateAarch64(relocationWords({0x70000000}),0x1000,0x400000000);
    check(page && address && page->bytes==relocationWords({0xd2820000,0xf2a00000,0xf2c00000,0xf2e00000}) &&
          address->bytes==relocationWords({0xd2820060,0xf2a00000,0xf2c00000,0xf2e00000}),
          "AArch64 ADR/ADRP preserve unaligned absolute addresses and architectural 4 KiB pages across arbitrary distances");
    bool literals=true;
    for (auto [word,load]:{std::pair{0x18000080u,0xb9400000u},std::pair{0x58000080u,0xf9400000u},std::pair{0x98000080u,0xb9800000u}}) {
        auto block=relocateAarch64(relocationWords({word}),0x1000,0x400000000);
        literals &= block && block->bytes.size()==20 && relocationWord(block->bytes,16)==load;
    }
    check(literals,"Far AArch64 integer and sign-extending literal loads use their own result register without borrowing live registers");
    Aarch64RelocationOptions scratch;scratch.scratchRegister=16;
    bool vectors=true;
    for (auto [word,load]:{std::pair{0x1c000080u,0xbd400200u},std::pair{0x5c000080u,0xfd400200u},std::pair{0x9c000080u,0x3dc00200u},std::pair{0xd8000080u,0xf9800200u},std::pair{0x5800009fu,0xf940021fu}}) {
        auto rejected=relocateAarch64(relocationWords({word}),0x1000,0x400000000);
        auto permitted=relocateAarch64(relocationWords({word}),0x1000,0x400000000,scratch);
        vectors &= !rejected && permitted && permitted->bytes.size()==20 && relocationWord(permitted->bytes,16)==load;
    }
    check(vectors,"Far AArch64 vector, prefetch and zero-register literals require an explicitly permitted scratch register");
    auto nearLiteral=relocateAarch64(relocationWords({0x58000080}),0x1000,0x2000);
    check(nearLiteral && relocationWord(nearLiteral->bytes,0)==0x58ff8080 && nearLiteral->bytes.size()==20,
          "Nearby AArch64 literal loads retain their original memory address instead of copying a stale literal value");
    scratch.allowIndirectBranches=true;Aarch64RelocationOptions calls;calls.allowIndirectBranches=true;
    auto farBranch=relocateAarch64(relocationWords({0x14000004}),0x1000,0x400000000,scratch);
    auto farCall=relocateAarch64(relocationWords({0x94000004}),0x1000,0x400000000,calls);
    check(farBranch && farCall && relocationWord(farBranch->bytes,16)==0xd61f0200 && relocationWord(farCall->bytes,16)==0xd63f03c0 &&
          !relocateAarch64(relocationWords({0x14000004}),0x1000,0x400000000) &&
          !relocateAarch64(relocationWords({0x14000004}),0x1000,0x400000000,calls),
          "Far AArch64 calls use LR and jumps require explicit indirect-landing and scratch-register permissions");
    Aarch64RelocationOptions invalid;invalid.scratchRegister=31;
    check(!relocateAarch64({},0x1000,0x2000) && !relocateAarch64(std::array<uint8_t,3>{},0x1000,0x2000) &&
          !relocateAarch64(original,0x1001,0x2000) && !relocateAarch64(original,0x1000,0x2001) &&
          !relocateAarch64(original,UINT64_MAX-3,0x2000) && !relocateAarch64(original,0x1000,UINT64_MAX-3) &&
          !relocateAarch64(original,0x1000,0x2000,invalid) && !relocateAarch64(relocationWords({0xffffffff}),0x1000,0x2000),
          "Malformed AArch64 blocks, overflowing ranges and invalid scratch registers fail before producing a patch");
    TargetBuffer process;
    process.description.program=process.description.host=*parseElfTarget(elf(EM_AARCH64,true));
    const auto adr=relocationWords({0x70000000});std::copy(adr.begin(),adr.end(),process.bytes.begin());
    const auto before=process.bytes;AutoAssembler assembler;
    auto enabled=assembler.execute(process,"[ENABLE]\n0x11000:\nreassemble(0x10000)\nlabel(after)\nafter:\ndb AB CD\n");
    const auto expected=relocationWords({0xd2800060,0xf2a00020,0xf2c00000,0xf2e00000});
    check(enabled.success && std::equal(expected.begin(),expected.end(),process.bytes.begin()+0x1000) &&
          process.bytes[0x1010]==0xab && process.bytes[0x1011]==0xcd && process.bytes[0]==0,
          "AutoAssembler AArch64 REASSEMBLE uses expanded instruction sizes for following labels and data");
    auto disabled=assembler.disable(process,"[DISABLE]",enabled.disableInfo);
    check(enabled.success && disabled.success && process.bytes==before,
          "Disabling expanded AArch64 REASSEMBLE restores every overwritten destination byte");
    TargetBuffer fault;fault.description.host=fault.description.program=*parseElfTarget(elf(EM_X86_64,true));
    fault.bytes[0]=0x90;fault.failReadAfterWrite=fault.base;
    const auto faultBefore=fault.bytes;AutoAssembler failing;
    auto failed=failing.execute(fault,"[ENABLE]\n0x11000:\ndb AB CD\nreassemble(0x10000)\ndb EF\n");
    check(!failed.success && failed.error.find("REASSEMBLE")!=std::string::npos && fault.bytes==faultBefore && fault.writes>=2,
          "A source becoming unreadable after sizing aborts REASSEMBLE and rolls back earlier writes instead of silently skipping it");
    // The target itself rewrites the source once the script starts writing,
    // after label sizing (the script's own writes cannot: REASSEMBLE reads the
    // code from before them).
    struct ChangingSource : TargetBuffer {
        std::vector<uint8_t> replacement;
        Result<size_t> read(uintptr_t address,void* buffer,size_t n) override {
            if (address==base && writes>0 && !replacement.empty()) {
                std::copy(replacement.begin(),replacement.end(),bytes.begin());
                replacement.clear();
            }
            return TargetBuffer::read(address,buffer,n);
        }
    };
    bool changedSizes=true;
    for (bool grow:{false,true}) {
        ChangingSource changed;
        changed.description.host=changed.description.program=*parseElfTarget(elf(EM_AARCH64,true));
        const auto source=relocationWords({grow ? 0xd503201fu : 0x10000000u});
        changed.replacement=relocationWords({grow ? 0x10000000u : 0xd503201fu});
        std::copy(source.begin(),source.end(),changed.bytes.begin());
        const std::vector<uint8_t> destination(changed.bytes.begin()+0x1000,changed.bytes.begin()+0x1020);
        AutoAssembler checked;
        auto result=checked.execute(changed,"[ENABLE]\nlabel(after)\n0x11000:\ndd after\nreassemble(0x10000)\nafter:\ndb AB CD\n");
        changedSizes &= !result.success && result.error.find("size changed after label sizing")!=std::string::npos &&
            std::equal(destination.begin(),destination.end(),changed.bytes.begin()+0x1000);
    }
    check(changedSizes,"AArch64 REASSEMBLE growth and shrinkage after sizing cannot corrupt forward label references; earlier data writes roll back");
    ChangingSource changedX86;
    changedX86.description.host=changedX86.description.program=*parseElfTarget(elf(EM_X86_64,true));
    changedX86.bytes[0]=0x90;changedX86.replacement={0xb8,0,0,0,0};
    const std::vector<uint8_t> destinationX86(changedX86.bytes.begin()+0x1000,changedX86.bytes.begin()+0x1010);
    AutoAssembler checkedX86;
    auto changedX86Result=checkedX86.execute(changedX86,"[ENABLE]\nlabel(after)\n0x11000:\ndb 90\nreassemble(0x10000)\nafter:\ndb AB CD\n");
    check(!changedX86Result.success && changedX86Result.error.find("size changed after label sizing")!=std::string::npos &&
          std::equal(destinationX86.begin(),destinationX86.end(),changedX86.bytes.begin()+0x1000),
          "The REASSEMBLE size-change guard also protects variable-length x86 instructions");
    for (bool arm:{true,false}) {
        TargetBuffer sameSize;
        sameSize.description.host=sameSize.description.program=*parseElfTarget(elf(arm ? EM_AARCH64 : EM_X86_64,true));
        const auto nop=arm ? relocationWords({0xd503201f}) : std::vector<uint8_t>{0x90};
        std::copy(nop.begin(),nop.end(),sameSize.bytes.begin());
        const auto savedSame=sameSize.bytes;AutoAssembler checkedSame;
        auto sameResult=checkedSame.execute(sameSize,std::string("[ENABLE]\nlabel(after)\n0x10000:\ndb ")+(arm ? "C0 03 5F D6" : "C3")+
                                                    "\n0x11000:\nreassemble(0x10000)\nafter:\ndb AB CD\n");
        bool sameOk=sameResult.success && std::equal(nop.begin(),nop.end(),sameSize.bytes.begin()+0x1000) &&
                    sameSize.bytes[0x1000+nop.size()]==0xab && sameSize.bytes[0]==(arm ? 0xc0 : 0xc3);
        auto sameDisable=checkedSame.disable(sameSize,"[DISABLE]",sameResult.disableInfo);
        check(sameOk && sameDisable.success && sameSize.bytes==savedSame,
              arm ? "AArch64 REASSEMBLE relocates the source from before the script's own write to it and disables cleanly"
                  : "x86 REASSEMBLE relocates the source from before the script's own write to it and disables cleanly");
    }
}
