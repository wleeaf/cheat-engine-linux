#include "arch/aarch64_relocator.hpp"
#include <array>
#include <cstdio>
#include <cstring>
#include <utility>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <unistd.h>

extern "C" {
extern unsigned char relocation_blob_start[],relocation_blob_end[];
extern unsigned char relocation_literal_word[],relocation_literal_double[],relocation_literal_vector[];
struct Result {uint64_t value,nzcv;};
Result relocation_call(void* address,uint64_t nzcv,uint64_t argument);
#define CASE(name) extern unsigned char relocation_##name[],relocation_##name##_end[];
CASE(adr_positive) CASE(adr_negative) CASE(adrp)
CASE(literal_w) CASE(literal_sw) CASE(literal_x) CASE(literal_s) CASE(literal_d) CASE(literal_q)
CASE(prefetch) CASE(zero_literal) CASE(internal_branch) CASE(loop)
CASE(conditional) CASE(conditional_external) CASE(cbz_x) CASE(cbnz_x) CASE(cbz_w) CASE(cbnz_w)
CASE(tbz_high) CASE(tbnz_high) CASE(tbz_low) CASE(tbnz_low) CASE(external_branch) CASE(external_call)
#undef CASE
}
static unsigned failures,checks,executions;
static void check(bool ok,const char* what) {
    ++checks;failures+=!ok;std::printf("%s: %s\n",ok ? "OK" : "FAILED",what);std::fflush(stdout);
}
static size_t offset(const unsigned char* address) {return address-relocation_blob_start;}
static bool prepare(unsigned char* memory,size_t size,size_t at,const void* bytes,size_t length) {
    if (at>size || length>size-at || mprotect(memory,size,PROT_READ|PROT_WRITE)) return false;
    std::memcpy(memory+at,bytes,length);
    __builtin___clear_cache(reinterpret_cast<char*>(memory+at),reinterpret_cast<char*>(memory+at+length));
    return !mprotect(memory,size,PROT_READ|PROT_EXEC);
}
int main() {
    struct utsname kernel{};uname(&kernel);
    const size_t size=65536,page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    std::printf("AARCH64_RELOCATION_KERNEL=%s pageSize=%zu\n",kernel.release,page);
    auto* source=static_cast<unsigned char*>(mmap(reinterpret_cast<void*>(0x20000000),size,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0));
    auto* destination=static_cast<unsigned char*>(mmap(reinterpret_cast<void*>(0x60000000),size,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0));
    check(source!=MAP_FAILED && destination!=MAP_FAILED,"independent source/destination mappings are one GiB apart without replacing another mapping");
    if (source!=MAP_FAILED && destination!=MAP_FAILED) {
        std::array<unsigned char,size> before{};std::memcpy(before.data(),relocation_blob_start,offset(relocation_blob_end));
        check(prepare(source,size,0,before.data(),before.size()),"seed GNU-assembled code and pools using W^X protection changes and explicit instruction-cache synchronization");
        ce::Aarch64RelocationOptions options;options.scratchRegister=16;options.allowIndirectBranches=true;
        auto run=[&](unsigned char* first,unsigned char* last,uint64_t argument,uint64_t nzcv,uint64_t expected,bool fixedFlags=true) {
            const size_t at=offset(first),length=last-first;
            ++executions;const auto original=relocation_call(source+at,nzcv,argument);
            auto code=ce::relocateAarch64({source+at,length},reinterpret_cast<uintptr_t>(source+at),reinterpret_cast<uintptr_t>(destination),options);
            if (!code) {std::fprintf(stderr,"Relocation error: %s\n",code.error().c_str());return false;}
            if (!prepare(destination,size,0,code->bytes.data(),code->bytes.size())) return false;
            ++executions;const auto moved=relocation_call(destination,nzcv,argument);
            return original.value==expected && moved.value==expected && moved.nzcv==original.nzcv && (!fixedFlags || moved.nzcv==nzcv);
        };
        check(run(relocation_adr_positive,relocation_adr_positive_end,0,0xa0000000,reinterpret_cast<uintptr_t>(source)+offset(relocation_adr_positive)+0x123),"far ADR retains the original unaligned absolute address and NZCV");
        check(run(relocation_adr_negative,relocation_adr_negative_end,0,0xa0000000,reinterpret_cast<uintptr_t>(source)+offset(relocation_adr_negative)-5),"negative ADR offsets preserve their original address");
        check(run(relocation_adrp,relocation_adrp_end,0,0xa0000000,reinterpret_cast<uintptr_t>(source)+0x3000),"ADRP uses architectural 4 KiB page arithmetic even when the Linux page size differs");
        check(run(relocation_literal_w,relocation_literal_w_end,0,0xa0000000,0x80000001),"far LDR W zero-extends original live literal data");
        check(run(relocation_literal_sw,relocation_literal_sw_end,0,0xa0000000,0xffffffff80000001),"far LDRSW retains sign extension and flags");
        check(run(relocation_literal_x,relocation_literal_x_end,0,0xa0000000,0x1234567890abcdef),"far LDR X reads the original 64-bit literal address");
        check(run(relocation_literal_s,relocation_literal_s_end,0,0xa0000000,0x80000001),"far SIMD S literal loads retain all 32 raw bits");
        check(run(relocation_literal_d,relocation_literal_d_end,0,0xa0000000,0x1234567890abcdef),"far SIMD D literal loads retain all 64 raw bits");
        check(run(relocation_literal_q,relocation_literal_q_end,0,0xa0000000,0x1234567890abcdefULL^0xfedcba0987654321ULL),"far SIMD Q literal loads retain both 64-bit halves");
        check(run(relocation_prefetch,relocation_prefetch_end,0,0xa0000000,42) && run(relocation_zero_literal,relocation_zero_literal_end,0,0xa0000000,42),"far prefetch and zero-register literals use only the explicitly permitted scratch register");
        auto liveLiteral=ce::relocateAarch64({source+offset(relocation_literal_x),size_t(relocation_literal_x_end-relocation_literal_x)},
            reinterpret_cast<uintptr_t>(source+offset(relocation_literal_x)),reinterpret_cast<uintptr_t>(destination),options);
        bool mutablePool=liveLiteral && prepare(destination,size,0,liveLiteral->bytes.data(),liveLiteral->bytes.size());
        const uint64_t changed=0x8877665544332211;
        mutablePool &= prepare(source,size,offset(relocation_literal_double),&changed,sizeof(changed));
        if (mutablePool) {++executions;mutablePool=relocation_call(destination,0,0).value==changed;}
        check(mutablePool,"changing a literal after relocation is observed by the same relocated code, without a stale copied pool");
        check(prepare(source,size,0,before.data(),before.size()),"restore the original source image after live pool mutation");
        check(run(relocation_internal_branch,relocation_internal_branch_end,0,0xa0000000,42) && run(relocation_loop,relocation_loop_end,0,0,3,false),"forward and backward internal branches follow relocated instruction boundaries");
        check(run(relocation_external_branch,relocation_external_branch_end,0,0xa0000000,42),"an explicitly permitted far tail branch preserves the caller's return link");
        check(run(relocation_external_call,relocation_external_call_end,0,0xa0000000,42),"far BLR X30 returns through the relocated call continuation and preserves the function's original return link");
        // Truth tables are independent of the relocator, assembler and decoder.
        const std::array<uint16_t,16> truth={0xf0f0,0x0f0f,0xcccc,0x3333,0xff00,0x00ff,0xaaaa,0x5555,0x0c0c,0xf3f3,0xaa55,0x55aa,0x0a05,0xf5fa,0xffff,0xffff};
        bool predicates=true;
        for (unsigned condition=0;condition<16;++condition) for (unsigned flags=0;flags<16;++flags) {
            const uint64_t expected=(truth[condition]&(1u<<flags)) ? 42 : 17;
            for (auto [first,last]:{std::pair<unsigned char*,unsigned char*>{relocation_conditional,relocation_conditional_end},
                                  std::pair<unsigned char*,unsigned char*>{relocation_conditional_external,relocation_conditional_external_end}}) {
                uint32_t word;std::memcpy(&word,before.data()+offset(first),4);word=(word&~15u)|condition;
                predicates &= prepare(source,size,offset(first),&word,sizeof(word));
                if (predicates) predicates=run(first,last,0,uint64_t(flags)<<28,expected);
            }
        }
        check(predicates,"all 256 NZCV/condition combinations preserve values and flags for internal and far external branches, including AL/NV");
        bool registerBranches=true;
        for (uint64_t value:{uint64_t(0),uint64_t(1),uint64_t(1)<<32,uint64_t(1)<<63}) {
#define CHECK_BRANCH(name,taken) registerBranches &= run(relocation_##name,relocation_##name##_end,value,0xa0000000,(taken) ? 42 : 17);
            CHECK_BRANCH(cbz_x,value==0) CHECK_BRANCH(cbnz_x,value!=0)
            CHECK_BRANCH(cbz_w,uint32_t(value)==0) CHECK_BRANCH(cbnz_w,uint32_t(value)!=0)
            CHECK_BRANCH(tbz_high,!(value&(uint64_t(1)<<63))) CHECK_BRANCH(tbnz_high,value&(uint64_t(1)<<63))
            CHECK_BRANCH(tbz_low,!(value&1)) CHECK_BRANCH(tbnz_low,value&1)
#undef CHECK_BRANCH
        }
        check(registerBranches,"far CBZ/CBNZ/TBZ/TBNZ preserve W/X widths, low/high bits and NZCV");
        check(prepare(source,size,0,before.data(),before.size()) && !std::memcmp(source,before.data(),before.size()),"restore every original code and literal byte after the execution matrix");
        check(!munmap(source,size) && !munmap(destination,size),"release both mappings after all actual Linux executions");
    } else {
        if (source!=MAP_FAILED) munmap(source,size);
        if (destination!=MAP_FAILED) munmap(destination,size);
    }
    std::printf("AARCH64_RELOCATION_RESULT=%s checks=%u executions=%u failures=%u\n",failures ? "FAILED" : "PASSED",checks,executions,failures);std::fflush(stdout);
    if (getpid()==1) {sync();reboot(RB_POWER_OFF);}
    return failures ? 1 : 0;
}
