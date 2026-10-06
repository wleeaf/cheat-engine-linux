#include "scanner/memory_scanner.hpp"
#include "core/target_machine.hpp"
#include <cstdio>
#include <unistd.h>
#include <cstring>
#include <stdexcept>
struct FaultProcess : ce::ProcessHandle {
    pid_t pid() const override {return getpid();}
    bool is64bit() const override {return true;}
    bool supportsConcurrentReads() const override {return true;}
    ce::TargetDescription targetDescription() override {ce::TargetDescription d;d.program=ce::nativeTargetMachine();return d;}
    ce::Result<size_t> read(uintptr_t,void*,size_t) override {throw std::bad_alloc();}
    std::vector<ce::MemoryRegion> queryRegions() override {return {{0x10000,70000,ce::MemProt::ReadWrite,ce::MemType::Private,ce::MemState::Committed,"fault fixture"}};}
    std::optional<ce::MemoryRegion> queryRegion(uintptr_t) override {return queryRegions()[0];}
    ce::Result<size_t> write(uintptr_t,const void*,size_t) override {return std::unexpected(std::make_error_code(std::errc::operation_not_supported));}
    ce::Result<uintptr_t> allocate(size_t,ce::MemProt,uintptr_t) override {return std::unexpected(std::make_error_code(std::errc::operation_not_supported));}
    ce::Result<void> free(uintptr_t,size_t) override {return {};}
    ce::Result<void> protect(uintptr_t,size_t,ce::MemProt) override {return {};}
    std::vector<ce::ModuleInfo> modules() override {return {};}
    std::vector<ce::ThreadInfo> threads() override {return {};}
};
int main(int argc,char** argv) {
    FaultProcess p;ce::MemoryScanner scanner(2);ce::ScanConfig c;
    c.valueType=ce::ValueType::Byte;c.compareType=ce::ScanCompare::Unknown;c.alignment=1;
    try {
        if(argc>1 && std::strcmp(argv[1],"next")==0) {
            ce::ScanResult previous(std::filesystem::temp_directory_path()/"previous");uint8_t byte=42;
            for(size_t i=0;i<70000;++i) previous.addResult(0x10000+i,&byte,1);
            previous.finalize();auto r=scanner.nextScan(p,c,previous);
            std::printf("NEXT_FALSE_SUCCESS count=%zu\n",r.count());
        } else {auto r=scanner.firstScan(p,c);std::printf("FIRST_FALSE_SUCCESS count=%zu\n",r.count());}
    } catch(const std::bad_alloc&) {std::puts("BAD_ALLOC_PROPAGATED");return 0;}
    return 2;
}
