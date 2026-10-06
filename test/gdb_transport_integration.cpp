#include "debug/gdb_remote.hpp"
#ifndef CE_GDB_LEGACY_PROBE
#include "platform/gdb_process.hpp"
#include "core/target_capabilities.hpp"
#include "core/value_io.hpp"
#include "scanner/memory_scanner.hpp"
#include "arch/disassembler.hpp"
#include "arch/target_arch.hpp"
#endif
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
static unsigned failures;
static void check(bool ok,const char* what) {std::printf("%s: %s\n",ok ? "OK" : "FAILED",what);std::fflush(stdout);failures+=!ok;}
#ifndef CE_GDB_LEGACY_PROBE
#include "test/gdb_register_bank_checks.inc"
#endif
int main(int argc,char** argv) {
    if (argc!=4) return 2;
    const std::string mode=argv[1],host=argv[2];const auto port=static_cast<uint16_t>(std::strtoul(argv[3],nullptr,10));
    if (mode.starts_with("raw-")) {
        ce::GdbRemoteClient client;std::string error;
#ifndef CE_GDB_LEGACY_PROBE
        client.setTimeout(std::chrono::milliseconds(75));
#endif
        if (!client.connectTcp(host,port,error)) {std::fprintf(stderr,"%s\n",error.c_str());return 1;}
#ifndef CE_GDB_LEGACY_PROBE
        std::stop_source cancellation;std::jthread cancelThread;
        if (mode=="raw-cancel") {
            client.setTimeout(std::chrono::milliseconds(1000));client.setCancellation(cancellation.get_token());
            cancelThread=std::jthread([&]{std::this_thread::sleep_for(std::chrono::milliseconds(25));cancellation.request_stop();});
        }
#endif
        if (mode=="raw-short" || mode=="raw-oversized" || mode=="raw-error") {
            auto result=client.readMemory(0x1000,mode=="raw-short" ? 4 : 2);
            check(mode=="raw-short" ? result && *result==std::vector<uint8_t>({0x11,0x22}) :
                  !result,"memory replies retain real short/error/oversized semantics");
        } else {
            const auto before=std::chrono::steady_clock::now();
            auto result=client.sendPacket(mode=="raw-escape" ? "X$#}*" : "g");
            const bool bad=mode.starts_with("raw-bad") || mode=="raw-timeout" || mode=="raw-eof" || mode=="raw-cancel";
            check(bad ? !result && !client.isConnected() :
                  result && *result==(mode=="raw-hex" ? "E012341234" : mode=="raw-escape" ? "$#}*" : mode=="raw-rle" ? "11112222" : "1122"),
                  "framed replies, escapes and retransmissions preserve actual payloads");
            if (mode=="raw-timeout") check(std::chrono::steady_clock::now()-before<std::chrono::milliseconds(200),"a stalled peer is bounded by one transaction deadline");
            if (mode=="raw-cancel") check(std::chrono::steady_clock::now()-before<std::chrono::milliseconds(250),"cancellation interrupts stalled socket polling before its ordinary deadline");
        }
        std::printf("GDB_RAW_RESULT=%s\n",failures ? "FAILED" : "PASSED");return failures ? 1 : 0;
    }
#ifndef CE_GDB_LEGACY_PROBE
    if (mode.starts_with("bank-")) return registerBankChecks(mode,host,port);
    if (mode=="adapter-high") {
        const uintptr_t base=static_cast<uintptr_t>(uint64_t(1)<<52);
        ce::GdbProcessOptions options;options.byteOrder=ce::ByteOrder::Big;options.pointerWidth=8;
        options.regions={{base,64,ce::MemProt::ReadWrite,ce::MemType::Private,ce::MemState::Committed,{}}};
        auto opened=ce::GdbProcessHandle::connect(host,port,options);check(bool(opened),"high-address guest transport connects");
        if (!opened) return 1;
        ce::MemoryScanner scanner(1);ce::ScanConfig config;config.valueType=ce::ValueType::Int32;config.intValue=0x11223344;config.alignment=1;
        auto result=scanner.firstScan(**opened,config);
        check(result.count()==1 && result.address(0)==base,"default shared scans include actual remote bytes beyond the old 47-bit ceiling");
        auto next=scanner.nextScan(**opened,config,result);check(next.count()==1 && next.address(0)==base,"high-address remote samples narrow without local address truncation");
        (*opened)->disconnect();
        printf("GDB_ADAPTER_RESULT=%s mode=adapter-high\n",failures ? "FAILED" : "PASSED");return failures ? 1 : 0;
    }
    if (mode=="adapter-width" || mode=="adapter-endian-conflict") {
        ce::GdbProcessOptions options;
        if (mode=="adapter-width") options.pointerWidth=4;
        else options.byteOrder=ce::ByteOrder::Big;
        auto opened=ce::GdbProcessHandle::connect(host,port,options);
        if (mode=="adapter-endian-conflict") check(!opened,"an explicit byte order cannot contradict an x86 description");
        else {
            check(opened.has_value(),"a known narrower program pointer width can be selected explicitly");
            if (opened) {
                const auto description=(**opened).targetDescription();
                check(description.live && description.program.pointerWidth==4 && description.program.abi==ce::TargetAbi::Unknown &&
                      description.program.instructionMode==ce::InstructionMode::X86_64,
                      "a pointer-width override preserves CPU mode without inventing a matching Linux program ABI");
            }
        }
        return failures ? 1 : 0;
    }
    if (mode=="adapter-fail") {
        auto opened=ce::GdbProcessHandle::connect(host,port);
        check(!opened,"a malformed stop or guest map cannot produce a live adapter");
        return failures ? 1 : 0;
    }
    if (mode=="adapter-dead") {
        auto opened=ce::GdbProcessHandle::connect(host,port);
        check(opened && !(**opened).targetDescription().live && !(**opened).read<uint32_t>(0x1000),
              "a real exit reply retires memory and register access without sending a stale detach");
        return failures ? 1 : 0;
    }
    if (mode=="xml" || mode=="xml-fail" || mode=="chunks" || mode=="partial-write") {
        ce::GdbRemoteClient client;client.setTimeout(std::chrono::milliseconds(250));std::string error;
        if (!client.connectTcp(host,port,error)) return 1;
        auto negotiated=client.negotiate();check(negotiated.has_value(),"qSupported and no-ack negotiation complete");
        if (!negotiated) return 1;
        if (mode.starts_with("xml")) {
            auto target=client.describeTarget();
            if (mode=="xml-fail") check(!target,"invalid or cyclic XML never creates a guessed target");
            else {
                if (!target) std::fprintf(stderr,"%s\n",target.error().c_str());
                check(target && target->machine.architecture==ce::CpuArchitecture::X86_64 && target->machine.pointerWidth==8 &&
                      target->machine.byteOrder==ce::ByteOrder::Little && target->machine.abi==ce::TargetAbi::LinuxX86_64 &&
                      target->registers.size()==2 && target->registers[1].number==20,"included XML preserves guest architecture, ABI and sparse register numbers");
                if (target) {
                    auto reg=client.readRegister(target->registers[1]);
                    check(reg && reg->size()==8 && (*reg)[0]==0xe0,"register data beginning with E is decoded using the described width");
                    auto wrong=client.writeRegister(target->registers[1],std::array<uint8_t,1>{0});
                    check(!wrong,"wrong-width register edits never reach the stub");
                }
            }
        } else {
            std::vector<uint8_t> bytes(300);for (size_t i=0;i<bytes.size();++i) bytes[i]=static_cast<uint8_t>(i);
            auto written=client.writeMemory(0x1000,bytes);
            check(written && *written==(mode=="partial-write" ? 12 : bytes.size()),"only confirmed write chunks are reported as completed");
            if (mode=="chunks") {auto read=client.readMemory(0x1000,bytes.size());check(read && *read==bytes,"memory reads respect the negotiated packet size");}
        }
        std::printf("GDB_PROTOCOL_RESULT=%s\n",failures ? "FAILED" : "PASSED");return failures ? 1 : 0;
    }
    ce::GdbProcessOptions options;options.byteOrder=mode=="adapter" ? ce::ByteOrder::Big : ce::ByteOrder::Little;
    options.runtime=ce::TargetRuntime::Emulated;
    const uintptr_t base=mode=="adapter" ? 0x1000 : 0x40000000;
    options.regions.push_back({base,4096,ce::MemProt::All,ce::MemType::Private,ce::MemState::Committed,{}});
    auto opened=ce::GdbProcessHandle::connect(host,port,options);
    if (!opened) {std::fprintf(stderr,"%s\n",opened.error().c_str());return 1;}
    auto& process=**opened;auto& api=static_cast<ce::ProcessHandle&>(process);
    const auto description=process.targetDescription();
    check(description.live && description.transport==ce::TargetTransport::Gdb && description.host.architecture==ce::CpuArchitecture::Unknown &&
          description.program.architecture==ce::CpuArchitecture::Arm64 && description.program.abi==ce::TargetAbi::Unknown &&
          description.program.instructionByteOrder==ce::ByteOrder::Little && process.pid()==0,"guest CPU metadata never becomes an invented local PID or host ABI");
    check(!process.supportsConcurrentReads() && process.queryRegion(base) && !process.queryRegion(base+4096),"guest ranges use the serialized remote adapter and retain exact boundaries");
    check(!process.allocate(4096,ce::MemProt::ReadWrite) && !process.protect(base,4096,ce::MemProt::ReadWrite) &&
          !process.free(base,4096),"unsupported guest memory-management operations cannot use local ptrace");
    if (mode=="adapter") {
        auto value=ce::readTypedValue(process,base,ce::ValueType::Int32);
        check(value && *value=="287454020","typed reads honor explicit guest big-endian data independently of instruction order");
        const uintptr_t addresses[]={base,base+4,base+8};std::array<uint8_t,12> data{};std::array<uint8_t,3> valid{};
        process.readMany(addresses,3,4,data.data(),valid.data());
        check(valid==std::array<uint8_t,3>{1,1,1} && data[0]==0x11,"batched reads use the ordinary shared process API");
        auto unavailable=process.readRegister("x0");check(!unavailable,"an unavailable described register is never turned into zero");
        auto incomplete=api.read<uint64_t>(base+4092);
        check(!incomplete,"a short remote word read fails instead of inventing adjacent bytes");
        ce::MemoryScanner scanner(1);ce::ScanConfig config;config.intValue=287454020;
        auto numeric=scanner.firstScan(process,config);
        check(numeric.count()==1 && numeric.address(0)==base && numeric.byteOrder()==ce::ByteOrder::Big,
              "the ordinary numeric scanner finds the actual big-endian guest integer and retains its data format");
        config.valueType=ce::ValueType::ByteArray;config.alignment=1;config.parseAOB("11 22 33 44");
        auto result=scanner.firstScan(process,config);
        check(result.count()==1 && result.address(0)==base,"ordinary byte scans remain available for a big-endian guest");
    } else if (mode=="qemu" || mode=="qemu-bank") {
        const bool bankOnly=mode=="qemu-bank";
        std::vector<uint8_t> original(4096);
        auto saved=process.read(base,original.data(),original.size());check(saved && *saved==original.size(),"the actual QEMU guest RAM is readable through the shared adapter");
        auto originalPc=process.readRegister("pc"),originalX0=process.readRegister("x0"),originalV0=process.readRegister("v0");
        auto originalBank=process.remoteCommand("g");
        check(originalPc && originalX0 && originalPc->size()==8 && originalBank &&
              (bankOnly ? !originalV0 : originalV0 && originalV0->size()==16),
              "actual core registers are readable while omitted whole-bank vectors remain unavailable");
        if (!saved || !originalPc || !originalX0 || !originalBank || (!bankOnly && !originalV0)) return 1;
        std::vector<uint8_t> seeded(4096);for (size_t i=0;i<seeded.size();++i) seeded[i]=static_cast<uint8_t>(i*7+3);
        const std::array<uint8_t,16> code={0xe0,0x00,0x80,0xd2,0x00,0x14,0x00,0x91,0x1f,0x20,0x03,0xd5,0x00,0x00,0x00,0x14};
        std::copy(code.begin(),code.end(),seeded.begin());
        const std::array<uint8_t,8> pattern={0xe0,0x12,0x34,0x56,0x78,0x90,0xab,0xcd};
        std::copy(pattern.begin(),pattern.end(),seeded.begin()+256);
        auto written=process.write(base,seeded.data(),seeded.size());std::vector<uint8_t> fresh(4096);
        auto read=process.read(base,fresh.data(),fresh.size());
        check(written && *written==seeded.size() && read && fresh==seeded,"chunked guest writes and reads preserve every actual RAM byte");
        const std::array<uint8_t,8> pc={0x00,0x00,0x00,0x40,0,0,0,0};std::array<uint8_t,16> vector{};
        for (size_t i=0;i<vector.size();++i) vector[i]=static_cast<uint8_t>(i+1);
        auto setPc=process.writeRegister("pc",pc);
        if (bankOnly) check(setPc.has_value(),"whole-register PC edits reach the actual QEMU CPU without changing other core fields");
        else {
            auto setVector=process.writeRegister("v0",vector);
            auto vectorRead=process.readRegister("v0");
            check(setPc && setVector && vectorRead && std::equal(vector.begin(),vector.end(),vectorRead->begin()),"guest PC and vector edits reach the actual QEMU CPU");
        }
        auto step=process.remoteCommand("s");auto x0=process.readRegister("x0");
        check(step && x0 && x0->size()==8 && (*x0)[0]==7,"one actual guest instruction produces its native MOV result");
        step=process.remoteCommand("s");x0=process.readRegister("x0");
        check(step && x0 && (*x0)[0]==12,"the second guest instruction executes the native ADD on the same CPU");
        auto architecture=ce::disassemblerArchFor(process,base);
        ce::Disassembler decoder(ce::Arch::ARM64);auto instructions=decoder.disassemble(base,code,2);
        check(architecture && *architecture==ce::Arch::ARM64 && instructions.size()==2 && instructions[1].mnemonic=="add","ordinary disassembly uses guest ARM64 instruction mode");
        auto bad=api.read<uint32_t>(0xfffffffffffff000ULL);
        check(!bad && process.targetDescription().live,"an unmapped guest read returns an error while the actual CPU remains stopped and usable");
        check((bankOnly || process.writeRegister("v0",*originalV0).has_value()) && process.writeRegister("x0",*originalX0).has_value() &&
              process.writeRegister("pc",*originalPc).has_value(),bankOnly ?
              "original guest scalar and PC state can be restored through actual G packets" :
              "original guest vector, scalar and PC state can be restored on the same transport");
        ce::ScanConfig config;config.valueType=ce::ValueType::ByteArray;config.compareType=ce::ScanCompare::Exact;
        config.alignment=1;config.startAddress=base;config.stopAddress=base+4095;config.byteArray.assign(pattern.begin(),pattern.end());
        config.byteArrayMask.assign(pattern.size(),0xff);
        ce::MemoryScanner scanner(1);auto scan=scanner.firstScan(process,config);
        check(!scan.hasWriteError() && scan.count()==1 && scan.address(0)==base+256,"the ordinary scanner finds the real guest byte pattern without local-process access");
        auto restored=process.write(base,original.data(),original.size());read=process.read(base,fresh.data(),fresh.size());
        auto pcRead=process.readRegister("pc"),x0Read=process.readRegister("x0"),v0Read=process.readRegister("v0");
        auto bankRead=process.remoteCommand("g");
        check(restored && *restored==original.size() && read && fresh==original && pcRead && *pcRead==*originalPc &&
              x0Read && *x0Read==*originalX0 && bankRead && *bankRead==*originalBank &&
              (bankOnly ? !v0Read : v0Read && *v0Read==*originalV0),"every modified guest RAM byte and the entire actual core register bank is restored exactly");
    } else return 2;
    check(process.detach().has_value() && !process.targetDescription().live && !api.read<uint32_t>(base),"confirmed detach retires the transport and rejects stale reads");
    std::printf("GDB_ADAPTER_RESULT=%s mode=%s\n",failures ? "FAILED" : "PASSED",mode.c_str());return failures ? 1 : 0;
#else
    return 2;
#endif
}
