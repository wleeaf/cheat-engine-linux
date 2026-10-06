#include "analysis/mono_dissector.hpp"
#include "analysis/managed_runtime.hpp"
#include "core/target_profile.hpp"
#include "platform/linux/linux_process.hpp"
#include "scripting/lua_engine.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <thread>

using namespace ce;
static unsigned checks=0,failures=0;
static void check(bool ok,const char* label) {
    ++checks;failures+=!ok;printf("%s: %s\n",ok ? "OK" : "FAILED",label);fflush(stdout);
}
static int finish(const std::string& phase) {
    printf("MONO_INTEGRATION_RESULT=%s phase=%s checks=%u failures=%u\n",failures ? "FAILED" : "PASSED",phase.c_str(),checks,failures);
    return failures ? 1 : 0;
}
int main(int argc,char** argv) {
    if (argc!=10) return 2;
    pid_t pid=static_cast<pid_t>(std::strtol(argv[1],nullptr,10));
    std::string agent=argv[2],phase=argv[3];
    uintptr_t flag=std::strtoull(argv[4],nullptr,16),data=std::strtoull(argv[5],nullptr,16);
    std::array<uintptr_t,3> expected{};
    for (unsigned i=0;i<3;++i) expected[i]=std::strtoull(argv[6+i],nullptr,16);
    bool release=std::string(argv[9])=="release";
    os::LinuxProcessHandle process(pid);
    auto description=process.targetDescription();
    check(description.live && description.host.architecture==CpuArchitecture::X86_64 && description.host.pointerWidth==8,
          "real Mono process exposes the live native ABI");
    check(description.runtime==TargetRuntime::Native && description.program==description.host,
          "a native Mono .exe keeps its Unix execution and pointer ABI");
    auto profile=probeTarget(pid);
    check(profile.valid && !profile.wine,"the target profile does not impose Wine restrictions on Mono");
    if (phase=="shutdown" || phase=="shutdown_mapped") {
        SymbolResolver resolver;resolver.loadProcess(process);
        const auto rejected=[&](const std::optional<MonoDissection>& result) {
            return result && !result->ready && result->images.empty() &&
                (result->error.find("shutting down")!=std::string::npos ||
                 (phase=="shutdown" && result->error.find("root domain is unavailable")!=std::string::npos));
        };
        auto stopped=dissectMono(process,resolver,agent,3000);
        check(rejected(stopped),"requests after real Mono cleanup report unavailable runtime without entering it");
        check(rejected(dissectMono(process,resolver,agent,3000)),
              "repeated post-cleanup requests remain safe on the resident agent");
        check(!findMonoFunction(process,resolver,agent,"Compatibility","Player","Compute",1,2000),
              "a method lookup cannot return freed JIT code after runtime cleanup");
        LuaEngine lua;lua.setProcess(&process);
        auto scripted=lua.evalToString("local d,err=monoDissect(3000); "
            "if d then assert(not d.ready and d.error~='' and #d.images==0) "
            "else assert(err=='no Mono runtime detected') end; "
            "assert(findMonoFunction('Compatibility','Player','Compute',1)==nil); return 'ok'");
        check(scripted && *scripted=="ok","Lua runtime requests cannot expose freed layouts or JIT addresses after cleanup");
        check(process.targetDescription().live && !process.targetDescription().pendingRecovery,
              "the original native application survives runtime cleanup and subsequent requests");
        uint32_t zero=0;auto released=process.write(flag,&zero,4);
        check(released && *released==4,"the original native application resumes after Mono is closed");
        return finish(phase);
    }
    auto runtimes=detectManagedRuntimes(process);
    check(std::any_of(runtimes.begin(),runtimes.end(),[](const auto& r){return r.kind==ManagedRuntimeKind::Mono;}),
          "runtime detection identifies the actual Mono executable");
    SymbolResolver resolver;resolver.loadProcess(process);
    if (phase=="limited") {
        auto limited=dissectMono(process,resolver,agent,3000);
        const auto rejected=[](const std::optional<MonoDissection>& result) {
            return result && !result->ready && result->images.empty() &&
                result->error.find("exceeds the protocol memory bound")!=std::string::npos;
        };
        check(rejected(limited),"oversized real metadata returns a clear error without a partial dump");
        check(rejected(dissectMono(process,resolver,agent,3000)),
              "resident overflow remains recoverable on the next request");
        check(findMonoFunction(process,resolver,agent,"Compatibility","Player","Compute",1,2000)==expected[0],
              "method lookup remains exact after metadata overflow");
        check(process.targetDescription().live && !process.targetDescription().pendingRecovery,
              "metadata overflow leaves the original application live without retained native cleanup");
        uint32_t zero=0;auto released=process.write(flag,&zero,4);
        check(released && *released==4,"the overflow fixture resumes its original native loop");
        return finish(phase);
    }
    auto first=dissectMono(process,resolver,agent,3000);
    check(first && first->ready && first->error.empty(),"a real agent returns a complete runtime metadata dump");
    if (first && !first->error.empty()) printf("MONO_DIAGNOSTIC %s\n",first->error.c_str());
    auto player=first ? first->findClass("Compatibility.Player") : nullptr;
    check(player && player->fields.size()==3,"the runtime returns the actual Player fields");
    const MonoField* score=nullptr;const MonoField* marker=nullptr;const MonoField* staticScore=nullptr;
    if (player) for (const auto& f : player->fields) {
        if (f.name=="Score") score=&f;
        if (f.name=="Marker") marker=&f;
        if (f.name=="StaticScore") staticScore=&f;
    }
    check(score && score->typeName=="System.Int32" && !score->isStatic &&
          marker && marker->typeName=="System.Int64" && !marker->isStatic &&
          staticScore && staticScore->isStatic,"field types, offsets and static flags come from Mono");
    uintptr_t object=score && data>=score->offset ? data-score->offset : 0;
    uint32_t actualScore=0;uint64_t actualMarker=0;
    auto a=process.read(data,&actualScore,4);
    auto b=marker && object ? process.read(object+marker->offset,&actualMarker,8) : Result<size_t>(std::unexpected(std::make_error_code(std::errc::bad_address)));
    check(a && *a==4 && actualScore==123 && b && *b==8 && actualMarker==0x123456789abcdef,
          "runtime field offsets address the real pinned managed object");
    uint32_t edited=555,restored=123,observed=0;
    auto write=process.write(data,&edited,4);auto read=process.read(data,&observed,4);
    auto restore=process.write(data,&restored,4);
    check(write && *write==4 && read && *read==4 && observed==edited && restore && *restore==4,
          "managed field read/write restores the exact original value");
    auto second=dissectMono(process,resolver,agent,1200);
    check(second && second->ready && second->findClass("Compatibility.Player"),
          "refresh returns fresh metadata from the already resident agent");
    auto compute=findMonoFunction(process,resolver,agent,"Compatibility","Player","Compute",1,2000);
    auto other=findMonoFunction(process,resolver,agent,"Compatibility","Player","Other",1,2000);
    std::string longName="LongManagedType"+std::string(300,'X');
    auto longMethod=findMonoFunction(process,resolver,agent,"Compatibility",longName,"ResolveMe",1,2000);
    check(compute==expected[0] && compute,"method lookup returns the runtime's actual JIT address");
    check(other==expected[1] && other!=compute,"different method requests keep distinct JIT results");
    check(longMethod==expected[2] && longMethod,"CLR names longer than 255 bytes remain exact");
    check(!findMonoFunction(process,resolver,agent,"Compatibility","Player","Compute",2,2000),
          "a nonexistent overload reports no method");
    check(!findMonoFunction(process,resolver,agent,"Compatibility","Missing","Compute",1,2000),
          "a nonexistent class reports no method");
    std::array<uintptr_t,8> results{};std::array<std::thread,8> callers;
    for (unsigned i=0;i<callers.size();++i) callers[i]=std::thread([&,i] {
        os::LinuxProcessHandle local(pid);
        results[i]=findMonoFunction(local,resolver,agent,"Compatibility","Player",i%2 ? "Other" : "Compute",1,2000);
    });
    for (auto& caller : callers) caller.join();
    bool isolated=true;for (unsigned i=0;i<results.size();++i) isolated=isolated && results[i]==expected[i%2];
    check(isolated,"concurrent clients receive only their own method response");
    LuaEngine lua;lua.setProcess(&process);
    auto scripted=lua.evalToString("local a=monoDissect(3000); assert(a and a.ready and a.error==''); "
        "local b=monoDissect(3000); assert(b and b.ready); "
        "assert(findMonoFunction('Compatibility','Player','Compute',1)=="+std::to_string(expected[0])+"); return 'ok'");
    check(scripted && *scripted=="ok","production Lua bindings refresh Mono metadata and return the exact JIT address");
    auto late=second ? second->findClass("Compatibility.Late.LoadedLater") : nullptr;
    if (phase=="loaded") {
        check(late && late->fields.size()==1 && late->fields[0].name=="Added",
              "a refreshed dump discovers assemblies loaded after injection");
        auto function=findMonoFunction(process,resolver,agent,"Compatibility.Late","LoadedLater","Compute",1,2000);
        check(function && process.queryRegion(function) && (process.queryRegion(function)->protection & MemProt::Exec),
              "the agent compiles a method from the newly loaded assembly");
    } else check(!late,"the initial dump does not invent an unloaded assembly");
    check(process.targetDescription().live && !process.targetDescription().pendingRecovery,
          "runtime operations leave the original application live without retained native cleanup");
    if (release) {
        uint32_t zero=0;auto released=process.write(flag,&zero,4);
        check(released && *released==4,"the managed application resumes its original native loop");
    }
    return finish(phase);
}
