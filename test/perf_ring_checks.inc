#include "debug/perf_ring.hpp"
#include "debug/intel_pt.hpp"
#include <linux/perf_event.h>
#include <thread>
#include <climits>

static void perfRingTests() {
    using namespace ce::detail;
    bool layouts=true,branches=true,corruption=true,auxiliary=true;
    for (size_t page:{size_t(4096),size_t(16384),size_t(65536)}) {
        auto layout=perfMappingSize(page,3);
        layouts=layouts && layout && layout->dataBytes==4*page && layout->mappingBytes==5*page;
        layouts=layouts && !perfMappingSize(page,0) && !perfMappingSize(page,-1);
        // Two control pages deliberately differ from the old fixed +4096 path.
        std::vector<uint64_t> storage(3*page/8,0);
        auto* control=reinterpret_cast<perf_event_mmap_page*>(storage.data());
        auto* memory=reinterpret_cast<uint8_t*>(storage.data());
        control->data_offset=2*page;control->data_size=page;
        std::span<uint8_t> mapped(memory,storage.size()*8);
        auto place=[&](std::span<const uint8_t> record,uint64_t position) {
            for (size_t i=0;i<record.size();++i) memory[2*page+(position+i)%page]=record[i];
        };
        // Serialize independent kernel-native bytes for a two-entry sample.
        const perf_event_header header{PERF_RECORD_SAMPLE,0,static_cast<uint16_t>(16+2*sizeof(perf_branch_entry))};
        const uint64_t count=2;
        perf_branch_entry entries[2]{};entries[0].from=0x10203040;entries[0].to=0x55667788;entries[0].mispred=1;
        entries[1].from=0x11223344;entries[1].to=0xaabbccdd;entries[1].predicted=1;
        std::vector<uint8_t> record(header.size);std::memcpy(record.data(),&header,8);std::memcpy(record.data()+8,&count,8);std::memcpy(record.data()+16,entries,sizeof(entries));
        for (uint64_t start:{uint64_t(0),uint64_t(page-4),UINT64_MAX-15}) {
            place(record,start);control->data_tail=start;control->data_head=start+record.size();
            auto found=drainPerfBranches(mapped,page);
            branches=branches && found.size()==2 && found[0].from==entries[0].from && found[0].to==entries[0].to && found[0].mispred &&
                found[1].to==entries[1].to && found[1].predicted && control->data_tail==control->data_head && drainPerfBranches(mapped,page).empty();
        }
        if (page>=16384) {
            std::vector<perf_branch_entry> entries(300);
            for (size_t i=0;i<entries.size();++i) {entries[i].from=0x1000+i;entries[i].to=0x2000+i;}
            const uint64_t count=entries.size();
            perf_event_header wide{PERF_RECORD_SAMPLE,0,static_cast<uint16_t>(16+entries.size()*sizeof(perf_branch_entry))};
            std::vector<uint8_t> record(wide.size);std::memcpy(record.data(),&wide,8);std::memcpy(record.data()+8,&count,8);std::memcpy(record.data()+16,entries.data(),entries.size()*sizeof(perf_branch_entry));
            place(record,page-4);control->data_tail=page-4;control->data_head=page-4+record.size();
            auto found=drainPerfBranches(mapped,page);
            branches=branches && found.size()==300 && found[0].from==0x1000 && found.back().to==0x2000+299;
        }
        // A short SAMPLE must never inspect a missing branch count.
        perf_event_header shortSample{PERF_RECORD_SAMPLE,0,8};
        place({reinterpret_cast<uint8_t*>(&shortSample),8},0);control->data_tail=0;control->data_head=8;
        corruption=corruption && drainPerfBranches(mapped,page).empty() && control->data_tail==8;
        auto damaged=record;const uint64_t huge=UINT64_MAX;std::memcpy(damaged.data()+8,&huge,8);
        place(damaged,0);control->data_tail=0;control->data_head=damaged.size();
        corruption=corruption && drainPerfBranches(mapped,page).empty();
        perf_event_header invalid{PERF_RECORD_SAMPLE,0,0};place({reinterpret_cast<uint8_t*>(&invalid),8},0);
        control->data_tail=0;control->data_head=8;
        corruption=corruption && drainPerfBranches(mapped,page).empty() && control->data_tail==8;
        control->data_tail=0;control->data_head=page+8;
        corruption=corruption && drainPerfBranches(mapped,page).empty() && control->data_tail==control->data_head;
        control->data_offset=mapped.size();control->data_size=page;
        corruption=corruption && drainPerfBranches(mapped,page).empty();
        control->data_offset=2*page;control->data_size=page-1;
        corruption=corruption && drainPerfBranches(mapped,page).empty();
        control->data_offset=2*page;control->data_size=page;
        std::vector<uint8_t> aux(page,0);
        control->aux_offset=mapped.size();control->aux_size=aux.size();
        const std::array<uint8_t,9> bytes{1,2,3,4,5,6,7,8,9};
        for (uint64_t start:{uint64_t(0),uint64_t(page-3),UINT64_MAX-3}) {
            for (size_t i=0;i<bytes.size();++i) aux[(start+i)%page]=bytes[i];
            control->aux_tail=start;control->aux_head=start+bytes.size();control->data_head=123;control->data_tail=0;
            auto found=drainPerfAux(mapped,aux,page);
            auxiliary=auxiliary && std::equal(found.begin(),found.end(),bytes.begin(),bytes.end()) &&
                control->aux_tail==control->aux_head && control->data_tail==control->data_head && drainPerfAux(mapped,aux,page).empty();
        }
        control->aux_tail=0;control->aux_head=page+1;
        auxiliary=auxiliary && drainPerfAux(mapped,aux,page).empty() && control->aux_tail==control->aux_head;
        control->aux_tail=2;control->aux_head=1;
        auxiliary=auxiliary && drainPerfAux(mapped,aux,page).empty() && control->aux_tail==1;
        control->aux_offset=page;
        auxiliary=auxiliary && drainPerfAux(mapped,aux,page).empty();
    }
    layouts=layouts && !perfMappingSize(0,1) && !perfMappingSize(3000,1) && !perfMappingSize(size_t(1)<<(sizeof(size_t)*8-1),INT_MAX);
    check(layouts,"perf ring sizing rounds positive counts using actual 4/16/64 KiB pages without overflow");
    check(branches,"branch-stack records retain chronological entries across ring boundaries and 64-bit counter wrap");
    check(corruption,"malformed branch headers, counts, spans and impossible intervals never fabricate samples or stall draining");
    check(auxiliary,"AUX bytes preserve wrap order, publish tails, release notifications and reject impossible intervals");
    LbrTracer lbr;IntelPtTracer pt;
    check(!lbr.start(0) && !lbr.lastError().empty() && !lbr.isActive() && !pt.start(0) && !pt.lastError().empty() && !pt.isActive(),
          "zero target TIDs cannot sample the frontend thread in either tracing backend");
    std::vector<std::thread> workers;
    for (int i=0;i<3;++i) workers.emplace_back([&]{for (int j=0;j<50;++j) {lbr.stop();pt.stop();(void)lbr.drain();(void)pt.drain();(void)lbr.start(-1);(void)pt.start(-1);}});
    for (auto& worker:workers) worker.join();
    check(!lbr.isActive() && !pt.isActive(),"concurrent inactive start, stop and drain calls remain serialized and release resources");
    TargetBuffer p;p.description.host=p.description.program=nativeTargetMachine();ce::LuaEngine lua;lua.setProcess(&p);
    check(lua.execute(R"lua(
        for _,seconds in ipairs({-1,math.huge,0/0,1e300}) do
          local value,err=branchMap(seconds); assert(value==nil and err:find('duration'))
          value,err=findWhatWrites(0,seconds); assert(value==nil and err:find('duration'))
        end
        for _,tid in ipairs({0,-1,0x100000000}) do
          local value,err=branchMap(0,tid); assert(value==nil and err:find('thread'))
        end
    )lua").empty(),"invalid Lua sampling durations and TIDs fail before hardware probing or ptrace");
}
