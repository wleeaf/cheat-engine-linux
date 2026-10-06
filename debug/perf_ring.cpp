#include "debug/perf_ring.hpp"
#include <linux/perf_event.h>
#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

namespace ce::detail {
namespace {
struct DataRing { perf_event_mmap_page* control; std::span<uint8_t> bytes; };
std::optional<DataRing> dataRing(std::span<uint8_t> mapping,size_t pageSize) {
    if (pageSize<sizeof(perf_event_mmap_page) || !std::has_single_bit(pageSize) || mapping.size()<pageSize ||
        reinterpret_cast<uintptr_t>(mapping.data())%alignof(perf_event_mmap_page)) return std::nullopt;
    auto* control=reinterpret_cast<perf_event_mmap_page*>(mapping.data());
    uint64_t offset=control->data_offset,size=control->data_size;
    // Legacy control pages did not report the layout. Both fields must be
    // absent before using the original one-control-page convention.
    if (!offset && !size) {offset=pageSize;size=mapping.size()-pageSize;}
    if (offset<pageSize || offset%pageSize || offset>mapping.size() || !size || !std::has_single_bit(size) ||
        size>mapping.size()-offset || size%pageSize) return std::nullopt;
    return DataRing{control,mapping.subspan(static_cast<size_t>(offset),static_cast<size_t>(size))};
}
void copyRing(std::span<const uint8_t> ring,uint64_t position,void* destination,size_t count) {
    const size_t offset=position%ring.size(),first=std::min(count,ring.size()-offset);
    std::memcpy(destination,ring.data()+offset,first);
    if (count>first) std::memcpy(static_cast<uint8_t*>(destination)+first,ring.data(),count-first);
}
}
std::optional<PerfMappingSize> perfMappingSize(size_t pageSize,int pages) {
    if (pages<=0 || pageSize<sizeof(perf_event_mmap_page) || !std::has_single_bit(pageSize)) return std::nullopt;
    const size_t rounded=std::bit_ceil(static_cast<size_t>(pages));
    if (rounded>SIZE_MAX/pageSize-1) return std::nullopt;
    return PerfMappingSize{rounded*pageSize,(rounded+1)*pageSize};
}
std::vector<LbrEntry> drainPerfBranches(std::span<uint8_t> mapping,size_t pageSize) {
    std::vector<LbrEntry> out;auto ring=dataRing(mapping,pageSize);if (!ring) return out;
    auto* control=ring->control;
    const uint64_t head=__atomic_load_n(&control->data_head,__ATOMIC_ACQUIRE);
    uint64_t tail=__atomic_load_n(&control->data_tail,__ATOMIC_RELAXED);
    uint64_t available=head-tail; // Unsigned subtraction also handles counter wrap.
    if (available>ring->bytes.size()) {
        // These are non-overwrite mappings. An impossible interval has no
        // trustworthy record boundary; discard it instead of inventing samples.
        __atomic_store_n(&control->data_tail,head,__ATOMIC_RELEASE);return out;
    }
    while (available>=sizeof(perf_event_header)) {
        perf_event_header header{};copyRing(ring->bytes,tail,&header,sizeof(header));
        if (header.size<sizeof(header) || header.size>available || header.size>ring->bytes.size()) {
            // data_head publishes complete records. Malformed/partial records
            // cannot be resumed by repeatedly polling the same damaged header.
            tail=head;break;
        }
        if (header.type==PERF_RECORD_SAMPLE && header.size>=sizeof(header)+sizeof(uint64_t)) {
            uint64_t count=0;copyRing(ring->bytes,tail+sizeof(header),&count,sizeof(count));
            const size_t payload=header.size-sizeof(header)-sizeof(count);
            if (count<=payload/sizeof(perf_branch_entry)) {
                for (size_t i=0;i<count;++i) {
                    perf_branch_entry entry{};
                    copyRing(ring->bytes,tail+sizeof(header)+sizeof(count)+i*sizeof(entry),&entry,sizeof(entry));
                    out.push_back({entry.from,entry.to,bool(entry.mispred),bool(entry.predicted)});
                }
            }
        }
        tail+=header.size;available-=header.size;
    }
    if (available && available<sizeof(perf_event_header)) tail=head;
    __atomic_store_n(&control->data_tail,tail,__ATOMIC_RELEASE);return out;
}
std::vector<uint8_t> drainPerfAux(std::span<uint8_t> mapping,std::span<uint8_t> auxiliary,size_t pageSize) {
    std::vector<uint8_t> out;auto ring=dataRing(mapping,pageSize);
    if (!ring || auxiliary.empty() || !std::has_single_bit(auxiliary.size()) || auxiliary.size()%pageSize) return out;
    auto* control=ring->control;
    const uint64_t dataEnd=static_cast<uint64_t>(ring->bytes.data()-mapping.data())+ring->bytes.size();
    if (control->aux_size!=auxiliary.size() || control->aux_offset<dataEnd || control->aux_offset%pageSize) return out;
    const uint64_t head=__atomic_load_n(&control->aux_head,__ATOMIC_ACQUIRE);
    const uint64_t tail=__atomic_load_n(&control->aux_tail,__ATOMIC_RELAXED);
    const uint64_t available=head-tail;
    if (available<=auxiliary.size()) {
        out.resize(static_cast<size_t>(available));
        if (available) copyRing(auxiliary,tail,out.data(),out.size());
    }
    // Impossible intervals are dropped, never clamped into misordered data.
    __atomic_store_n(&control->aux_tail,head,__ATOMIC_RELEASE);
    // The raw capture API does not expose PERF_RECORD_AUX notifications. Release
    // their complete data-ring records too so notifications cannot fill the ring.
    const uint64_t dataHead=__atomic_load_n(&control->data_head,__ATOMIC_ACQUIRE);
    __atomic_store_n(&control->data_tail,dataHead,__ATOMIC_RELEASE);
    return out;
}
} // namespace ce::detail
