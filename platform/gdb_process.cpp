#include "platform/gdb_process.hpp"
#include "tinyxml2.h"
#include <algorithm>
#include <charconv>
#include <cstring>

namespace ce {
namespace {
Error unsupported() {return std::make_error_code(std::errc::operation_not_supported);}
bool addressNumber(const char* text,uintptr_t& value) {
    if (!text || !*text) return false;
    std::string_view s(text);int base=10;
    if (s.starts_with("0x") || s.starts_with("0X")) {s.remove_prefix(2);base=16;}
    const auto [end,error]=std::from_chars(s.data(),s.data()+s.size(),value,base);
    return !s.empty() && error==std::errc{} && end==s.data()+s.size();
}

bool validRegion(const MemoryRegion& region) {return region.size && region.size<=UINTPTR_MAX-region.base;}
bool stoppedReply(const std::string& reply) {
    auto hex=[](char c){return (c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F');};
    return reply.size()>=3 && hex(reply[1]) && hex(reply[2]) &&
        ((reply[0]=='S' && reply.size()==3) || reply[0]=='T');
}
}

GdbProcessHandle::~GdbProcessHandle() {if (ownsSession_) (void)detach();else disconnect();}

std::expected<std::unique_ptr<GdbProcessHandle>,std::string> GdbProcessHandle::connect(
    const std::string& host,uint16_t port,const GdbProcessOptions& options) {
    if (options.pointerWidth && options.pointerWidth!=4 && options.pointerWidth!=8)
        return std::unexpected("GDB pointer width must be 4 or 8");
    for (const auto& region:options.regions) if (!validRegion(region)) return std::unexpected("Invalid GDB guest memory range");
    if (options.regions.size()>4096) return std::unexpected("Too many explicit GDB guest ranges");
    auto handle=std::unique_ptr<GdbProcessHandle>(new GdbProcessHandle);
    handle->client_.setTimeout(options.timeout);
    handle->client_.setCancellation(options.cancellation);
    if (!handle->client_.connectTcp(host,port,handle->error_)) return std::unexpected(handle->error_);
    auto negotiated=handle->client_.negotiate();if (!negotiated) return std::unexpected(negotiated.error());
    auto stopped=handle->client_.sendPacket("?");
    if (!stopped) return std::unexpected(stopped.error());
    if (!stoppedReply(*stopped))
        return std::unexpected("GDB memory adapter requires a stopped target");
    auto target=handle->client_.describeTarget();if (!target) return std::unexpected(target.error());
    handle->target_=std::move(*target);handle->runtime_=options.runtime;
    if (options.byteOrder!=ByteOrder::Unknown) {
        if (handle->target_.machine.byteOrder!=ByteOrder::Unknown && handle->target_.machine.byteOrder!=options.byteOrder)
            return std::unexpected("Explicit byte order conflicts with the described target architecture");
        handle->target_.machine.byteOrder=options.byteOrder;
    }
    if (options.pointerWidth) {
        if (options.pointerWidth!=handle->target_.machine.pointerWidth)
            handle->target_.machine.abi=TargetAbi::Unknown;
        handle->target_.machine.pointerWidth=options.pointerWidth;
    }
    handle->regions_=options.regions;
    if (handle->regions_.empty() && handle->client_.supports("qXfer:memory-map:read")) {
        auto xml=handle->client_.readObject("memory-map","");if (!xml) return std::unexpected(xml.error());
        tinyxml2::XMLDocument doc;
        if (doc.Parse(xml->data(),xml->size())!=tinyxml2::XML_SUCCESS || !doc.FirstChildElement("memory-map"))
            return std::unexpected("Invalid GDB memory map XML");
        for (auto* memory=doc.FirstChildElement("memory-map")->FirstChildElement("memory");memory;memory=memory->NextSiblingElement("memory")) {
            MemoryRegion region;uintptr_t length=0;
            if (!addressNumber(memory->Attribute("start"),region.base) || !addressNumber(memory->Attribute("length"),length))
                return std::unexpected("Invalid GDB memory map range");
            region.size=length;region.state=MemState::Committed;region.protection=MemProt::Read;
            const char* type=memory->Attribute("type");
            if (!type || (std::strcmp(type,"ram") && std::strcmp(type,"rom") && std::strcmp(type,"flash")))
                return std::unexpected("Unknown GDB memory map type");
            if (!std::strcmp(type,"ram")) region.protection=MemProt::ReadWrite;
            if (!validRegion(region) || handle->regions_.size()>=4096) return std::unexpected("Invalid or excessive GDB memory map");
            handle->regions_.push_back(std::move(region));
        }
    }
    std::sort(handle->regions_.begin(),handle->regions_.end(),[](const auto& a,const auto& b){return a.base<b.base;});
    for (size_t i=1;i<handle->regions_.size();++i) if (handle->regions_[i-1].base+handle->regions_[i-1].size>handle->regions_[i].base)
        return std::unexpected("Overlapping GDB memory map ranges");
    if (options.cancellation.stop_requested()) return std::unexpected("GDB connection canceled");
    handle->ownsSession_=true;
    return handle;
}
TargetDescription GdbProcessHandle::targetDescription() {
    std::lock_guard lock(mutex_);TargetDescription description;
    description.program=target_.machine;description.transport=TargetTransport::Gdb;
    description.runtime=runtime_;description.live=false;
    if (client_.isConnected()) {
        auto stop=client_.sendPacket("?");
        if (stop && stoppedReply(*stop)) description.live=true;
        else {error_=stop ? "GDB target is no longer stopped or has exited" : stop.error();client_.close();}
    }
    return description;
}
Result<size_t> GdbProcessHandle::read(uintptr_t address,void* buffer,size_t size) {
    std::lock_guard lock(mutex_);
    if (size && !buffer) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    auto bytes=client_.readMemory(address,size);
    if (!bytes) {error_=bytes.error();return std::unexpected(std::make_error_code(std::errc::io_error));}
    if (!bytes->empty()) std::memcpy(buffer,bytes->data(),bytes->size());
    return bytes->size();
}
Result<size_t> GdbProcessHandle::write(uintptr_t address,const void* buffer,size_t size) {
    std::lock_guard lock(mutex_);
    if (size && !buffer) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    auto written=client_.writeMemory(address,{static_cast<const uint8_t*>(buffer),size});
    if (!written) {error_=written.error();return std::unexpected(std::make_error_code(std::errc::io_error));}return *written;
}
std::vector<MemoryRegion> GdbProcessHandle::queryRegions() {std::lock_guard lock(mutex_);return client_.isConnected() ? regions_ : std::vector<MemoryRegion>{};}
std::optional<MemoryRegion> GdbProcessHandle::queryRegion(uintptr_t address) {
    for (const auto& region:queryRegions()) if (address>=region.base && address-region.base<region.size) return region;
    return std::nullopt;
}
Result<uintptr_t> GdbProcessHandle::allocate(size_t,MemProt,uintptr_t) {return std::unexpected(unsupported());}
Result<void> GdbProcessHandle::free(uintptr_t,size_t) {return std::unexpected(unsupported());}
Result<void> GdbProcessHandle::protect(uintptr_t,size_t,MemProt) {return std::unexpected(unsupported());}
std::expected<std::vector<uint8_t>,std::string> GdbProcessHandle::readRegister(const std::string& name) {
    std::lock_guard lock(mutex_);auto reg=std::find_if(target_.registers.begin(),target_.registers.end(),[&](const auto& r){return r.name==name;});
    if (reg==target_.registers.end()) return std::unexpected("Register absent from GDB target XML");
    return client_.readRegister(*reg);
}
std::expected<void,std::string> GdbProcessHandle::writeRegister(const std::string& name,std::span<const uint8_t> bytes) {
    std::lock_guard lock(mutex_);auto reg=std::find_if(target_.registers.begin(),target_.registers.end(),[&](const auto& r){return r.name==name;});
    if (reg==target_.registers.end()) return std::unexpected("Register absent from GDB target XML");
    return client_.writeRegister(*reg,bytes);
}
std::string GdbProcessHandle::lastTransportError() const {std::lock_guard lock(mutex_);return error_;}
std::expected<std::string,std::string> GdbProcessHandle::remoteCommand(const std::string& command) {
    std::lock_guard lock(mutex_);auto response=client_.sendPacket(command);
    if (!response) error_=response.error();
    else if (response->size()>=3 && ((*response)[0]=='W' || (*response)[0]=='X')) client_.close();
    return response;
}
void GdbProcessHandle::disconnect() {std::lock_guard lock(mutex_);client_.close();}
std::expected<void,std::string> GdbProcessHandle::detach() {
    std::lock_guard lock(mutex_);
    if (!client_.isConnected()) return {};
    auto result=client_.sendPacket("D");client_.close();
    if (!result) {error_=result.error();return std::unexpected(error_);}
    if (*result!="OK") {error_="GDB detach was not confirmed";return std::unexpected(error_);}
    return {};
}
}
