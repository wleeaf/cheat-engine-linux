#include "debug/gdb_remote.hpp"
#include "tinyxml2.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <algorithm>
#include <charconv>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <functional>
#include <set>
#include <string_view>

namespace ce {
namespace {
constexpr size_t maxWire=1u<<20, maxDecoded=16u<<20, maxObject=4u<<20;
int hexValue(char c) {
    if (c>='0' && c<='9') return c-'0';
    if (c>='a' && c<='f') return c-'a'+10;
    if (c>='A' && c<='F') return c-'A'+10;
    return -1;
}
std::string hexNumber(uint64_t n) {
    char text[17]; auto [end,error]=std::to_chars(text,text+sizeof(text),n,16);
    return error==std::errc{} ? std::string(text,end) : std::string{};
}
std::string hexBytes(std::span<const uint8_t> bytes) {
    constexpr char digits[]="0123456789abcdef";
    std::string text; text.reserve(bytes.size()*2);
    for (uint8_t b:bytes) { text.push_back(digits[b>>4]); text.push_back(digits[b&15]); }
    return text;
}
std::expected<std::vector<uint8_t>,std::string> decodeHex(std::string_view text) {
    if (text.size()%2) return std::unexpected("Odd hexadecimal response length");
    std::vector<uint8_t> bytes; bytes.reserve(text.size()/2);
    for (size_t i=0;i<text.size();i+=2) {
        int a=hexValue(text[i]),b=hexValue(text[i+1]);
        if (a<0 || b<0) return std::unexpected("Unavailable or non-hexadecimal response data");
        bytes.push_back(static_cast<uint8_t>((a<<4)|b));
    }
    return bytes;
}
bool number(std::string_view text,uint32_t& value,int base=10) {
    auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),value,base);
    return !text.empty() && error==std::errc{} && end==text.data()+text.size();
}
bool token(const std::string& text,bool empty=false) {
    return (empty || !text.empty()) && text.size()<=256 &&
        std::all_of(text.begin(),text.end(),[](unsigned char c) {return c>=33 && c<127 && c!=':' && c!=',' && c!=';';});
}
bool xmlInclude(const tinyxml2::XMLElement* element) {
    const std::string_view name=element->Name();
    const auto colon=name.find(':');
    if ((colon==std::string_view::npos ? name : name.substr(colon+1))!="include") return false;
    const std::string declaration=colon==std::string_view::npos ? "xmlns" : "xmlns:"+std::string(name.substr(0,colon));
    for (auto* node=element;node;node=node->Parent() ? node->Parent()->ToElement() : nullptr)
        if (const char* uri=node->Attribute(declaration.c_str()))
            return std::strcmp(uri,"http://www.w3.org/2001/XInclude")==0;
    // GDB/QEMU also use the conventional xi form without an explicit namespace
    // declaration. Preserve that form without fetching external DTD content.
    return name=="xi:include";
}
std::string ioError(const char* prefix) {return std::string(prefix)+": "+std::strerror(errno);}
TargetMachine targetMachine(const std::string& architecture,const std::string& osAbi) {
    TargetMachine m;
    if (architecture=="i386" || architecture=="i386:x86-64" || architecture=="i386:x64-32") {
        m.architecture=architecture=="i386" ? CpuArchitecture::X86_32 : CpuArchitecture::X86_64;
        m.pointerWidth=architecture=="i386:x86-64" ? 8 : 4;
        m.byteOrder=m.instructionByteOrder=ByteOrder::Little;
        m.instructionMode=architecture=="i386" ? InstructionMode::X86_32 : InstructionMode::X86_64;
        if (osAbi=="GNU/Linux") m.abi=architecture=="i386" ? TargetAbi::LinuxI386 :
            architecture=="i386:x64-32" ? TargetAbi::LinuxX32 : TargetAbi::LinuxX86_64;
    } else if (architecture=="aarch64" || architecture=="aarch64:ilp32") {
        m.architecture=CpuArchitecture::Arm64; m.pointerWidth=architecture=="aarch64" ? 8 : 4;
        m.instructionMode=InstructionMode::Aarch64; m.instructionByteOrder=ByteOrder::Little;
        if (osAbi=="GNU/Linux" && m.pointerWidth==8) m.abi=TargetAbi::LinuxAarch64;
    } else if (architecture=="arm") {
        m.architecture=CpuArchitecture::Arm32; m.pointerWidth=4;
        // XML alone does not identify ARM/Thumb, BE8, or data byte order.
        if (osAbi=="GNU/Linux") m.abi=TargetAbi::LinuxArmEabi;
    } else if (architecture=="riscv:rv32" || architecture=="riscv:rv64") {
        m.architecture=architecture=="riscv:rv32" ? CpuArchitecture::RiscV32 : CpuArchitecture::RiscV64;
        m.pointerWidth=architecture=="riscv:rv32" ? 4 : 8;
        if (osAbi=="GNU/Linux") m.abi=TargetAbi::LinuxRiscV;
    } else if (!architecture.empty()) m.architecture=CpuArchitecture::Other;
    return m;
}
}

GdbRemoteClient::~GdbRemoteClient() { close(); }
void GdbRemoteClient::setTimeout(std::chrono::milliseconds timeout) {
    std::lock_guard lock(mutex_); timeout_=std::clamp(timeout,std::chrono::milliseconds(1),std::chrono::milliseconds(60000));
}
void GdbRemoteClient::setCancellation(std::stop_token token) {
    std::lock_guard lock(mutex_);cancellation_=token;
}
bool GdbRemoteClient::connectTcp(const std::string& host,uint16_t port,std::string& error) {
    std::lock_guard lock(mutex_); close(); error.clear();
    if (host.empty() || host.find('\0')!=std::string::npos || !port) {error="Invalid GDB endpoint";return false;}
    if (cancellation_.stop_requested()) {error="GDB connection canceled";return false;}
    addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    addrinfo* addresses=nullptr; const auto service=std::to_string(port);
    int result=getaddrinfo(host.c_str(),service.c_str(),&hints,&addresses);
    if (result) {error=gai_strerror(result);return false;}
    if (cancellation_.stop_requested()) {freeaddrinfo(addresses);error="GDB connection canceled";return false;}
    deadline_=std::chrono::steady_clock::now()+timeout_;
    for (auto* address=addresses;address;address=address->ai_next) {
        fd_=::socket(address->ai_family,address->ai_socktype|SOCK_CLOEXEC|SOCK_NONBLOCK,address->ai_protocol);
        if (fd_<0) {error=ioError("socket");continue;}
        result=::connect(fd_,address->ai_addr,address->ai_addrlen);
        if (result && errno==EINPROGRESS && waitReady(POLLOUT,error)) {
            int failure=0; socklen_t length=sizeof(failure);
            result=getsockopt(fd_,SOL_SOCKET,SO_ERROR,&failure,&length);
            if (!result && failure) {errno=failure;result=-1;}
        }
        if (!result) {error.clear();freeaddrinfo(addresses);return true;}
        if (error.empty()) error=ioError("connect");
        ::close(fd_);fd_=-1;
    }
    freeaddrinfo(addresses);return false;
}
void GdbRemoteClient::close() {
    std::lock_guard lock(mutex_);
    if (fd_>=0) ::close(fd_);
    fd_=-1;noAck_=false;packetSize_=1024;features_.clear();
    registerLayout_.clear();individualReads_=individualWrites_=true;
}
bool GdbRemoteClient::waitReady(short events,std::string& error) {
    for (;;) {
        if (cancellation_.stop_requested()) {error="GDB operation canceled";return false;}
        const auto remaining=deadline_-std::chrono::steady_clock::now();
        if (remaining<=std::chrono::steady_clock::duration::zero()) {error="GDB operation timed out";return false;}
        const auto ms=std::chrono::ceil<std::chrono::milliseconds>(remaining).count();
        const auto pollMs=std::min<int64_t>(ms,cancellation_.stop_possible() ? 50 : INT_MAX);
        pollfd descriptor{fd_,events,0};int ready=poll(&descriptor,1,static_cast<int>(pollMs));
        if (ready<0 && errno==EINTR) continue;
        if (!ready) continue;
        if (ready<0) {error=ioError("poll");return false;}
        // Read buffered bytes even when HUP is also set; recv then observes EOF.
        if (descriptor.revents&events) return true;
        error="GDB peer disconnected";return false;
    }
}
bool GdbRemoteClient::sendAll(const std::string& data,std::string& error) {
    size_t sent=0;
    while (sent<data.size()) {
        if (!waitReady(POLLOUT,error)) return false;
        ssize_t n=::send(fd_,data.data()+sent,data.size()-sent,MSG_NOSIGNAL);
        if (n<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)) continue;
        if (n<=0) {error=n ? ioError("send") : "GDB peer disconnected";return false;}
        sent+=static_cast<size_t>(n);
    }
    return true;
}
std::expected<char,std::string> GdbRemoteClient::readByte() {
    for (;;) {
        std::string error;if (!waitReady(POLLIN,error)) return std::unexpected(error);
        char c=0;ssize_t n=::recv(fd_,&c,1,0);
        if (n<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)) continue;
        if (n!=1) return std::unexpected(n ? ioError("recv") : "GDB peer disconnected");
        return c;
    }
}
std::expected<std::string,std::string> GdbRemoteClient::readPacket() {
    for (unsigned attempt=0;attempt<3;++attempt) {
        std::string raw;uint8_t checksum=0;
        for (size_t ignored=0;;++ignored) {
            auto c=readByte();if (!c) return std::unexpected(c.error());
            if (*c=='$') break;
            if (*c!='+' || ignored>16) return std::unexpected("Unexpected GDB packet prefix");
        }
        for (;;) {
            auto c=readByte();if (!c) return std::unexpected(c.error());
            if (*c=='#') break;
            if (raw.size()>=maxWire) return std::unexpected("GDB packet exceeds size limit");
            raw.push_back(*c);checksum=static_cast<uint8_t>(checksum+static_cast<unsigned char>(*c));
        }
        auto hi=readByte(),lo=readByte();
        if (!hi) return std::unexpected(hi.error());
        if (!lo) return std::unexpected(lo.error());
        int a=hexValue(*hi),b=hexValue(*lo);
        std::string error;
        if (a<0 || b<0 || checksum!=((a<<4)|b)) {
            if (noAck_ || !sendAll("-",error)) return std::unexpected("Invalid GDB checksum");
            continue;
        }
        std::string decoded;
        for (size_t i=0;i<raw.size();++i) {
            unsigned char c=raw[i];
            if (c=='}') {
                if (++i==raw.size()) return std::unexpected("Truncated GDB escape");
                c=static_cast<unsigned char>(raw[i])^0x20;
            } else if (c=='*') {
                if (decoded.empty() || ++i==raw.size()) return std::unexpected("Invalid GDB run-length data");
                unsigned char count=raw[i];
                if (count<32 || count>126 || count=='$' || count=='#' || count=='+' || count=='-')
                    return std::unexpected("Invalid GDB run-length count");
                const size_t repeat=count-29;
                if (repeat>maxDecoded-decoded.size()) return std::unexpected("Decoded GDB packet exceeds size limit");
                decoded.append(repeat,decoded.back());continue;
            }
            if (decoded.size()>=maxDecoded) return std::unexpected("Decoded GDB packet exceeds size limit");
            decoded.push_back(static_cast<char>(c));
        }
        if (!noAck_ && !sendAll("+",error)) return std::unexpected(error);
        return decoded;
    }
    return std::unexpected("Repeated GDB checksum failures");
}
std::expected<std::string,std::string> GdbRemoteClient::sendPacket(const std::string& payload) {
    std::lock_guard lock(mutex_);
    if (fd_<0) return std::unexpected("GDB transport is not connected");
    if (cancellation_.stop_requested()) {close();return std::unexpected("GDB operation canceled");}
    std::string raw;raw.reserve(std::min(payload.size(),packetSize_));
    for (unsigned char c:payload) {
        if (c=='$' || c=='#' || c=='}' || c=='*') {raw.push_back('}');c^=0x20;}
        raw.push_back(static_cast<char>(c));
        if (raw.size()>packetSize_) return std::unexpected("Request exceeds negotiated GDB packet size");
    }
    uint8_t sum=0;for (unsigned char c:raw) sum=static_cast<uint8_t>(sum+c);
    char suffix[4];std::snprintf(suffix,sizeof(suffix),"#%02x",sum);
    const std::string packet="$"+raw+suffix;
    deadline_=std::chrono::steady_clock::now()+timeout_;
    auto failure=[&](std::string error)->std::expected<std::string,std::string> {close();return std::unexpected(std::move(error));};
    std::string error;
    bool accepted=noAck_;
    for (unsigned attempt=0;attempt<3;++attempt) {
        if (!sendAll(packet,error)) return failure(error);
        if (noAck_) break;
        auto ack=readByte();if (!ack) return failure(ack.error());
        if (*ack=='+') {accepted=true;break;}
        if (*ack!='-') return failure("Unexpected GDB acknowledgment");
    }
    if (!accepted) return failure("Repeated GDB request rejection");
    for (unsigned output=0;output<64;++output) {
        auto response=readPacket();if (!response) return failure(response.error());
        // Hex E is valid register/memory data. Recognize the actual E nn form.
        if ((response->size()==3 && (*response)[0]=='E' && hexValue((*response)[1])>=0 && hexValue((*response)[2])>=0) ||
            response->starts_with("E.")) return std::unexpected("GDB error response: "+*response);
        if (response->size()>1 && (*response)[0]=='O' && (response->size()-1)%2==0 &&
            std::all_of(response->begin()+1,response->end(),[](char c){return hexValue(c)>=0;})) continue;
        return response;
    }
    return failure("Too many GDB console packets");
}
bool GdbRemoteClient::supports(const std::string& feature) const {
    std::lock_guard lock(mutex_);return std::find(features_.begin(),features_.end(),feature+"+")!=features_.end();
}
std::expected<void,std::string> GdbRemoteClient::negotiate() {
    std::lock_guard lock(mutex_);
    auto response=sendPacket("qSupported:qXfer:features:read+");if (!response) return std::unexpected(response.error());
    features_.clear();std::set<std::string> names;
    for (size_t offset=0;offset<response->size();) {
        auto end=response->find(';',offset);if (end==std::string::npos) end=response->size();
        auto entry=response->substr(offset,end-offset);offset=end+1;
        if (entry.empty()) continue;
        auto separator=entry.find('=');
        if (separator==std::string::npos && (entry.back()=='+' || entry.back()=='-' || entry.back()=='?')) separator=entry.size()-1;
        const auto name=entry.substr(0,separator);
        if (name.empty() || !names.insert(name).second) {close();return std::unexpected("Conflicting GDB features");}
        if (entry.starts_with("PacketSize=")) {
            uint32_t n=0;if (!number(std::string_view(entry).substr(11),n,16) || n<64) {close();return std::unexpected("Invalid GDB PacketSize");}
            packetSize_=std::min<size_t>(n,maxWire);
        }
        features_.push_back(std::move(entry));
    }
    if (supports("QStartNoAckMode")) {
        auto mode=sendPacket("QStartNoAckMode");if (!mode) return std::unexpected(mode.error());
        if (*mode=="OK") noAck_=true;
        else if (!mode->empty()) {close();return std::unexpected("Invalid no-ack negotiation response");}
    }
    return {};
}
std::expected<std::string,std::string> GdbRemoteClient::readObject(const std::string& object,const std::string& annex) {
    std::lock_guard lock(mutex_);
    if (!token(object) || !token(annex,true)) return std::unexpected("Invalid GDB object or annex");
    if (!supports("qXfer:"+object+":read")) return std::unexpected("GDB stub does not advertise this object");
    std::string data;
    const size_t chunk=std::min<size_t>(4096,(packetSize_-1)/2);
    const auto endTime=std::chrono::steady_clock::now()+timeout_*10;
    for (;;) {
        if (std::chrono::steady_clock::now()>=endTime) return std::unexpected("GDB object transfer timed out");
        auto response=sendPacket("qXfer:"+object+":read:"+annex+":"+hexNumber(data.size())+","+hexNumber(chunk));
        if (!response) return std::unexpected(response.error());
        if (response->empty() || ((*response)[0]!='m' && (*response)[0]!='l') || response->size()-1>chunk ||
            (response->size()==1 && (*response)[0]=='m')) return std::unexpected("Invalid GDB object chunk");
        if (response->size()-1>maxObject-data.size()) return std::unexpected("GDB object exceeds size limit");
        data.append(*response,1,std::string::npos);
        if ((*response)[0]=='l') return data;
    }
}
std::expected<GdbTargetDescription,std::string> GdbRemoteClient::describeTarget() {
    std::lock_guard lock(mutex_);GdbTargetDescription target;
    registerLayout_.clear();
    std::set<std::string> active,registerNames;std::set<uint32_t> numbers;
    uint32_t next=0;size_t documents=0,total=0;
    const auto endTime=std::chrono::steady_clock::now()+timeout_*10;
    std::function<std::expected<void,std::string>(const std::string&,unsigned)> load;
    load=[&](const std::string& annex,unsigned depth)->std::expected<void,std::string> {
        if (std::chrono::steady_clock::now()>=endTime) return std::unexpected("GDB description transfer timed out");
        if (depth>8 || ++documents>128 || !active.insert(annex).second) return std::unexpected("GDB XML inclusion cycle or depth limit");
        auto xml=readObject("features",annex);if (!xml) return std::unexpected(xml.error());
        total+=xml->size();if (total>maxObject) return std::unexpected("GDB XML exceeds total size limit");
        tinyxml2::XMLDocument doc;
        if (doc.Parse(xml->data(),xml->size())!=tinyxml2::XML_SUCCESS || !doc.RootElement()) return std::unexpected("Invalid GDB target XML");
        std::function<std::expected<void,std::string>(const tinyxml2::XMLElement*,unsigned)> visit;
        visit=[&](const tinyxml2::XMLElement* element,unsigned nesting)->std::expected<void,std::string> {
            if (nesting>64) return std::unexpected("GDB XML nesting limit");
            std::string name=element->Name();
            if (xmlInclude(element)) {
                const char* href=element->Attribute("href");if (!href) return std::unexpected("Missing GDB XML include name");
                return load(href,depth+1);
            }
            if (name=="architecture" || name=="osabi") {
                const char* text=element->GetText();if (!text || std::strlen(text)>256) return std::unexpected("Invalid GDB architecture or OS ABI");
                std::string value=text;auto begin=value.find_first_not_of(" \r\n\t"),end=value.find_last_not_of(" \r\n\t");
                if (begin==std::string::npos) return std::unexpected("Empty GDB architecture or OS ABI");
                value=value.substr(begin,end-begin+1);auto& destination=name=="architecture" ? target.architecture : target.osAbi;
                if (!destination.empty() && destination!=value) return std::unexpected("Conflicting GDB target descriptions");
                destination=std::move(value);
            } else if (name=="reg") {
                const char* regName=element->Attribute("name"),*bits=element->Attribute("bitsize"),*regNum=element->Attribute("regnum");
                GdbRegisterDescription reg;
                if (!regName || !*regName || std::strlen(regName)>256 || !bits || !number(bits,reg.bits) || !reg.bits || reg.bits>524288)
                    return std::unexpected("Invalid GDB register description");
                reg.name=regName;reg.number=next;
                if (regNum && !number(regNum,reg.number)) return std::unexpected("Invalid GDB register number");
                if (reg.number>65535 || target.registers.size()>=2048 || !numbers.insert(reg.number).second ||
                    !registerNames.insert(reg.name).second) return std::unexpected("Duplicate or excessive GDB register description");
                if (const char* type=element->Attribute("type")) reg.type=type;
                next=reg.number+1;target.registers.push_back(std::move(reg));
            }
            for (auto* child=element->FirstChildElement();child;child=child->NextSiblingElement()) {
                auto result=visit(child,nesting+1);if (!result) return result;
            }
            return {};
        };
        auto result=visit(doc.RootElement(),0);active.erase(annex);return result;
    };
    auto result=load("target.xml",0);if (!result) return std::unexpected(result.error());
    if (target.architecture.empty() || target.registers.empty()) return std::unexpected("Incomplete GDB target description");
    target.machine=targetMachine(target.architecture,target.osAbi);
    registerLayout_=target.registers;
    // XML declaration order may differ from the wire order. Sparse register
    // numbers do not introduce bytes for registers absent from the description.
    std::sort(registerLayout_.begin(),registerLayout_.end(),[](const auto& a,const auto& b){return a.number<b.number;});
    return target;
}
std::expected<std::string,std::string> GdbRemoteClient::readRegisters() {return sendPacket("g");}
std::expected<GdbRemoteClient::RegisterBank,std::string> GdbRemoteClient::readRegisterBank(const GdbRegisterDescription& reg) {
    if (registerLayout_.empty()) return std::unexpected("Whole-register access requires a target XML layout");
    RegisterBank bank;size_t total=0;bool found=false;
    for (const auto& field:registerLayout_) {
        const size_t width=2*((field.bits+7)/8);
        if (width>maxDecoded-total) return std::unexpected("GDB register bank exceeds size limit");
        if (field.number==reg.number) {
            if (field.name!=reg.name || field.bits!=reg.bits) return std::unexpected("Register does not match target XML");
            bank.offset=total;bank.width=width;found=true;
        }
        total+=width;
    }
    if (!found) return std::unexpected("Register absent from GDB target XML");
    auto response=readRegisters();if (!response) return std::unexpected(response.error());
    if (response->size()>total || response->size()%2) return std::unexpected("GDB register bank size does not match target XML");
    size_t boundary=0;
    for (const auto& field:registerLayout_) {
        if (boundary==response->size()) break;
        boundary+=2*((field.bits+7)/8);
    }
    if (boundary!=response->size()) return std::unexpected("GDB register bank ends inside a register");
    for (size_t i=0;i<response->size();i+=2)
        if (!(hexValue((*response)[i])>=0 && hexValue((*response)[i+1])>=0) &&
            !((*response)[i]=='x' && (*response)[i+1]=='x'))
            return std::unexpected("Invalid GDB register bank data");
    if (bank.offset>response->size() || bank.width>response->size()-bank.offset)
        return std::unexpected("Register unavailable in the GDB register bank");
    bank.data=std::move(*response);return bank;
}
std::expected<std::vector<uint8_t>,std::string> GdbRemoteClient::readRegister(const GdbRegisterDescription& reg) {
    std::lock_guard lock(mutex_);
    if (!reg.bits || reg.bits>524288) return std::unexpected("Invalid GDB register width");
    if (individualReads_) {
        auto response=sendPacket("p"+hexNumber(reg.number));if (!response) return std::unexpected(response.error());
        if (!response->empty()) {
            auto bytes=decodeHex(*response);if (!bytes) return bytes;
            if (bytes->size()!=(reg.bits+7)/8) return std::unexpected("GDB register size does not match target XML");
            return bytes;
        }
        // An empty response is the RSP indication of an unsupported packet.
        // Errors and malformed nonempty data must not trigger a fallback.
        individualReads_=false;
    }
    auto bank=readRegisterBank(reg);if (!bank) return std::unexpected(bank.error());
    return decodeHex(std::string_view(bank->data).substr(bank->offset,bank->width));
}
std::expected<void,std::string> GdbRemoteClient::writeRegister(const GdbRegisterDescription& reg,std::span<const uint8_t> bytes) {
    std::lock_guard lock(mutex_);
    if (!reg.bits || reg.bits>524288 || bytes.size()!=(reg.bits+7)/8) return std::unexpected("GDB register write size mismatch");
    if (individualWrites_) {
        auto response=sendPacket("P"+hexNumber(reg.number)+"="+hexBytes(bytes));if (!response) return std::unexpected(response.error());
        if (*response=="OK") return {};
        if (!response->empty()) return std::unexpected("GDB register write was not confirmed");
        individualWrites_=false;
    }
    // Read a fresh stopped bank for every edit. Never replay a previous UI
    // snapshot, fill unknown registers with zero, or split a G packet.
    auto bank=readRegisterBank(reg);if (!bank) return std::unexpected(bank.error());
    if (bank->data.size()+1>packetSize_) return std::unexpected("Whole-register write exceeds negotiated GDB packet size");
    bank->data.replace(bank->offset,bank->width,hexBytes(bytes));
    if (!std::all_of(bank->data.begin(),bank->data.end(),[](char c){return hexValue(c)>=0;}))
        return std::unexpected("Whole-register write cannot preserve unavailable registers");
    auto response=sendPacket("G"+bank->data);if (!response) return std::unexpected(response.error());
    if (*response!="OK") return std::unexpected("GDB whole-register write was not confirmed");
    return {};
}
std::expected<std::vector<uint8_t>,std::string> GdbRemoteClient::readMemory(uintptr_t address,size_t size) {
    std::lock_guard lock(mutex_);
    if (size>maxDecoded || (size && size-1>UINTPTR_MAX-address)) return std::unexpected("GDB memory read size or address overflow");
    std::vector<uint8_t> bytes;bytes.reserve(size);
    while (bytes.size()<size) {
        const size_t count=std::min(size-bytes.size(),packetSize_/2);
        auto response=sendPacket("m"+hexNumber(address+bytes.size())+","+hexNumber(count));
        if (!response) return bytes.empty() ? std::expected<std::vector<uint8_t>,std::string>(std::unexpected(response.error())) : bytes;
        auto block=decodeHex(*response);if (!block) return std::unexpected(block.error());
        if (block->size()>count) return std::unexpected("GDB memory reply exceeds requested size");
        bytes.insert(bytes.end(),block->begin(),block->end());if (block->size()<count) break;
    }
    return bytes;
}
std::expected<size_t,std::string> GdbRemoteClient::writeMemory(uintptr_t address,std::span<const uint8_t> bytes) {
    std::lock_guard lock(mutex_);
    if (bytes.size()>maxDecoded || (bytes.size() && bytes.size()-1>UINTPTR_MAX-address)) return std::unexpected("GDB memory write size or address overflow");
    size_t done=0;
    while (done<bytes.size()) {
        const size_t count=std::min(bytes.size()-done,(packetSize_-40)/2);
        auto response=sendPacket("M"+hexNumber(address+done)+","+hexNumber(count)+":"+hexBytes(bytes.subspan(done,count)));
        if (!response) return done ? std::expected<size_t,std::string>(done) : std::unexpected(response.error());
        if (*response!="OK") return done ? std::expected<size_t,std::string>(done) : std::unexpected("GDB memory write was not confirmed");
        done+=count;
    }
    return done;
}
}
