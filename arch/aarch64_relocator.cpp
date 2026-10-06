#include "arch/aarch64_relocator.hpp"
#include "arch/disassembler.hpp"
#include <algorithm>
#include <limits>

namespace ce {
namespace {
constexpr uint32_t nop=0xd503201f;
enum class Kind { Copy, Address, Branch, Conditional, Compare, Test, Literal };
Kind kind(uint32_t word) {
    if ((word&0x1f000000)==0x10000000) return Kind::Address;
    if ((word&0x7c000000)==0x14000000) return Kind::Branch;
    if ((word&0xff000000)==0x54000000) return Kind::Conditional;
    if ((word&0x7e000000)==0x34000000) return Kind::Compare;
    if ((word&0x7e000000)==0x36000000) return Kind::Test;
    if ((word&0x3b000000)==0x18000000) return Kind::Literal;
    return Kind::Copy;
}
size_t slot(Kind type) {
    switch (type) {
        case Kind::Copy: return 4;
        case Kind::Address: return 16;
        case Kind::Branch: case Kind::Literal: return 20;
        default: return 24;
    }
}
uint32_t wordAt(std::span<const uint8_t> bytes,size_t offset) {
    return uint32_t(bytes[offset])|(uint32_t(bytes[offset+1])<<8)|
        (uint32_t(bytes[offset+2])<<16)|(uint32_t(bytes[offset+3])<<24);
}
void emit(std::vector<uint8_t>& bytes,uint32_t word) {
    for (unsigned i=0;i<4;++i) bytes.push_back(static_cast<uint8_t>(word>>(8*i)));
}
void constant(std::vector<uint8_t>& bytes,unsigned reg,uint64_t value) {
    for (unsigned i=0;i<4;++i)
        emit(bytes,(i ? 0xf2800000u : 0xd2800000u)|(i<<21)|
             (uint32_t((value>>(16*i))&0xffff)<<5)|reg);
}
int64_t signedField(uint32_t value,unsigned bits) {
    const int64_t sign=int64_t(1)<<(bits-1);
    return (int64_t(value)^sign)-sign;
}
std::expected<uint64_t,std::string> absolute(uint64_t pc,int64_t offset) {
    if (offset>=0) {
        if (uint64_t(offset)>UINT64_MAX-pc) return std::unexpected("AArch64 source operand overflows its address space");
        return pc+uint64_t(offset);
    }
    const uint64_t magnitude=uint64_t(-(offset+1))+1;
    if (magnitude>pc) return std::unexpected("AArch64 source operand underflows its address space");
    return pc-magnitude;
}
std::optional<uint32_t> relative(uint64_t from,uint64_t to,unsigned bits) {
    // Avoid signed overflow and preserve the asymmetric positive/negative limit.
    if ((from&3)!=(to&3)) return {};
    const uint64_t units=(to>=from ? to-from : from-to)/4;
    const uint64_t limit=uint64_t(1)<<(bits-1);
    if (units>(to>=from ? limit-1 : limit)) return {};
    return uint32_t(to>=from ? units : uint64_t(0)-units)&((uint32_t(1)<<bits)-1);
}
std::expected<void,std::string> branch(std::vector<uint8_t>& out,uint64_t pc,uint64_t target,
                                      bool link,const Aarch64RelocationOptions& options) {
    if (auto rel=relative(pc,target,26)) {
        emit(out,(link ? 0x94000000u : 0x14000000u)|*rel);return {};
    }
    if (!options.allowIndirectBranches)
        return std::unexpected("Far AArch64 branch requires an explicitly allowed indirect veneer and a compatible landing site");
    if (!link && !options.scratchRegister)
        return std::unexpected("Far AArch64 branch requires an explicitly permitted scratch register");
    const unsigned reg=link ? 30 : *options.scratchRegister;
    constant(out,reg,target);
    // BL already overwrites LR. BLR X30 reads the destination before replacing
    // LR with the relocated return PC, without borrowing another live register.
    emit(out,(link ? 0xd63f0000u : 0xd61f0000u)|(reg<<5));return {};
}
}

std::expected<Aarch64RelocatedCode,std::string> relocateAarch64(
    std::span<const uint8_t> code,uint64_t source,uint64_t destination,
    const Aarch64RelocationOptions& options) {
    if (code.empty() || code.size()%4 || source%4 || destination%4)
        return std::unexpected("AArch64 relocation requires aligned whole instructions");
    if (code.size()>1024*1024 || code.size()>UINT64_MAX-source)
        return std::unexpected("AArch64 source block size or address overflow");
    if (options.scratchRegister && *options.scratchRegister>30)
        return std::unexpected("AArch64 scratch register must be X0 through X30");
    Disassembler decoder(Arch::ARM64);
    const auto decoded=decoder.disassemble(static_cast<uintptr_t>(source),code);
    if (decoded.size()!=code.size()/4 ||
        std::any_of(decoded.begin(),decoded.end(),[](const auto& in){return in.size!=4;}))
        return std::unexpected("AArch64 source block contains an invalid or unsupported encoding");
    Aarch64RelocatedCode result;result.instructionOffsets.reserve(decoded.size());
    size_t size=0;
    for (size_t i=0;i<code.size();i+=4) {
        result.instructionOffsets.push_back(size);
        size+=source==destination ? 4 : slot(kind(wordAt(code,i)));
    }
    if (size>UINT64_MAX-destination) return std::unexpected("AArch64 relocated block overflows its address space");
    if (source==destination) {result.bytes.assign(code.begin(),code.end());return result;}
    result.bytes.reserve(size);
    auto mapBranch=[&](uint64_t target) {
        return target>=source && target-source<code.size()
            ? destination+result.instructionOffsets[(target-source)/4] : target;
    };
    for (size_t i=0;i<code.size();i+=4) {
        const uint32_t word=wordAt(code,i);const Kind type=kind(word);
        const uint64_t oldPc=source+i,newPc=destination+result.bytes.size();
        const size_t end=result.bytes.size()+slot(type);
        if (type==Kind::Address) {
            const auto immediate=signedField(((word>>5)&0x7ffff)*4+((word>>29)&3),21);
            const bool page=word>>31;
            auto target=absolute(page ? oldPc&~uint64_t(4095) : oldPc,page ? immediate*4096 : immediate);
            if (!target) return std::unexpected(target.error());
            constant(result.bytes,word&31,*target);
        } else if (type==Kind::Branch || type==Kind::Conditional || type==Kind::Compare || type==Kind::Test) {
            const unsigned bits=type==Kind::Branch ? 26 : type==Kind::Test ? 14 : 19;
            const uint32_t immediate=type==Kind::Branch ? word&0x3ffffff : (word>>5)&((uint32_t(1)<<bits)-1);
            auto target=absolute(oldPc,signedField(immediate,bits)*4);
            if (!target) return std::unexpected(target.error());
            const uint64_t mapped=mapBranch(*target);
            const bool always=type==Kind::Conditional && (word&15)>=14;
            if (type!=Kind::Branch && !always) {
                const uint32_t mask=((uint32_t(1)<<bits)-1)<<5;
                // AL and NV are both always true; XOR inversion is only valid
                // for the fourteen genuinely conditional NZCV predicates.
                emit(result.bytes,((word&~mask)^(type==Kind::Conditional ? 1u : 0x01000000u))|
                     (uint32_t(slot(type)/4)<<5));
            }
            auto emitted=branch(result.bytes,destination+result.bytes.size(),mapped,
                                 type==Kind::Branch && (word>>31),options);
            if (!emitted) return std::unexpected(emitted.error());
        } else if (type==Kind::Literal) {
            auto target=absolute(oldPc,signedField((word>>5)&0x7ffff,19)*4);
            if (!target) return std::unexpected(target.error());
            if (auto rel=relative(newPc,*target,19)) emit(result.bytes,(word&~0x00ffffe0u)|(*rel<<5));
            else {
                const unsigned opc=word>>30,rt=word&31;const bool vector=word&(1u<<26);
                const auto reg=!vector && opc<3 && rt!=31 ? std::optional<unsigned>(rt) : options.scratchRegister;
                if (!reg) return std::unexpected("Far AArch64 literal requires an explicitly permitted scratch register");
                constant(result.bytes,*reg,*target);
                const uint32_t load=vector ? (opc==0 ? 0xbd400000u : opc==1 ? 0xfd400000u : 0x3dc00000u) :
                    opc==0 ? 0xb9400000u : opc==1 ? 0xf9400000u : opc==2 ? 0xb9800000u : 0xf9800000u;
                emit(result.bytes,load|(*reg<<5)|rt);
            }
        } else emit(result.bytes,word);
        while (result.bytes.size()<end) emit(result.bytes,nop);
    }
    return result;
}
}
