#include "platform/linux/register_image.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

namespace ce::os {
namespace {
Error kernelError() { return {errno, std::system_category()}; }
Error unsupported() { return std::make_error_code(std::errc::not_supported); }
Error brokenRestore() { return std::make_error_code(std::errc::state_not_recoverable); }
bool missing(const Error& error) {
    return error==std::errc::io_error || error==std::errc::invalid_argument || error==std::errc::no_such_device;
}
Result<NativeExtendedContext::Regset> capture(pid_t tid,unsigned note) {
    NativeExtendedContext::Regset image;
    image.note=note;
    constexpr size_t maximum=16*1024*1024;
#if defined(__aarch64__)
    if (note==0x405 || note==0x40b || note==0x40c) {
        // SVE/SME expose their active length in a fixed header. The regset's
        // kernel descriptor can be much larger than the live payload.
        image.bytes.resize(16);
        iovec header{image.bytes.data(),image.bytes.size()};
        if (ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(uintptr_t(note)),&header)<0)
            return std::unexpected(kernelError());
        if (header.iov_len!=image.bytes.size()) return std::unexpected(unsupported());
        uint32_t size=0;
        std::memcpy(&size,image.bytes.data(),sizeof(size));
        if (size<16 || size>maximum) return std::unexpected(unsupported());
        image.bytes.resize(size);
        iovec io{image.bytes.data(),image.bytes.size()};
        if (ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(uintptr_t(note)),&io)<0)
            return std::unexpected(kernelError());
        if (io.iov_len!=size) return std::unexpected(unsupported());
        image.verification.resize(size);
        return image;
    }
#endif
    // Regsets return the transferred length rather than a required-size query.
    // Grow until a complete short transfer, retaining all extension bytes.
    for (size_t capacity=4096;capacity<=maximum;capacity*=2) {
        image.bytes.resize(capacity);
        iovec io{image.bytes.data(),image.bytes.size()};
        if (ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(uintptr_t(note)),&io)<0)
            return std::unexpected(kernelError());
        if (!io.iov_len || io.iov_len>capacity) return std::unexpected(unsupported());
        if (io.iov_len==capacity) continue;
        image.bytes.resize(io.iov_len);
        image.verification.resize(io.iov_len);
        return image;
    }
    return std::unexpected(std::make_error_code(std::errc::value_too_large));
}
bool equal(pid_t tid,NativeExtendedContext::Regset& image) {
    iovec io{image.verification.data(),image.verification.size()};
    return ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(uintptr_t(image.note)),&io)==0 &&
        io.iov_len==image.bytes.size() && image.verification==image.bytes;
}
bool write(pid_t tid,const NativeExtendedContext::Regset& image,size_t length=0) {
#if defined(__arm__)
    // ARM's legacy fpa_set copies directly into task_struct storage. Real
    // hardened-usercopy kernels can panic on that path, rather than return an
    // error. Keep this bank for read-only verification; a changed FPA image
    // must retain recovery until a safe restoration adapter is available.
    if (image.note==NT_PRFPREG) return false;
#endif
    iovec io{const_cast<uint8_t*>(image.bytes.data()),length ? length : image.bytes.size()};
    return ptrace(PTRACE_SETREGSET,tid,reinterpret_cast<void*>(uintptr_t(image.note)),&io)==0;
}
#if defined(__aarch64__)
bool writeVectorHeader(pid_t tid,const NativeExtendedContext::Regset& image) {
    std::array<uint8_t,16> header;
    std::memcpy(header.data(),image.bytes.data(),header.size());
    if (image.note==0x40b) {
        // GETREGSET represents an inactive streaming bank with FPSIMD flags.
        // SETREGSET only accepts SVE format for SSVE, even without payload.
        uint16_t flags;
        std::memcpy(&flags,header.data()+12,sizeof(flags));
        flags|=1;
        std::memcpy(header.data()+12,&flags,sizeof(flags));
    }
    iovec io{header.data(),header.size()};
    return ptrace(PTRACE_SETREGSET,tid,reinterpret_cast<void*>(uintptr_t(image.note)),&io)==0;
}
bool vectorConfigurationEqual(pid_t tid,const NativeExtendedContext::Regset& image) {
    std::array<uint8_t,16> header;
    iovec io{header.data(),header.size()};
    if (ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(uintptr_t(image.note)),&io)<0 ||
        io.iov_len!=header.size()) return false;
    uint16_t savedFlags,currentFlags;
    std::memcpy(&savedFlags,image.bytes.data()+12,sizeof(savedFlags));
    std::memcpy(&currentFlags,header.data()+12,sizeof(currentFlags));
    return std::memcmp(header.data()+8,image.bytes.data()+8,4)==0 &&
        (savedFlags&~uint16_t{1})==(currentFlags&~uint16_t{1});
}
#endif
}

Result<NativeExtendedContext> captureNativeExtendedContext(pid_t tid) {
    NativeExtendedContext context;
    auto append=[&](unsigned note,bool required)->Result<void> {
        auto image=capture(tid,note);
        if (!image) {
            if (!required && missing(image.error())) return {};
            return std::unexpected(image.error());
        }
        context.regsets.push_back(std::move(*image));
        return {};
    };
#if defined(__x86_64__)
    auto xstate=capture(tid,NT_X86_XSTATE);
    if (xstate) context.regsets.push_back(std::move(*xstate));
    else {
        if (!missing(xstate.error())) return std::unexpected(xstate.error());
        auto fp=append(NT_PRFPREG,true);
        if (!fp) return std::unexpected(fp.error());
        auto xmm=append(NT_PRXFPREG,false);
        if (!xmm) return std::unexpected(xmm.error());
    }
    // The selector bank is separate from GETREGS for a genuine i386 task.
    for (unsigned note : {0x200u,0x204u}) { // NT_386_TLS, NT_X86_SHSTK.
        auto read=append(note,false);
        if (!read) return std::unexpected(read.error());
    }
#elif defined(__aarch64__) || defined(__arm__)
    // The active task's regset ABI, rather than the controller's architecture,
    // determines the FP bank. ARM64 compat tasks expose ARM_VFP, not PRFPREG.
    auto general=capture(tid,NT_PRSTATUS);
    if (!general) return std::unexpected(general.error());
    if (general->bytes.size()==18*sizeof(uint32_t)) {
#if defined(__arm__)
        // Native ARM kernels also expose the legacy FPA image. A compat ARM64
        // kernel may omit it; VFP is required there instead.
        auto fpa=append(NT_PRFPREG,false);
        if (!fpa) return std::unexpected(fpa.error());
#endif
        auto vfp=append(0x400u,true); // NT_ARM_VFP: D0-D31 and FPSCR.
        if (!vfp) return std::unexpected(vfp.error());
        for (const auto& image:context.regsets)
            if (image.note==0x400u && image.bytes.size()!=32*sizeof(uint64_t)+sizeof(uint32_t))
                return std::unexpected(unsupported());
        // Native ARM kernels need a separate TLS adapter. ARM64 compat kernels
        // expose a four-byte TLS image through this note; preserve it if present.
        auto tls=append(0x401u,false);
        if (!tls) return std::unexpected(tls.error());
        return context;
    }
    if (general->bytes.size()!=34*sizeof(uint64_t)) return std::unexpected(unsupported());
#if defined(__aarch64__)
    auto fp=append(NT_PRFPREG,true);
    if (!fp) return std::unexpected(fp.error());
    for (unsigned note : {0x401u,0x405u,0x40bu,0x40cu,0x40du,0x40eu,0x40fu,0x410u}) {
        // TLS, SVE, streaming SVE, ZA, ZT, FPMR, POE, guarded control stack.
        auto read=append(note,false);
        if (!read) return std::unexpected(read.error());
    }
#else
    // A native ARM controller has no adapter for AArch64 extension images.
    return std::unexpected(unsupported());
#endif
#else
    (void)tid;
    return std::unexpected(unsupported());
#endif
    return context;
}

Result<void> verifyNativeExtendedContext(pid_t tid,NativeExtendedContext& saved) {
    for (auto& image : saved.regsets) if (!equal(tid,image)) return std::unexpected(brokenRestore());
    return {};
}

Result<void> restoreNativeExtendedContext(pid_t tid,NativeExtendedContext& saved) {
    // Avoid rewriting already exact banks. In particular SETREGSET of an
    // inactive streaming bank changes mode, and writing ZT enables ZA.
    bool unchanged=true;
    for (auto& image : saved.regsets) unchanged=equal(tid,image) && unchanged;
    if (unchanged) return {};
#if defined(__aarch64__)
    auto find=[&](unsigned note)->NativeExtendedContext::Regset* {
        for (auto& image : saved.regsets) if (image.note==note) return &image;
        return nullptr;
    };
    auto sve=find(0x405),ssve=find(0x40b),za=find(0x40c),zt=find(0x40d);
    constexpr size_t headerSize=16;
    // Restore both vector lengths before data. Changing streaming length can
    // invalidate ZA; a saved header alone deliberately omits register payload.
    if (sve && !vectorConfigurationEqual(tid,*sve) && !writeVectorHeader(tid,*sve))
        return std::unexpected(brokenRestore());
    if (ssve && !vectorConfigurationEqual(tid,*ssve) && !writeVectorHeader(tid,*ssve))
        return std::unexpected(brokenRestore());
    for (auto& image : saved.regsets) {
        if (image.note==0x405 || image.note==0x40b || image.note==0x40c || image.note==0x40d) continue;
        if (!equal(tid,image) && !write(tid,image)) return std::unexpected(brokenRestore());
    }
    if (za && (!equal(tid,*za) || (zt && !equal(tid,*zt)))) {
        // A matrix payload means ZA was active. ZT writes enable ZA, so never
        // write an inactive bank's zero-filled ZT image.
        if (za->bytes.size()>headerSize && zt && !write(tid,*zt)) return std::unexpected(brokenRestore());
        if (!write(tid,*za)) return std::unexpected(brokenRestore());
    }
    // Writing SVE selects non-streaming mode; SSVE selects streaming mode.
    // The original live bank, which includes payload, must be written last.
    if (sve && sve->bytes.size()>headerSize) {
        if (!write(tid,*sve)) return std::unexpected(brokenRestore());
    } else if (ssve && ssve->bytes.size()>headerSize) {
        if (!write(tid,*ssve)) return std::unexpected(brokenRestore());
    } else if (sve && !write(tid,*sve,headerSize)) return std::unexpected(brokenRestore());
#else
    for (auto& image : saved.regsets)
        if (!equal(tid,image) && !write(tid,image)) return std::unexpected(brokenRestore());
#endif
    for (auto& image : saved.regsets) if (!equal(tid,image)) return std::unexpected(brokenRestore());
    return {};
}

} // namespace ce::os
