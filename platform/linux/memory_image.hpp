#pragma once
#include "platform/linux/target_syscall.hpp"
#include "core/types.hpp"
#include <span>
#include <memory>
namespace ce { class ProcessHandle; }
namespace ce::os {
class NativeCallOwner;
// A saved operation belongs to this address space, not a numeric PID reopened
// later. Callers still coordinate execution and mapping lifetime.
class NativeMemoryImage {
public:
    NativeMemoryImage() = default;
    NativeMemoryImage(const NativeMemoryImage&) = delete;
    NativeMemoryImage& operator=(const NativeMemoryImage&) = delete;
    static std::expected<std::shared_ptr<NativeMemoryImage>,std::error_code> capture(
        const TargetProcessIdentity&,const TargetMachine&);
    ~NativeMemoryImage();
    std::expected<void,std::error_code> check() const;
    // Caller owns the stop. 'owner' created a fresh private anonymous mapping
    // at address in its captured mm, and keeps it mapped throughout this check.
    // Only that unpublished mapping is modified; this image is read-only here.
    std::expected<void,std::error_code> sharesPrivateMapping(
        const NativeMemoryImage& owner,uintptr_t address) const;
    std::expected<int,std::error_code> duplicateFd() const;
    std::expected<size_t,std::error_code> read(uintptr_t,void*,size_t) const;
    std::expected<size_t,std::error_code> write(uintptr_t,std::span<const uint8_t>,bool executable) const;
    std::expected<uintptr_t,std::error_code> allocate(size_t,MemProt,uintptr_t) const;
    std::expected<void,std::error_code> protect(uintptr_t,size_t,MemProt) const;
    std::expected<void,std::error_code> free(uintptr_t,size_t) const;
    pid_t pid() const {return identity_.pid;}
    const TargetProcessIdentity& identity() const {return identity_;}
private:
    friend class NativeCallOwner;
    friend class TargetSyscallRecovery;
    // Private scratch sites may end at a page boundary. Probe only bytes that
    // the recovery owner actually owns, without extending its scratch contract.
    std::expected<void,std::error_code> sharesPrivateBytes(
        const NativeMemoryImage&,uintptr_t,size_t) const;
    // The native call owner has already opened this descriptor under its stop.
    // Duplicate its original mm without upgrading a read-only descriptor.
    static std::expected<std::shared_ptr<NativeMemoryImage>,std::error_code> retainStoppedFd(
        int,const TargetProcessIdentity&,const TargetMachine&);
    int fd_=-1;
    TargetProcessIdentity identity_;
    TargetMachine host_;
};
// Native handles opt into a pinned mm; model/remote adapters retain their own
// transport behavior and do not open frontend /proc entries.
std::expected<std::shared_ptr<NativeMemoryImage>,std::error_code> pinNativeMemoryImage(ProcessHandle&);
}
