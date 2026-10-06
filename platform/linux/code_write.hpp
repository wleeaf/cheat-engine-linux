#pragma once
#include "platform/linux/target_syscall.hpp"
#include <span>

namespace ce::os {
class NativeMemoryImage;
// The descriptor pins the original address space. Recovery never reopens a
// numeric PID/address after exec or exit. Callers coordinate execution and the
// lifetime of code mappings when changing more than one instruction.
class CodeWriteRecovery {
public:
    static std::expected<std::shared_ptr<CodeWriteRecovery>,std::error_code> prepare(
        const TargetProcessIdentity& identity,uintptr_t address,size_t size,const NativeMemoryImage* image=nullptr);
    ~CodeWriteRecovery();
    std::expected<void,std::error_code> write(std::span<const uint8_t> bytes);
    std::expected<void,std::error_code> restore();
    bool changed() const {return attempted_!=0;}
    bool overlaps(uintptr_t address,size_t size) const;
private:
    int fd_=-1;
    uintptr_t address_=0;
    size_t attempted_=0;
    std::vector<uint8_t> original_;
    std::expected<void,std::error_code> verify(std::span<const uint8_t> bytes);
};
}
