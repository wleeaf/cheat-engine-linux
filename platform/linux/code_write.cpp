#include "platform/linux/code_write.hpp"
#include "platform/linux/memory_image.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <stdexcept>
#include <unistd.h>

namespace ce::os {
namespace {
std::error_code error() {return {errno,std::system_category()};}
constexpr size_t chunkSize=65536;
}
CodeWriteRecovery::~CodeWriteRecovery() {if (fd_>=0) close(fd_);}
std::expected<std::shared_ptr<CodeWriteRecovery>,std::error_code> CodeWriteRecovery::prepare(
    const TargetProcessIdentity& identity,uintptr_t address,size_t size,const NativeMemoryImage* image) {
    if (!size || size-1>UINTPTR_MAX-address)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    try {
        auto state=std::make_shared<CodeWriteRecovery>();
        state->address_=address;
        state->original_.resize(size); // Allocate all recovery storage before mutation.
        if(image) {
            if(image->identity()!=identity) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            auto fd=image->duplicateFd();if(!fd) return std::unexpected(fd.error());
            state->fd_=*fd;
        } else {
            auto actual=processMemoryIdentity(identity.pid);
            if (!actual) return std::unexpected(actual.error());
            if (*actual!=identity) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
            auto task=processMemoryTask(identity.pid);
            if (!task) return std::unexpected(task.error());
            auto member=targetProcessIdentity(*task);
            if (!member) return std::unexpected(member.error());
            const auto path="/proc/"+std::to_string(*task)+"/mem";
            state->fd_=open(path.c_str(),O_RDWR|O_CLOEXEC);
            if (state->fd_<0) return std::unexpected(error());
            actual=processMemoryIdentity(identity.pid);
            auto now=targetProcessIdentity(*task);
            if (!actual || !now || *actual!=identity || *now!=*member)
                return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        }
        for (size_t offset=0;offset<size;) {
            const size_t count=std::min(chunkSize,size-offset);
            ssize_t read;
            do {read=pread(state->fd_,state->original_.data()+offset,count,static_cast<off_t>(address+offset));} while (read<0 && errno==EINTR);
            if (read<0) return std::unexpected(error());
            if (!read) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
            if (static_cast<size_t>(read)!=count) return std::unexpected(std::make_error_code(std::errc::io_error));
            offset+=count;
        }
        return state;
    } catch (const std::bad_alloc&) {return std::unexpected(std::make_error_code(std::errc::not_enough_memory));}
      catch (const std::length_error&) {return std::unexpected(std::make_error_code(std::errc::value_too_large));}
}
std::expected<void,std::error_code> CodeWriteRecovery::verify(std::span<const uint8_t> bytes) {
    std::array<uint8_t,chunkSize> actual;
    for (size_t offset=0;offset<bytes.size();) {
        const size_t count=std::min(actual.size(),bytes.size()-offset);
        ssize_t read;
        do {read=pread(fd_,actual.data(),count,static_cast<off_t>(address_+offset));} while (read<0 && errno==EINTR);
        if (read<0) return std::unexpected(error());
        if (!read) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (static_cast<size_t>(read)!=count || std::memcmp(actual.data(),bytes.data()+offset,count))
            return std::unexpected(std::make_error_code(std::errc::io_error));
        offset+=count;
    }
    return {};
}
std::expected<void,std::error_code> CodeWriteRecovery::write(std::span<const uint8_t> bytes) {
    if (bytes.size()!=original_.size() || changed())
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    for (size_t offset=0;offset<bytes.size();) {
        const size_t count=std::min(chunkSize,bytes.size()-offset);
        // An error may be reported after mutation. Own the entire attempted
        // chunk before issuing the write, including the ambiguous error case.
        attempted_=offset+count;
        ssize_t written;
        do {written=pwrite(fd_,bytes.data()+offset,count,static_cast<off_t>(address_+offset));} while (written<0 && errno==EINTR);
        if (written<0) return std::unexpected(error());
        if (!written) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (static_cast<size_t>(written)<=count) attempted_=offset+static_cast<size_t>(written);
        if (static_cast<size_t>(written)!=count) return std::unexpected(std::make_error_code(std::errc::io_error));
        offset+=count;
    }
    // /proc/pid/mem uses access_remote_vm/copy_to_user_page. On ARM64 an
    // executable VMA receives the kernel's instruction-cache maintenance.
    return verify(bytes);
}
std::expected<void,std::error_code> CodeWriteRecovery::restore() {
    if (!changed()) return {};
    const auto original=std::span(original_).first(attempted_);
    auto matches=verify(original);
    if (matches) {attempted_=0;return {};}
    if (matches.error()==std::errc::operation_canceled) return matches;
    for (size_t offset=0;offset<original.size();) {
        const size_t count=std::min(chunkSize,original.size()-offset);
        ssize_t written;
        do {written=pwrite(fd_,original.data()+offset,count,static_cast<off_t>(address_+offset));} while (written<0 && errno==EINTR);
        if (written<0) return std::unexpected(error());
        if (!written) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (static_cast<size_t>(written)!=count) return std::unexpected(std::make_error_code(std::errc::io_error));
        offset+=count;
    }
    matches=verify(original);
    if (matches) attempted_=0;
    return matches;
}
bool CodeWriteRecovery::overlaps(uintptr_t address,size_t size) const {
    if (!size || !attempted_) return false;
    return address>=address_ ? address-address_<attempted_ : address_-address<size;
}
}
