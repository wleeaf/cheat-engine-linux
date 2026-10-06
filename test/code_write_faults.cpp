#include "test/code_write_faults.hpp"
#include <atomic>
#include <cerrno>
#include <sys/types.h>
#include <unistd.h>
namespace code_write_test {
static std::atomic<Fault> current{Fault::None};
static std::atomic<unsigned> writes{0},failures{0};
void arm(Fault fault) {writes=0;failures=0;current=fault;}
void clear() {current=Fault::None;}
unsigned triggered() {return failures;}
}
extern "C" ssize_t __real_pwrite(int,const void*,size_t,off_t);
extern "C" ssize_t __wrap_pwrite(int fd,const void* bytes,size_t size,off_t offset) {
    using namespace code_write_test;
    const auto fault=current.load();
    if (fault==Fault::None) return __real_pwrite(fd,bytes,size,offset);
    const unsigned index=writes++;
    if (fault==Fault::SecondShortWrite || fault==Fault::ThirdAfterMutation) {
        if (index!=(fault==Fault::SecondShortWrite ? 1u : 2u)) return __real_pwrite(fd,bytes,size,offset);
        ++failures;
        if (fault==Fault::SecondShortWrite) return __real_pwrite(fd,bytes,size/2,offset);
        auto changed=__real_pwrite(fd,bytes,size,offset);
        if (changed<0) return changed;
        errno=EIO;return -1;
    }
    if (index==0) {
        ++failures;
        if (fault==Fault::DropWrite) return static_cast<ssize_t>(size);
        if (fault==Fault::ShortWrite) return __real_pwrite(fd,bytes,size/2,offset);
        auto changed=__real_pwrite(fd,bytes,size,offset);
        if (changed<0) return changed;
        errno=EIO;return -1;
    }
    if (fault==Fault::RestoreBlocked) {++failures;errno=EIO;return -1;}
    return __real_pwrite(fd,bytes,size,offset);
}
