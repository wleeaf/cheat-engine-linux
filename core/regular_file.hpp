#pragma once
// Opening files named by a target process (its mapped modules, paths under
// /proc/<pid>/root) for reading. A path checked with stat() and then opened
// by name can be swapped for a FIFO in between, and opening a FIFO blocks
// until a writer appears; a device such as a GPU node can block a read
// forever. These helpers open without blocking, check the opened file itself,
// and only then hand it out.

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <fstream>
#include <string>

namespace ce {

/// Open `path` into `f` (binary) only if it is a regular file. On success the
/// stream reads the very file that was checked: it is reopened through
/// /proc/self/fd, which names the open file, not the path. `size`, if given,
/// receives the file's size.
inline bool openRegularFile(std::ifstream& f, const std::string& path, uint64_t* size = nullptr) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat st{};
    const bool regular = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    if (regular) {
        f.open("/proc/self/fd/" + std::to_string(fd), std::ios::binary);
        if (size) *size = static_cast<uint64_t>(st.st_size);
    }
    ::close(fd);
    return regular && f.is_open();
}

/// A read-only mapping of a whole regular file. Game binaries can be
/// gigabytes (an executable with an embedded asset pack); mapping touches only
/// the pages a parser reads, where copying the file reads all of it.
class MappedFile {
public:
    MappedFile() = default;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    ~MappedFile() { if (data_) ::munmap(const_cast<uint8_t*>(data_), size_); }
    // Map path if it is a regular file (non-blocking open: never a FIFO).
    bool open(const std::string& path) {
        const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) return false;
        struct stat st{};
        if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) { ::close(fd); return false; }
        void* p = ::mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
        ::close(fd);
        if (p == MAP_FAILED) return false;
        data_ = static_cast<const uint8_t*>(p);
        size_ = static_cast<size_t>(st.st_size);
        return true;
    }
    const uint8_t* data() const { return data_; }
    size_t size() const { return size_; }
    uint8_t operator[](size_t i) const { return data_[i]; }
private:
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
};

} // namespace ce
