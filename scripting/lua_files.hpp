#pragma once
/// Opening the files Lua scripts write.
///
/// cecore often runs as root, so a symbolic link planted where a script saves
/// ("save.dat" pointing at /etc/shadow) must not redirect the write. Checking
/// for a link and then opening the path leaves a window in which the link can
/// appear; O_NOFOLLOW refuses a link in the same call that opens the file.
/// The stream is then opened on that pinned file through /proc/self/fd.

#include <fcntl.h>
#include <unistd.h>

#include <ios>
#include <string>

namespace ce {

/// Opens `stream` (an std::fstream or std::ofstream) on `path` with `mode`,
/// creating and truncating as that mode does. False when the last component
/// of `path` is a symbolic link or the file cannot be opened.
template <typename Stream>
bool openNoFollow(Stream& stream, const std::string& path, std::ios::openmode mode) {
    const bool in = (mode & std::ios::in) != 0;
    const bool append = (mode & std::ios::app) != 0;
    const bool truncate = (mode & std::ios::trunc) != 0;
    const bool out = (mode & std::ios::out) != 0 || append;
    int flags = in && out ? O_RDWR : out ? O_WRONLY : O_RDONLY;
    // As the stream would: "r+" opens an existing file only; "w" and "a" create.
    if (out && (!in || truncate || append)) flags |= O_CREAT;
    if (truncate) flags |= O_TRUNC;
    const int fd = ::open(path.c_str(), flags | O_NOFOLLOW | O_CLOEXEC, 0666);
    if (fd < 0) return false;
    stream.open("/proc/self/fd/" + std::to_string(fd), mode);
    ::close(fd);
    return stream.is_open();
}

} // namespace ce
