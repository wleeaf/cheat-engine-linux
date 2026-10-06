#pragma once
#include <array>
#include <fstream>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unistd.h>

namespace ce::os {
// A managed assembly or ordinary application argument can end in .exe without
// using Wine. Require its Unix loader or runtime rather than a filename suffix.
inline bool hasWineLoader(pid_t task) {
    const auto base=[](std::string_view path) {
        return path.substr(path.find_last_of('/')==std::string_view::npos ? 0 : path.find_last_of('/')+1);
    };
    std::string proc="/proc/"+std::to_string(task);
    std::array<char,4096> path{};
    ssize_t count=readlink((proc+"/exe").c_str(),path.data(),path.size());
    if (count>0 && static_cast<size_t>(count)<path.size()) {
        std::string_view name=base({path.data(),static_cast<size_t>(count)});
        if (name.ends_with(" (deleted)")) name.remove_suffix(10);
        if (name=="wine" || name=="wine64" || name=="wine-preloader" || name=="wine64-preloader") return true;
    }
    std::ifstream maps(proc+"/maps");std::string line;
    while (std::getline(maps,line)) {
        auto slash=line.find('/');if (slash==std::string::npos) continue;
        std::string_view name=base(std::string_view(line).substr(slash));
        if (name.ends_with(" (deleted)")) name.remove_suffix(10);
        if (name=="ntdll.so" || name=="libwine.so" || name.starts_with("libwine.so.")) return true;
    }
    return false;
}
} // namespace ce::os
