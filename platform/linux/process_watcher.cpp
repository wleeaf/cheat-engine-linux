#include "platform/linux/process_watcher.hpp"
#include "core/log.hpp"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>

namespace ce::os {

ProcessWatcher::~ProcessWatcher() { stop(); }

void ProcessWatcher::start(const std::string& processName, Callback callback, int pollIntervalMs) {
    std::lock_guard lock(lifecycleMutex_);
    if (running_) return;
    if (thread_.joinable()) thread_.join();

    std::set<pid_t> known;
    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator("/proc", ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        auto name = it->path().filename().string();
        pid_t pid = 0;
        auto parsed = std::from_chars(name.data(), name.data() + name.size(), pid);
        if (parsed.ec == std::errc{} && parsed.ptr == name.data() + name.size()) known.insert(pid);
    }
    stopRequested_ = false;
    running_ = true;
    try {
        thread_ = std::thread(&ProcessWatcher::watchLoop, this, processName,
                              std::move(callback), std::max(1, pollIntervalMs), std::move(known));
        workerId_ = thread_.get_id();
    } catch (...) {
        running_ = false;
        throw;
    }
}

void ProcessWatcher::stop() {
    std::thread toJoin;
    {
        std::lock_guard lock(lifecycleMutex_);
        stopRequested_ = true;
        wake_.notify_all();
        if (workerId_ == std::this_thread::get_id()) return;
        toJoin = std::move(thread_);
    }
    if (toJoin.joinable()) toJoin.join();
}

void ProcessWatcher::watchLoop(std::string target, Callback callback, int pollMs, std::set<pid_t> known) {
    auto lower = [](unsigned char c) { return static_cast<char>(std::tolower(c)); };
    std::transform(target.begin(), target.end(), target.begin(), lower);
    try {
        while (!stopRequested_) {
            {
                std::unique_lock lock(lifecycleMutex_);
                if (wake_.wait_for(lock, std::chrono::milliseconds(pollMs),
                                   [this] { return stopRequested_.load(); })) break;
            }
            std::set<pid_t> observed;
            std::error_code ec;
            for (auto it = std::filesystem::directory_iterator("/proc", ec);
                 !ec && it != std::filesystem::directory_iterator() && !stopRequested_; it.increment(ec)) {
                auto name = it->path().filename().string();
                pid_t pid = 0;
                auto parsed = std::from_chars(name.data(), name.data() + name.size(), pid);
                if (parsed.ec != std::errc{} || parsed.ptr != name.data() + name.size()) continue;
                observed.insert(pid);
                if (known.count(pid)) continue;
                std::string comm;
                std::ifstream in("/proc/" + name + "/comm");
                if (!std::getline(in, comm) || comm.empty()) continue;
                std::string commLower = comm;
                std::transform(commLower.begin(), commLower.end(), commLower.begin(), lower);
                if (commLower.find(target) != std::string::npos) {
                    known.insert(pid);
                    if (callback) callback(pid, comm);
                }
            }
            // Keep unmatched new PIDs eligible after exec or a name change, and
            // remove vanished PIDs so their future reuse is treated as new.
            if (!ec) std::erase_if(known, [&](pid_t pid) { return !observed.count(pid); });
        }
    } catch (const std::exception& error) {
        ce::log::warn(ce::log::Cat::General, "process watcher stopped: {}", error.what());
    } catch (...) {
        ce::log::warn(ce::log::Cat::General, "process watcher stopped after callback failure");
    }
    {
        std::lock_guard lock(lifecycleMutex_);
        running_ = false;
        workerId_ = {};
    }
    wake_.notify_all();
}

} // namespace ce::os
