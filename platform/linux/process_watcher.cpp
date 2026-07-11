#include "platform/linux/process_watcher.hpp"
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <algorithm>

namespace ce::os {

void ProcessWatcher::start(const std::string& processName, Callback callback, int pollIntervalMs) {
    // Claim ownership atomically: only the caller that flips running_ false->true
    // proceeds, so two concurrent start() calls can't both spawn a watchLoop
    // (which would leak/overwrite a joinable thread_ -> std::terminate).
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) return;

    // A previous run may have requested stop without join (e.g. via the
    // destructor path); make sure any old thread is joined before we
    // reassign thread_ below.
    if (thread_.joinable()) thread_.join();

    target_ = processName;
    callback_ = std::move(callback);
    pollMs_ = pollIntervalMs;
    stopRequested_ = false;

    // Snapshot current PIDs
    knownPids_.clear();
    for (auto& entry : std::filesystem::directory_iterator("/proc")) {
        auto name = entry.path().filename().string();
        try { knownPids_.insert(std::stoi(name)); } catch (...) {}
    }

    thread_ = std::thread(&ProcessWatcher::watchLoop, this);
}

void ProcessWatcher::stop() {
    stopRequested_ = true;
    if (thread_.joinable()) thread_.join();
    running_ = false;
}

void ProcessWatcher::watchLoop() {
    // Convert target to lowercase for case-insensitive match
    std::string targetLower = target_;
    std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::tolower);

    while (!stopRequested_) {
        usleep(pollMs_ * 1000);

        for (auto& entry : std::filesystem::directory_iterator("/proc")) {
            auto pidStr = entry.path().filename().string();
            pid_t pid;
            try { pid = std::stoi(pidStr); } catch (...) { continue; }

            if (knownPids_.count(pid)) continue; // Already known
            knownPids_.insert(pid);

            // Read process name
            std::string comm;
            std::ifstream f("/proc/" + pidStr + "/comm");
            if (f) std::getline(f, comm);

            std::string commLower = comm;
            std::transform(commLower.begin(), commLower.end(), commLower.begin(), ::tolower);

            if (commLower.find(targetLower) != std::string::npos) {
                callback_(pid, comm);
            }
        }
    }
}

} // namespace ce::os
