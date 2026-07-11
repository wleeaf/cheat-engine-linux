#pragma once
/// Process watcher — monitors /proc for new processes matching a name pattern.

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <set>

namespace ce::os {

class ProcessWatcher {
public:
    using Callback = std::function<void(pid_t pid, const std::string& name)>;

    void start(const std::string& processName, Callback callback, int pollIntervalMs = 500);
    void stop();
    bool running() const { return running_.load(); }

private:
    void watchLoop();

    std::string target_;
    Callback callback_;
    int pollMs_ = 500;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::thread thread_;
    std::set<pid_t> knownPids_;
};

} // namespace ce::os
