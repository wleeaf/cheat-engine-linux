#pragma once
/// Process watcher — monitors /proc for new processes matching a name pattern.

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <set>
#include <mutex>
#include <condition_variable>

namespace ce::os {

class ProcessWatcher {
public:
    using Callback = std::function<void(pid_t pid, const std::string& name)>;

    ~ProcessWatcher();

    void start(const std::string& processName, Callback callback, int pollIntervalMs = 500);
    void stop();
    bool running() const { return running_.load(); }

private:
    void watchLoop(std::string target, Callback callback, int pollMs, std::set<pid_t> knownPids);
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::thread thread_;
    std::thread::id workerId_;
    std::mutex lifecycleMutex_;
    std::condition_variable wake_;
};

} // namespace ce::os
