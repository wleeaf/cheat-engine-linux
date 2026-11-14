#pragma once
/// Code Filter (Cheat Engine's frmCodeFilter): plant a one-shot software
/// breakpoint on many code addresses (usually every CALL in a module), let the
/// program run, and see which of them executed. Filtering on "has been
/// executed" or "has not been executed" between game actions narrows the list
/// to the code behind one action.

#include "platform/process_api.hpp"

#include <expected>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace ce {

class DebugSession;

class CodeFilter {
public:
    CodeFilter();
    ~CodeFilter();
    CodeFilter(const CodeFilter&) = delete;
    CodeFilter& operator=(const CodeFilter&) = delete;

    void setAddresses(std::vector<uintptr_t> addresses);
    std::vector<uintptr_t> addresses() const;

    /// Attach and plant a breakpoint on every address. A hit records the
    /// address and removes its breakpoint, so each costs one stop. Returns how
    /// many were planted.
    std::expected<size_t, std::string> start(ProcessHandle& process);
    /// Remove the remaining breakpoints and detach (also done on destruction).
    void stop();
    bool running() const;

    /// Addresses that executed since start.
    std::vector<uintptr_t> executed() const;
    size_t executedCount() const;
    /// Keep the addresses that executed (true) or did not (false); clears the
    /// executed set for the next round. Only while stopped.
    void filter(bool keepExecuted);

    /// The CALL instructions (or, with callsOnly false, every instruction) in
    /// the executable regions of [base, base + size), at most `limit`.
    static std::vector<uintptr_t> codeAddresses(ProcessHandle& process, uintptr_t base, size_t size,
                                                bool callsOnly, size_t limit = 500000);

private:
    mutable std::mutex mutex_;
    std::vector<uintptr_t> addresses_;
    std::set<uintptr_t> executed_;
    std::unique_ptr<DebugSession> session_;
};

} // namespace ce
