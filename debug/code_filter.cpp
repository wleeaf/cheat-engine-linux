#include "debug/code_filter.hpp"

#include "arch/disassembler.hpp"
#include "arch/target_arch.hpp"
#include "core/target_capabilities.hpp"
#include "debug/debug_session.hpp"

#include <algorithm>
#include <map>

namespace ce {

CodeFilter::CodeFilter() = default;

CodeFilter::~CodeFilter() { stop(); }

void CodeFilter::setAddresses(std::vector<uintptr_t> addresses) {
    std::sort(addresses.begin(), addresses.end());
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
    std::lock_guard lock(mutex_);
    addresses_ = std::move(addresses);
    executed_.clear();
}

std::vector<uintptr_t> CodeFilter::addresses() const {
    std::lock_guard lock(mutex_);
    return addresses_;
}

std::expected<size_t, std::string> CodeFilter::start(ProcessHandle& process) {
    stop();
    if (auto reason = unsupportedTargetOperation(process, TargetFeature::Debugger)) return std::unexpected(*reason);
    auto session = std::make_unique<DebugSession>();
    if (!session->attach(process.pid(), &process))
        return std::unexpected(targetOperationError(process, TargetFeature::Debugger, session->lastError()));
    std::vector<uintptr_t> pending;
    {
        std::lock_guard lock(mutex_);
        for (uintptr_t address : addresses_)
            if (!executed_.contains(address)) pending.push_back(address);
    }
    // The ids, read by the hit callback on the tracer thread.
    auto ids = std::make_shared<std::map<uintptr_t, int>>();
    for (uintptr_t address : pending) {
        const int id = session->setSoftwareBreakpoint(address);
        if (id >= 0) (*ids)[address] = id;
    }
    DebugSession* raw = session.get();
    session->setEventCallback([this, raw, ids](const DebugEvent& event) {
        if (event.type == DebugEventType::BreakpointHit) {
            auto it = ids->find(event.address);
            if (it != ids->end()) {
                {
                    std::lock_guard lock(mutex_);
                    executed_.insert(event.address);
                }
                raw->removeSoftwareBreakpoint(it->second);   // one hit is enough
                ids->erase(it);
            }
        }
        raw->continueExecution();   // runs inline on the tracer thread
    });
    const size_t planted = ids->size();
    if (!session->continueExecution()) {
        session->detach();
        return std::unexpected(targetOperationError(process, TargetFeature::Debugger, session->lastError()));
    }
    std::lock_guard lock(mutex_);
    session_ = std::move(session);
    return planted;
}

void CodeFilter::stop() {
    std::unique_ptr<DebugSession> session;
    {
        std::lock_guard lock(mutex_);
        session = std::move(session_);
    }
    if (session) session->detach();   // removes the breakpoints that never hit
}

bool CodeFilter::running() const {
    std::lock_guard lock(mutex_);
    return session_ != nullptr;
}

std::vector<uintptr_t> CodeFilter::executed() const {
    std::lock_guard lock(mutex_);
    return {executed_.begin(), executed_.end()};
}

size_t CodeFilter::executedCount() const {
    std::lock_guard lock(mutex_);
    return executed_.size();
}

void CodeFilter::filter(bool keepExecuted) {
    std::lock_guard lock(mutex_);
    std::erase_if(addresses_, [&](uintptr_t address) { return executed_.contains(address) != keepExecuted; });
    executed_.clear();
}

std::vector<uintptr_t> CodeFilter::codeAddresses(ProcessHandle& process, uintptr_t base, size_t size,
                                                 bool callsOnly, size_t limit) {
    std::vector<uintptr_t> out;
    if (!size || base > UINTPTR_MAX - size) return out;
    const uintptr_t end = base + size;
    std::vector<uint8_t> chunk;
    for (const auto& region : process.queryRegions()) {
        if (!(region.protection & MemProt::Exec) || region.base + region.size <= base || region.base >= end) continue;
        uintptr_t at = std::max(region.base, base);
        const uintptr_t stop = std::min<uintptr_t>(region.base + region.size, end);
        auto architecture = disassemblerArchFor(process, at);
        if (!architecture) continue;
        Disassembler disassembler(*architecture);
        while (at < stop && out.size() < limit) {
            chunk.resize(std::min<size_t>(64 * 1024, stop - at));
            auto read = process.read(at, chunk.data(), chunk.size());
            if (!read || !*read) break;
            const auto instructions = disassembler.disassemble(at, {chunk.data(), *read}, 0);
            if (instructions.empty()) { at += 1; continue; }   // skip an undecodable byte
            uintptr_t consumed = at;
            for (const auto& instruction : instructions) {
                // One that runs past the chunk is decoded again next round.
                if (instruction.address + instruction.size > at + *read) break;
                if (!callsOnly || instruction.isCall) out.push_back(instruction.address);
                consumed = instruction.address + instruction.size;
                if (out.size() >= limit) break;
            }
            at = consumed > at ? consumed : at + 1;
        }
    }
    return out;
}

} // namespace ce
