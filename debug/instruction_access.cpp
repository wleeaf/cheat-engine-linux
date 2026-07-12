#include "debug/instruction_access.hpp"
#include "debug/debug_session.hpp"
#include "arch/disassembler.hpp"

#include <atomic>
#include <map>
#include <mutex>
#include <algorithm>
#include <unistd.h>

namespace ce {

std::vector<InstructionAccess> findInstructionAccesses(
    ProcessHandle& proc, uintptr_t instructionAddress, int maxHits, int timeoutMs) {

    DebugSession session;
    Disassembler dis(Arch::X86_64);

    if (!session.attach(proc.pid(), &proc)) return {};

    // Decode the instruction ONCE from its original bytes, before the software
    // breakpoint overwrites byte 0 with int3 (0xCC) — reading it back afterwards
    // would disassemble the trap, not the real instruction. The decoded operand
    // is fixed; only the effective address (register-dependent) varies per hit.
    Instruction insn;
    bool haveInsn = false;
    {
        uint8_t code[16];
        auto rr = proc.read(instructionAddress, code, sizeof(code));
        if (rr && *rr) {
            auto insns = dis.disassemble(instructionAddress, {code, *rr}, 1);
            if (!insns.empty() && insns[0].memory.present) { insn = insns[0]; haveInsn = true; }
        }
    }
    if (!haveInsn) { session.detach(); return {}; }

    std::mutex m;
    std::map<uintptr_t, InstructionAccess> recs;
    std::atomic<int> hits{0};

    session.setEventCallback([&](const DebugEvent& e) {
        if (e.type == DebugEventType::BreakpointHit && e.address == instructionAddress) {
            // e.context is captured after the rip rewind, i.e. the register state
            // right before the instruction runs — exactly what its address needs.
            uintptr_t ea = computeEffectiveAddress(insn, e.context);
            {
                std::lock_guard lk(m);
                auto& rec = recs[ea];
                if (rec.hitCount == 0) { rec.address = ea; rec.firstContext = e.context; }
                rec.hitCount++;
            }
            hits.fetch_add(1);
            session.continueExecution();   // runs inline on the tracer thread
        }
    });

    session.setSoftwareBreakpoint(instructionAddress);
    session.continueExecution();

    for (int i = 0; i < timeoutMs / 10 && hits.load() < maxHits; ++i)
        usleep(10000);

    session.detach();

    std::vector<InstructionAccess> out;
    {
        std::lock_guard lk(m);
        out.reserve(recs.size());
        for (auto& [_, v] : recs) out.push_back(v);
    }
    std::sort(out.begin(), out.end(),
        [](const InstructionAccess& a, const InstructionAccess& b) {
            return a.hitCount > b.hitCount;
        });
    return out;
}

} // namespace ce
