#pragma once
#include <algorithm>
#include <cstdint>
#include <vector>

namespace ce {
class AutoAssembler;
namespace gui {
// GUI operations use a shared, stateful assembler on the UI thread. Lua and
// event callbacks can reenter another editor/model on that same thread.
class AutoAsmUiOperation {
public:
    enum class Purpose { Execute, Cleanup, Retire };
    explicit AutoAsmUiOperation(const AutoAssembler* assembler, Purpose purpose = Purpose::Execute) {
        const bool allowed = assembler && std::none_of(current_.begin(), current_.end(), [&](const Active& active) {
            return active.assembler == assembler && !(purpose == Purpose::Cleanup && active.purpose == Purpose::Retire);
        });
        if (allowed) {
            assembler_ = assembler;
            current_.push_back({assembler, purpose});
        }
    }
    ~AutoAsmUiOperation() { if (assembler_) current_.pop_back(); }
    AutoAsmUiOperation(const AutoAsmUiOperation&) = delete;
    AutoAsmUiOperation& operator=(const AutoAsmUiOperation&) = delete;
    explicit operator bool() const { return assembler_ != nullptr; }
    static bool busy(const AutoAssembler* assembler) {
        return std::any_of(current_.begin(), current_.end(), [&](const Active& active) { return active.assembler == assembler; });
    }
    static bool retiring(const AutoAssembler* assembler) {
        return std::any_of(current_.begin(), current_.end(), [&](const Active& active) { return active.assembler == assembler && active.purpose == Purpose::Retire; });
    }
    static uint64_t nextOrder() { return ++order_; }
private:
    struct Active { const AutoAssembler* assembler; Purpose purpose; };
    const AutoAssembler* assembler_ = nullptr;
    inline static thread_local std::vector<Active> current_;
    inline static thread_local uint64_t order_ = 0;
};
} // namespace gui
} // namespace ce
