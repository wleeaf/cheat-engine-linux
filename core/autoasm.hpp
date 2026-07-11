#pragma once
/// Auto-assembler engine — parses CE-style scripts and injects code into processes.

#include "platform/process_api.hpp"
#include "arch/assembler.hpp"
#include "arch/disassembler.hpp"
#include "scanner/memory_scanner.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <expected>

namespace ce {

/// Tracks state needed to disable (undo) an auto-assembler script.
struct DisableInfo {
    struct AllocEntry { std::string name; uintptr_t address; size_t size; };
    struct OriginalBytes { uintptr_t address; std::vector<uint8_t> bytes; };

    std::vector<AllocEntry> allocs;
    std::vector<OriginalBytes> originals;
    std::unordered_map<std::string, uintptr_t> symbols;
};

/// Result of auto-assembler execution.
struct AutoAsmResult {
    bool success = false;
    std::string error;
    DisableInfo disableInfo;
    std::vector<std::string> log; // Execution log messages
};

/// The auto-assembler engine.
class AutoAssembler {
public:
    using CustomCommandHandler = std::function<bool(const std::string& args,
        std::vector<std::string>& outputLines, std::vector<std::string>& log,
        std::string& error)>;
    using ScriptHook = std::function<bool(std::string& code,
        std::vector<std::string>& log, std::string& error)>;

    AutoAssembler() = default;

    /// Execute an auto-assembler script (enable section).
    AutoAsmResult execute(ProcessHandle& proc, const std::string& script);

    /// Execute the disable section of a script, using saved DisableInfo.
    AutoAsmResult disable(ProcessHandle& proc, const std::string& script, const DisableInfo& info);

    /// Syntax check only (no memory modifications).
    AutoAsmResult check(const std::string& script);

    /// Register a global symbol (accessible to scripts).
    void registerSymbol(const std::string& name, uintptr_t address);
    void unregisterSymbol(const std::string& name);
    uintptr_t resolveSymbol(const std::string& name) const;

    /// Register a parser extension command. Command names are case-insensitive.
    void registerCommand(const std::string& name, CustomCommandHandler handler);
    void unregisterCommand(const std::string& name);

    /// Register script transformation hooks for plugin-style preprocessing.
    void addPreprocessorHook(ScriptHook hook);
    void addPostprocessorHook(ScriptHook hook);
    void clearPreprocessorHooks();
    void clearPostprocessorHooks();

    /// Set the Lua evaluator used to expand `{$lua} ... {$asm}` (or `{$endlua}`)
    /// blocks at preprocess time. The evaluator runs the embedded Lua chunk
    /// and returns its return value as a string, which replaces the block in
    /// the AA stream. Without an evaluator set, encountering a `{$lua}` block
    /// is an explicit syntax error.
    using LuaEvaluator = std::function<std::expected<std::string, std::string>(const std::string& code)>;
    void setLuaEvaluator(LuaEvaluator eval) { luaEvaluator_ = std::move(eval); }

private:
    // ── Internal types ──
    struct Alloc { std::string name; size_t size = 0; uintptr_t preferred = 0; uintptr_t address = 0;
                   std::string preferredExpr; }; // 3rd alloc arg, resolved at alloc time (may be a symbol)
    struct Label { std::string name; uintptr_t address; };
    struct Define { std::string name; std::string value; };
    struct AsmLine { std::string label; std::string code; uintptr_t targetAddr; };
    struct WriteBlock { uintptr_t address; std::vector<uint8_t> bytes; };

    // ── Parsing ──
    std::string extractSection(const std::string& script, const std::string& section);
    bool parseLine(const std::string& line,
        std::vector<Alloc>& allocs, std::vector<Label>& labels,
        std::vector<Define>& defines, std::vector<std::string>& registeredSymbols,
        std::vector<std::string>& asmLines, std::vector<std::string>& log,
        ProcessHandle* proc, std::string& error, int includeDepth = 0);

    // ── Resolution ──
    uintptr_t resolveAddress(const std::string& expr,
        const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
        const std::vector<Define>& defines) const;
    std::string substituteSymbols(const std::string& line,
        const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
        const std::vector<Define>& defines) const;
    bool resolveForwardLabels(const std::vector<std::string>& asmLines,
        const std::vector<Alloc>& allocs, std::vector<Label>& labels,
        const std::vector<Define>& defines, ProcessHandle& proc,
        std::string& error);
    bool selectTryExceptBranches(const std::vector<std::string>& asmLines,
        std::vector<std::string>& selectedLines,
        const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
        const std::vector<Define>& defines, ProcessHandle* proc,
        std::vector<std::string>& log, std::string& error) const;
    bool tryBranchCanExecute(const std::vector<std::string>& branchLines,
        const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
        const std::vector<Define>& defines, ProcessHandle* proc,
        std::string& reason) const;

    // ── Global symbol table ──
    // Thread-safety contract: a single AutoAssembler instance is NOT
    // thread-safe. execute()/disable() and the register*/unregister* methods
    // mutate the maps below without locking, so all calls on one instance must
    // be serialized on a single thread (current callers do this: the GUI owns
    // one instance driven from the UI thread, and Lua bindings construct fresh
    // per-call instances). Guard these maps with a mutex before sharing an
    // instance across threads.
    std::unordered_map<std::string, uintptr_t> globalSymbols_;
    std::unordered_map<std::string, DisableInfo::AllocEntry> knownAllocations_;
    std::unordered_map<std::string, CustomCommandHandler> customCommands_;
    std::vector<ScriptHook> preprocessorHooks_;
    std::vector<ScriptHook> postprocessorHooks_;
    LuaEvaluator luaEvaluator_;
    Assembler asm64_{AsmArch::X86_64};
    Assembler asm32_{AsmArch::X86_32};
    // Set from the target's bitness at the start of execute(); selects which
    // assembler/disassembler the cave code is built with so a 32-bit target gets
    // 32-bit machine code (and vice versa).
    bool targetIs32_ = false;
    Assembler& targetAsm() { return targetIs32_ ? asm32_ : asm64_; }
    Arch targetDisArch() const { return targetIs32_ ? Arch::X86_32 : Arch::X86_64; }

    /// Run the full preprocessing chain (lua blocks → conditional blocks →
    /// anonymous labels → preprocessor hooks → struct definitions →
    /// postprocessor hooks) over `code`, replacing it in place. Both
    /// execute() and check() call this so the two front-ends stay identical:
    /// a script that passes check() preprocesses byte-for-byte the same at
    /// execute() time.
    bool preprocessScript(std::string& code, std::vector<std::string>& log,
                          std::string& error);

    bool expandLuaBlocks(std::string& code, std::vector<std::string>& log,
                         std::string& error);
    /// Expand `{$if}` / `{$else}` / `{$endif}` preprocessor regions. The
    /// condition expression is evaluated through luaEvaluator_ as a Lua chunk
    /// that returns a truthy value; without an evaluator, encountering
    /// `{$if}` is a syntax error. Nested ifs are not currently supported.
    bool expandConditionalBlocks(std::string& code, std::vector<std::string>& log,
                                 std::string& error);
    /// Resolve `@@:` anonymous labels and `@F`/`@B` forward/backward
    /// references. `@@:` defines an anonymous label; `@F` refers to the next
    /// `@@:` after the current line, `@B` to the previous one.
    bool resolveAnonymousLabels(std::string& code, std::vector<std::string>& log,
                                std::string& error);

    /// Compile the body of a `{$ccode}` block via libtcc, scan for the
    /// `_ce_inject` function's bytes, return an AA `db` line containing the
    /// machine code. Only defined when CECORE_HAVE_TINYCC is enabled; the
    /// out-of-line definition is gated by that macro.
    static bool compileCCodeBlock(const std::string& source,
                                  std::string& emittedAa,
                                  std::string& error);
};

} // namespace ce
