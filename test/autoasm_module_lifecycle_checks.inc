#include <filesystem>
#include <cstdlib>

namespace autoasm_module_test {
struct Checks {
    unsigned width, count = 0, failed = 0;
    void operator()(bool ok, const char* name) {
        ++count; failed += !ok;
        failures += !ok;
        std::printf("AA_MODULE %u %s: %s\n", width, ok ? "OK" : "FAILED", name);
    }
};
static std::string hex(uintptr_t value) {
    std::ostringstream stream; stream << std::hex << value; return stream.str();
}
static bool profile(const char* executable, unsigned width, const std::filesystem::path& directory) {
    Checks check{width};
    const std::string firstName = "original_module" + std::to_string(width);
    const std::string nextName = "replacement+module-" + std::to_string(width) + ".bin";
    const auto firstPath = directory / firstName, nextPath = directory / nextName;
    std::filesystem::copy_file(executable, firstPath);
    std::filesystem::copy_file(executable, nextPath);
    Fixture first(firstPath.c_str(), nextPath.c_str()), next(nextPath.c_str());
    auto initial = ready(first), other = ready(next);
    check(initial.width == width && other.width == width && initial.value == other.value,
          "two real target applications start with the required ABI and reused virtual addresses");
    if (initial.width != width || other.width != width) return false;
    os::LinuxProcessHandle process(first.pid), replacement(next.pid);
    const auto modules = process.modules(), replacementModules = replacement.modules();
    const auto find = [](const auto& list, const std::string& name) -> uintptr_t {
        for (const auto& module : list) if (module.name == name) return module.base;
        return 0;
    };
    const auto base = find(modules, firstName), newBase = find(replacementModules, nextName);
    check(base && newBase && base == newBase && initial.value > base && other.value > newBase,
          "real module identities differ while their actual mapped addresses overlap");
    if (!base || !newBase) return false;
    const auto oldExpression = "\"" + firstName + "\"+" + hex(initial.value - base);
    const auto newExpression = "\"" + nextName + "\"+" + hex(other.value - newBase);
    auto observes = [](Fixture& target, const char* value) {
        return target.command('r') && target.line() == value;
    };
    auto observeTransition = [&](Fixture& target, const char* stage) {
        const auto value = target.command('r') ? target.line() : std::string{};
        std::printf("AA_MODULE_OBSERVATION width=%u stage=%s value=%s\n", width, stage, value.c_str());
        return value;
    };
    auto writeScript = [](const std::string& expression, int value) {
        return "[ENABLE]\n" + expression + ":\ndd #" + std::to_string(value) + "\n[DISABLE]\n";
    };
    auto cleanup = [](AutoAssembler& assembler, ProcessHandle& proc, const std::string& script, const AutoAsmResult& result) {
        return assembler.disable(proc, script, result.disableInfo).success;
    };
    AutoAssembler assembler;
    const auto primeScript = "assert(" + oldExpression + ",15 CD 5B 07)\n";
    auto prime = assembler.execute(process, primeScript);
    check(prime.success && assembler.resolveSymbol(firstName) == base,
          "the first execution resolves the live original module");
    cleanup(assembler, process, primeScript, prime);

    const auto staleScript = writeScript(oldExpression, 111);
    auto stale = assembler.execute(replacement, staleScript);
    const auto replacedValue = observeTransition(next, "target-replacement");
    check(!stale.success && replacedValue == "123456789",
          "target replacement rejects a removed module without patching its reused address");
    cleanup(assembler, replacement, staleScript, stale);
    check(assembler.resolveSymbol(firstName) == 0 && assembler.resolveSymbol(nextName) == newBase,
          "automatic module lookup contains only the latest target snapshot");
    const auto currentScript = writeScript(newExpression, 222);
    auto current = assembler.execute(replacement, currentScript);
    check(current.success && observes(next, "222"),
          "quoted current module arithmetic accepts plus and minus characters in its filename");
    check(cleanup(assembler, replacement, currentScript, current) && observes(next, "123456789"),
          "current module writes restore exact application data");

    assembler.registerSymbol(nextName, other.value);
    const auto manualScript = writeScript("\"" + nextName + "\"", 333);
    auto manual = assembler.execute(replacement, manualScript);
    check(manual.success && assembler.resolveSymbol(nextName) == other.value && observes(next, "333"),
          "an explicit symbol with a module name retains its registered address");
    check(cleanup(assembler, replacement, manualScript, manual) && observes(next, "123456789") &&
          assembler.resolveSymbol(nextName) == other.value,
          "ordinary cleanup preserves an independently registered module-named symbol");
    assembler.unregisterSymbol(nextName);
    check(assembler.resolveSymbol(nextName) == newBase,
          "unregistering an explicit symbol exposes the current module again");

    const auto ownerScript = "define(" + nextName + "," + hex(other.value) + ")\nregistersymbol(" + nextName + ")\n";
    auto owner = assembler.execute(replacement, ownerScript);
    check(owner.success && owner.disableInfo.symbols.contains(nextName) && assembler.resolveSymbol(nextName) == other.value,
          "a script can own a registered symbol that shares a current module name");
    auto ownedWrite = assembler.execute(replacement, manualScript);
    check(ownedWrite.success && assembler.resolveSymbol(nextName) == other.value && observes(next, "333"),
          "another execution does not replace the registered owner during module discovery");
    cleanup(assembler, replacement, manualScript, ownedWrite);
    check(cleanup(assembler, replacement, ownerScript, owner) && assembler.resolveSymbol(nextName) == newBase && observes(next, "123456789"),
          "the original owner removes its symbol and reveals the module after cleanup");

    AutoAssembler transition;
    auto enabledScript = writeScript(oldExpression, 444);
    auto enabled = transition.execute(process, enabledScript);
    check(enabled.success && observes(first, "444"),
          "the original application owns a live patch before exec");
    check(first.command('x'), "the original process performs a real exec");
    auto changed = ready(first);
    check(changed.width == width && changed.value == initial.value && observes(first, "123456789"),
          "exec replaces the application while reusing the same data address");
    check(cleanup(transition, process, enabledScript, enabled) && observes(first, "123456789"),
          "old-image undo retires without modifying the replacement application");
    auto execStale = transition.execute(process, staleScript);
    const auto execValue = observeTransition(first, "exec");
    check(!execStale.success && execValue == "123456789",
          "the same handle rejects its pre-exec module name before writing");
    cleanup(transition, process, staleScript, execStale);
    check(transition.resolveSymbol(firstName) == 0 && transition.resolveSymbol(nextName) == newBase,
          "same-handle module resolution refreshes after exec");
    auto afterExec = transition.execute(process, currentScript);
    check(afterExec.success && observes(first, "222") && cleanup(transition, process, currentScript, afterExec) && observes(first, "123456789"),
          "the replacement module can be patched and restored through the original handle");

    transition.registerSymbol("manual_address", changed.value);
    auto syntax = transition.check("label(local_label)\nlocal_label:\nnop\n");
    check(syntax.success && transition.resolveSymbol(nextName) == 0 && transition.resolveSymbol("manual_address") == changed.value,
          "syntax-only checking discards target modules while retaining explicit symbols");
    const auto refreshScript = "assert(" + newExpression + ",15 CD 5B 07)\n";
    auto refreshed = transition.execute(process, refreshScript);
    check(refreshed.success && transition.resolveSymbol(nextName) == newBase && cleanup(transition, process, refreshScript, refreshed),
          "a later execution reacquires the live module snapshot after syntax checking");
    check(first.finish() && next.finish(), "both original applications finish normally after restoration");
    auto exited = transition.execute(process, currentScript);
    check(!exited.success && transition.resolveSymbol(nextName) == 0 && transition.resolveSymbol("manual_address") == changed.value,
          "failed capture of an exited target clears modules without erasing explicit symbols");
    std::printf("AA_MODULE_RESULT width=%u checks=%u failures=%u\n", width, check.count, check.failed);
    return check.failed == 0;
}
static void run(const char* native64, const char* native32) {
    char pattern[] = "/tmp/ce-aa-modules-XXXXXX";
    const char* path = mkdtemp(pattern);
    if (!path) { check(false, "owned module lifecycle directory created"); return; }
    const auto directory = std::filesystem::path(path);
    try { profile(native64, 8, directory); profile(native32, 4, directory); }
    catch (const std::exception& error) { std::fprintf(stderr, "module lifecycle error: %s\n", error.what()); ++failures; }
    std::error_code ignored; std::filesystem::remove_all(directory, ignored);
}
} // namespace autoasm_module_test
