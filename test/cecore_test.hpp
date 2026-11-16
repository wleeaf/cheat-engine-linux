#pragma once

// An ASan or TSan build: such a process reserves terabytes of shadow address
// space, so tests that scan a whole process or fork and trace a target skip.
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define CE_TEST_SANITIZED 1
#else
#define CE_TEST_SANITIZED 0
#endif
/// Shared by the cecore_test sources (main.cpp and cecore_test_*.cpp): the
/// failure-counting printf, the FakeProcessHandle model, the in-process ceserver
/// stub and the declarations of the tests main() runs.

#include "test_target.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/linux/ceserver_client.hpp"
#include "platform/linux/ceserver_server.hpp"
#include "platform/linux/mono_debugger_client.hpp"
#include "platform/linux/process_watcher.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/linux/ceserver_debugger.hpp"
#include "platform/linux/kernel_driver.hpp"
#include "platform/network_compression.hpp"
#include "platform/vulkan_overlay_injector.hpp"
#include "platform/linux/injector.hpp"
#include "platform/linux/wine_memory.hpp"
#include "platform/linux/memory_image.hpp"
#ifdef CE_HAVE_VULKAN
#include <vulkan/vulkan.h>
#include <vulkan/vk_layer.h>
#include <dlfcn.h>
#endif
#include "scanner/pointer_scanner.hpp"
#include "scanner/snapshot.hpp"
#include "core/target_capabilities.hpp"
#include "core/value_io.hpp"
#include "core/autoasm.hpp"
#include "core/aa_templates.hpp"
#include "core/injection_gen.hpp"
#include "core/ct_file.hpp"
#include "analysis/mono_dissector.hpp"
#include "core/simple_hook.hpp"
#include "core/log.hpp"
#include "core/target_profile.hpp"
#include "core/guest_view.hpp"
#include "core/ns_attach.hpp"
#include "core/value_codec.hpp"
#include "core/value_transform.hpp"
#include "arch/disassembler.hpp"
#include "arch/cpu_flags.hpp"
#include "core/expression.hpp"
#include "core/memview_nav.hpp"
#include "core/trainer.hpp"
#include "analysis/code_analysis.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/il2cpp_metadata.hpp"
#include "analysis/il2cpp_binary.hpp"
#include "analysis/signature.hpp"
#include "analysis/pe_exports.hpp"
#include "analysis/structure_tools.hpp"
#include "debug/breakpoint_manager.hpp"
#include "debug/stack_trace.hpp"
#include "debug/tracer.hpp"
#include "debug/debug_session.hpp"
#include "debug/gdb_remote.hpp"
#include "debug/managed_breakpoint.hpp"
#include "debug/code_finder.hpp"
#include "debug/instruction_access.hpp"
#include "debug/patch.hpp"
#include "symbols/kernel_symbols.hpp"
#include "symbols/dwarf_symbols.hpp"
#include "scripting/lua_engine.hpp"
#include "core/address_list.hpp"
#include "core/simple_address_list.hpp"
#include "plugins/plugin_loader.hpp"
#include <cstdio>
#include <cstdlib>
#include "symbols/elf_symbols.hpp"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <csignal>
#include <thread>
#include <chrono>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <future>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <cstdarg>
#include <stdexcept>
#include "core/mcp_server.hpp"
#include "core/agent_chat.hpp"
#include "arch/target_arch.hpp"
#include "core/json.hpp"
#include <unistd.h>
#include <sys/wait.h>
#include <csignal>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <poll.h>

using namespace ce;
using namespace ce::os;

// ── Test failure gate ──
// The suite prints "... FAILED" on a failed check but historically returned 0
// unconditionally, so CI only caught crashes. Wrap printf to count every line
// containing "FAILED" (the token appears ONLY in real failure results — there
// are no "N FAILED" summary lines and no stderr failures) and make main() exit
// non-zero if any fired. vasprintf avoids truncating long test output.
extern int g_test_failures;
int ce_test_printf(const char* fmt, ...);
#define printf ce_test_printf

extern "C" void cecore_trace_target_tick();

class FakeProcessHandle : public ProcessHandle {
public:
    struct Segment {
        MemoryRegion region;
        std::vector<uint8_t> data;
    };

    explicit FakeProcessHandle(std::vector<Segment> segments, std::vector<ModuleInfo> modules,
                               bool is64bit = true)
        : segments_(std::move(segments)), modules_(std::move(modules)), is64bit_(is64bit) {}

    pid_t pid() const override { return getpid(); }
    bool is64bit() const override { return is64bit_; }
    TargetDescription targetDescription() override { return ce::test::x86Target(is64bit(), runs32BitCode()); }

    Result<size_t> read(uintptr_t address, void* buffer, size_t size) override {
        for (const auto& segment : segments_) {
            auto start = segment.region.base;
            auto end = start + segment.data.size();
            if (address < start || address >= end) continue;
            auto offset = address - start;
            auto count = std::min<size_t>(size, segment.data.size() - offset);
            std::memcpy(buffer, segment.data.data() + offset, count);
            return count;
        }
        return std::unexpected(std::make_error_code(std::errc::bad_address));
    }

    Result<size_t> write(uintptr_t, const void*, size_t) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }

    std::vector<MemoryRegion> queryRegions() override {
        std::vector<MemoryRegion> regions;
        for (const auto& segment : segments_) regions.push_back(segment.region);
        return regions;
    }

    std::optional<MemoryRegion> queryRegion(uintptr_t address) override {
        for (const auto& segment : segments_) {
            auto start = segment.region.base;
            auto end = start + segment.region.size;
            if (address >= start && address < end) return segment.region;
        }
        return std::nullopt;
    }

    Result<uintptr_t> allocate(size_t, MemProt, uintptr_t = 0) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }
    Result<void> free(uintptr_t, size_t) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }
    Result<void> protect(uintptr_t, size_t, MemProt) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }
    std::vector<ModuleInfo> modules() override { return modules_; }
    std::vector<ThreadInfo> threads() override { return {}; }

private:
    std::vector<Segment> segments_;
    std::vector<ModuleInfo> modules_;
    bool is64bit_;
};

// The in-process ceserver stub (cecore_test_stub.cpp).
struct StubFixture {
    int server = -1;
    uint16_t port = 0;
    std::thread thread;
    std::atomic<bool> stop{false};
    bool ok() const { return server >= 0 && port != 0; }
};

constexpr int32_t kStubHandle = 0xCAFE;
constexpr int32_t kStubPid = 99999;
constexpr uint64_t kStubAlloc = 0x77777000ull;
extern std::vector<uint8_t> g_lastSetContextBlob;
void runStubServer(StubFixture* fx);
bool startStub(StubFixture& fx);
void stopStub(StubFixture& fx);

#ifdef __x86_64__
extern "C" void cecore_fs_load();
#endif

// Function execution needs an ordinary native user-mode thread. The general
// memory tests keep their syscall-parked sleep fixture; call rejection and
// unchanged parked-wait timing are covered by native_call_integration.
class NativeCallRegressionFixture {
public:
    pid_t pid=-1;
    int input=-1,output=-1;
    NativeCallRegressionFixture() {
#ifdef CE_NATIVE_CALL_FIXTURE
        int in[2],out[2];
        if (pipe(in)) return;
        if (pipe(out)) { close(in[0]); close(in[1]); return; }
        pid=fork();
        if (!pid) {
            dup2(in[0],0); dup2(out[1],1);
            close(in[0]); close(in[1]); close(out[0]); close(out[1]);
            execl(CE_NATIVE_CALL_FIXTURE,CE_NATIVE_CALL_FIXTURE,nullptr); _exit(127);
        }
        close(in[0]); close(out[1]); input=in[1]; output=out[0];
        std::string ready;
        for (unsigned i=0;i<4096;++i) {
            fd_set descriptors; FD_ZERO(&descriptors); FD_SET(output,&descriptors);
            timeval timeout{2,0};
            if (select(output+1,&descriptors,nullptr,nullptr,&timeout)<=0) break;
            char c;
            if (read(output,&c,1)!=1) break;
            if (c=='\n') break;
            ready+=c;
        }
        if (!ready.starts_with("CE_NATIVE_CALL ")) {
            if (pid>0) { kill(pid,SIGKILL); while (waitpid(pid,nullptr,0)<0 && errno==EINTR) {} }
            pid=-1;
        }
#endif
    }
    ~NativeCallRegressionFixture() {
        if (pid>0) { kill(pid,SIGKILL); while (waitpid(pid,nullptr,0)<0 && errno==EINTR) {} }
        if (input>=0) close(input);
        if (output>=0) close(output);
    }
};

// The tests, by file.
void test_memory_access_problem();
void test_agent_chat();
void test_scan_directory_cleanup();
void test_scan_review_fixes();
void test_agent_mcp();
void test_recover_store();
void test_value_codec();
void test_value_transform();
void test_ns_attach();
void test_dolphin_guest_ram();
void test_yuzu_guest_ram();
void test_rpcs3_mirror_dedup();
void test_parser_fuzz();
void test_target_profile();
void test_eflags_decode();
void test_guest_view();
void test_cheat_table_json();
void test_wx_double_mapped_code();
void test_free_without_size();
void test_wine_memory_helper();
void test_perf_map_symbols();
void test_device_mapping_not_module();
void test_pointer_path_expression();
void test_ce_table_import();
void test_ct_review_fixes();
void test_ct_load_from_string();
void test_mono_dissector_parse();
void test_breakpoint_condition();
void test_simple_hook();
void test_lua_stringlist();
void test_lua_timers();
void test_logging();
void test_ct_format_detection();
void test_ct_forms_roundtrip();
void test_trainer_generation();
void test_code_analysis_references();
void test_find_references_static();
void test_disassembler_multiarch();
void test_effective_address();
void test_managed_runtime_detection();
void test_managed_object_enumeration();
void test_managed_type_extraction();
void test_gdb_remote_client();
void test_process_owner_check();
void test_ceserver_client();
void test_mono_debugger_client();
void test_process_watcher();
void test_mono_debugger_real_agent();
void test_ceserver_memory_ops();
void test_ceserver_extended_ops();
void test_ceserver_debug_ops();
void test_remote_process_adapter();
void test_remote_debugger();
void test_network_compression();
void test_distributed_pointer_scan();
void test_pointer_scan_shard_through_static();
void test_pointer_scan_persistence();
void test_ct_table_luascript_after_entries();
void test_ct_json_pointer_roundtrip();
void test_il2cpp_pe_header_bounds();
void test_dwarf_symbols();
void test_elf32_symbols();
void test_inject_library_32bit();
void test_autoasm_lua_blocks();
void test_autoasm_conditional_blocks();
void test_autoasm_anonymous_labels();
void test_autoasm_globalalloc_break();
void test_code_injection_builder();
void test_lua_streams();
void test_snapshot_engine();
void test_plugin_abi();
void test_stack_trace_frame_walk();
void test_break_and_trace();
void test_break_and_trace_multithread();
void test_break_and_trace_step_over_recursion();
void test_break_and_trace_busy_threads();
void test_codefinder_software_stack_refused();
void test_instruction_access_segment();
void test_exception_breakpoint();
void bp_marker();   // the instruction test_software_breakpoint traps by default
void test_software_breakpoint(uintptr_t marker = reinterpret_cast<uintptr_t>(&bp_marker));
void test_software_breakpoint_page_end();
void test_multithread_watchpoint();
void test_multithread_software_breakpoint();
void test_nop_instruction();
void test_lua_nop_instruction();
void test_lua_region_file();
void test_lua_more_bindings();
void test_lua_string_extensions();
void test_lua_getUniqueAOB();
void test_lua_aobScanUnique();
void test_lua_disassembleBytes();
void test_lua_fileUtils();
void test_lua_encoding();
void test_lua_enumModules();
void test_lua_memory_region_info();
void test_lua_md5memory();
void test_instruction_access();
void test_debug_register_edit();
void test_debug_thread_switch();
void test_debug_xmm();
void test_lua_real_breakpoint();
void test_lua_breakpoint_regwrite();
void test_lua_hw_breakpoint();
void test_ceserver_roundtrip();
void test_ceserver_debug();
void test_ceserver_alloc();
void test_speedhack_got_injection();
void test_speedhack_speed_changes();
void test_speedhack_sleeps();
void test_parser_fuzz_negatives();
void test_lua_shellexecute_gate();
void test_lua_localwrite_gate();
void test_lua_exception_firewall();
void test_symbol_build_id_debuglink();
void test_pointer_rescan_by_value();
void test_pe_exports();
void test_signature_generation();
void test_pointer_map_reuse();
void test_pointer_scan_search_limits();
void test_codefinder_watch_size();
void test_lua_symbol_info();
void test_lua_region_info();
void test_il2cpp_metadata();
void test_il2cpp_metadata_tables();
void test_il2cpp_locate();
void test_il2cpp_real_file();
void test_il2cpp_binary_offsets();
void test_il2cpp_structure_typing();
void test_injection_script_generation();
void test_structure_tools();
void test_lua_memrec();
void test_lua_memrec_groups();
void test_lua_headless_bindings();
void test_lua_ceserver_connect();
void test_autoassembler_unregister_symbol(pid_t pid);
void test_autoassembler_dealloc(pid_t pid);
void test_autoassembler_far_forward_jump(pid_t pid);
void test_autoassembler_dealloc_no_cross_evict(pid_t pid);
void test_autoassembler_data_directive_widths(pid_t pid);
void test_autoassembler_comment_in_string(pid_t pid);
void test_autoassembler_globalalloc_shared(pid_t pid);
void test_autoassembler_review_fixes();
void test_autoassembler_disable_section(pid_t pid);
void test_autoassembler_windows_runtime_labels();
void test_autoassembler_nop_fillmem(pid_t pid);
void test_autoassembler_try_except(pid_t pid);
void test_autoassembler_forward_labels(pid_t pid);
void test_autoassembler_module_offset();
void test_autoassembler_code_injection_template(pid_t pid);
void test_autoassembler_assert(pid_t pid);
void test_autoassembler_create_thread();
void test_autoassembler_ds(pid_t pid);
void test_autoassembler_custom_commands(pid_t pid);
void test_autoassembler_processing_hooks(pid_t pid);
void test_autoassembler_loadbinary(pid_t pid);
void test_autoassembler_loadlibrary();
void test_autoassembler_struct_definitions(pid_t pid);
void test_autoassembler_aobscanmodule(pid_t pid);
void test_autoassembler_aobscanregion(pid_t pid);
void test_autoassembler_aobscanall(pid_t pid);
void test_autoassembler_aobscan_inject_label(pid_t pid);
void test_autoassembler_requires_target(pid_t pid);
void test_breakpoint_conditions();
void test_one_shot_breakpoints();
void test_thread_filtered_breakpoints();
void test_managed_method_breakpoints();
void test_kernel_symbol_resolver();
void test_kernel_driver_client();
void test_vulkan_overlay_injector();
void test_vulkan_overlay_layer_interface();
void test_lua_file_aliases();
void test_lua_local_memory();
void test_lua_autoassemble_check();
void test_lua_utility_bindings();
void test_lua_hotkey_bindings();
void test_lua_thread_bindings();
void test_lua_custom_type_bindings();
void test_lua_address_list_bindings();
void test_lua_debug_bindings();
void test_lua_process_bindings(pid_t pid);
void test_lua_code_analysis(pid_t pid);
void test_example_scripts();
void test_lua_executecode();
void test_lua_memscan();
void test_binary_scan_bitmask();
void test_aob_nibble_wildcard();
void test_all_types_no_duplicate_addresses();
void test_protection_filter_scan();
void test_memtype_filter_scan();
void test_module_offset_string();
void test_between_numeric_scan();
void test_nextscan_size_guard();
void test_prune_scan_result();
void test_decode_string_bytes();
void test_unicode_string_scan();
void test_codepage_string_scan();
void test_all_types_scan();
void test_grouped_scan();
void test_custom_formula_scan();
void test_lua_memscan_grouped_custom();
void test_percentage_scan();
void test_same_as_first_scan();
void test_pointer_type_scan();
void test_float_rounding_scan();
void test_process_enumeration();
void test_process_memory(pid_t pid);
void test_write_memory(pid_t pid);
void test_string_case_insensitive_scan();
void test_between_reversed_bounds();
void test_unknown_scan_chain();
void test_scan_alignment();
void test_nextscan_comparators();
void test_cpp_symbol_demangling();
void test_symbol_size0_extent_cap();
void test_plt_import_resolution();
void test_freeze_should_write();
void test_memview_pane_choice();
void test_aob_signature();
void test_conditional_jump();
void test_group_collapse();
void test_expression_parser();
void test_review_regressions();
void test_lua_default_deny();
void test_lua_review_fixes();
void test_scanner_differential();
