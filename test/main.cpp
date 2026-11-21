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

#include "test/cecore_test.hpp"

int g_test_failures = 0;
#undef printf
int ce_test_printf(const char* fmt, ...) {
    char* buf = nullptr;
    va_list ap;
    va_start(ap, fmt);
    int n = vasprintf(&buf, fmt, ap);
    va_end(ap);
    if (n >= 0 && buf) {
        if (std::strstr(buf, "FAILED")) g_test_failures++;
        std::fputs(buf, stdout);
        std::free(buf);
    }
    return n;
}
#define printf ce_test_printf

static uint64_t g_traceTargetCounter = 0;

extern "C" __attribute__((noinline)) void cecore_trace_target_tick() {
    ++g_traceTargetCounter;
    asm volatile("nop\nnop\nnop\n" ::: "memory");
}


int main(int argc, char* argv[]) {
    // The suite exercises every Lua binding, file writes included; the
    // default-deny test switches this off for itself.
    setenv("CECORE_LUA_ALLOW_UNSAFE", "1", 1);
    test_lua_default_deny();
    test_lua_review_fixes();
    if (getuid() != 0) {
        fprintf(stderr, "WARNING: Not running as root. Some operations may fail.\n");
    }

    pid_t targetPid = 0;

    if (argc > 1) {
        targetPid = atoi(argv[1]);
        printf("Using target PID: %d\n", targetPid);
    } else {
        // Spawn a test process
        targetPid = fork();
        if (targetPid == 0) {
            // Child — just sleep
            execl("/usr/bin/sleep", "sleep", "9999", nullptr);
            _exit(1);
        }
        printf("Spawned test process: sleep 9999 (PID %d)\n", targetPid);
        usleep(200000); // Wait for it to start
    }

    test_target_profile();
    test_dolphin_guest_ram();
    test_yuzu_guest_ram();
    test_rpcs3_mirror_dedup();
    test_parser_fuzz();
    test_eflags_decode();
    test_guest_view();
    test_ns_attach();
    test_review_regressions();
    test_value_codec();
    test_value_transform();
    test_recover_store();
    test_memory_access_problem();
    test_agent_mcp();
    test_agent_chat();
    test_process_owner_check();
    test_device_mapping_not_module();
    test_scan_directory_cleanup();
    test_scan_review_fixes();
    test_cheat_table_json();
    test_mono_dissector_parse();
    test_breakpoint_condition();
    test_simple_hook();
    test_lua_stringlist();
    test_lua_timers();
    test_logging();
    test_ce_table_import();
    test_pointer_path_expression();
    test_perf_map_symbols();
    test_wx_double_mapped_code();
    test_free_without_size();
    test_wine_memory_helper();
    test_ct_load_from_string();
    test_ct_review_fixes();
    test_ct_format_detection();
    test_ct_forms_roundtrip();
    test_trainer_generation();
    test_code_analysis_references();
    test_find_references_static();
    test_disassembler_multiarch();
    test_effective_address();
    test_cpp_symbol_demangling();
    test_symbol_size0_extent_cap();
    test_plt_import_resolution();
    test_freeze_should_write();
    test_expression_parser();
    test_memview_pane_choice();
    test_conditional_jump();
    test_group_collapse();
    test_aob_signature();
    test_string_case_insensitive_scan();
    test_between_reversed_bounds();
    test_unknown_scan_chain();
    test_scan_alignment();
    test_nextscan_comparators();
    test_managed_runtime_detection();
    test_managed_object_enumeration();
    test_managed_type_extraction();
    test_gdb_remote_client();
    test_ceserver_client();
    test_mono_debugger_client();
    test_mono_debugger_real_agent();
    test_process_watcher();
    test_ceserver_memory_ops();
    test_ceserver_extended_ops();
    test_ceserver_debug_ops();
    test_remote_process_adapter();
    test_remote_debugger();
    test_network_compression();
    test_distributed_pointer_scan();
    test_pointer_scan_shard_through_static();
    test_pointer_scan_persistence();
    test_ct_table_luascript_after_entries();
    test_ct_entry_tag_attributes();
    test_ct_json_pointer_roundtrip();
    test_il2cpp_pe_header_bounds();
    test_dwarf_symbols();
    test_plugin_abi();
    test_autoasm_lua_blocks();
    test_autoasm_conditional_blocks();
    test_autoasm_anonymous_labels();
    test_autoasm_globalalloc_break();
    test_code_injection_builder();
    test_lua_streams();
    test_snapshot_engine();
    test_stack_trace_frame_walk();
    test_break_and_trace();
    test_break_and_trace_multithread();
    test_break_and_trace_step_over_recursion();
    test_break_and_trace_busy_threads();
    test_codefinder_software_stack_refused();
#ifdef __x86_64__
    test_instruction_access_segment();
#endif
#ifndef __SANITIZE_ADDRESS__
    test_exception_breakpoint();   // deliberate bad-pointer fault trips UBSan (skip under ASan)
#endif
    test_software_breakpoint();
    test_software_breakpoint_page_end();
    test_multithread_watchpoint();
    test_multithread_software_breakpoint();
    test_debug_register_edit();
    test_debug_thread_switch();
    test_debug_xmm();
    test_lua_real_breakpoint();
    test_lua_breakpoint_regwrite();
    test_lua_hw_breakpoint();
    test_ceserver_roundtrip();
    test_ceserver_debug();
    test_ceserver_alloc();
    test_instruction_access();
    test_nop_instruction();
    test_lua_nop_instruction();
    test_lua_region_file();
    test_lua_more_bindings();
    test_lua_string_extensions();
    test_lua_getUniqueAOB();
    test_lua_aobScanUnique();
    test_lua_disassembleBytes();
    test_lua_fileUtils();
    test_lua_encoding();
    test_lua_enumModules();
    test_lua_memory_region_info();
    test_lua_md5memory();
    test_speedhack_got_injection();
    test_speedhack_speed_changes();
    test_speedhack_sleeps();
    test_parser_fuzz_negatives();
    test_lua_shellexecute_gate();
    test_lua_localwrite_gate();
    test_lua_exception_firewall();
    test_symbol_build_id_debuglink();
    test_elf32_symbols();
#ifndef __SANITIZE_ADDRESS__
    test_inject_library_32bit();   // ptrace + poison-ret inject: skip under ASan
#endif
    test_pointer_rescan_by_value();
    test_pointer_map_reuse();
    test_pointer_scan_search_limits();
    test_signature_generation();
    test_pe_exports();
    test_lua_symbol_info();
    test_lua_region_info();
    test_codefinder_watch_size();
    test_il2cpp_metadata();
    test_il2cpp_metadata_tables();
    test_il2cpp_locate();
    test_il2cpp_real_file();
    test_il2cpp_binary_offsets();
    test_il2cpp_structure_typing();
    test_injection_script_generation();
    test_structure_tools();
    test_lua_memrec();
    test_lua_memrec_groups();
    test_lua_headless_bindings();
    test_lua_ceserver_connect();
    test_autoassembler_unregister_symbol(targetPid);
    test_autoassembler_dealloc(targetPid);
    test_autoassembler_dealloc_no_cross_evict(targetPid);
    test_autoassembler_far_forward_jump(targetPid);
    test_autoassembler_data_directive_widths(targetPid);
    test_autoassembler_comment_in_string(targetPid);
    test_autoassembler_nop_fillmem(targetPid);
    test_autoassembler_globalalloc_shared(targetPid);
    test_autoassembler_review_fixes();
    test_autoassembler_disable_section(targetPid);
    test_autoassembler_windows_runtime_labels();
    test_autoassembler_try_except(targetPid);
    test_autoassembler_forward_labels(targetPid);
    test_autoassembler_module_offset();
    test_autoassembler_code_injection_template(targetPid);
    test_autoassembler_assert(targetPid);
    test_autoassembler_create_thread();
    test_autoassembler_ds(targetPid);
    test_autoassembler_custom_commands(targetPid);
    test_autoassembler_processing_hooks(targetPid);
    test_autoassembler_loadbinary(targetPid);
#ifndef __SANITIZE_ADDRESS__
    test_autoassembler_loadlibrary();  // dlopen-injects a lib; conflicts with ASan
#endif
    test_autoassembler_struct_definitions(targetPid);
    test_autoassembler_aobscanmodule(targetPid);
    test_autoassembler_aobscanregion(targetPid);
    test_autoassembler_aobscanall(targetPid);
    test_autoassembler_aobscan_inject_label(targetPid);
    test_autoassembler_requires_target(targetPid);
    test_breakpoint_conditions();
    test_one_shot_breakpoints();
    test_thread_filtered_breakpoints();
    test_managed_method_breakpoints();
    test_kernel_symbol_resolver();
    test_kernel_driver_client();
    test_vulkan_overlay_injector();
#ifdef CE_HAVE_VULKAN
    test_vulkan_overlay_layer_interface();
#endif
    test_lua_file_aliases();
    test_lua_local_memory();
    test_lua_autoassemble_check();
    test_lua_utility_bindings();
    test_lua_hotkey_bindings();
    test_lua_thread_bindings();
    test_lua_custom_type_bindings();
    test_lua_address_list_bindings();
    test_lua_debug_bindings();
    test_lua_process_bindings(targetPid);
    test_lua_executecode();
    test_lua_code_analysis(targetPid);
    test_example_scripts();
    test_lua_memscan();
    test_binary_scan_bitmask();
    test_aob_nibble_wildcard();
    test_all_types_no_duplicate_addresses();
    test_protection_filter_scan();
    test_memtype_filter_scan();
    test_module_offset_string();
    test_between_numeric_scan();
    test_nextscan_size_guard();
    test_prune_scan_result();
    test_decode_string_bytes();
    test_unicode_string_scan();
    test_codepage_string_scan();
    test_all_types_scan();
    test_grouped_scan();
    test_custom_formula_scan();
    test_percentage_scan();
    test_same_as_first_scan();
    test_pointer_type_scan();
    test_float_rounding_scan();
    test_scanner_differential();
    test_lua_memscan_grouped_custom();
    test_process_enumeration();
    test_process_memory(targetPid);
    test_write_memory(targetPid);

    // Cleanup spawned process
    if (argc <= 1) {
        kill(targetPid, SIGTERM);
        waitpid(targetPid, nullptr, 0);
        printf("\nKilled test process %d\n", targetPid);
    }

    // Gate self-check: with this env set, force one failure to prove the exit
    // code actually flips (CECORE_TEST_FORCE_FAIL=1 ./cecore_test => exit 1).
    if (std::getenv("CECORE_TEST_FORCE_FAIL")) printf("  gate selfcheck: FAILED\n");

    std::fflush(stdout);
    if (g_test_failures) {
        std::fprintf(stderr, "\n%d check(s) reported failure (see FAILED lines above).\n",
                     g_test_failures);
        return 1;
    }
    printf("\nAll tests complete.\n");
    return 0;
}
