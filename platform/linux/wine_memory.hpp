#pragma once
/// Memory that Wine itself commits in a Wine process.
///
/// Wine 11.20 reserves the address space around a program's code, and all of
/// the low 4 GiB of a WoW64 process, as PROT_NONE mappings of its own (issue
/// #9). No gap is left there for a mapping of ours, and mapping over the
/// reservation would let Wine hand the same range to the program later. Wine
/// can still commit memory there: a small Windows program, started with the
/// target's own Wine and prefix, calls OpenProcess and VirtualAllocEx on it,
/// as Cheat Engine for Windows does. The program is a PE32+ image generated
/// here with its parameters in its data section, so nothing has to be shipped
/// or compiled for Windows.

#include "core/types.hpp"
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>
#include <sys/types.h>

namespace ce::os {

/// The Windows process id of a Wine process. A 64-bit TEB is page aligned and
/// holds its own address at +0x30 (NtTib.Self) and ClientId.UniqueProcess at
/// +0x40, so the small private writable regions are searched for such a page;
/// every TEB found must name the same process.
std::expected<uint32_t, std::error_code> wineWindowsProcessId(pid_t pid);

/// Commits `size` bytes in the Wine process `pid` through Wine. The block
/// starts in [low, high], nearest to `preferred`, searched in 64 KiB steps
/// (Windows' allocation granularity). Fails with not_supported when the
/// helper cannot run for this target: another mount namespace (a Proton or
/// Flatpak container), another user, or no Wine loader beside its executable.
std::expected<uintptr_t, std::error_code> wineVirtualAlloc(pid_t pid, size_t size, MemProt protection,
                                                           uintptr_t preferred, uintptr_t low, uintptr_t high);

/// Releases a block wineVirtualAlloc returned (VirtualFreeEx, MEM_RELEASE).
std::expected<void, std::error_code> wineVirtualFree(pid_t pid, uintptr_t address);

/// The helper's machine code and the source it was assembled from, for the
/// test that reassembles the source and compares (this file must not depend
/// on the assembler: the VM test builds compile it without Keystone).
std::span<const uint8_t> wineHelperCode();
std::string_view wineHelperSource();

/// The helper image for one request (exposed for tests).
struct WineHelperRequest {
    uint64_t operation = 1;   // 1 allocate, 2 release
    uint32_t windowsPid = 0;
    uint64_t preferred = 0, low = 0, high = 0, size = 0, protection = 0, address = 0;
};
std::vector<uint8_t> wineHelperImage(const WineHelperRequest& request);

} // namespace ce::os
