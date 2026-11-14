#pragma once
/// Declarations shared by the Lua binding sources (lua_bindings.cpp and
/// lua_bindings_*.cpp): the binding functions registerExtendedBindings
/// registers and the helpers several of those files use. Not for other files.

#include "platform/process_api.hpp"
#include "symbols/elf_symbols.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <sys/types.h>

extern "C" {
#include <lua.h>
}

namespace ce::lua_detail {

// Helpers defined in lua_bindings.cpp.
ProcessHandle* getProc(lua_State* L);
SymbolResolver* getResolver(lua_State* L);

// lua_bindings_memory.cpp
bool readExact(ProcessHandle* proc, uintptr_t address, void* data, size_t size);
bool writeExact(ProcessHandle* proc, uintptr_t address, const void* data, size_t size);
bool checkAddress(lua_State* L, int index, ProcessHandle* process, uintptr_t& address);
int l_getTargetInfo(lua_State* L);
int l_getTargetCapabilities(lua_State* L);
int l_retryPendingOperations(lua_State* L);
int l_resumePendingCallSignal(lua_State* L);
int l_readByte(lua_State* L);
int l_readSmallInteger(lua_State* L);
int l_readQword(lua_State* L);
int l_readPointer(lua_State* L);
int l_readDouble(lua_State* L);
int l_readString(lua_State* L);
int l_writeByte(lua_State* L);
int l_writeSmallInteger(lua_State* L);
int l_writeQword(lua_State* L);
int l_writeDouble(lua_State* L);
int l_writeString(lua_State* L);
void checkByteTable(lua_State* L, int idx, lua_Integer first, lua_Integer last, bool strict);
int l_writeBytes(lua_State* L);
int l_readInteger(lua_State* L);
int l_writeInteger(lua_State* L);
int l_readFloat(lua_State* L);
int l_writeFloat(lua_State* L);
int l_byteTableToString(lua_State* L);
int l_stringToByteTable(lua_State* L);
int l_wideStringToByteTable(lua_State* L);
int l_byteTableToWideString(lua_State* L);
int l_signExtend(lua_State* L);
int l_getCPUCount(lua_State* L);
int l_wordToByteTable(lua_State* L);
int l_dwordToByteTable(lua_State* L);
int l_qwordToByteTable(lua_State* L);
int l_byteTableToDwordTable(lua_State* L);
int l_convertToUTF8(lua_State* L);
int l_convertFromUTF8(lua_State* L);
int l_ansiToUTF8(lua_State* L);
int l_extractFileName(lua_State* L);
int l_extractFilePath(lua_State* L);
int l_extractFileExt(lua_State* L);
int l_extractFileNameWithoutExt(lua_State* L);
int l_getFileList(lua_State* L);
int l_getCEVersion(lua_State* L);
int l_readBytes(lua_State* L);
int l_readRegionToFile(lua_State* L);
int l_writeRegionFromFile(lua_State* L);
int l_getModuleAddress(lua_State* L);
int l_compareMemory(lua_State* L);
int l_floatToByteTable(lua_State* L);
int l_doubleToByteTable(lua_State* L);
int l_byteTableToFloat(lua_State* L);
int l_byteTableToDouble(lua_State* L);
int l_byteTableToWord(lua_State* L);
int l_byteTableToDword(lua_State* L);
int l_byteTableToQword(lua_State* L);
int l_readByteLocal(lua_State* L);
int l_readSmallIntegerLocal(lua_State* L);
int l_readIntegerLocal(lua_State* L);
int l_readQwordLocal(lua_State* L);
int l_readPointerLocal(lua_State* L);
int l_readFloatLocal(lua_State* L);
int l_readDoubleLocal(lua_State* L);
int l_readBytesLocal(lua_State* L);
int l_readStringLocal(lua_State* L);
int l_writeByteLocal(lua_State* L);
int l_writeSmallIntegerLocal(lua_State* L);
int l_writeIntegerLocal(lua_State* L);
int l_writeQwordLocal(lua_State* L);
int l_writePointerLocal(lua_State* L);
int l_writeFloatLocal(lua_State* L);
int l_writeDoubleLocal(lua_State* L);
int l_writeBytesLocal(lua_State* L);
int l_writeStringLocal(lua_State* L);

// lua_bindings_process.cpp
pid_t parseProcessId(std::string_view text);
pid_t findProcessIdByName(std::string_view target);
int l_getProcessList(lua_State* L);
int l_getProcessIDFromProcessName(lua_State* L);
const ce::ModuleInfo* findModuleByName(ProcessHandle* p, const std::string& want);
int l_getModuleBase(lua_State* L);
int l_pauseSignal(lua_State* L, int sig);
int l_pause(lua_State* L);
int l_unpause(lua_State* L);
int l_inModule(lua_State* L);
int l_isAddress(lua_State* L);
int l_copyMemory(lua_State* L);
int l_enumMemoryRegions(lua_State* L);
int l_allocateMemory(lua_State* L);
int l_deAlloc(lua_State* L);
int l_getModuleSize(lua_State* L);
int l_getModuleList(lua_State* L);
int l_enumModules(lua_State* L);
int l_getPointerSize(lua_State* L);
int l_getMemoryRegionInfo(lua_State* L);
int l_getNameFromAddress(lua_State* L);
int l_getAddressFromName(lua_State* L);

// lua_bindings_assembler.cpp
int l_speedhack_setSpeed(lua_State* L);
int l_injectLibrary(lua_State* L);
int l_disassemble(lua_State* L);
int l_disassembleRange(lua_State* L);
int l_disassembleBytes(lua_State* L);
int l_getInstructionSize(lua_State* L);
int l_nopInstruction(lua_State* L);
int l_getPreviousOpcode(lua_State* L);
int l_assemble(lua_State* L);
int l_aaDisableInfoGc(lua_State* L);
int l_autoAssemble(lua_State* L);
int l_generateCodeInjectionScript(lua_State* L);
int l_generateAOBInjectionScript(lua_State* L);
int l_generateFullInjectionScript(lua_State* L);
int l_autoAssembleCheck(lua_State* L);

// lua_bindings_utility.cpp
int l_stringToMD5String(lua_State* L);
int l_md5memory(lua_State* L);
int l_bAnd(lua_State* L);
int l_bOr(lua_State* L);
int l_bXor(lua_State* L);
int l_bNot(lua_State* L);
int l_bShl(lua_State* L);
int l_bShr(lua_State* L);
int l_showMessage(lua_State* L);
int l_messageDialog(lua_State* L);
int l_canvas_noop(lua_State* L);
int l_canvas_getTextWidth(lua_State* L);
int l_canvas_getTextHeight(lua_State* L);
int l_canvas_getPixel(lua_State* L);
int l_getScreenCanvas(lua_State* L);
int l_sleep(lua_State* L);
int l_getTickCount(lua_State* L);
int l_outputDebugString(lua_State* L);
int l_getCheatEngineDir(lua_State* L);
int l_getApplicationDir(lua_State* L);
int l_getTempPath(lua_State* L);
int l_getOperatingSystem(lua_State* L);
int l_cheatEngineIs64Bit(lua_State* L);
int l_targetIs64Bit(lua_State* L);
int l_inputQuery(lua_State* L);
int l_inputBox(lua_State* L);
int l_readFromFile(lua_State* L);
int l_writeToFile(lua_State* L);
int l_fileExists(lua_State* L);
int l_getTempDir(lua_State* L);
int l_getProcessDir(lua_State* L);
int l_isKeyPressed(lua_State* L);
int l_createTimer(lua_State* L);
int l_timer_setInterval(lua_State* L);
int l_timer_onTimer(lua_State* L);
int l_timer_setEnabled(lua_State* L);
int l_object_destroy(lua_State* L);
int l_createStringlist(lua_State* L);
int l_stringlist_add(lua_State* L);
int l_stringlist_getCount(lua_State* L);
int l_stringlist_getString(lua_State* L);
int l_stringlist_setString(lua_State* L);
int l_stringlist_remove(lua_State* L);
int l_stringlist_clear(lua_State* L);
int l_selectFilePath(lua_State* L);
int l_playSound(lua_State* L);
int l_registerCustomTypeLua(lua_State* L);
int l_unregisterCustomType(lua_State* L);
int l_getCustomType(lua_State* L);
int l_getCustomTypeSize(lua_State* L);
int l_customTypeToValue(lua_State* L);
int l_customTypeToBytes(lua_State* L);

// lua_bindings_scan.cpp
int l_createMemScan(lua_State* L);
int l_pointerScan(lua_State* L);
int l_dissectStructure(lua_State* L);

// lua_bindings_debug.cpp
int l_debug_getThreadList(lua_State* L);
int l_debug_setBreakpoint(lua_State* L);
int l_debug_pumpEvents(lua_State* L);
int l_debug_removeBreakpoint(lua_State* L);
int l_debug_continueFromBreakpoint(lua_State* L);
int l_debug_getBreakpointList(lua_State* L);
int l_debug_isDebugging(lua_State* L);
int l_debug_isBroken(lua_State* L);
int l_debug_getRegisters(lua_State* L);
int l_debug_setRegister(lua_State* L);
int l_debug_getStack(lua_State* L);
int l_findWhatWrites(lua_State* L);
int l_findWhatAccesses(lua_State* L);
int l_breakAndTrace(lua_State* L);
int l_branchMapAvailable(lua_State* L);
int l_branchMap(lua_State* L);

// lua_bindings_addresslist.cpp
int l_addressList_getCount(lua_State* L);
int l_getTableEntry(lua_State* L);
int l_setTableEntry(lua_State* L);
int l_addressList_addEntry(lua_State* L);
int l_addressList_removeEntry(lua_State* L);
int l_addressList_clear(lua_State* L);
int l_saveTable(lua_State* L);
int l_loadTable(lua_State* L);
int l_generateTrainerSource(lua_State* L);
int l_generateTrainer(lua_State* L);

// lua_bindings_runtimes.cpp
int l_getManagedRuntimes(lua_State* L);
int l_monoDissect(lua_State* L);
int l_createSimpleHook(lua_State* L);
int l_removeSimpleHook(lua_State* L);
int l_findMonoFunction(lua_State* L);
int l_findMonoInstances(lua_State* L);
int l_createSignature(lua_State* L);
int l_executeCode(lua_State* L);
int l_getIl2CppMetadataPath(lua_State* L);
int l_getIl2CppClasses(lua_State* L);
void checkOptionalStrings(lua_State* L, int first, int last);
int l_getIl2CppClassLayout(lua_State* L);
int l_getIl2CppObjectLayout(lua_State* L);
int l_getIl2CppStructure(lua_State* L);
int l_getDwarfStructure(lua_State* L);
int l_listDwarfStructs(lua_State* L);
int l_getIl2CppMethods(lua_State* L);
int l_findIl2CppMethod(lua_State* L);

// lua_bindings_analysis.cpp
int l_findStatics(lua_State* L);
int l_findReferences(lua_State* L);
int l_getModuleExports(lua_State* L);
int l_getModuleImports(lua_State* L);
int l_enumerateFunctions(lua_State* L);
int l_buildCallGraph(lua_State* L);
int l_findReferencedStrings(lua_State* L);
int l_findCodeCaves(lua_State* L);
int l_findAssemblyPattern(lua_State* L);

// lua_bindings_compat.cpp
int l_openProcess(lua_State* L);
int l_connectToCeserver(lua_State* L);
std::expected<void,std::string> gdbOptionField(lua_State* L,int index,const char* name);
int l_connectToGdb(lua_State* L);
int l_disconnectProcess(lua_State* L);
int l_getGdbRegisterInfo(lua_State* L);
int l_gdbRegister(lua_State* L,bool write);
int l_readGdbRegister(lua_State* L);
int l_writeGdbRegister(lua_State* L);
int l_getOpenedProcessID(lua_State* L);
int l_writePointer(lua_State* L);
int l_getOpenedProcesses(lua_State* L);
int l_getUserDefinedSymbolByName(lua_State* L);
int l_getUserDefinedSymbolByAddress(lua_State* L);
int l_registerSymbol(lua_State* L);
int l_unregisterSymbol(lua_State* L);
int l_inputQuery(lua_State* L);
int l_shellExecute(lua_State* L);
int l_getScreenWidth(lua_State* L);
int l_getScreenHeight(lua_State* L);
int l_inMainThread(lua_State* L);
int l_getProcessName(lua_State* L);
int l_getThreadList(lua_State* L);
int l_readRegionFromFile(lua_State* L);
int l_writeRegionToFile(lua_State* L);
int l_AOBScan(lua_State* L);
int l_AOBScanEx(lua_State* L);
int l_getUniqueAOB(lua_State* L);
int l_AOBScanModule(lua_State* L);
int l_AOBScanUnique(lua_State* L);
int l_AOBScanModuleUnique(lua_State* L);
int l_fullAccess(lua_State* L);

// lua_bindings_threads.cpp
int l_hotkey_gc(lua_State* L);
int l_hotkey_trigger(lua_State* L);
int l_hotkey_destroy(lua_State* L);
int l_hotkey_getKeys(lua_State* L);
int l_hotkey_index(lua_State* L);
int l_hotkey_newindex(lua_State* L);
int l_createHotkey(lua_State* L);
int l_setHotkeyAction(lua_State* L);
int l_thread_gc(lua_State* L);
int l_thread_waitfor(lua_State* L);
int l_thread_terminate(lua_State* L);
int l_thread_suspend(lua_State* L);
int l_thread_resume(lua_State* L);
int l_thread_index(lua_State* L);
int l_thread_newindex(lua_State* L);
int l_createThread(lua_State* L);
int l_synchronize(lua_State* L);
int l_queue(lua_State* L);

} // namespace ce::lua_detail
