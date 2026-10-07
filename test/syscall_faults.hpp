#pragma once
#include <cstdint>
#include <cstddef>
#include <sys/types.h>

namespace syscall_test {
enum class Fault { None, RestoreRegisters, RestoreInstruction, RestoreExtended, FrameWriteFailure, FrameRestoreFailure, Detach, UserTrap,
                   HardwareWriteOnce, HardwareRestoreFailure, HardwareCleanupFailure, SoftwareVerifyAndRestore,
                   IgnoredStepSignal, ForbidTextWrite, PreflightDetach, PreflightRegistersAndDetach, InterruptFailure,
                   PreflightAllocationAndDetach, AllocationBeforeSeize, InitialInstructionWrite,
                   InitialRegistersWrite, InitialSyscallWrite, FunctionRestoreRegisters,
                   FunctionReturnRead, FunctionReturnOpcode, FunctionInterruptRace,
                   MetadataAfterSeize, MetadataAfterStep,
                   RestartInfoAfterStep, RestartEmulateBefore, RestartEmulateAfter,
                   RestartEntryRead, RestartInterruptBefore, RestartInterruptAfter,
                   RestartResumeAfter, RestartVerification,
                   RestartMaskRead, RestartMaskWriteBefore, RestartMaskWriteAfter,
                   RestartMaskVerify, RestartMaskRestoreAfter, RestartQueuedSignal,
                   RestartQueuedStop, RestartCanceledStop, RestartListenBefore, RestartListenAfter,
                   RestartResumeBefore, RestartProbeRestoreBefore, RestartProbeRestoreAfter };
void arm(Fault fault);
void clear();
uintptr_t originalPc();
unsigned triggered();
unsigned singleSteps();
uint64_t completedResult();
void watchAllocation(pid_t tid);
bool allocationObserved();
void holdAfterDetach(pid_t tid);
bool detachHeld();
void releaseDetach();
// Resume the restored application at a controlled failed DETACH so it exits
// its own selected thread. Leave the actual terminal event for production.
void exitBeforeDetach(pid_t selected,pid_t survivor,uintptr_t exitFlag);
bool detachExitObserved();
pid_t detachExitOwner();
bool detachExitContextReady();
uint64_t detachExitAllocation();
bool detachExitAllocationPresent();
bool survivorContextVerified();
void clearDetachExit();
// Arrange a real INTERRUPT stop with an owned hardware trap still queued.
void queueHardwareRace(pid_t tid,uintptr_t address,int signal=0);
bool hardwareRaceObserved();
bool restartGroupStopMatches(const void* registers,size_t size,uint64_t mask);
void queueRestartContinueRace(pid_t tid);
bool restartContinueRaceObserved();
}
