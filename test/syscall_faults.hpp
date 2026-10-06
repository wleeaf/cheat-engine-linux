#pragma once
#include <cstdint>
#include <sys/types.h>

namespace syscall_test {
enum class Fault { None, RestoreRegisters, RestoreInstruction, RestoreExtended, FrameWriteFailure, FrameRestoreFailure, Detach, UserTrap,
                   HardwareWriteOnce, HardwareRestoreFailure, HardwareCleanupFailure, SoftwareVerifyAndRestore,
                   IgnoredStepSignal, ForbidTextWrite, PreflightDetach, PreflightRegistersAndDetach, InterruptFailure,
                   PreflightAllocationAndDetach, AllocationBeforeSeize, InitialInstructionWrite,
                   InitialRegistersWrite, InitialSyscallWrite, FunctionRestoreRegisters,
                   FunctionReturnRead, FunctionReturnOpcode, FunctionInterruptRace,
                   MetadataAfterSeize, MetadataAfterStep };
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
// Arrange a real INTERRUPT stop with an owned hardware trap still queued.
void queueHardwareRace(pid_t tid,uintptr_t address,int signal=0);
bool hardwareRaceObserved();
}
