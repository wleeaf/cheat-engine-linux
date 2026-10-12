// Mono and CoreCLR frontend fixture: a JIT-compiled writer updates an
// off-heap value (Marshal.AllocHGlobal memory does not move with the GC).
// Mono writes its perf map with --jitmap, CoreCLR with DOTNET_PerfMapEnabled=1.
// stdin: 'b' runs the writer and prints the value, 'r' prints it.
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public static class JitFixture {
    static IntPtr view;

    // A raw pointer store keeps the write in JIT code (Mono implements
    // Marshal.WriteInt32 as a native call). Build with unsafe code enabled.
    [MethodImpl(MethodImplOptions.NoInlining)]
    static unsafe int ceJitWriter(IntPtr target) {
        int* slot = (int*)target;
        *slot = *slot + 1;
        return *slot;
    }

    public static void Main() {
        view = Marshal.AllocHGlobal(16);
        Marshal.WriteInt32(view, 0);
        for (int i = 0; i < 200000; i++) ceJitWriter(view);   // tier up the writer
        Marshal.WriteInt32(view, 1515852340);                 // 0x5a5a1234 marker
        Console.WriteLine("CE_RUNTIME " + System.Diagnostics.Process.GetCurrentProcess().Id);
        Console.Out.Flush();
        var input = Console.OpenStandardInput();
        for (int command; (command = input.ReadByte()) != -1;) {
            if (command == 'b') Console.WriteLine(ceJitWriter(view));
            else if (command == 'r') Console.WriteLine(Marshal.ReadInt32(view));
            Console.Out.Flush();
        }
    }
}
