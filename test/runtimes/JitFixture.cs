// Mono and CoreCLR frontend fixture: a JIT-compiled writer updates an
// off-heap value (Marshal.AllocHGlobal memory does not move with the GC).
// Mono writes its perf map with --jitmap, CoreCLR with DOTNET_PerfMapEnabled=1.
// stdin: 'b' runs the writer and prints the value, 'r' prints it, 's'/'x'
// start/stop a busy thread (executing user code, like a game loop).
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public static class JitFixture {
    static IntPtr view;
    static volatile bool spinning;
    static System.Threading.Thread spinner;

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
        // Reach the steady state a long-running game has: CoreCLR promotes hot
        // methods to optimized code in the background after a quiet period.
        for (int round = 0; round < 3; round++) {
            for (int i = 0; i < 200000; i++) ceJitWriter(view);
            System.Threading.Thread.Sleep(400);
        }
        Marshal.WriteInt32(view, 1515852340);                 // 0x5a5a1234 marker
        Console.WriteLine("CE_RUNTIME " + System.Diagnostics.Process.GetCurrentProcess().Id);
        Console.Out.Flush();
        var input = Console.OpenStandardInput();
        for (int command; (command = input.ReadByte()) != -1;) {
            if (command == 'b') Console.WriteLine(ceJitWriter(view));
            else if (command == 'r') Console.WriteLine(Marshal.ReadInt32(view));
            else if (command == 's') {
                if (spinner == null) {
                    spinning = true;
                    spinner = new System.Threading.Thread(() => { long n = 0; while (spinning) n++; });
                    spinner.Start();
                    System.Threading.Thread.Sleep(300);
                }
                Console.WriteLine(1);
            } else if (command == 'x') {
                spinning = false;
                if (spinner != null) spinner.Join();
                spinner = null;
                Console.WriteLine(0);
            }
            Console.Out.Flush();
        }
    }
}
