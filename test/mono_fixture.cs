using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Compatibility {
    [StructLayout(LayoutKind.Sequential)]
    public class Player {
        public int Score = 123;
        public long Marker = 0x123456789abcdef;
        public static int StaticScore = 456;
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int Compute(int value) { return value * 3 + 7; }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int Other(int value) { return value - 11; }
    }
    public class Program {
        [DllImport("mono_fixture_control", CallingConvention=CallingConvention.Cdecl)]
        static extern void mono_fixture_wait(IntPtr data, int collections, int value,
                                            IntPtr compute, IntPtr other, IntPtr longMethod);
        public static void Main(string[] args) {
            Player player = new Player();
            GCHandle pin = GCHandle.Alloc(player, GCHandleType.Pinned);
            try {
                for (;;) {
                    mono_fixture_wait(pin.AddrOfPinnedObject(), GC.CollectionCount(0) + GC.CollectionCount(1),
                                      Player.Compute(10), typeof(Player).GetMethod("Compute").MethodHandle.GetFunctionPointer(),
                                      typeof(Player).GetMethod("Other").MethodHandle.GetFunctionPointer(),
                                      typeof(LongManagedTypeXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX).GetMethod("ResolveMe").MethodHandle.GetFunctionPointer());
                    string command = Console.ReadLine();
                    if (command == "exit" || command == null) break;
                    if (command == "collect") {
                        for (int i=0; i<32; ++i) { byte[] garbage=new byte[65536]; garbage[0]=1; }
                        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
                    } else if (command == "load") Assembly.LoadFrom(args[0]);
                }
                Console.WriteLine("MONO_EXIT " + player.Score);
            } finally { pin.Free(); }
        }
    }
    public class LongManagedTypeXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int ResolveMe(int value) { return value + 42; }
    }
}
