// HotSpot frontend fixture: a JIT-compiled writer updates an off-heap value
// (a direct ByteBuffer's storage does not move with the GC). The gate asks the
// live JVM for its perf map with `jcmd <pid> Compiler.perfmap`.
// stdin: 'b' runs the writer and prints the value, 'r' prints it, 's'/'x'
// start/stop a busy thread (executing user code, like a game loop).
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class JitFixture {
    static final ByteBuffer VIEW = ByteBuffer.allocateDirect(16).order(ByteOrder.nativeOrder());

    static int ceJitWriter(ByteBuffer target) {
        int next = target.getInt(0) + 1;
        target.putInt(0, next);
        return next;
    }

    static volatile boolean spinning;
    static Thread spinner;

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 200000; i++) ceJitWriter(VIEW);   // C2-compile the writer
        VIEW.putInt(0, 1515852340);                            // 0x5a5a1234 marker
        System.out.println("CE_RUNTIME " + ProcessHandle.current().pid());
        System.out.flush();
        for (int command; (command = System.in.read()) != -1;) {
            if (command == 'b') System.out.println(ceJitWriter(VIEW));
            else if (command == 'r') System.out.println(VIEW.getInt(0));
            else if (command == 's') {
                if (spinner == null) {
                    spinning = true;
                    spinner = new Thread(() -> { long n = 0; while (spinning) n++; });
                    spinner.start();
                    Thread.sleep(300);
                }
                System.out.println(1);
            } else if (command == 'x') {
                spinning = false;
                if (spinner != null) spinner.join();
                spinner = null;
                System.out.println(0);
            }
            System.out.flush();
        }
    }
}
