// Node/V8 frontend fixture: a JIT-compiled writer updates an off-heap value
// (a SharedArrayBuffer's backing store does not move with the GC). Run with
// --perf-basic-prof so V8 names its generated code in /tmp/perf-<pid>.map.
// stdin: 'b' runs the writer and prints the value, 'r' prints it, 's'/'x'
// start/stop a busy worker thread (executing user code, like a game loop).
'use strict';
const { Worker } = require('node:worker_threads');
let spinner = null;
const view = new Int32Array(new SharedArrayBuffer(16));
function ceJitWriter(target) { target[0] = target[0] + 1; return target[0]; }
for (let i = 0; i < 200000; i++) ceJitWriter(view);   // tier up to optimized code
view[0] = 1515852340;                                   // 0x5a5a1234 marker
console.log('CE_RUNTIME ' + process.pid);
process.stdin.on('data', (data) => {
  for (const command of data.toString()) {
    if (command === 'b') console.log(ceJitWriter(view));
    else if (command === 'r') console.log(view[0]);
    else if (command === 's') {
      if (!spinner) spinner = new Worker('for (;;) {}', { eval: true });
      // Give the worker time to start executing its loop.
      setTimeout(() => console.log(1), 500);
    } else if (command === 'x') {
      const stopping = spinner ? spinner.terminate() : Promise.resolve();
      spinner = null;
      stopping.then(() => console.log(0));
    }
  }
});
