.text
.global entry, published, returning
entry:
 bti c
 stp x19,x30,[sp,#-16]!
 mov x19,x0
 sub sp,sp,#16
 add x9,sp,#32
 str x9,[x19,#64]
 str x30,[x19,#56]
 mov x8,#178
 svc #0
 str x0,[x19]
 ldr x9,[x19,#72]
 stp xzr,x9,[sp]
start_check:
 add x17,x19,#8
start_wait:
 ldar x9,[x17]
 cbnz x9,dispatch
 mov x0,sp
 mov x1,#0
 mov x8,#101
 svc #0
 b start_check
dispatch:
 cmp x9,#1
 b.ne cancel
 ldr x16,[x19,#32]
 ldr x0,[x19,#40]
 blr x16
 b finished
cancel:
 mov x0,#0
finished:
 str x0,[x19,#48]
ready_sleep:
 mov x0,sp
 mov x1,#0
 mov x8,#101
 svc #0
 mov x9,#1
 add x17,x19,#16
 stlr x9,[x17]
 add x17,x19,#24
published:
 ldar x9,[x17]
 cbz x9,ready_sleep
returning:
 ldr x0,[x19,#48]
 add sp,sp,#16
 ldp x19,x30,[sp],#16
 ret
