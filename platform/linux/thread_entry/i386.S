.text
.global entry, published, returning
entry:
 endbr32
 push %ebx
 mov 8(%esp),%ebx
 lea 4(%esp),%ecx
 mov %ecx,32(%ebx)
 mov 4(%esp),%ecx
 mov %ecx,28(%ebx)
 mov $224,%eax
 int $0x80
 mov %eax,(%ebx)
 sub $8,%esp
 movl $0,(%esp)
 mov 36(%ebx),%eax
 mov %eax,4(%esp)
start_wait:
 cmpl $0,4(%ebx)
 jne dispatch
 push %ebx
 lea 4(%esp),%ebx
 xor %ecx,%ecx
 mov $162,%eax
 int $0x80
 pop %ebx
 jmp start_wait
dispatch:
 cmpl $1,4(%ebx)
 jne cancel
 sub $12,%esp
 push 20(%ebx)
 call *16(%ebx)
 add $16,%esp
 jmp finished
cancel:
 xor %eax,%eax
finished:
 mov %eax,24(%ebx)
ready_sleep:
 push %ebx
 lea 4(%esp),%ebx
 xor %ecx,%ecx
 mov $162,%eax
 int $0x80
 pop %ebx
 movl $1,8(%ebx)
published:
 cmpl $0,12(%ebx)
 je ready_sleep
returning:
 mov 24(%ebx),%eax
 add $8,%esp
 pop %ebx
 ret
