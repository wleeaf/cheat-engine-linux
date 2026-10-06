.text
.global entry, published, returning
entry:
 endbr64
 push %r12
 mov %edi,%r12d
 lea 8(%rsp),%r11
 mov %r11d,32(%r12)
 mov 8(%rsp),%r11d
 mov %r11d,28(%r12)
 mov $(0x40000000+186),%eax
 syscall
 mov %eax,(%r12)
 sub $16,%rsp
 # x32 timespec has 64-bit seconds and nanoseconds, unlike its pointers.
 movq $0,(%rsp)
 mov 36(%r12),%eax
 mov %rax,8(%rsp)
start_wait:
 cmpl $0,4(%r12)
 jne dispatch
 mov $(0x40000000+35),%eax
 mov %rsp,%rdi
 xor %esi,%esi
 syscall
 jmp start_wait
dispatch:
 cmpl $1,4(%r12)
 jne cancel
 mov 20(%r12),%edi
 mov 16(%r12),%eax
 call *%rax
 jmp finished
cancel:
 xor %eax,%eax
finished:
 mov %eax,24(%r12)
ready_sleep:
 mov $(0x40000000+35),%eax
 mov %rsp,%rdi
 xor %esi,%esi
 syscall
 movl $1,8(%r12)
published:
 cmpl $0,12(%r12)
 je ready_sleep
returning:
 mov 24(%r12),%eax
 add $16,%rsp
 pop %r12
 ret
