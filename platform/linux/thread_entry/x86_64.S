.text
.global entry, published, returning
entry:
 endbr64
 push %r12
 mov %rdi,%r12
 lea 8(%rsp),%r11
 mov %r11,64(%r12)
 mov 8(%rsp),%r11
 mov %r11,56(%r12)
 mov $186,%eax
 syscall
 mov %rax,(%r12)
 sub $16,%rsp
 movq $0,(%rsp)
 mov 72(%r12),%rax
 mov %rax,8(%rsp)
start_wait:
 cmpq $0,8(%r12)
 jne dispatch
 mov $35,%eax
 mov %rsp,%rdi
 xor %esi,%esi
 syscall
 jmp start_wait
dispatch:
 cmpq $1,8(%r12)
 jne cancel
 mov 40(%r12),%rdi
 call *32(%r12)
 jmp finished
cancel:
 xor %eax,%eax
finished:
 mov %rax,48(%r12)
ready_sleep:
 mov $35,%eax
 mov %rsp,%rdi
 xor %esi,%esi
 syscall
 movq $1,16(%r12)
published:
 cmpq $0,24(%r12)
 je ready_sleep
returning:
 mov 48(%r12),%rax
 add $16,%rsp
 pop %r12
 ret
