// Independent GNU assembler fixtures. Relocated blocks contain whole code only;
// mutable literal pools and external callees remain in the original mapping.
.text
.balign 65536
.global relocation_blob_start
relocation_blob_start:
.macro begin name
.global relocation_\name
relocation_\name:
.endm
.macro end name
.global relocation_\name\()_end
relocation_\name\()_end:
.endm
begin adr_positive
adr x0, .+0x123
ret
end adr_positive
begin adr_negative
adr x0, .-5
ret
end adr_negative
begin literal_w
ldr w0, literal_word
ret
end literal_w
begin literal_sw
ldrsw x0, literal_word
ret
end literal_sw
begin literal_x
ldr x0, literal_double
ret
end literal_x
begin literal_s
ldr s0, literal_word
fmov w0, s0
ret
end literal_s
begin literal_d
ldr d0, literal_double
fmov x0, d0
ret
end literal_d
begin literal_q
ldr q0, literal_vector
umov x0, v0.d[0]
umov x1, v0.d[1]
eor x0, x0, x1
ret
end literal_q
begin prefetch
prfm pldl1keep, literal_double
mov x0, #42
ret
end prefetch
begin zero_literal
ldr xzr, literal_double
mov x0, #42
ret
end zero_literal
begin internal_branch
b 1f
mov x0, #17
1: mov x0, #42
ret
end internal_branch
begin loop
mov x1, #3
mov x0, #0
1: add x0, x0, #1
subs x1, x1, #1
b.ne 1b
ret
end loop
begin conditional
b.eq 1f
mov x0, #17
ret
1: mov x0, #42
ret
end conditional
begin conditional_external
b.eq external_target
mov x0, #17
ret
end conditional_external
begin cbz_x
cbz x0, external_target
mov x0, #17
ret
end cbz_x
begin cbnz_x
cbnz x0, external_target
mov x0, #17
ret
end cbnz_x
begin cbz_w
cbz w0, external_target
mov x0, #17
ret
end cbz_w
begin cbnz_w
cbnz w0, external_target
mov x0, #17
ret
end cbnz_w
begin tbz_high
tbz x0, #63, external_target
mov x0, #17
ret
end tbz_high
begin tbnz_high
tbnz x0, #63, external_target
mov x0, #17
ret
end tbnz_high
begin tbz_low
tbz w0, #0, external_target
mov x0, #17
ret
end tbz_low
begin tbnz_low
tbnz w0, #0, external_target
mov x0, #17
ret
end tbnz_low
begin external_branch
b external_target
end external_branch
begin external_call
stp x29, x30, [sp, #-16]!
bl external_target
ldp x29, x30, [sp], #16
ret
end external_call
.org 0x700
external_target:
mov x0, #42
ret
.org 0x800
.global relocation_literal_word, relocation_literal_double, relocation_literal_vector
relocation_literal_word:
literal_word: .word 0x80000001
.balign 8
relocation_literal_double:
literal_double: .quad 0x1234567890abcdef
relocation_literal_vector:
literal_vector: .quad 0x1234567890abcdef, 0xfedcba0987654321
.org 0x1ffc
begin adrp
adrp x0, page_target
ret
end adrp
.org 0x3000
page_target: .word 0
.global relocation_blob_end
relocation_blob_end:

// Return {value, NZCV} using AAPCS64's X0/X1 aggregate return convention.
.global relocation_call
.type relocation_call, %function
relocation_call:
stp x29, x30, [sp, #-16]!
mov x9, x0
msr nzcv, x1
mov x0, x2
blr x9
mrs x1, nzcv
ldp x29, x30, [sp], #16
ret
.size relocation_call, .-relocation_call
.section .note.GNU-stack,"",%progbits
