	.file	"fake_write.c"
	.text
	.p2align 4,,15
	.globl	write
	.type	write, @function
write:
.LFB6:
	.cfi_startproc
	movl	%edi, %r8d
	movq	%rsi, %r9
	xorl	%esi, %esi
	movq	$3, -24(%rsp)
	movq	$100000, -16(%rsp)
	leaq	-24(%rsp), %rdi
	movl	$35, %eax
#APP
# 39 "fake_write.c" 1
	syscall
# 0 "" 2
#NO_APP
	movl	$1, %eax
	movl	%r8d, %edi
	movq	%r9, %rsi
#APP
# 26 "fake_write.c" 1
	syscall
# 0 "" 2
#NO_APP
	ret
	.cfi_endproc
.LFE6:
	.size	write, .-write
	.ident	"GCC: (GNU) 8.5.0 20210514 (Red Hat 8.5.0-4)"
	.section	.note.GNU-stack,"",@progbits
