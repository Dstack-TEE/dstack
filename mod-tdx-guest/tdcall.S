/*
 * Copyright (c) 2023, Intel Inc
 * SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>

#include <linux/linkage.h>
#include <linux/errno.h>

#include <asm/frame.h>
#include <asm/tdx.h>

/*
 * TDCALL and SEAMCALL are supported in Binutils >= 2.36.
 */
#define tdcall		.byte 0x66,0x0f,0x01,0xcc
#define seamcall	.byte 0x66,0x0f,0x01,0xcf

/*
 * TDX_MODULE_CALL - common helper macro for both
 *                 TDCALL and SEAMCALL instructions.
 *
 * TDCALL   - used by TDX guests to make requests to the
 *            TDX module and hypercalls to the VMM.
 * SEAMCALL - used by TDX hosts to make requests to the
 *            TDX module.
 *
 *-------------------------------------------------------------------------
 * TDCALL/SEAMCALL ABI:
 *-------------------------------------------------------------------------
 * Input Registers:
 *
 * RAX                        - TDCALL/SEAMCALL Leaf number.
 * RCX,RDX,RDI,RSI,RBX,R8-R15 - TDCALL/SEAMCALL Leaf specific input registers.
 *
 * Output Registers:
 *
 * RAX                        - TDCALL/SEAMCALL instruction error code.
 * RCX,RDX,RDI,RSI,RBX,R8-R15 - TDCALL/SEAMCALL Leaf specific output registers.
 *
 *-------------------------------------------------------------------------
 *
 * So while the common core (RAX,RCX,RDX,R8-R11) fits nicely in the
 * callee-clobbered registers and even leaves RDI,RSI free to act as a
 * base pointer, some leafs (e.g., VP.ENTER) make a giant mess of things.
 *
 * For simplicity, assume that anything that needs the callee-saved regs
 * also tramples on RDI,RSI.  This isn't strictly true, see for example
 * TDH.EXPORT.MEM.
 */
.macro TDX_MODULE_CALL host:req ret=0
	FRAME_BEGIN

	/* Move Leaf ID to RAX */
	mov %rdi, %rax

	/* Move other input regs from 'struct tdx_module_args' */
	movq	TDX_MODULE_rcx(%rsi), %rcx
	movq	TDX_MODULE_rdx(%rsi), %rdx
	movq	TDX_MODULE_r8(%rsi),  %r8
	movq	TDX_MODULE_r9(%rsi),  %r9
	movq	TDX_MODULE_r10(%rsi), %r10
	movq	TDX_MODULE_r11(%rsi), %r11

.if \host
.Lseamcall\@:
	seamcall
	/*
	 * SEAMCALL instruction is essentially a VMExit from VMX root
	 * mode to SEAM VMX root mode.  VMfailInvalid (CF=1) indicates
	 * that the targeted SEAM firmware is not loaded or disabled,
	 * or P-SEAMLDR is busy with another SEAMCALL.  %rax is not
	 * changed in this case.
	 *
	 * Set %rax to TDX_SEAMCALL_VMFAILINVALID for VMfailInvalid.
	 * This value will never be used as actual SEAMCALL error code as
	 * it is from the Reserved status code class.
	 */
	jc .Lseamcall_vmfailinvalid\@
.else
	tdcall
.endif

.if \ret
	/* Copy output registers to the structure */
	movq %rcx, TDX_MODULE_rcx(%rsi)
	movq %rdx, TDX_MODULE_rdx(%rsi)
	movq %r8,  TDX_MODULE_r8(%rsi)
	movq %r9,  TDX_MODULE_r9(%rsi)
	movq %r10, TDX_MODULE_r10(%rsi)
	movq %r11, TDX_MODULE_r11(%rsi)
.endif	/* \ret */

.if \host
.Lout\@:
.endif

	FRAME_END
	RET

.if \host
.Lseamcall_vmfailinvalid\@:
	mov $TDX_SEAMCALL_VMFAILINVALID, %rax
	jmp .Lseamcall_fail\@

.Lseamcall_trap\@:
	/*
	 * SEAMCALL caused #GP or #UD.  By reaching here RAX contains
	 * the trap number.  Convert the trap number to the TDX error
	 * code by setting TDX_SW_ERROR to the high 32-bits of RAX.
	 *
	 * Note cannot OR TDX_SW_ERROR directly to RAX as OR instruction
	 * only accepts 32-bit immediate at most.
	 */
	movq $TDX_SW_ERROR, %rdi
	orq  %rdi, %rax

.Lseamcall_fail\@:
	jmp .Lout\@

	_ASM_EXTABLE_FAULT(.Lseamcall\@, .Lseamcall_trap\@)
.endif	/* \host */

.endm

.section .noinstr.text, "ax"

/*
 * __tdcall()  - Used by TDX guests to request services from the TDX
 * module (does not include VMM services) using TDCALL instruction.
 *
 * __tdcall() function ABI:
 *
 * @fn   (RDI)	- TDCALL Leaf ID, moved to RAX
 * @args (RSI)	- struct tdx_module_args for input
 *
 * Only RCX/RDX/R8-R11 are used as input registers.
 *
 * Return status of TDCALL via RAX.
 */
SYM_FUNC_START(__tdcall)
	TDX_MODULE_CALL host=0
SYM_FUNC_END(__tdcall)

/*
 * __tdcall_ret() - Used by TDX guests to request services from the TDX
 * module (does not include VMM services) using TDCALL instruction, with
 * saving output registers to the 'struct tdx_module_args' used as input.
 *
 * __tdcall_ret() function ABI:
 *
 * @fn   (RDI)	- TDCALL Leaf ID, moved to RAX
 * @args (RSI)	- struct tdx_module_args for input and output
 *
 * Only RCX/RDX/R8-R11 are used as input/output registers.
 *
 * Return status of TDCALL via RAX.
 */
SYM_FUNC_START(__tdcall_ret)
	TDX_MODULE_CALL host=0 ret=1
SYM_FUNC_END(__tdcall_ret)
