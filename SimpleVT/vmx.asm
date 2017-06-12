
; vmx.asm
; 

_ASM segment para 'CODE'

extern VMExitHandler:proc

SAVESTATE MACRO ; saves state on the stack
 push r15
 mov r15, rsp
 add r15, 8
 push r14
 push r13
 push r12
 push r11
 push r10
 push r9
 push r8
 push rdi
 push rsi
 push rbp
 push r15	; rsp
 push rbx
 push rdx
 push rcx
 push rax
ENDM

LOADSTATE MACRO ; loads state from stack
 pop rax
 pop rcx
 pop rdx
 pop rbx
 add rsp, 8
 pop rbp
 pop rsi
 pop rdi
 pop r8
 pop r9
 pop r10
 pop r11
 pop r12
 pop r13
 pop r14
 pop r15
ENDM

_VMExitHandler PROC

 cli
 SAVESTATE	; Or use RtlCaptureContext instead?
 mov rcx, rsp	; calling convention 

 sub rsp, 0100h
 call VMExitHandler
 add rsp, 0100h

 LOADSTATE	; loads state contains the change
 sti
__do_resume:
 vmresume ; return to VM non-root
 ret

_VMExitHandler ENDP

_ASM ENDS
END