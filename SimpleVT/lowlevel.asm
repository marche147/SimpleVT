
; lowlevel.asm
; 

_ASM segment para 'CODE'

ALIGN 16
__readcs PROC
 mov rax, cs
 ret
__readcs ENDP

__readds PROC
 mov rax, ds
 ret
__readds ENDP

__readss PROC
 mov rax, ss
 ret
__readss ENDP

__reades PROC
 mov rax, es
 ret
__reades ENDP

__readfs PROC
 mov rax, fs
 ret
__readfs ENDP

__readgs PROC
 mov rax, gs
 ret
__readgs ENDP

__sldt PROC
 sldt rax
 ret
__sldt ENDP

__str PROC
 str rax
 ret
__str ENDP

_StackPointer PROC
 mov rax, rsp
 sub rax, sizeof(QWORD)		; 
 ret
_StackPointer ENDP

_NextInstructionPointer PROC
 mov rax, [rsp]
 ret
_NextInstructionPointer ENDP

__sgdt PROC
 mov rax, rcx
 sgdt [rax]
 ret
__sgdt ENDP

__invd PROC ; what if we just "mov eax,cr3;mov cr3, eax"
 invd
 ret
__invd ENDP

__writeds PROC
 mov ds, cx
 ret
__writeds ENDP

__writees PROC
 mov es, cx
 ret
__writees ENDP

__writefs PROC
 mov fs, cx
 ret
__writefs ENDP

_ASM ENDS
END