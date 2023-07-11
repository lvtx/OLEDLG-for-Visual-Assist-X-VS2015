;/*********************************************************************
;* Filename:   masm.asm
;* Author:     lvtx (wiflvtx@gmail.com)
;*********************************************************************/
TITLE masm.asm

;-------------------------------
;           FOR X64
;-------------------------------
IFDEF _M_X64
.CODE
prevFunc proc
	mov qword ptr [rsp+38h], rcx
	mov qword ptr [rsp+40h], rdx
	mov qword ptr [rsp+48h], r8
	mov qword ptr [rsp+50h], r9
	ret
prevFunc endp

setFunc proc
	mov rax, rcx
	ret
setFunc endp

endFunc proc
	pop rbx
	add rsp, 28h
	pop rbx
	pop rcx
	pop rdx
	pop r8
	pop r9
	sub rsp, 20h
	push rbx
	jmp qword ptr [rax]
	ret
endFunc endp
ENDIF

;-------------------------------
;           FOR X86
;-------------------------------
IFDEF _M_IX86
.MODEL FLAT
.CODE
_prevFunc proc
	mov dword ptr ss:[esp+38h], ecx
	mov dword ptr ss:[esp+40h], edx
	mov dword ptr ss:[esp+48h], esi
	mov dword ptr ss:[esp+50h], edi
	ret
_prevFunc endp

_setFunc proc
	mov eax, ecx
	ret
_setFunc endp

_endFunc proc
	pop ebx
	add esp, 28h
	pop ebx
	pop ecx
	pop edx
	pop esi
	pop edi
	sub esp, 20h
	push ebx
	jmp dword ptr ds:[eax]
	ret
_endFunc endp
ENDIF
END