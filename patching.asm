public SysCallingThePatch 


.code 

SysCallingThePatch proc
    mov rdx,0H
    mov r8, 0H 
    mov r9, 0H 
    call rcx 
    ret

SysCallingThePatch endp


end
