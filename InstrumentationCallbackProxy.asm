.model flat

assume fs:nothing
extern _InstrumentationCallback:near

.code
_InstrumentationCallbackProxy proc

    mov     fs:1b0h, ecx                ; InstrumentationCallbackPreviousPc
    mov     fs:1b4h, esp                ; InstrumentationCallbackPreviousSp
    
    push    eax                         ; Return value
    push    ecx                         ; Return address
    call    _InstrumentationCallback

    mov     esp, fs:1b4h
    mov     ecx, fs:1b0h
    jmp     ecx

_InstrumentationCallbackProxy endp

assume fs:error
end
