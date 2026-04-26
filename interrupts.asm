[BITS 32]

global isr_irq0
global isr_irq1
global isr_irq2
global isr_irq3
global isr_irq4
global isr_irq5
global isr_irq6
global isr_irq7
global isr_irq8
global isr_irq9
global isr_irq10
global isr_irq11
global isr_irq12
global isr_irq13
global isr_irq14
global isr_irq15
global isr_syscall
global isr_default
global gdt_flush
global tss_flush
global enter_user_mode

extern irq_handler_c
extern default_handler_c
extern syscall_handler_c

%macro IRQ_STUB 1
isr_irq%1:
    pushad
    cld
    push esp
    push dword %1
    call irq_handler_c
    add esp, 8
    mov esp, eax
    popad
    iretd
%endmacro

IRQ_STUB 0
IRQ_STUB 1
IRQ_STUB 2
IRQ_STUB 3
IRQ_STUB 4
IRQ_STUB 5
IRQ_STUB 6
IRQ_STUB 7
IRQ_STUB 8
IRQ_STUB 9
IRQ_STUB 10
IRQ_STUB 11
IRQ_STUB 12
IRQ_STUB 13
IRQ_STUB 14
IRQ_STUB 15

isr_syscall:
    pushad
    cld
    push esp
    call syscall_handler_c
    add esp, 4
    mov [esp + 28], eax
    popad
    iretd

isr_default:
    pushad
    cld
    call default_handler_c
    popad
    iretd

gdt_flush:
    mov eax, [esp + 4]
    lgdt [eax]
    mov ax, [esp + 8]
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov eax, [esp + 12]
    push eax
    push .flush_done
    retf
.flush_done:
    ret

tss_flush:
    mov ax, [esp + 4]
    ltr ax
    ret

enter_user_mode:
    mov eax, [esp + 4]
    mov edx, [esp + 8]
    mov ecx, [esp + 12]
    mov ebx, [esp + 16]
    mov ds, cx
    mov es, cx
    mov fs, cx
    mov gs, cx

    push ecx
    push eax
    pushfd
    or dword [esp], 0x200
    push ebx
    push edx
    iretd
