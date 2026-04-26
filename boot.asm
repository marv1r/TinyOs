[BITS 16]
[ORG 0x7C00]

KERNEL_SEGMENT equ 0x1000
KERNEL_OFFSET  equ 0x0000
KERNEL_SECTORS equ 64

; GDT selectors for our own protected-mode layout.
CODE_SEL equ 0x08
DATA_SEL equ 0x10

start:
    mov [boot_drive], dl

    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    mov ax, 0x0003
    int 0x10

    mov ax, KERNEL_SEGMENT
    mov es, ax
    xor bx, bx
    mov ah, 0x02
    mov al, KERNEL_SECTORS
    mov ch, 0x00
    mov cl, 0x02
    mov dh, 0x00
    mov dl, [boot_drive]
    int 0x13
    jc disk_error

    in al, 0x92
    or al, 0x02
    out 0x92, al

    cli
    lgdt [gdt_descriptor]
    mov eax, cr0
    or eax, 0x1
    mov cr0, eax
    jmp CODE_SEL:protected_mode

disk_error:
    mov ah, 0x0E
    mov al, 'E'
    int 0x10
    jmp $

[BITS 32]
protected_mode:
    mov ax, DATA_SEL
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x90000

    mov eax, KERNEL_SEGMENT * 16 + KERNEL_OFFSET
    call eax

hang:
    cli
    hlt
    jmp hang

[BITS 16]
boot_drive db 0

align 8
gdt_start:
    ; 0x00: null descriptor
    dq 0x0000000000000000
    ; 0x08: 32-bit code segment, base=0x0, limit=0xFFFFF, granularity=4KiB
    dq 0x00CF9A000000FFFF
    ; 0x10: 32-bit data segment, base=0x0, limit=0xFFFFF, granularity=4KiB
    dq 0x00CF92000000FFFF
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

times 510 - ($ - $$) db 0
dw 0xAA55
