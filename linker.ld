ENTRY(kernel_entry)

SECTIONS
{
    . = 0x00010000;

    .text :
    {
        *(.entry)
        *(.text*)
    }

    .rodata :
    {
        *(.rodata*)
    }

    .data :
    {
        *(.data*)
    }

    .bss :
    {
        *(COMMON)
        *(.bss*)
    }

    __kernel_end = .;
}
