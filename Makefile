CC := D:/msys/usr/bin/clang.exe
AS := nasm
LD := D:/msys/usr/bin/ld.lld.exe
OBJCOPY := D:/msys/usr/bin/objcopy.exe
QEMU ?= C:/Users/marki/scoop/apps/qemu/current/qemu-system-i386.exe

CFLAGS := --target=i686-elf -m32 -ffreestanding -fno-stack-protector -fno-pic -nostdlib -Wall -Wextra
ASFLAGS := -f bin
ISR_ASFLAGS := -f elf32
LDFLAGS := -m elf_i386 -T linker.ld -nostdlib

KERNEL_ELF := kernel.elf
KERNEL_BIN := kernel.bin
BOOT_BIN := boot.bin
IMAGE_BIN := os-image.bin
KERNEL_SECTORS := 64

.PHONY: all clean run

all: $(IMAGE_BIN)

$(BOOT_BIN): boot.asm
	$(AS) $(ASFLAGS) $< -o $@

kernel.o: kernel.c
	$(CC) $(CFLAGS) -c $< -o $@

interrupts.o: interrupts.asm
	$(AS) $(ISR_ASFLAGS) $< -o $@

entry.o: entry.asm
	$(AS) $(ISR_ASFLAGS) $< -o $@

$(KERNEL_ELF): entry.o kernel.o interrupts.o linker.ld
	$(LD) $(LDFLAGS) entry.o kernel.o interrupts.o -o $@

$(KERNEL_BIN): $(KERNEL_ELF)
	$(OBJCOPY) -O binary $(KERNEL_ELF) $(KERNEL_BIN)
	powershell -NoProfile -Command "if ((Get-Item '$(KERNEL_BIN)').Length -gt $(KERNEL_SECTORS)*512) { throw 'kernel.bin is larger than configured KERNEL_SECTORS' }"

$(IMAGE_BIN): $(BOOT_BIN) $(KERNEL_BIN)
	D:/msys/usr/bin/bash.exe -lc "cd /d/cursor_code && dd if=/dev/zero of=$(IMAGE_BIN) bs=512 count=2880 && dd if=$(BOOT_BIN) of=$(IMAGE_BIN) conv=notrunc && dd if=$(KERNEL_BIN) of=$(IMAGE_BIN) bs=512 seek=1 conv=notrunc"

run: $(IMAGE_BIN)
	$(QEMU) -drive format=raw,file=$(IMAGE_BIN),if=floppy -boot a -netdev user,id=net0 -device rtl8139,netdev=net0

clean:
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue *.o, '$(BOOT_BIN)', '$(KERNEL_ELF)', '$(KERNEL_BIN)', '$(IMAGE_BIN)'"
