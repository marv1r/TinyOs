#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

enum {
    VGA_WIDTH = 80,
    VGA_HEIGHT = 25,
    VGA_COLOR_LIGHT_GREY = 0x07,
    PIC1_COMMAND = 0x20,
    PIC1_DATA = 0x21,
    PIC2_COMMAND = 0xA0,
    PIC2_DATA = 0xA1,
    PIT_COMMAND = 0x43,
    PIT_CHANNEL0 = 0x40,
    PAGE_PRESENT = 0x001,
    PAGE_RW = 0x002,
    PAGE_USER = 0x004,
    PCI_CONFIG_ADDRESS = 0xCF8,
    PCI_CONFIG_DATA = 0xCFC
};

static volatile uint8_t* const VGA = (volatile uint8_t*)0xB8000;
static volatile uint32_t g_ticks = 0;
static volatile uint32_t g_task_a_ticks = 0;
static volatile uint32_t g_task_b_ticks = 0;
static uint8_t g_console_color = VGA_COLOR_LIGHT_GREY;
static int g_cursor_x = 0;
static int g_cursor_y = 0;

extern uint8_t __kernel_end;

struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t zero;
    uint8_t type_attr;
    uint16_t offset_high;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

struct gdt_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t granularity;
    uint8_t base_high;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

struct tss_entry {
    uint32_t prev_tss;
    uint32_t esp0;
    uint32_t ss0;
    uint32_t esp1;
    uint32_t ss1;
    uint32_t esp2;
    uint32_t ss2;
    uint32_t cr3;
    uint32_t eip;
    uint32_t eflags;
    uint32_t eax;
    uint32_t ecx;
    uint32_t edx;
    uint32_t ebx;
    uint32_t esp;
    uint32_t ebp;
    uint32_t esi;
    uint32_t edi;
    uint32_t es;
    uint32_t cs;
    uint32_t ss;
    uint32_t ds;
    uint32_t fs;
    uint32_t gs;
    uint32_t ldt;
    uint16_t trap;
    uint16_t iomap_base;
} __attribute__((packed));

extern void isr_irq0(void);
extern void isr_irq1(void);
extern void isr_irq2(void);
extern void isr_irq3(void);
extern void isr_irq4(void);
extern void isr_irq5(void);
extern void isr_irq6(void);
extern void isr_irq7(void);
extern void isr_irq8(void);
extern void isr_irq9(void);
extern void isr_irq10(void);
extern void isr_irq11(void);
extern void isr_irq12(void);
extern void isr_irq13(void);
extern void isr_irq14(void);
extern void isr_irq15(void);
extern void isr_syscall(void);
extern void isr_default(void);
extern void gdt_flush(const struct gdt_ptr* ptr, uint32_t data_sel, uint32_t code_sel);
extern void tss_flush(uint32_t tss_sel);
extern void enter_user_mode(uint32_t user_stack, uint32_t entry, uint32_t user_data_sel, uint32_t user_code_sel);

static struct idt_entry g_idt[256];
static struct gdt_entry g_gdt[6];
static struct gdt_ptr g_gdtr;
static struct tss_entry g_tss;
static uint32_t g_page_directory[1024] __attribute__((aligned(4096)));
static uint32_t g_first_page_table[1024] __attribute__((aligned(4096)));
static uint8_t g_ring0_stack[4096] __attribute__((aligned(16)));

enum {
    MAX_TASKS = 2,
    TASK_STACK_SIZE = 4096
};

struct task {
    uint32_t esp;
};

static struct task g_tasks[MAX_TASKS];
static uint8_t g_task_stacks[MAX_TASKS][TASK_STACK_SIZE] __attribute__((aligned(16)));
static int g_task_count = 0;
static int g_current_task = -1;
static int g_scheduler_enabled = 0;
static volatile uint32_t g_syscall_ticks = 0;
static uint16_t g_rtl_io_base = 0;
static uint8_t g_nic_mac[6];
static uint8_t g_host_mac[6];
static uint8_t g_host_mac_known = 0;
static uint8_t g_nic_ip[4] = {192, 168, 100, 2};
static uint8_t g_host_ip[4] = {192, 168, 100, 1};
static uint8_t g_rtl_rx_buf[8192 + 16 + 1500] __attribute__((aligned(16)));
static uint8_t g_rtl_tx_buf[4][1600] __attribute__((aligned(16)));
static uint32_t g_rtl_rx_offset = 0;
static uint32_t g_rtl_tx_slot = 0;
static uint8_t g_dns_server_ip[4] = {192, 168, 100, 1};
static uint16_t g_udp_echo_port = 4000;
static uint16_t g_udp_out_port = 4001;
static uint16_t g_dns_src_port = 53000;
static uint16_t g_dns_txid = 0x1337;
static uint8_t g_dns_query_sent = 0;
static uint8_t g_dns_answered = 0;
static uint32_t g_udp_last_tx_tick = 0;
static uint16_t g_tcp_listen_port = 8080;

enum {
    TCP_STATE_LISTEN = 0,
    TCP_STATE_SYN_RCVD = 1,
    TCP_STATE_ESTABLISHED = 2
};

struct tcp_conn_state {
    uint8_t state;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t src_ip[4];
    uint8_t src_mac[6];
    uint32_t iss;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    uint8_t banner_sent;
    uint8_t fin_sent;
};

static struct tcp_conn_state g_tcp;

static void* kmemset(void* dst, uint8_t value, uint32_t size);
static void (*const g_irq_stubs[16])(void) = {
    isr_irq0,  isr_irq1,  isr_irq2,  isr_irq3,
    isr_irq4,  isr_irq5,  isr_irq6,  isr_irq7,
    isr_irq8,  isr_irq9,  isr_irq10, isr_irq11,
    isr_irq12, isr_irq13, isr_irq14, isr_irq15
};

static void put_char_at(char c, uint8_t color, int x, int y) {
    uint32_t index = (uint32_t)(y * VGA_WIDTH + x) * 2;
    VGA[index] = (uint8_t)c;
    VGA[index + 1] = color;
}

static uint32_t align_up_u32(uint32_t value, uint32_t alignment) {
    uint32_t mask = alignment - 1u;
    return (value + mask) & ~mask;
}

static void scroll_if_needed(void) {
    if (g_cursor_y < VGA_HEIGHT) {
        return;
    }
    for (int y = 1; y < VGA_HEIGHT; ++y) {
        for (int x = 0; x < VGA_WIDTH; ++x) {
            uint32_t from = (uint32_t)(y * VGA_WIDTH + x) * 2u;
            uint32_t to = (uint32_t)((y - 1) * VGA_WIDTH + x) * 2u;
            VGA[to] = VGA[from];
            VGA[to + 1] = VGA[from + 1];
        }
    }
    for (int x = 0; x < VGA_WIDTH; ++x) {
        put_char_at(' ', g_console_color, x, VGA_HEIGHT - 1);
    }
    g_cursor_y = VGA_HEIGHT - 1;
}

static void console_putc(char c) {
    if (c == '\n') {
        g_cursor_x = 0;
        ++g_cursor_y;
        scroll_if_needed();
        return;
    }
    if (c == '\r') {
        g_cursor_x = 0;
        return;
    }
    put_char_at(c, g_console_color, g_cursor_x, g_cursor_y);
    ++g_cursor_x;
    if (g_cursor_x >= VGA_WIDTH) {
        g_cursor_x = 0;
        ++g_cursor_y;
        scroll_if_needed();
    }
}

static void clear_screen(uint8_t color) {
    for (int y = 0; y < VGA_HEIGHT; ++y) {
        for (int x = 0; x < VGA_WIDTH; ++x) {
            put_char_at(' ', color, x, y);
        }
    }
}

typedef void (*emit_char_fn)(char c, void* ctx);

struct buffer_writer {
    char* dst;
    size_t size;
    size_t len;
};

static void emit_console(char c, void* ctx) {
    (void)ctx;
    console_putc(c);
}

static void emit_buffer(char c, void* ctx) {
    struct buffer_writer* w = (struct buffer_writer*)ctx;
    if (w->len + 1 < w->size) {
        w->dst[w->len] = c;
    }
    ++w->len;
}

static void emit_repeat(emit_char_fn emit, void* ctx, char c, int count) {
    for (int i = 0; i < count; ++i) {
        emit(c, ctx);
    }
}

static int u32_to_base(char* out, uint32_t value, uint32_t base, int uppercase) {
    static const char digits_l[17] = "0123456789abcdef";
    static const char digits_u[17] = "0123456789ABCDEF";
    const char* digits = uppercase ? digits_u : digits_l;
    int idx = 0;
    if (value == 0u) {
        out[idx++] = '0';
        return idx;
    }
    while (value != 0u) {
        out[idx++] = digits[value % base];
        value /= base;
    }
    for (int i = 0; i < idx / 2; ++i) {
        char tmp = out[i];
        out[i] = out[idx - 1 - i];
        out[idx - 1 - i] = tmp;
    }
    return idx;
}

static void emit_padded(emit_char_fn emit, void* ctx, const char* text, int len, int width, char pad) {
    if (width > len) {
        emit_repeat(emit, ctx, pad, width - len);
    }
    for (int i = 0; i < len; ++i) {
        emit(text[i], ctx);
    }
}

static void kvformat(emit_char_fn emit, void* ctx, const char* fmt, va_list args) {
    while (*fmt != '\0') {
        if (*fmt != '%') {
            emit(*fmt++, ctx);
            continue;
        }
        ++fmt;
        int zero_pad = 0;
        int width = 0;
        if (*fmt == '0') {
            zero_pad = 1;
            ++fmt;
        }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            ++fmt;
        }
        char num_buf[34];
        int len = 0;
        char sign = '\0';
        switch (*fmt) {
            case '%':
                emit('%', ctx);
                break;
            case 'c':
                emit((char)va_arg(args, int), ctx);
                break;
            case 's': {
                const char* s = va_arg(args, const char*);
                if (s == NULL) {
                    s = "(null)";
                }
                while (s[len] != '\0') {
                    ++len;
                }
                emit_padded(emit, ctx, s, len, width, zero_pad ? '0' : ' ');
                break;
            }
            case 'd':
            case 'i': {
                int32_t value = va_arg(args, int32_t);
                uint32_t abs_val = (uint32_t)value;
                if (value < 0) {
                    sign = '-';
                    abs_val = (uint32_t)(-(value + 1)) + 1u;
                }
                len = u32_to_base(num_buf, abs_val, 10u, 0);
                if (sign != '\0') {
                    if (zero_pad && width > len + 1) {
                        emit(sign, ctx);
                        emit_repeat(emit, ctx, '0', width - len - 1);
                    } else {
                        emit_repeat(emit, ctx, ' ', (width > len + 1) ? (width - len - 1) : 0);
                        emit(sign, ctx);
                    }
                    for (int i = 0; i < len; ++i) {
                        emit(num_buf[i], ctx);
                    }
                } else {
                    emit_padded(emit, ctx, num_buf, len, width, zero_pad ? '0' : ' ');
                }
                break;
            }
            case 'u':
                len = u32_to_base(num_buf, va_arg(args, uint32_t), 10u, 0);
                emit_padded(emit, ctx, num_buf, len, width, zero_pad ? '0' : ' ');
                break;
            case 'x':
                len = u32_to_base(num_buf, va_arg(args, uint32_t), 16u, 0);
                emit_padded(emit, ctx, num_buf, len, width, zero_pad ? '0' : ' ');
                break;
            case 'X':
                len = u32_to_base(num_buf, va_arg(args, uint32_t), 16u, 1);
                emit_padded(emit, ctx, num_buf, len, width, zero_pad ? '0' : ' ');
                break;
            case 'p': {
                uint32_t ptr = (uint32_t)(uintptr_t)va_arg(args, void*);
                emit('0', ctx);
                emit('x', ctx);
                len = u32_to_base(num_buf, ptr, 16u, 0);
                emit_padded(emit, ctx, num_buf, len, (width == 0) ? 8 : width, '0');
                break;
            }
            default:
                emit('%', ctx);
                emit(*fmt, ctx);
                break;
        }
        if (*fmt != '\0') {
            ++fmt;
        }
    }
}

static void kprintf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    kvformat(emit_console, NULL, fmt, args);
    va_end(args);
}

static int ksnprintf(char* dst, size_t size, const char* fmt, ...) {
    if (dst == NULL || size == 0u) {
        return 0;
    }
    struct buffer_writer w;
    w.dst = dst;
    w.size = size;
    w.len = 0;
    va_list args;
    va_start(args, fmt);
    kvformat(emit_buffer, &w, fmt, args);
    va_end(args);
    if (w.len < size) {
        dst[w.len] = '\0';
    } else {
        dst[size - 1] = '\0';
    }
    return (int)w.len;
}

static void* kmemset(void* dst, uint8_t value, uint32_t size) {
    uint8_t* p = (uint8_t*)dst;
    for (uint32_t i = 0; i < size; ++i) {
        p[i] = value;
    }
    return dst;
}

struct heap_block {
    uint32_t size;
    struct heap_block* next;
    uint32_t magic;
};

enum {
    HEAP_MAGIC_USED = 0xC0DEC0DEu
};

static uint32_t g_heap_curr = 0;
static uint32_t g_heap_end = 0;
static struct heap_block* g_heap_free_list = NULL;

static void init_heap(void) {
    g_heap_curr = align_up_u32((uint32_t)(uintptr_t)&__kernel_end, 8u);
    g_heap_end = 0x00088000u;
    g_heap_free_list = NULL;
}

static void init_paging(void) {
    for (uint32_t i = 0; i < 1024u; ++i) {
        g_page_directory[i] = 0u;
        g_first_page_table[i] = (i * 0x1000u) | PAGE_PRESENT | PAGE_RW | PAGE_USER;
    }

    g_page_directory[0] = ((uint32_t)(uintptr_t)g_first_page_table) | PAGE_PRESENT | PAGE_RW | PAGE_USER;

    __asm__ volatile ("mov %0, %%cr3" : : "r"((uint32_t)(uintptr_t)g_page_directory) : "memory");

    uint32_t cr0;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x80000000u;
    __asm__ volatile ("mov %0, %%cr0" : : "r"(cr0) : "memory");
}

static void* heap_raw_alloc(uint32_t payload_size) {
    struct heap_block* prev = NULL;
    struct heap_block* cur = g_heap_free_list;
    while (cur != NULL) {
        if (cur->size >= payload_size) {
            uint32_t remaining = cur->size - payload_size;
            if (remaining > sizeof(struct heap_block) + 8u) {
                struct heap_block* split = (struct heap_block*)((uint8_t*)(cur + 1) + payload_size);
                split->size = remaining - (uint32_t)sizeof(struct heap_block);
                split->next = cur->next;
                split->magic = 0u;
                if (prev != NULL) {
                    prev->next = split;
                } else {
                    g_heap_free_list = split;
                }
                cur->size = payload_size;
            } else {
                if (prev != NULL) {
                    prev->next = cur->next;
                } else {
                    g_heap_free_list = cur->next;
                }
            }
            cur->next = NULL;
            cur->magic = HEAP_MAGIC_USED;
            return (void*)(cur + 1);
        }
        prev = cur;
        cur = cur->next;
    }
    uint32_t total = (uint32_t)sizeof(struct heap_block) + payload_size;
    uint32_t block_start = align_up_u32(g_heap_curr, 8u);
    uint32_t block_end = block_start + total;
    if (block_end < block_start || block_end > g_heap_end) {
        return NULL;
    }
    struct heap_block* block = (struct heap_block*)(uintptr_t)block_start;
    block->size = payload_size;
    block->next = NULL;
    block->magic = HEAP_MAGIC_USED;
    g_heap_curr = block_end;
    return (void*)(block + 1);
}

static void heap_free_raw(void* payload) {
    if (payload == NULL) {
        return;
    }
    struct heap_block* block = ((struct heap_block*)payload) - 1;
    if (block->magic != HEAP_MAGIC_USED) {
        return;
    }
    block->magic = 0u;
    block->next = NULL;
    if (g_heap_free_list == NULL || block < g_heap_free_list) {
        block->next = g_heap_free_list;
        g_heap_free_list = block;
    } else {
        struct heap_block* cur = g_heap_free_list;
        while (cur->next != NULL && cur->next < block) {
            cur = cur->next;
        }
        block->next = cur->next;
        cur->next = block;
    }
    struct heap_block* cur = g_heap_free_list;
    while (cur != NULL && cur->next != NULL) {
        uint8_t* cur_end = (uint8_t*)(cur + 1) + cur->size;
        if (cur_end == (uint8_t*)cur->next) {
            cur->size += (uint32_t)sizeof(struct heap_block) + cur->next->size;
            cur->next = cur->next->next;
            continue;
        }
        cur = cur->next;
    }
}

static void* kmalloc_aligned(uint32_t size, uint32_t alignment) {
    if (size == 0u || alignment == 0u || (alignment & (alignment - 1u)) != 0u) {
        return NULL;
    }
    uint32_t overhead = alignment + (uint32_t)sizeof(uint32_t);
    void* raw = heap_raw_alloc(size + overhead);
    if (raw == NULL) {
        return NULL;
    }
    uintptr_t base = (uintptr_t)raw;
    uintptr_t aligned = align_up_u32((uint32_t)(base + sizeof(uint32_t)), alignment);
    uint32_t offset = (uint32_t)(aligned - base);
    *(uint32_t*)(aligned - sizeof(uint32_t)) = offset;
    return (void*)aligned;
}

static void* kmalloc(uint32_t size) {
    return kmalloc_aligned(size, 8u);
}

static void* kcalloc(uint32_t count, uint32_t size) {
    if (count == 0u || size == 0u) {
        return NULL;
    }
    uint32_t total = count * size;
    if (total / count != size) {
        return NULL;
    }
    void* ptr = kmalloc(total);
    if (ptr != NULL) {
        kmemset(ptr, 0, total);
    }
    return ptr;
}

static void kfree(void* ptr) {
    if (ptr == NULL) {
        return;
    }
    uintptr_t p = (uintptr_t)ptr;
    uint32_t offset = *(uint32_t*)(p - sizeof(uint32_t));
    if (offset >= sizeof(uint32_t) && offset <= 4096u) {
        uintptr_t raw = p - offset;
        if (raw >= (uintptr_t)&__kernel_end && raw < g_heap_end) {
            heap_free_raw((void*)raw);
            return;
        }
    }
    heap_free_raw(ptr);
}

static uint32_t build_initial_task_stack(void* stack_top, void (*entry)(void)) {
    uint32_t* sp = (uint32_t*)stack_top;

    *--sp = 0x00000202u;                    /* EFLAGS (IF=1) */
    *--sp = 0x00000008u;                    /* CS */
    *--sp = (uint32_t)(uintptr_t)entry;     /* EIP */

    *--sp = 0u; /* EAX */
    *--sp = 0u; /* ECX */
    *--sp = 0u; /* EDX */
    *--sp = 0u; /* EBX */
    *--sp = 0u; /* ESP (ignored by POPAD) */
    *--sp = 0u; /* EBP */
    *--sp = 0u; /* ESI */
    *--sp = 0u; /* EDI */

    return (uint32_t)(uintptr_t)sp;
}

static int create_task(void (*entry)(void)) {
    if (g_task_count >= MAX_TASKS) {
        return -1;
    }
    int id = g_task_count++;
    void* top = (void*)(g_task_stacks[id] + TASK_STACK_SIZE);
    g_tasks[id].esp = build_initial_task_stack(top, entry);
    return id;
}

static void task_a(void) {
    for (;;) {
        ++g_task_a_ticks;
        put_char_at('A', VGA_COLOR_LIGHT_GREY, 10, 5);
        put_char_at((char)('0' + (g_task_a_ticks % 10u)), VGA_COLOR_LIGHT_GREY, 12, 5);
        for (volatile uint32_t delay = 0; delay < 250000u; ++delay) {
        }
    }
}

static void task_b(void) {
    for (;;) {
        ++g_task_b_ticks;
        put_char_at('B', VGA_COLOR_LIGHT_GREY, 10, 6);
        put_char_at((char)('0' + (g_task_b_ticks % 10u)), VGA_COLOR_LIGHT_GREY, 12, 6);
        for (volatile uint32_t delay = 0; delay < 250000u; ++delay) {
        }
    }
}

static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void outw(uint16_t port, uint16_t value) {
    __asm__ volatile ("outw %0, %1" : : "a"(value), "Nd"(port));
}

static inline void outl(uint16_t port, uint32_t value) {
    __asm__ volatile ("outl %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint32_t inl(uint16_t port) {
    uint32_t value;
    __asm__ volatile ("inl %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static uint16_t bswap16(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}

static uint32_t bswap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) |
           ((v & 0xFF000000u) >> 24);
}

static uint16_t htons(uint16_t v) { return bswap16(v); }
static uint16_t ntohs(uint16_t v) { return bswap16(v); }
static uint32_t htonl(uint32_t v) { return bswap32(v); }
static uint32_t ntohl(uint32_t v) { return bswap32(v); }

static void kmemcpy(void* dst, const void* src, uint32_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < n; ++i) {
        d[i] = s[i];
    }
}

static int kmemcmp(const void* a, const void* b, uint32_t n) {
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    for (uint32_t i = 0; i < n; ++i) {
        if (pa[i] != pb[i]) {
            return (int)pa[i] - (int)pb[i];
        }
    }
    return 0;
}

static inline void io_wait(void) {
    outb(0x80, 0);
}

static uint32_t pci_config_read32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t address = 0x80000000u |
        ((uint32_t)bus << 16) |
        ((uint32_t)slot << 11) |
        ((uint32_t)func << 8) |
        (offset & 0xFCu);
    outl(PCI_CONFIG_ADDRESS, address);
    return inl(PCI_CONFIG_DATA);
}

static void pci_config_write32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t value) {
    uint32_t address = 0x80000000u |
        ((uint32_t)bus << 16) |
        ((uint32_t)slot << 11) |
        ((uint32_t)func << 8) |
        (offset & 0xFCu);
    outl(PCI_CONFIG_ADDRESS, address);
    outl(PCI_CONFIG_DATA, value);
}

static uint16_t pci_config_read16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t data = pci_config_read32(bus, slot, func, offset);
    return (uint16_t)((data >> ((offset & 2u) * 8u)) & 0xFFFFu);
}

static uint16_t pci_scan_for_rtl8139(uint8_t* out_bus, uint8_t* out_slot, uint8_t* out_func) {
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t slot = 0; slot < 32; ++slot) {
            uint16_t vendor = pci_config_read16((uint8_t)bus, slot, 0, 0x00);
            if (vendor == 0xFFFFu) {
                continue;
            }
            uint16_t device = pci_config_read16((uint8_t)bus, slot, 0, 0x02);
            if (vendor == 0x10ECu && device == 0x8139u) {
                *out_bus = (uint8_t)bus;
                *out_slot = slot;
                *out_func = 0;
                return 1;
            }
        }
    }
    return 0;
}

static void rtl8139_send(const uint8_t* frame, uint16_t len) {
    if (g_rtl_io_base == 0 || len > 1500u) {
        return;
    }
    uint32_t slot = g_rtl_tx_slot & 3u;
    kmemcpy(g_rtl_tx_buf[slot], frame, len);
    outl(g_rtl_io_base + 0x20u + (uint16_t)(slot * 4u), (uint32_t)(uintptr_t)g_rtl_tx_buf[slot]);
    outl(g_rtl_io_base + 0x10u + (uint16_t)(slot * 4u), len);
    g_rtl_tx_slot = (g_rtl_tx_slot + 1u) & 3u;
}

static uint16_t checksum_bytes_be(const uint8_t* data, uint16_t len, uint32_t seed) {
    uint32_t sum = seed;
    uint16_t i = 0;
    while ((uint16_t)(i + 1u) < len) {
        uint16_t word = (uint16_t)(((uint16_t)data[i] << 8) | data[i + 1u]);
        sum += word;
        i += 2u;
    }
    if (i < len) {
        sum += (uint16_t)((uint16_t)data[i] << 8);
    }
    while ((sum >> 16) != 0u) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint16_t ip_checksum(const void* data, uint16_t len) {
    return checksum_bytes_be((const uint8_t*)data, len, 0u);
}

static uint16_t tcp_udp_checksum_ipv4(const uint8_t src_ip[4], const uint8_t dst_ip[4], uint8_t proto, const uint8_t* segment, uint16_t len) {
    uint32_t seed = 0u;
    seed += ((uint16_t)src_ip[0] << 8) | src_ip[1];
    seed += ((uint16_t)src_ip[2] << 8) | src_ip[3];
    seed += ((uint16_t)dst_ip[0] << 8) | dst_ip[1];
    seed += ((uint16_t)dst_ip[2] << 8) | dst_ip[3];
    seed += (uint16_t)proto;
    seed += len;
    return checksum_bytes_be(segment, len, seed);
}

static void send_arp_request(const uint8_t target_ip[4]) {
    uint8_t frame[42];
    for (int i = 0; i < 6; ++i) {
        frame[i] = 0xFFu;
    }
    kmemcpy(frame + 6, g_nic_mac, 6u);
    *(uint16_t*)(frame + 12) = htons(0x0806u);
    *(uint16_t*)(frame + 14) = htons(1u);
    *(uint16_t*)(frame + 16) = htons(0x0800u);
    frame[18] = 6;
    frame[19] = 4;
    *(uint16_t*)(frame + 20) = htons(1u);
    kmemcpy(frame + 22, g_nic_mac, 6u);
    kmemcpy(frame + 28, g_nic_ip, 4u);
    for (int i = 0; i < 6; ++i) {
        frame[32 + i] = 0u;
    }
    kmemcpy(frame + 38, target_ip, 4u);
    rtl8139_send(frame, 42u);
}

static void send_udp_ipv4(const uint8_t dst_mac[6], const uint8_t dst_ip[4], uint16_t src_port, uint16_t dst_port, const uint8_t* payload, uint16_t payload_len) {
    if (payload_len > 1400u) {
        return;
    }
    uint16_t ip_total = (uint16_t)(20u + 8u + payload_len);
    uint16_t frame_len = (uint16_t)(14u + ip_total);
    uint8_t frame[1600];

    kmemcpy(frame + 0, dst_mac, 6u);
    kmemcpy(frame + 6, g_nic_mac, 6u);
    *(uint16_t*)(frame + 12) = htons(0x0800u);

    uint8_t* ip = frame + 14;
    ip[0] = 0x45u;
    ip[1] = 0u;
    *(uint16_t*)(ip + 2) = htons(ip_total);
    *(uint16_t*)(ip + 4) = 0u;
    *(uint16_t*)(ip + 6) = 0u;
    ip[8] = 64u;
    ip[9] = 17u;
    *(uint16_t*)(ip + 10) = 0u;
    kmemcpy(ip + 12, g_nic_ip, 4u);
    kmemcpy(ip + 16, dst_ip, 4u);
    *(uint16_t*)(ip + 10) = htons(ip_checksum(ip, 20u));

    uint8_t* udp = ip + 20;
    *(uint16_t*)(udp + 0) = htons(src_port);
    *(uint16_t*)(udp + 2) = htons(dst_port);
    *(uint16_t*)(udp + 4) = htons((uint16_t)(8u + payload_len));
    *(uint16_t*)(udp + 6) = 0u; /* checksum optional for IPv4 */
    if (payload_len > 0u) {
        kmemcpy(udp + 8, payload, payload_len);
    }

    rtl8139_send(frame, frame_len);
}

static void send_tcp_ipv4(const uint8_t dst_mac[6], const uint8_t dst_ip[4], uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags, const uint8_t* payload, uint16_t payload_len) {
    if (payload_len > 1300u) {
        return;
    }
    uint16_t tcp_len = (uint16_t)(20u + payload_len);
    uint16_t ip_total = (uint16_t)(20u + tcp_len);
    uint16_t frame_len = (uint16_t)(14u + ip_total);
    uint8_t frame[1600];

    kmemcpy(frame + 0, dst_mac, 6u);
    kmemcpy(frame + 6, g_nic_mac, 6u);
    *(uint16_t*)(frame + 12) = htons(0x0800u);

    uint8_t* ip = frame + 14;
    ip[0] = 0x45u;
    ip[1] = 0u;
    *(uint16_t*)(ip + 2) = htons(ip_total);
    *(uint16_t*)(ip + 4) = 0u;
    *(uint16_t*)(ip + 6) = 0u;
    ip[8] = 64u;
    ip[9] = 6u;
    *(uint16_t*)(ip + 10) = 0u;
    kmemcpy(ip + 12, g_nic_ip, 4u);
    kmemcpy(ip + 16, dst_ip, 4u);
    *(uint16_t*)(ip + 10) = htons(ip_checksum(ip, 20u));

    uint8_t* tcp = ip + 20;
    *(uint16_t*)(tcp + 0) = htons(src_port);
    *(uint16_t*)(tcp + 2) = htons(dst_port);
    *(uint32_t*)(tcp + 4) = htonl(seq);
    *(uint32_t*)(tcp + 8) = htonl(ack);
    tcp[12] = (uint8_t)(5u << 4);
    tcp[13] = flags;
    *(uint16_t*)(tcp + 14) = htons(64240u);
    *(uint16_t*)(tcp + 16) = 0u;
    *(uint16_t*)(tcp + 18) = 0u;
    if (payload_len > 0u) {
        kmemcpy(tcp + 20, payload, payload_len);
    }
    *(uint16_t*)(tcp + 16) = htons(tcp_udp_checksum_ipv4(g_nic_ip, dst_ip, 6u, tcp, tcp_len));
    rtl8139_send(frame, frame_len);
}

static uint16_t dns_encode_name(uint8_t* out, const char* name) {
    uint16_t pos = 0;
    uint16_t label_len = 0;
    uint16_t label_start = 0;
    for (uint16_t i = 0;; ++i) {
        char c = name[i];
        if (c == '.' || c == '\0') {
            if (label_len == 0 || label_len > 63u) {
                return 0;
            }
            out[label_start] = (uint8_t)label_len;
            if (c == '\0') {
                out[pos++] = 0u;
                return pos;
            }
            label_start = pos++;
            label_len = 0;
            continue;
        }
        if (pos >= 253u) {
            return 0;
        }
        if (label_len == 0u) {
            out[label_start] = 0u;
        }
        out[pos++] = (uint8_t)c;
        ++label_len;
    }
}

static void dns_send_query(const char* host) {
    if (!g_host_mac_known || g_dns_query_sent) {
        return;
    }
    uint8_t pkt[300];
    uint16_t p = 0;
    *(uint16_t*)(pkt + p) = htons(g_dns_txid); p += 2;
    *(uint16_t*)(pkt + p) = htons(0x0100u); p += 2;
    *(uint16_t*)(pkt + p) = htons(1u); p += 2;
    *(uint16_t*)(pkt + p) = 0u; p += 2;
    *(uint16_t*)(pkt + p) = 0u; p += 2;
    *(uint16_t*)(pkt + p) = 0u; p += 2;
    uint16_t nlen = dns_encode_name(pkt + p, host);
    if (nlen == 0u) {
        return;
    }
    p += nlen;
    *(uint16_t*)(pkt + p) = htons(1u); p += 2;
    *(uint16_t*)(pkt + p) = htons(1u); p += 2;
    send_udp_ipv4(g_host_mac, g_dns_server_ip, g_dns_src_port, 53u, pkt, p);
    g_dns_query_sent = 1;
    kprintf("dns: query %s -> %u.%u.%u.%u\n", host, g_dns_server_ip[0], g_dns_server_ip[1], g_dns_server_ip[2], g_dns_server_ip[3]);
}

static const uint8_t* dns_skip_name(const uint8_t* p, const uint8_t* end) {
    while (p < end) {
        uint8_t len = *p++;
        if (len == 0u) {
            return p;
        }
        if ((len & 0xC0u) == 0xC0u) {
            if (p >= end) {
                return NULL;
            }
            return p + 1;
        }
        if (p + len > end) {
            return NULL;
        }
        p += len;
    }
    return NULL;
}

static void dns_handle_response(const uint8_t* payload, uint16_t len) {
    if (len < 12u || g_dns_answered) {
        return;
    }
    const uint8_t* end = payload + len;
    uint16_t txid = ntohs(*(const uint16_t*)(payload + 0));
    uint16_t flags = ntohs(*(const uint16_t*)(payload + 2));
    uint16_t qd = ntohs(*(const uint16_t*)(payload + 4));
    uint16_t an = ntohs(*(const uint16_t*)(payload + 6));
    if (txid != g_dns_txid || (flags & 0x8000u) == 0u || qd == 0u || an == 0u) {
        return;
    }
    const uint8_t* p = payload + 12;
    p = dns_skip_name(p, end);
    if (p == NULL || p + 4 > end) {
        return;
    }
    p += 4;
    for (uint16_t i = 0; i < an; ++i) {
        p = dns_skip_name(p, end);
        if (p == NULL || p + 10 > end) {
            return;
        }
        uint16_t type = ntohs(*(const uint16_t*)(p + 0));
        uint16_t cls = ntohs(*(const uint16_t*)(p + 2));
        uint16_t rdlen = ntohs(*(const uint16_t*)(p + 8));
        p += 10;
        if (p + rdlen > end) {
            return;
        }
        if (type == 1u && cls == 1u && rdlen == 4u) {
            kprintf("dns: A = %u.%u.%u.%u\n", p[0], p[1], p[2], p[3]);
            g_dns_answered = 1;
            return;
        }
        p += rdlen;
    }
}

static void handle_arp_packet(const uint8_t* frame, uint16_t len) {
    if (len < 42u) {
        return;
    }
    const uint8_t* arp = frame + 14;
    uint16_t htype = ntohs(*(const uint16_t*)(arp + 0));
    uint16_t ptype = ntohs(*(const uint16_t*)(arp + 2));
    uint8_t hlen = arp[4];
    uint8_t plen = arp[5];
    uint16_t oper = ntohs(*(const uint16_t*)(arp + 6));
    if (htype != 1u || ptype != 0x0800u || hlen != 6u || plen != 4u || oper != 1u) {
        return;
    }
    const uint8_t* sender_mac = arp + 8;
    const uint8_t* sender_ip = arp + 14;
    const uint8_t* target_ip = arp + 24;
    if (kmemcmp(target_ip, g_nic_ip, 4u) != 0) {
        return;
    }
    kmemcpy(g_host_mac, sender_mac, 6u);
    kmemcpy(g_host_ip, sender_ip, 4u);
    g_host_mac_known = 1;

    uint8_t reply[42];
    kmemcpy(reply + 0, sender_mac, 6u);
    kmemcpy(reply + 6, g_nic_mac, 6u);
    *(uint16_t*)(reply + 12) = htons(0x0806u);
    *(uint16_t*)(reply + 14) = htons(1u);
    *(uint16_t*)(reply + 16) = htons(0x0800u);
    reply[18] = 6;
    reply[19] = 4;
    *(uint16_t*)(reply + 20) = htons(2u);
    kmemcpy(reply + 22, g_nic_mac, 6u);
    kmemcpy(reply + 28, g_nic_ip, 4u);
    kmemcpy(reply + 32, sender_mac, 6u);
    kmemcpy(reply + 38, sender_ip, 4u);
    rtl8139_send(reply, 42u);
}

static void handle_icmp_echo(const uint8_t* frame, uint16_t len) {
    if (len < 42u) {
        return;
    }
    const uint8_t* ip = frame + 14;
    uint8_t ihl = (uint8_t)((ip[0] & 0x0Fu) * 4u);
    if (ihl < 20u || len < (uint16_t)(14u + ihl + 8u)) {
        return;
    }
    uint16_t total_len = ntohs(*(const uint16_t*)(ip + 2));
    if (total_len < ihl + 8u || len < (uint16_t)(14u + total_len)) {
        return;
    }
    if (ip[9] != 1u) {
        return;
    }
    const uint8_t* src_ip = ip + 12;
    const uint8_t* dst_ip = ip + 16;
    if (kmemcmp(dst_ip, g_nic_ip, 4u) != 0) {
        return;
    }
    const uint8_t* icmp = ip + ihl;
    if (icmp[0] != 8u || icmp[1] != 0u) {
        return;
    }
    uint16_t frame_len = (uint16_t)(14u + total_len);
    uint8_t reply[1600];
    kmemcpy(reply, frame, frame_len);

    kmemcpy(reply + 0, frame + 6, 6u);
    kmemcpy(reply + 6, g_nic_mac, 6u);
    kmemcpy(reply + 26, g_nic_ip, 4u);
    kmemcpy(reply + 30, src_ip, 4u);

    uint8_t* rip = reply + 14;
    rip[8] = 64u;
    rip[10] = 0u;
    rip[11] = 0u;
    *(uint16_t*)(rip + 10) = htons(ip_checksum(rip, ihl));

    uint8_t* ricmp = rip + ihl;
    ricmp[0] = 0u;
    ricmp[2] = 0u;
    ricmp[3] = 0u;
    *(uint16_t*)(ricmp + 2) = htons(ip_checksum(ricmp, (uint16_t)(total_len - ihl)));
    rtl8139_send(reply, frame_len);
}

static void handle_udp_packet(const uint8_t* frame, uint16_t len) {
    if (len < 42u) {
        return;
    }
    const uint8_t* ip = frame + 14;
    uint8_t ihl = (uint8_t)((ip[0] & 0x0Fu) * 4u);
    if (ihl < 20u || len < (uint16_t)(14u + ihl + 8u)) {
        return;
    }
    uint16_t total_len = ntohs(*(const uint16_t*)(ip + 2));
    if (total_len < ihl + 8u || len < (uint16_t)(14u + total_len)) {
        return;
    }
    if (ip[9] != 17u || kmemcmp(ip + 16, g_nic_ip, 4u) != 0) {
        return;
    }
    const uint8_t* udp = ip + ihl;
    uint16_t src_port = ntohs(*(const uint16_t*)(udp + 0));
    uint16_t dst_port = ntohs(*(const uint16_t*)(udp + 2));
    uint16_t udp_len = ntohs(*(const uint16_t*)(udp + 4));
    if (udp_len < 8u || (uint16_t)(ihl + udp_len) > total_len) {
        return;
    }
    const uint8_t* payload = udp + 8;
    uint16_t payload_len = (uint16_t)(udp_len - 8u);

    if (dst_port == g_udp_echo_port) {
        put_char_at('U', VGA_COLOR_LIGHT_GREY, 0, 4);
        put_char_at('D', VGA_COLOR_LIGHT_GREY, 1, 4);
        put_char_at('P', VGA_COLOR_LIGHT_GREY, 2, 4);
        put_char_at(':', VGA_COLOR_LIGHT_GREY, 3, 4);
        put_char_at((char)('0' + ((payload_len / 10u) % 10u)), VGA_COLOR_LIGHT_GREY, 5, 4);
        put_char_at((char)('0' + (payload_len % 10u)), VGA_COLOR_LIGHT_GREY, 6, 4);
        if (payload_len > 0u) {
            uint8_t ch = payload[0];
            if (ch < 32u || ch > 126u) {
                ch = '.';
            }
            put_char_at((char)ch, VGA_COLOR_LIGHT_GREY, 8, 4);
        }
        kmemcpy(g_host_mac, frame + 6, 6u);
        kmemcpy(g_host_ip, ip + 12, 4u);
        g_host_mac_known = 1;
        send_udp_ipv4(g_host_mac, g_host_ip, g_udp_echo_port, src_port, payload, payload_len);
    } else if (dst_port == g_dns_src_port) {
        dns_handle_response(payload, payload_len);
    }
}

static void handle_tcp_packet(const uint8_t* frame, uint16_t len) {
    if (len < 54u) {
        return;
    }
    const uint8_t* ip = frame + 14;
    uint8_t ihl = (uint8_t)((ip[0] & 0x0Fu) * 4u);
    if (ihl < 20u || len < (uint16_t)(14u + ihl + 20u)) {
        return;
    }
    uint16_t total_len = ntohs(*(const uint16_t*)(ip + 2));
    if (total_len < ihl + 20u || len < (uint16_t)(14u + total_len)) {
        return;
    }
    if (ip[9] != 6u || kmemcmp(ip + 16, g_nic_ip, 4u) != 0) {
        return;
    }
    const uint8_t* tcp = ip + ihl;
    uint8_t data_off = (uint8_t)((tcp[12] >> 4) * 4u);
    if (data_off < 20u || (uint16_t)(ihl + data_off) > total_len) {
        return;
    }
    uint16_t src_port = ntohs(*(const uint16_t*)(tcp + 0));
    uint16_t dst_port = ntohs(*(const uint16_t*)(tcp + 2));
    uint32_t seq = ntohl(*(const uint32_t*)(tcp + 4));
    uint32_t ack = ntohl(*(const uint32_t*)(tcp + 8));
    uint8_t flags = tcp[13];
    uint16_t payload_len = (uint16_t)(total_len - ihl - data_off);

    if (dst_port != g_tcp_listen_port) {
        return;
    }

    if (g_tcp.state == TCP_STATE_LISTEN) {
        if ((flags & 0x02u) != 0u) { /* SYN */
            kmemcpy(g_tcp.src_mac, frame + 6, 6u);
            kmemcpy(g_tcp.src_ip, ip + 12, 4u);
            g_tcp.src_port = src_port;
            g_tcp.dst_port = dst_port;
            g_tcp.iss = 0x1000u + (g_ticks & 0xFFu);
            g_tcp.snd_nxt = g_tcp.iss + 1u;
            g_tcp.rcv_nxt = seq + 1u;
            g_tcp.banner_sent = 0u;
            g_tcp.fin_sent = 0u;
            send_tcp_ipv4(g_tcp.src_mac, g_tcp.src_ip, g_tcp.dst_port, g_tcp.src_port, g_tcp.iss, g_tcp.rcv_nxt, 0x12u, NULL, 0u); /* SYN+ACK */
            g_tcp.state = TCP_STATE_SYN_RCVD;
            put_char_at('T', VGA_COLOR_LIGHT_GREY, 0, 5);
            put_char_at('C', VGA_COLOR_LIGHT_GREY, 1, 5);
            put_char_at('P', VGA_COLOR_LIGHT_GREY, 2, 5);
            put_char_at(':', VGA_COLOR_LIGHT_GREY, 3, 5);
            put_char_at('S', VGA_COLOR_LIGHT_GREY, 5, 5);
        }
        return;
    }

    if (g_tcp.state == TCP_STATE_SYN_RCVD) {
        if (src_port == g_tcp.src_port &&
            kmemcmp(ip + 12, g_tcp.src_ip, 4u) == 0 &&
            (flags & 0x10u) != 0u &&
            ack == g_tcp.snd_nxt &&
            seq == g_tcp.rcv_nxt) {
            g_tcp.state = TCP_STATE_ESTABLISHED;
            put_char_at('E', VGA_COLOR_LIGHT_GREY, 5, 5);
            static const uint8_t http_resp[] =
                "HTTP/1.0 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Hello from TinyOS TCP server!\r\n";
            send_tcp_ipv4(
                g_tcp.src_mac, g_tcp.src_ip,
                g_tcp.dst_port, g_tcp.src_port,
                g_tcp.snd_nxt, g_tcp.rcv_nxt,
                0x18u,
                http_resp, (uint16_t)(sizeof(http_resp) - 1u)
            ); /* PSH+ACK */
            g_tcp.snd_nxt += (uint32_t)(sizeof(http_resp) - 1u);
            g_tcp.banner_sent = 1u;
            send_tcp_ipv4(
                g_tcp.src_mac, g_tcp.src_ip,
                g_tcp.dst_port, g_tcp.src_port,
                g_tcp.snd_nxt, g_tcp.rcv_nxt,
                0x11u,
                NULL, 0u
            ); /* FIN+ACK */
            g_tcp.snd_nxt += 1u;
            g_tcp.fin_sent = 1u;
        }
        return;
    }

    if (g_tcp.state == TCP_STATE_ESTABLISHED) {
        if (src_port != g_tcp.src_port || kmemcmp(ip + 12, g_tcp.src_ip, 4u) != 0) {
            return;
        }
        if (payload_len > 0u && seq == g_tcp.rcv_nxt) {
            g_tcp.rcv_nxt += payload_len;
            send_tcp_ipv4(g_tcp.src_mac, g_tcp.src_ip, g_tcp.dst_port, g_tcp.src_port, g_tcp.snd_nxt, g_tcp.rcv_nxt, 0x10u, NULL, 0u);
            put_char_at('D', VGA_COLOR_LIGHT_GREY, 7, 5);
        } else if ((flags & 0x01u) != 0u) { /* FIN */
            g_tcp.rcv_nxt = seq + 1u;
            send_tcp_ipv4(g_tcp.src_mac, g_tcp.src_ip, g_tcp.dst_port, g_tcp.src_port, g_tcp.snd_nxt, g_tcp.rcv_nxt, 0x10u, NULL, 0u);
            g_tcp.state = TCP_STATE_LISTEN;
            put_char_at('L', VGA_COLOR_LIGHT_GREY, 5, 5);
        } else if (g_tcp.fin_sent && (flags & 0x10u) != 0u && ack == g_tcp.snd_nxt) {
            g_tcp.state = TCP_STATE_LISTEN;
            put_char_at('L', VGA_COLOR_LIGHT_GREY, 5, 5);
        }
    }
}

static void handle_ipv4_packet(const uint8_t* frame, uint16_t len) {
    if (len < 34u) {
        return;
    }
    const uint8_t* ip = frame + 14;
    if ((ip[0] >> 4) != 4u) {
        return;
    }
    if (ip[9] == 1u) {
        handle_icmp_echo(frame, len);
    } else if (ip[9] == 17u) {
        handle_udp_packet(frame, len);
    } else if (ip[9] == 6u) {
        handle_tcp_packet(frame, len);
    }
}

static void handle_ethernet_frame(const uint8_t* frame, uint16_t len) {
    if (len < 14u) {
        return;
    }
    uint16_t eth_type = ntohs(*(const uint16_t*)(frame + 12));
    if (eth_type == 0x0806u) {
        handle_arp_packet(frame, len);
    } else if (eth_type == 0x0800u) {
        handle_ipv4_packet(frame, len);
    }
}

static void rtl8139_poll_rx(void) {
    if (g_rtl_io_base == 0) {
        return;
    }
    while ((inb(g_rtl_io_base + 0x37u) & 0x01u) == 0u) {
        uint8_t* packet = g_rtl_rx_buf + g_rtl_rx_offset;
        uint16_t status = *(uint16_t*)(packet + 0);
        uint16_t len = *(uint16_t*)(packet + 2);
        if ((status & 0x01u) != 0u && len >= 64u && len <= 1600u) {
            uint16_t payload_len = (uint16_t)(len - 4u);
            handle_ethernet_frame(packet + 4, payload_len);
        }
        g_rtl_rx_offset = (g_rtl_rx_offset + len + 4u + 3u) & ~3u;
        g_rtl_rx_offset %= 8192u;
        outw(g_rtl_io_base + 0x38u, (uint16_t)((g_rtl_rx_offset - 16u) & 0x1FFFu));
    }
    outw(g_rtl_io_base + 0x3Eu, 0xFFFFu);
}

static void init_rtl8139(void) {
    uint8_t bus = 0;
    uint8_t slot = 0;
    uint8_t func = 0;
    if (!pci_scan_for_rtl8139(&bus, &slot, &func)) {
        kprintf("pci: rtl8139 not found\n");
        return;
    }
    uint32_t bar0 = pci_config_read32(bus, slot, func, 0x10);
    g_rtl_io_base = (uint16_t)(bar0 & ~3u);
    uint16_t cmd = pci_config_read16(bus, slot, func, 0x04);
    cmd |= 0x0005u;
    uint32_t cmdreg = pci_config_read32(bus, slot, func, 0x04);
    cmdreg = (cmdreg & 0xFFFF0000u) | cmd;
    pci_config_write32(bus, slot, func, 0x04, cmdreg);

    outb(g_rtl_io_base + 0x52u, 0x00u);
    outb(g_rtl_io_base + 0x37u, 0x10u);
    while ((inb(g_rtl_io_base + 0x37u) & 0x10u) != 0u) {
    }

    outl(g_rtl_io_base + 0x30u, (uint32_t)(uintptr_t)g_rtl_rx_buf);
    outl(g_rtl_io_base + 0x44u, 0x0000E70Fu);
    outl(g_rtl_io_base + 0x40u, 0x00000300u);
    outw(g_rtl_io_base + 0x3Cu, 0x0005u);
    outw(g_rtl_io_base + 0x3Eu, 0xFFFFu);
    outb(g_rtl_io_base + 0x37u, 0x0Cu);

    for (int i = 0; i < 6; ++i) {
        g_nic_mac[i] = inb(g_rtl_io_base + (uint16_t)i);
    }
    kprintf("pci: rtl8139 b%u:s%u io=0x%x\n", bus, slot, g_rtl_io_base);
    kprintf("nic: mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%u.%u.%u.%u\n",
        g_nic_mac[0], g_nic_mac[1], g_nic_mac[2], g_nic_mac[3], g_nic_mac[4], g_nic_mac[5],
        g_nic_ip[0], g_nic_ip[1], g_nic_ip[2], g_nic_ip[3]);
}

static void set_idt_gate(int vector, void (*handler)(void), uint8_t flags) {
    uint32_t addr = (uint32_t)handler;
    g_idt[vector].offset_low = (uint16_t)(addr & 0xFFFF);
    g_idt[vector].selector = 0x08;
    g_idt[vector].zero = 0;
    g_idt[vector].type_attr = flags;
    g_idt[vector].offset_high = (uint16_t)((addr >> 16) & 0xFFFF);
}

static void set_gdt_entry(int index, uint32_t base, uint32_t limit, uint8_t access, uint8_t gran) {
    g_gdt[index].base_low = (uint16_t)(base & 0xFFFFu);
    g_gdt[index].base_mid = (uint8_t)((base >> 16) & 0xFFu);
    g_gdt[index].base_high = (uint8_t)((base >> 24) & 0xFFu);
    g_gdt[index].limit_low = (uint16_t)(limit & 0xFFFFu);
    g_gdt[index].granularity = (uint8_t)(((limit >> 16) & 0x0Fu) | (gran & 0xF0u));
    g_gdt[index].access = access;
}

static void kmemzero(void* dst, uint32_t size) {
    kmemset(dst, 0u, size);
}

static void init_gdt_tss(void) {
    kmemzero(g_gdt, (uint32_t)sizeof(g_gdt));
    set_gdt_entry(0, 0u, 0u, 0u, 0u);
    set_gdt_entry(1, 0u, 0xFFFFFu, 0x9Au, 0xCFu);
    set_gdt_entry(2, 0u, 0xFFFFFu, 0x92u, 0xCFu);
    set_gdt_entry(3, 0u, 0xFFFFFu, 0xFAu, 0xCFu);
    set_gdt_entry(4, 0u, 0xFFFFFu, 0xF2u, 0xCFu);

    kmemzero(&g_tss, (uint32_t)sizeof(g_tss));
    g_tss.ss0 = 0x10u;
    g_tss.esp0 = (uint32_t)(uintptr_t)(g_ring0_stack + sizeof(g_ring0_stack));
    g_tss.cs = 0x0Bu;
    g_tss.ss = 0x13u;
    g_tss.ds = 0x13u;
    g_tss.es = 0x13u;
    g_tss.fs = 0x13u;
    g_tss.gs = 0x13u;
    g_tss.iomap_base = (uint16_t)sizeof(g_tss);

    set_gdt_entry(5, (uint32_t)(uintptr_t)&g_tss, (uint32_t)sizeof(g_tss) - 1u, 0x89u, 0x40u);
    g_gdtr.limit = (uint16_t)(sizeof(g_gdt) - 1u);
    g_gdtr.base = (uint32_t)(uintptr_t)&g_gdt[0];

    gdt_flush(&g_gdtr, 0x10u, 0x08u);
    tss_flush(0x28u);
}

static void load_idt(void) {
    struct idt_ptr idtr;
    idtr.limit = (uint16_t)(sizeof(g_idt) - 1);
    idtr.base = (uint32_t)&g_idt[0];
    __asm__ volatile ("lidt %0" : : "m"(idtr));
}

static void remap_pic(void) {
    uint8_t mask1 = inb(PIC1_DATA);
    uint8_t mask2 = inb(PIC2_DATA);

    outb(PIC1_COMMAND, 0x11);
    io_wait();
    outb(PIC2_COMMAND, 0x11);
    io_wait();

    outb(PIC1_DATA, 0x20);
    io_wait();
    outb(PIC2_DATA, 0x28);
    io_wait();

    outb(PIC1_DATA, 0x04);
    io_wait();
    outb(PIC2_DATA, 0x02);
    io_wait();

    outb(PIC1_DATA, 0x01);
    io_wait();
    outb(PIC2_DATA, 0x01);
    io_wait();

    outb(PIC1_DATA, mask1);
    outb(PIC2_DATA, mask2);
}

static void init_pit(uint32_t hz) {
    if (hz < 19) {
        hz = 19;
    }
    if (hz > 1193180u) {
        hz = 1193180u;
    }
    uint16_t divisor = (uint16_t)(1193180u / hz);
    outb(PIT_COMMAND, 0x36);
    outb(PIT_CHANNEL0, (uint8_t)(divisor & 0xFF));
    outb(PIT_CHANNEL0, (uint8_t)((divisor >> 8) & 0xFF));
}

static void init_idt(void) {
    for (int i = 0; i < 256; ++i) {
        set_idt_gate(i, isr_default, 0x8E);
    }
    for (int irq = 0; irq < 16; ++irq) {
        set_idt_gate(32 + irq, g_irq_stubs[irq], 0x8E);
    }
    set_idt_gate(0x80, isr_syscall, 0xEE);
    load_idt();
}

uint32_t irq_handler_c(uint32_t irq, uint32_t current_esp) {
    static const char spinner[4] = {'|', '/', '-', '\\'};
    uint32_t next_esp = current_esp;
    if (irq == 0) {
        ++g_ticks;
        if ((g_ticks % 10u) == 0u) {
            put_char_at(spinner[(g_ticks / 10u) & 3u], VGA_COLOR_LIGHT_GREY, 0, 0);
            put_char_at((char)('0' + ((g_ticks / 10u) % 10u)), VGA_COLOR_LIGHT_GREY, 2, 0);
        }
        if (g_scheduler_enabled && g_task_count > 0) {
            if (g_current_task >= 0) {
                g_tasks[g_current_task].esp = current_esp;
            }
            if (g_current_task < 0) {
                g_current_task = 0;
            } else {
                g_current_task = (g_current_task + 1) % g_task_count;
            }
            next_esp = g_tasks[g_current_task].esp;
        }
    } else if (irq == 1) {
        uint8_t scancode = inb(0x60);
        put_char_at('K', VGA_COLOR_LIGHT_GREY, 0, 1);
        put_char_at(':', VGA_COLOR_LIGHT_GREY, 1, 1);
        static const char hex_digits[17] = "0123456789ABCDEF";
        put_char_at(hex_digits[(scancode >> 4) & 0x0F], VGA_COLOR_LIGHT_GREY, 3, 1);
        put_char_at(hex_digits[scancode & 0x0F], VGA_COLOR_LIGHT_GREY, 4, 1);
    }
    if (irq >= 8) {
        outb(PIC2_COMMAND, 0x20);
    }
    outb(PIC1_COMMAND, 0x20);
    return next_esp;
}

uint32_t syscall_handler_c(uint32_t* regs_top) {
    uint32_t eax = regs_top[7];
    if (eax == 1u) {
        ++g_syscall_ticks;
        put_char_at('U', VGA_COLOR_LIGHT_GREY, 0, 3);
        put_char_at(':', VGA_COLOR_LIGHT_GREY, 1, 3);
        put_char_at((char)('0' + (g_syscall_ticks % 10u)), VGA_COLOR_LIGHT_GREY, 3, 3);
        return g_syscall_ticks;
    }
    return 0xFFFFFFFFu;
}

void default_handler_c(void) {
    outb(PIC1_COMMAND, 0x20);
    outb(PIC2_COMMAND, 0x20);
}

void kernel_main(void) {
    clear_screen(VGA_COLOR_LIGHT_GREY);
    g_cursor_x = 0;
    g_cursor_y = 0;
    kprintf("TinyOS kernel start\n");
    kprintf("T: _\n");
    kprintf("K: --\n");

    init_paging();
    init_gdt_tss();
    kprintf("paging: on (identity 0-4MB)\n");
    kprintf("gdt: ring3+tss ready\n");

    init_heap();
    void* a = kmalloc(64);
    void* b = kmalloc_aligned(128, 16u);
    void* c = kcalloc(32, 4);
    char fmt_buf[64];
    ksnprintf(fmt_buf, sizeof(fmt_buf), "fmt test: %08x %d", 0x1AFu, -42);
    kprintf("heap: start=0x%x end=0x%x\n", (uint32_t)(uintptr_t)&__kernel_end, g_heap_end);
    kprintf("alloc: a=0x%x b=0x%x c=0x%x\n", (uint32_t)(uintptr_t)a, (uint32_t)(uintptr_t)b, (uint32_t)(uintptr_t)c);
    kprintf("%s\n", fmt_buf);
    kfree(b);
    void* d = kmalloc_aligned(96, 32u);
    kprintf("reuse: d=0x%x\n", (uint32_t)(uintptr_t)d);
    create_task(task_a);
    create_task(task_b);
    kprintf("sched: round-robin tasks=%d\n", g_task_count);

    remap_pic();
    init_idt();
    init_pit(100);

    outb(PIC1_DATA, 0xFC);
    outb(PIC2_DATA, 0xFF);
    g_scheduler_enabled = 0;

    init_rtl8139();
    kprintf("net: arp+icmp+udp+dns ready\n");
    kprintf("udp: listen=%u send->host:%u\n", g_udp_echo_port, g_udp_out_port);
    g_tcp.state = TCP_STATE_LISTEN;
    kprintf("tcp: listen=%u (3-way handshake)\n", g_tcp_listen_port);

    __asm__ volatile ("sti");

    for (;;) {
        if (!g_host_mac_known && (g_ticks % 100u) == 0u) {
            send_arp_request(g_host_ip);
        }
        if (g_host_mac_known && (g_ticks - g_udp_last_tx_tick) >= 100u) {
            static const uint8_t msg[] = "hello from kernel udp";
            send_udp_ipv4(g_host_mac, g_host_ip, g_udp_echo_port, g_udp_out_port, msg, (uint16_t)(sizeof(msg) - 1u));
            g_udp_last_tx_tick = g_ticks;
        }
        if (g_host_mac_known && !g_dns_query_sent) {
            dns_send_query("example.com");
        }
        rtl8139_poll_rx();
        __asm__ volatile ("hlt");
    }
}
