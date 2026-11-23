/* Independent qemu-i386 harness for the genuine E2E Crunch wrapper.
 *
 * Loads the genuine SysUpdt.embedded.elf image at 0x608000, patches the
 * three allocator entry points (operator new 0x657c80, malloc 0x657c40,
 * free 0x6569a0) to bump-allocator stubs at 0x90000, then calls the
 * genuine wrapper fcn.006470c0(input, insize, &outbuf, &outsize).
 *
 * Build: gcc -m32 -nostdlib -static -fno-pic -no-pie -o qemu_harness qemu_harness.c
 * Run:   qemu-i386 ./qemu_harness vxworks-image.bin e2_fw-vxWorks.bin out.bin
 */
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define IMG_BASE   0x608000u
#define IMG_MAP    0x600000u
#define IMG_SIZE   0x200000u
#define INPUT_BASE 0x1000000u
#define INPUT_MAX  0x1000000u
#define OUTPUT_MAX 0x1000000u
#define STUB_PAGE  0x90000u
#define HEAP_PTR   0x90100u
#define HEAP_BASE  0x15000000u
#define HEAP_END   0x19000000u

#define WRAPPER    0x6470c0u
#define STREAM_OFF 6u

static long sys1(long n, long a)
{ long r; asm volatile("int $0x80" : "=a"(r) : "a"(n), "b"(a) : "memory"); return r; }
static long sys3(long n, long a, long b, long c)
{ long r; asm volatile("int $0x80" : "=a"(r) : "a"(n), "b"(a), "c"(b), "d"(c) : "memory"); return r; }

static void *map_fixed(u32 addr, u32 len)
{
    /* old_mmap (90) takes a pointer to 6 args: avoids ebp reg constraint */
    u32 args[6];
    args[0] = addr;
    args[1] = len;
    args[2] = 7;        /* PROT_READ|PROT_WRITE|PROT_EXEC */
    args[3] = 0x32;     /* MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED */
    args[4] = (u32)-1;
    args[5] = 0;
    return (void *)sys1(90, (long)args);
}

static void puts_(const char *s)
{
    u32 n = 0;
    while (s[n]) n++;
    sys3(4, 1, (long)s, n);
}

static void put_hex(u32 v)
{
    char buf[11];
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 8; i++) {
        u32 nib = (v >> ((7 - i) * 4)) & 0xf;
        buf[2 + i] = nib < 10 ? '0' + nib : 'a' + nib - 10;
    }
    buf[10] = '\n';
    sys3(4, 1, (long)buf, 11);
}

static int read_file(const char *path, u32 addr, u32 max)
{
    int fd = (int)sys3(5, (long)path, 0, 0);
    if (fd < 0) return -1;
    u32 total = 0;
    for (;;) {
        long n = sys3(3, fd, addr + total, max - total);
        if (n <= 0) break;
        total += (u32)n;
        if (total >= max) break;
    }
    sys1(6, fd);
    return (int)total;
}

/* bump allocator stub: returns old heap ptr, advances by align16(size)     */
/* fail returns 0. free stub: plain ret.                                    */
static const u8 stub_alloc[] = {
    0xA1, 0x00, 0x01, 0x09, 0x00,             /* mov eax,[0x90100]      */
    0x8B, 0x4C, 0x24, 0x04,                   /* mov ecx,[esp+4]        */
    0x83, 0xC1, 0x0F,                         /* add ecx,15             */
    0x83, 0xE1, 0xF0,                         /* and ecx,-16            */
    0x01, 0xC1,                               /* add ecx,eax            */
    0x81, 0xF9, 0x00, 0x00, 0x00, 0x19,       /* cmp ecx,HEAP_END       */
    0x77, 0x05,                               /* ja fail                */
    0x89, 0x0D, 0x00, 0x01, 0x09, 0x00,       /* mov [0x90100],ecx      */
    0xC3,                                     /* ret                    */
    0x31, 0xC0,                               /* fail: xor eax,eax      */
    0xC3,                                     /* ret                    */
};
#define STUB_FREE (STUB_PAGE + 0x40)

static void patch_hook(u8 *img, u32 va, u32 stub)
{
    u8 *p = img + (va - IMG_BASE);
    p[0] = 0xB8;                              /* mov eax, stub */
    p[1] = (u8)stub;
    p[2] = (u8)(stub >> 8);
    p[3] = (u8)(stub >> 16);
    p[4] = (u8)(stub >> 24);
    p[5] = 0xFF;                              /* jmp eax */
    p[6] = 0xE0;
}

__attribute__((naked)) void _start(void)
{
    asm volatile("mov %esp,%eax\n\tpush %eax\n\tcall c_start\n");
}

void c_start(u32 *sp)
{
    char **argv = (char **)&sp[1];
    if (sp[0] < 4) { puts_("usage: harness image input output\n"); sys1(1, 2); }

    if (!map_fixed(IMG_MAP, IMG_SIZE)) { puts_("map img fail\n"); sys1(1, 1); }
    if (!map_fixed(INPUT_BASE, INPUT_MAX)) { puts_("map in fail\n"); sys1(1, 1); }
    if (!map_fixed(HEAP_BASE, HEAP_END - HEAP_BASE)) { puts_("map heap fail\n"); sys1(1, 1); }
    if (!map_fixed(STUB_PAGE, 0x2000)) { puts_("map stub fail\n"); sys1(1, 1); }

    u8 *img = (u8 *)IMG_BASE;
    int imgsz = read_file(argv[1], IMG_BASE, IMG_SIZE - (IMG_BASE - IMG_MAP));
    int insz = read_file(argv[2], INPUT_BASE, INPUT_MAX);
    if (imgsz <= 0 || insz <= (int)STREAM_OFF) { puts_("read fail\n"); sys1(1, 1); }

    u8 *stub = (u8 *)STUB_PAGE;
    for (u32 i = 0; i < sizeof(stub_alloc); i++) stub[i] = stub_alloc[i];
    *(u8 *)STUB_FREE = 0xC3;                  /* free: ret */
    *(u32 *)HEAP_PTR = HEAP_BASE;

    patch_hook(img, 0x657c80u, STUB_PAGE);    /* operator new */
    patch_hook(img, 0x657c40u, STUB_PAGE);    /* malloc       */
    patch_hook(img, 0x6569a0u, STUB_FREE);    /* free         */

    u32 outbuf = 0, outsize = 0;
    u32 input = INPUT_BASE + STREAM_OFF;
    u32 input_size = (u32)insz - STREAM_OFF;
    int (*wrapper)(u32, u32, u32 *, u32 *) = (void *)WRAPPER;
    int ok = wrapper(input, input_size, &outbuf, &outsize);

    u8 *obj = (u8 *)HEAP_BASE;
    u32 declared = *(u32 *)(input + 4);
    u32 produced = *(u32 *)(obj + 0x14);
    u32 consumed = *(u32 *)(obj + 0x04) - input;
    u32 flags = *(u16 *)(obj + 0x20);
    u32 heapbuf = ((HEAP_BASE + 0xef74) + 15u) & ~15u;

    puts_("ok=");       put_hex((u32)ok);
    puts_("declared="); put_hex(declared);
    puts_("produced="); put_hex(produced);
    puts_("consumed="); put_hex(consumed);
    puts_("flags=");    put_hex(flags);
    puts_("outbuf=");   put_hex(outbuf);
    puts_("outsize=");  put_hex(outsize);

    if (ok != 1 && produced == declared && produced <= OUTPUT_MAX) {
        outbuf = heapbuf;
        outsize = produced;
        puts_("dumping buffer despite wrapper rejection\n");
    }
    if (outbuf && outsize && outsize <= OUTPUT_MAX) {
        int fd = (int)sys3(5, (long)argv[3], 0x241, 0666); /* O_WRONLY|CREAT|TRUNC */
        if (fd >= 0) {
            u32 done = 0;
            while (done < outsize) {
                long n = sys3(4, fd, outbuf + done, outsize - done);
                if (n <= 0) break;
                done += (u32)n;
            }
            sys1(6, fd);
        }
    }
    sys1(1, ok == 1 ? 0 : 3);
}
