/* libgetreg.c - Helper library to directly get a register value in C */

#if __aarch64__
#error "syscall not implemented for aarch64"
#elif __arm__
#error "syscall not implemented for arm"
#elif __ppc__
#error "syscall not implemented for ppc"
#elif __ppc64__
#error "syscall not implemented for ppc64"
#elif __sparc__
#error "syscall not implemented for sparc"
#elif __mips__
#error "syscall not implemented for mips"
#elif __alpha__
#error "syscall not implemented for alpha"
#elif __i386__
#error "syscall not implemented for i386"
#elif __x86_64__
#define getreg(dest, src)                                                      \
  register long long dest __asm__(#src);                                       \
  __asm__("" : "=r"(dest));

#define getip(dest)                                                            \
  uintptr_t dest = 0;                                                          \
  __asm__(".intel_syntax noprefix\n"                                           \
          "lea %V0, [rip+0];\n"                                                \
          : "=r"(dest)                                                         \
          :                                                                    \
          : "rax");
#else
#error
#endif