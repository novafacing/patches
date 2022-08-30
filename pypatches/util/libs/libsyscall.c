/* libsyscall.c - Provide syscall wrappers */

#include <stdarg.h>
#include <stdint.h>

// I think
#define MAX_ARGS (7)

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
uint64_t _syscall(uint64_t nr, uint64_t arg0, uint64_t arg1, uint64_t arg2,
                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
  uint64_t rv;
  __asm__(".intel_syntax noprefix\n"
          "mov rax, %1\n"
          "mov rdi, %2\n"
          "mov rsi, %3\n"
          "mov rdx, %4\n"
          "mov r10, %5\n"
          "mov r8, %6\n"
          "mov r9, %7\n"
          "syscall\n"
          "mov %0, rax\n"
          : "=r"(rv)
          : "m"(nr), "m"(arg0), "m"(arg1), "m"(arg2), "m"(arg3), "m"(arg4),
            "m"(arg5)
          : "rax", "rdi", "rsi", "rdx", "r8", "r9", "r10", "r11", "r12", "r13",
            "r14", "r15", "memory");
  return rv;
}
#define _syscall0(nr)                                                          \
  _syscall(nr, (uint64_t)0, (uint64_t)0, (uint64_t)0, (uint64_t)0,             \
           (uint64_t)0, (uint64_t)0)
#define _syscall1(nr, a0)                                                      \
  _syscall(nr, (uint64_t)a0, (uint64_t)0, (uint64_t)0, (uint64_t)0,            \
           (uint64_t)0, (uint64_t)0)
#define _syscall2(nr, a0, a1)                                                  \
  _syscall(nr, (uint64_t)a0, (uint64_t)a1, (uint64_t)0, (uint64_t)0,           \
           (uint64_t)0, (uint64_t)0)
#define _syscall3(nr, a0, a1, a2)                                              \
  _syscall(nr, (uint64_t)a0, (uint64_t)a1, (uint64_t)a2, (uint64_t)0,          \
           (uint64_t)0, (uint64_t)0)
#define _syscall4(nr, a0, a1, a2, a3)                                          \
  _syscall(nr, (uint64_t)a0, (uint64_t)a1, (uint64_t)a2, (uint64_t)a3,         \
           (uint64_t)0, (uint64_t)0)
#define _syscall5(nr, a0, a1, a2, a3, a4)                                      \
  _syscall(nr, (uint64_t)a0, (uint64_t)a1, (uint64_t)a2, (uint64_t)a3,         \
           (uint64_t)a4, (uint64_t)0)
#define _syscall6(nr, a0, a1, a2, a3, a4, a5)                                  \
  _syscall(nr, (uint64_t)a0, (uint64_t)a1, (uint64_t)a2, (uint64_t)a3,         \
           (uint64_t)a4, (uint64_t)a5)
#else
#error
#endif