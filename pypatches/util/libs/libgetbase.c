/* libgetbase.c - Get the base address of the binary */

#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if __aarch64__
#error "getbase not implemented for aarch64"
#elif __arm__
#error "getbase not implemented for arm"
#elif __ppc__
#error "getbase not implemented for ppc"
#elif __ppc64__
#error "getbase not implemented for ppc64"
#elif __sparc__
#error "getbase not implemented for sparc"
#elif __mips__
#error "getbase not implemented for mips"
#elif __alpha__
#error "getbase not implemented for alpha"
#elif __i386__
#error "getbase not implemented for i386"
#elif __x86_64__

uint64_t _getbase(void) {
  char buf[4096];
  char *maps_str = "/proc/self/maps";
  int fd = _syscall3(SYS_open, maps_str, O_RDONLY, 0);
  _syscall3(SYS_read, fd, buf, sizeof(buf));
  _syscall1(SYS_close, fd);
  uint64_t base = 0;
  char *bufp = &buf[0];
  char c;
  char v;
  // Hexstr to int
  while ((c = *bufp++) != '-') {
    v = (c & 0xf) + (c >> 6) | ((c >> 3) & 0x8);
    base = (base << 4) | (uint64_t)v;
  }
  return base;
}
#else
#error
#endif