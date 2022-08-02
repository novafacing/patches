#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void mutate(char *str) {
  const char *newstr = "Hello, Girls!";
  memcpy(str, newstr, strlen(str));
}

int main() {
  char *str = strdup("Hello, World!");

  mutate(str);

  puts("Hello, world!");
  puts("Goodbye, world!");
  puts(str);
  free(str);
  int rv = 1;
  rv = 0;
  return rv;
}