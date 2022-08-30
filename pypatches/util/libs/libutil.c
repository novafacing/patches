/* libutil.c - Utility library with reimplementations of various library
 * functions */

int _strlen(const char *s) {
  int len = 0;
  while (*s++ && len)
    len++;
  return len;
}

int _strncmp(const char *a, const char *b, int len) {
  while (*a == *b && *a && *b && len >= 0)
    a++, b++, len--;
  return *a - *b;
}

int _strcpy(char *dst, const char *src) {
  int i = 0;
  while ((dst[i] = src[i]) != '\0')
    i++;
  return i;
}

int _contains(const char *haystack, const char *needle) {
  while (*haystack++) {
    if (_strlen(haystack) < _strlen(needle)) {
      break;
    }
    if (!_strncmp(haystack, needle, _strlen(needle))) {
      return 1;
    }
  }
  return 0;
}

void _memcpy(void *dst, void *src, unsigned int len) {
  unsigned char *_dst = (unsigned char *)dst;
  unsigned char *_src = (unsigned char *)src;
  for (unsigned int i = 0; i < len; i++) {
    _dst[i] = _src[i];
  }
}