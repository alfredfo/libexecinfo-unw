#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define D10(x) ceil(log10(((x) == 0) ? 2 : ((x) + 1)))

inline static void *
realloc_safe(void *ptr, size_t size) {
    void *nptr;

    nptr = realloc(ptr, size);
    if (nptr == NULL)
        free(ptr);
    return nptr;
}

int backtrace(void** buffer, int size) {
  unw_cursor_t cur;
  unw_context_t ctx;

  unw_getcontext(&ctx);
  unw_init_local(&cur, &ctx);
  unw_step(&cur); // step over the 'backtrace' call. (this function)
  int i = 0;

  do {
    if (++i == size) {
      return i - 1;
    }
    unw_word_t ip;
    unw_get_reg(&cur, UNW_REG_IP, &ip);
    buffer[i - 1] = (void*)ip;
  } while (unw_step(&cur));
  return i - 1;
}

// pasted from resslinux/libexecinfo

char **backtrace_symbols(void *const *buffer, int size) {
  size_t clen, alen;
  int i, offset;
  char **rval;
  Dl_info info;

  clen = size * sizeof(char *);
  rval = malloc(clen);
  if (rval == NULL)
    return NULL;
  for (i = 0; i < size; i++) {
    if (dladdr(buffer[i], &info) != 0) {
      if (info.dli_sname == NULL) {
        info.dli_sname = "???"; // "cannot find symbol name :d ";
      }
      if (info.dli_saddr == NULL) {
        info.dli_saddr = buffer[i];
      }
      offset = buffer[i] - info.dli_saddr;
      /* "0x01234567 <function+offset> at filename" */
      alen = 2 +                      /* "0x" */
        (sizeof(void *) * 2) +   /* "01234567" */
        2 +                      /* " <" */
        strlen(info.dli_sname) + /* "function" */
        1 +                      /* "+" */
        10 +                     /* "offset */
        5 +                      /* "> at " */
        strlen(info.dli_fname) + /* "filename" */
        1;                       /* "\0" */
      rval = realloc_safe(rval, clen + alen);
      if (rval == NULL)
        return NULL;
      snprintf((char *) rval + clen, alen, "%p <%s+%d> at %s",
               buffer[i], info.dli_sname, offset, info.dli_fname);
    } else {
      alen = 2 +                      /* "0x" */
        (sizeof(void *) * 2) +   /* "01234567" */
        1;                       /* "\0" */
      rval = realloc_safe(rval, clen + alen);
      if (rval == NULL)
        return NULL;
      snprintf((char *) rval + clen, alen, "%p", buffer[i]);
    }
    rval[i] = (char *) clen;
    clen += alen;
  }

  for (i = 0; i < size; i++)
    rval[i] += (long) rval;

  return rval;
}

void backtrace_symbols_fd(void *const *buffer, int size, int fd) {
    int i, len, offset;
    char *buf;
    Dl_info info;

    for (i = 0; i < size; i++) {
        if (dladdr(buffer[i], &info) != 0) {
            if (info.dli_sname == NULL)
                info.dli_sname = "???";
            if (info.dli_saddr == NULL)
                info.dli_saddr = buffer[i];
            offset = buffer[i] - info.dli_saddr;
            /* "0x01234567 <function+offset> at filename" */
            len = 2 +                      /* "0x" */
                  (sizeof(void *) * 2) +   /* "01234567" */
                  2 +                      /* " <" */
                  strlen(info.dli_sname) + /* "function" */
                  1 +                      /* "+" */
                  D10(offset) +            /* "offset */
                  5 +                      /* "> at " */
                  strlen(info.dli_fname) + /* "filename" */
                  2;                       /* "\n\0" */
            buf = alloca(len);
            if (buf == NULL)
                return;
            snprintf(buf, len, "%p <%s+%d> at %s\n",
              buffer[i], info.dli_sname, offset, info.dli_fname);
        } else {
            len = 2 +                      /* "0x" */
                  (sizeof(void *) * 2) +   /* "01234567" */
                  2;                       /* "\n\0" */
            buf = alloca(len);
            if (buf == NULL)
                return;
            snprintf(buf, len, "%p\n", buffer[i]);
        }
        write(fd, buf, strlen(buf));
    }
}
