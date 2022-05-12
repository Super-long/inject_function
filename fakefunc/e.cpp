#include <unistd.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>
#include <sys/syscall.h>

inline int real_nanosleep(const struct timespec *req, struct timespec *rem) {
  int ret;
  asm volatile
    (
      "syscall"
      : "=a" (ret)
      : "0"(__NR_nanosleep), "D"(req), "S"(rem)
      : "rcx", "r11", "memory"
    );

  return ret;
}

int main() {
    struct timespec req;
    req.tv_sec = 3;
    req.tv_nsec = 2;
    nanosleep(&req, NULL);
    printf("nihao\n");
    getchar();
    write(1, "nihao a", 10);
    write(1, "nihao a", 10);
    write(1, "nihao a", 10);
    return 0;
}