#include <unistd.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>
#include <sys/syscall.h>
#include <fcntl.h>

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
    real_nanosleep(&req, NULL);
    printf("nihao\n");
    getchar();
    int fd = open("hello.txt", O_CREAT | O_WRONLY , 0777);
    write(1, "nihao a", 7);
    write(1, "nihao a", 7);
    write(1, "nihao a", 7);
    fsync(fd);

    return 0;
}