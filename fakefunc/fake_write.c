/*
 * Copyright 2021 Chaos Mesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <time.h>
#include <inttypes.h>
#include <sys/syscall.h>


#if defined(__amd64__)
inline int real_write(int fd, const void *buf, size_t count) {
  //return syscall(__NR_write, fd, buf, count);
  int ret;
  asm volatile
    (
      "syscall"
      : "=a" (ret)
      : "0"(__NR_write), "D"(fd), "S"(buf), "d"(count)
      : "rcx", "r11", "memory"
    );

  return ret;
}
#elif defined(__aarch64__)
inline int real_write(int fd, const void *buf, size_t count)
//inline int real_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    register int w0 __asm__("w0");

    register int x0 __asm__("x0") = fd;
    register const void*x1 __asm__("x1") = buf;
	register size_t x2 __asm__("x2") = count;
    register uint64_t w8 __asm__("w8") = SYS_write; /* syscall number */
    __asm__ __volatile__(
        "svc 0;"
        : "+r"(w0)
        : "r"(x0), "r" (x1), "r"(x2) ,"r"(w8)
        : "memory");

    return w0;
}
#endif

int write(int fd, const void *buf, size_t count) {
  struct timespec req;
  req.tv_sec = X;
  req.tv_nsec = Y;
  nanosleep(&req, NULL);
  
  return real_write(fd, buf, count);
}