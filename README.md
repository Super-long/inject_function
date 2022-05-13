# 项目说明

这个项目实现了向目标pid的write函数注入任意延迟的功能(目前仅仅支持x86-64)，执行以下语句复现：


1. g++ e.cpp -g -o e.out
2. cd fakefunc
3. gcc fake_write.c -fPIE -DX=3 -DY=100000 -O2 -c 
4. cd .. 
5. ./e.out (ps -ef | grep e.out)检查此进程pid
6. sudo -s echo 0 > /proc/sys/kernel/randomize_va_space 关闭PIE
7. go build -o inject inject.go load_fake_fun.go wrapper_linux.go 
8. ./inject --pid={pid}
