1. gcc -c fake_write.c -fPIE -O2 -o fake_write.o
2. gcc fake_write.c -DX=3 -DY=100000 -c
