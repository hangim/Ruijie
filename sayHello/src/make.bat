@echo off
g++ process.cpp -c
g++ -I..\WpdPack\Include sayHello.cpp -c -Wno-write-strings -fexec-charset=GBK
g++ -L..\WpdPack\Lib process.o sayHello.o -o ..\bin\sayHello.exe -lwpcap -lpacket -lws2_32 -pthread
del process.o sayHello.o