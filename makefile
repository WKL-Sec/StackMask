CCX64	:= x86_64-w64-mingw32-gcc
CCX86	:= i686-w64-mingw32-gcc

OUTX64	:= stackMask.exe

all: x64

x64:
	@ echo Compiling the code...
	@ $(CCX64) stackMask.c -o $(OUTX64)
