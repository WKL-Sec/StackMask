//---------------------
//Author: Kleiton Kurti
//Twitter: @kleiton0x7e
//----------------------
//To compile
//x86_64-w64-mingw32-gcc stackMask.c
//----------------------
//A stack encryptor prior to custom sleeping by leveraging CPU cycles

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

DWORD WINAPI EncryptThread(LPVOID lpParameter);

unsigned long long __get_timestamp()
{
	const size_t UNIX_TIME_START = 0x019DB1DED53E8000; // Start of Unix epoch in ticks.
	const size_t TICKS_PER_MILLISECOND = 10000; // A tick is 100ns.
	LARGE_INTEGER time;
	time.LowPart = *(DWORD*)(0x7FFE0000 + 0x14); // Read LowPart as unsigned long.
	time.HighPart = *(long*)(0x7FFE0000 + 0x1c); // Read High1Part as long.
	return (unsigned long long)((time.QuadPart - UNIX_TIME_START) / TICKS_PER_MILLISECOND);
}

void __alt_sleepms(size_t ms)
{
	volatile size_t x = rand(); // random buffer var 
	const unsigned long long end = __get_timestamp() + ms; // calculate when we shall stop sleeping
	while (__get_timestamp() < end) { x += 1; } // increment random var by 1 till we reach our endtime
	if (__get_timestamp() - end > 2000) return; // Fast Forward check, might need some tuning	
}

int main() {

    //some variables to save on stack
    //const char secret[] = "this is my super secret private message stored in stack";

    // Get the values of RSP via assembly
    unsigned char *rsp;
    asm("movq %%rsp, %0;" : "=r" (rsp));
    printf("[+] The address of rsp is %p\n", rsp);

    // create a thread to perform the encryption and decryption
    HANDLE hThread = CreateThread(NULL, 0, EncryptThread, rsp, 0, NULL);
    if (hThread == NULL) {
        printf("[-] Failed to create thread\n");
        return 1;
    }

    // wait for 2 seconds to allow the thread to perform the encryption
    __alt_sleepms(2*1000); //performing a custom sleep for 5 seconds

    // resume the thread to allow it to perform the decryption
    printf("[+] Resuming encryption thread\n");
    ResumeThread(hThread);

    // wait for 5 seconds to allow the decryption to finish
    printf("[+] Sleeping for 5 seconds...\n");
    __alt_sleepms(5*1000); //performing a custom sleep for 5 seconds

    // suspend the thread again
    printf("[+] Suspending encryption thread\n");
    SuspendThread(hThread);

    // clean up and exit
    CloseHandle(hThread);
    printf("[+] Done\n");

    return 0;
}

DWORD WINAPI EncryptThread(LPVOID lpParameter) {
    //saving the XOR key in Heap, so it won't get changed during stack encryption
    char *key = (char*) malloc(13*sizeof(char));
    strcpy(key, "myprivatekey");
    int keyLength = strlen(key);
    
    // cast the parameter to the stack pointer
    unsigned char *rsp = (unsigned char *) lpParameter;
    
    // Get the address range of the stack where the shellcode is stored
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(rsp, &mbi, sizeof(mbi));

    //calculate the stack Base (bottom of Stack) and the size of it
    unsigned char *stackRegion = mbi.BaseAddress - 8192;
    unsigned char *stackBase = stackRegion + mbi.RegionSize + 8192;
    int stackSize = stackBase - rsp;
    printf("[+] The address of stack region: 0x%p\n", stackRegion);
    printf("[+] The address of stack base: 0x%p\n", stackBase);
    printf("[+] The stack size: %d bytes\n", stackSize);

    // mask the stack with a XOR key
    unsigned char *p = (unsigned char *)rsp;
    for (int i = 0; i < stackSize; i++) {
        *(p++) ^= key[i % keyLength];
    }

    printf("[+] Stack is encrypted\n");

    // wait to be resumed by the main thread
    printf("[+] Encryption thread suspended\n");
    __alt_sleepms(5*1000); //performing a custom sleep for 5 seconds

    // unmask the stack
    unsigned char *h = (unsigned char *)rsp;
    for (int i = 0; i < stackSize; i++) {
        *(h++) ^= key[i % keyLength];
    }
    
    printf("[+] Stack is decrypted\n");
    free(key);
}
