
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>

int main(int argc, char* argv[])
{
	int CPUInfo[4];

	printf("CPUID(0x41414141)");

	__cpuidex(CPUInfo, 0x41414141, 0x12345678);

	printf("EAX = %08X EBX = %08X\n", CPUInfo[0], CPUInfo[1]);
	printf("ECX = %08X EDX = %08X\n", CPUInfo[2], CPUInfo[3]);
	return 0;
}