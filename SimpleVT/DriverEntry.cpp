
#include <ntifs.h>
#include "SimpleVT.h"
#include <intrin.h>

void* __cdecl operator new(unsigned __int64 size) {
	PHYSICAL_ADDRESS highest;

	highest.QuadPart = 0xFFFFFFFFFFFFFFFF;
	return MmAllocateContiguousMemory(size, highest);
}

typedef struct _DPC_CONTEXT {
	ULONG_PTR Cr3;
} DPC_CONTEXT, *PDPC_CONTEXT;

EXTERN_C
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);

EXTERN_C
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);

EXTERN_C
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);

VOID VTLoadDpc(
	_In_ struct _KDPC *Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	//UNREFERENCED_PARAMETER(DeferredContext);
	PDPC_CONTEXT ctx = (PDPC_CONTEXT)DeferredContext;

	DbgPrint("Current Processor : %d\n", KeGetCurrentProcessorIndex());

	SimpleVT* vt = new SimpleVT();
	vt->SetRootmodeCR3(ctx->Cr3);

	if (vt->Install()) {
		DbgPrint("Success!\n");
	}
	else {
		DbgPrint("Failed!\n");
	}

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);

	return;
}

VOID VTLoad(void)
{
	DPC_CONTEXT ctx;

	ctx.Cr3 = __readcr3();

	KeGenericCallDpc(VTLoadDpc, &ctx);
	return;
}

#ifdef __cplusplus
#if __cplusplus
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING ustrRegPath)
#else
NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING ustrRegPath)
#endif
#endif 
{
	UNREFERENCED_PARAMETER(pDrvObj);
	UNREFERENCED_PARAMETER(ustrRegPath);

	DbgPrint("Driver Entry\n");

	SimpleVT* vt = new SimpleVT();
	vt->SetRootmodeCR3(__readcr3());
	if (vt->Install()) {
		DbgPrint("Success!\n");
	}
	else {
		DbgPrint("Failed!\n");
	}

	//VTLoad();

	int cpuid[4];

	__cpuidex(cpuid, 0x41414141, 0);
	DbgPrint("%x %x %x %x\n", cpuid[0], cpuid[1], cpuid[2], cpuid[3]);

	DbgPrint("Exit Driver Entry\n");

	return STATUS_SUCCESS;
}