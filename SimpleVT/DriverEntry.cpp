
#include <ntifs.h>
#include "SimpleVT.h"

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

	NTSTATUS s = STATUS_UNSUCCESSFUL;

	return s;
}