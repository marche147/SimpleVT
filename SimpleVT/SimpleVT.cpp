
#include <ntifs.h>
#include <intrin.h>
#include "SimpleVT.h"

#ifndef _VT_DEBUG
#define VMERR_RET(x, s) if((x) != 0) return FALSE;
#else
#define VMERR_RET(x, s) if((x) != 0) { DbgPrint("%s Failure\n", s); return FALSE; }
#endif 

#define VMWRITE_ERR_RET(e, v, s) VMERR_RET(vmwrite(e, v), "vmwrite-" s)
#define VMREAD_ERR_RET(e, v, s) VMERR_RET(vmread(e, v), "vmread-" s)

/* May fails with VMError, check return value */
__forceinline unsigned char vmwrite(VMCSFIELD Encoding, ULONG_PTR Value)
{
	return __vmx_vmwrite(Encoding, Value);
}

__forceinline unsigned char vmread(VMCSFIELD Encoding, ULONG_PTR* Value)
{
	return __vmx_vmread(Encoding, Value);
}

__forceinline unsigned char vmlaunch(void)
{
	return __vmx_vmlaunch();
}

__forceinline unsigned char vmresume(void)
{
	return __vmx_vmresume();
}

__forceinline unsigned char vmxon(ULONG_PTR VmxRegion)
{
	return __vmx_on(&VmxRegion);
}

__forceinline void vmxoff(void)
{
	return __vmx_off();
}

__forceinline unsigned char vmclear(ULONG_PTR Vmcs)
{
	return __vmx_vmclear(&Vmcs);
}

__forceinline unsigned char vmptrld(ULONG_PTR Vmcs)
{
	return __vmx_vmptrld(&Vmcs);
}

__forceinline void vmptrst(ULONG_PTR Vmcs)
{
	return __vmx_vmptrst(&Vmcs);
}

SimpleVT::SimpleVT()
{
	/* Allocate vmx region and vmcs */
	m_VMXRegion = reinterpret_cast<ULONG_PTR*>(MmAllocateNonCachedMemory(PAGE_SIZE));
	if (m_VMXRegion) RtlSecureZeroMemory(m_VMXRegion, PAGE_SIZE);
	m_VMCS = reinterpret_cast<ULONG_PTR*>(MmAllocateNonCachedMemory(PAGE_SIZE));
	if (m_VMCS) RtlSecureZeroMemory(m_VMCS, PAGE_SIZE);
	m_VMXOn = FALSE;

	return;
}

BOOLEAN SimpleVT::CheckVTSupported(void) {
	int ctx[4];		// EAX, EBX, ECX, EDX
	BOOLEAN result = TRUE;

	/* check processor capability */
	__cpuidex(ctx, 1, 0);
	if ((ctx[2] & CPUID_1_ECX_VMX) == 0) {	// check VMX bit
		result = FALSE;
	}

	return result;
}

BOOLEAN SimpleVT::CheckVTEnabled(void) {
	ULONG_PTR msr;

	msr = __readmsr(IA32_FEATURE_CONTROL_CODE);
	if ((msr & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX) == 0)	return FALSE;
	return TRUE;
}

BOOLEAN SimpleVT::InitVMCS(void) {
	ULONG_PTR ReturnAddress;
	PHYSICAL_ADDRESS VmcsPhysAddr, VmxRegionPhysAddr;

	ReturnAddress = reinterpret_cast<ULONG_PTR>(_ReturnAddress());

	if (!m_VMCS || !m_VMXRegion) {	/* memory allocation failure */
		return FALSE;
	}
	VmcsPhysAddr = MmGetPhysicalAddress(m_VMCS);
	VmxRegionPhysAddr = MmGetPhysicalAddress(m_VMXRegion);

	/* Check features */
	m_VmxBasic = __readmsr(IA32_VMX_BASIC_MSR_CODE);
	m_VmxFeatureControl = __readmsr(IA32_FEATURE_CONTROL_CODE);

	*(m_VMXRegion) = m_VmxBasic;
	*(m_VMCS) = m_VmxBasic;

	/* Enable VMX Operation */
	__writecr4(__readcr4() | CR4_VMXE);

	/* Initialize guest state */
	// {
	m_GuestState.cs = __readcs();
	m_GuestState.ds = __readds();
	m_GuestState.ss = __readss();
	m_GuestState.es = __reades();
	m_GuestState.fs = __readfs();
	m_GuestState.gs = __readgs();
	m_GuestState.ldtr = __sldt();
	m_GuestState.tr = __str();
	m_GuestState.rip = ReturnAddress;
	m_GuestState.rflags = __readeflags();
	m_GuestState.rsp = _StackPointer();
	__sgdt(&(m_GuestState.gdt));
	__sidt(&(m_GuestState.idt));
	m_GuestState.cr3 = __readcr3();
	m_GuestState.cr0 = (__readcr0() & (__readmsr(IA32_VMX_CR0_FIXED0) | __readmsr(IA32_VMX_CR0_FIXED1) | CR0_PE | CR0_NE | CR0_PG));
	m_GuestState.cr4 = (__readcr4() & (__readmsr(IA32_VMX_CR4_FIXED0) | __readmsr(IA32_VMX_CR4_FIXED1) | CR4_VMXE | CR4_DE));
	// }

	/* Setup VMX */
	VMERR_RET(vmxon(VmxRegionPhysAddr.QuadPart), "vmxon");	// vmxon
	DbgPrint("vmxon success\n");
	m_VMXOn = TRUE;

	VMERR_RET(vmclear(VmcsPhysAddr.QuadPart), "vmclear");
	VMERR_RET(vmptrld(VmcsPhysAddr.QuadPart), "vmptrld");
	DbgPrint("VMCS loaded\n");

	/* Setup Guest VMCS */
	// B.1.2 16-Bit Guest state fields
	VMWRITE_ERR_RET(GUEST_ES_SELECTOR, m_GuestState.es, "ES_Selector");
	VMWRITE_ERR_RET(GUEST_CS_SELECTOR, m_GuestState.es, "CS_Selector");
	VMWRITE_ERR_RET(GUEST_SS_SELECTOR, m_GuestState.es, "SS_Selector");
	VMWRITE_ERR_RET(GUEST_DS_SELECTOR, m_GuestState.es, "DS_Selector");
	VMWRITE_ERR_RET(GUEST_FS_SELECTOR, m_GuestState.es, "FS_Selector");
	VMWRITE_ERR_RET(GUEST_GS_SELECTOR, m_GuestState.es, "GS_Selector");
	VMWRITE_ERR_RET(GUEST_LDTR_SELECTOR, m_GuestState.ldtr, "LDTR_Selector");
	VMWRITE_ERR_RET(GUEST_TR_SELECTOR, m_GuestState.tr, "TR_Selector");



	return FALSE;
}