#pragma once

/* CPUID */
// {
#define CPUID_1_ECX_VMX (1<<5)
// }

/* CR3 */
// {
#define CR3_PWT (1 << 3)    /**< Page-level Writes Transparent */
#define CR3_PCD (1 << 4)    /**< Page-level Cache Disable */
// }

/* CR4 */
// {
#define CR3_PWT (1 << 3)    /**< Page-level Writes Transparent */
#define CR3_PCD (1 << 4)    /**< Page-level Cache Disable */

#define CR4_VME (1 << 0)    /**< Virtual-8086 Mode Extensions */
#define CR4_PVI (1 << 1)    /**< Protected-mode Virtual Interrupt */
#define CR4_TSD (1 << 2)    /**< Time Stamp Disable */
#define CR4_DE  (1 << 3)    /**< Debugging Extensions */
#define CR4_PSE (1 << 4)    /**< Page Size Extensions */
#define CR4_PAE (1 << 5)    /**< Physical Address Extension */
#define CR4_MCE (1 << 6)    /**< Machine Check Enable */
#define CR4_PGE (1 << 7)    /**< Page Global Enable */
#define CR4_PCE (1 << 8)    /**< Performance-monitoring Counter Enable */
#define CR4_OSFXSR (1 << 9) /**< Operating System Support FXSAVE/FXSTOR */
/** Operating System Support for Unmasked SIMD Floating-Point Exceptions
*
* @note Intel's naming convention has gotten out of hand.
*/
#define CR4_OSXMMEXCPT (1 << 10)
#define CR4_VMXE (1 << 13)  /**< Virtual-Machine eXtensions Enable */
#define CR4_SMXE (1 << 14)  /**< Safer-Mode eXtensions Enable */
// }

/* CR0 */
// {
#define CR0_PE  (1 << 0)    /**< Protection Enable */
#define CR0_MP  (1 << 1)    /**< Monitor coProcessor (FPU) */
#define CR0_EM  (1 << 2)    /**< EMulation (FPU) */
#define CR0_TS  (1 << 3)    /**< Task Switched */
#define CR0_ET  (1 << 4)    /**< Extension Type (FPU) */
#define CR0_NE  (1 << 5)    /**< Numeric Error */
#define CR0_WP  (1 << 16)   /**< Write Protect */
/** Alignment Mask.
*
* @note On to enable alignment checks.  This is not the only relevant
*       bit for alignment checking -- see EFLAGS:AM.
*/
#define CR0_AM  (1 << 18)
#define CR0_NW  (1 << 29)   /**< Not Write-through */
#define CR0_CD  (1 << 30)   /**< Cache Disable */
#define CR0_PG  (1 << 31)   /**< PaGing */
// }

/* CR8 */
// {
#define CR8_TPL_MASK  0x0000000F  /**< Task Priority Level (64-bit mode) */
// }

enum VMCSFIELD {
	VIRTUAL_PROCESSOR_ID = 0x00000000,
	POSTED_INTR_NOTIFICATION_VECTOR = 0x00000002,
	EPTP_INDEX = 0x00000004,
	GUEST_ES_SELECTOR = 0x00000800,
	GUEST_CS_SELECTOR = 0x00000802,
	GUEST_SS_SELECTOR = 0x00000804,
	GUEST_DS_SELECTOR = 0x00000806,
	GUEST_FS_SELECTOR = 0x00000808,
	GUEST_GS_SELECTOR = 0x0000080a,
	GUEST_LDTR_SELECTOR = 0x0000080c,
	GUEST_TR_SELECTOR = 0x0000080e,
	GUEST_INTR_STATUS = 0x00000810,
	GUEST_PML_INDEX = 0x00000812,
	HOST_ES_SELECTOR = 0x00000c00,
	HOST_CS_SELECTOR = 0x00000c02,
	HOST_SS_SELECTOR = 0x00000c04,
	HOST_DS_SELECTOR = 0x00000c06,
	HOST_FS_SELECTOR = 0x00000c08,
	HOST_GS_SELECTOR = 0x00000c0a,
	HOST_TR_SELECTOR = 0x00000c0c,
	IO_BITMAP_A = 0x00002000,
	IO_BITMAP_B = 0x00002002,
	MSR_BITMAP = 0x00002004,
	VM_EXIT_MSR_STORE_ADDR = 0x00002006,
	VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
	VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
	PML_ADDRESS = 0x0000200e,
	TSC_OFFSET = 0x00002010,
	VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
	APIC_ACCESS_ADDR = 0x00002014,
	PI_DESC_ADDR = 0x00002016,
	VM_FUNCTION_CONTROL = 0x00002018,
	EPT_POINTER = 0x0000201a,
	EOI_EXIT_BITMAP0 = 0x0000201c,
	EPTP_LIST_ADDR = 0x00002024,
	VMREAD_BITMAP = 0x00002026,
	VMWRITE_BITMAP = 0x00002028,
	VIRT_EXCEPTION_INFO = 0x0000202a,
	XSS_EXIT_BITMAP = 0x0000202c,
	TSC_MULTIPLIER = 0x00002032,
	GUEST_PHYSICAL_ADDRESS = 0x00002400,
	VMCS_LINK_POINTER = 0x00002800,
	GUEST_IA32_DEBUGCTL = 0x00002802,
	GUEST_PAT = 0x00002804,
	GUEST_EFER = 0x00002806,
	GUEST_PERF_GLOBAL_CTRL = 0x00002808,
	GUEST_PDPTE0 = 0x0000280a,
	GUEST_BNDCFGS = 0x00002812,
	HOST_PAT = 0x00002c00,
	HOST_EFER = 0x00002c02,
	HOST_PERF_GLOBAL_CTRL = 0x00002c04,
	PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
	CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
	EXCEPTION_BITMAP = 0x00004004,
	PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	CR3_TARGET_COUNT = 0x0000400a,
	VM_EXIT_CONTROLS = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VM_ENTRY_CONTROLS = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VM_ENTRY_INTR_INFO = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	TPR_THRESHOLD = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
	PLE_GAP = 0x00004020,
	PLE_WINDOW = 0x00004022,
	VM_INSTRUCTION_ERROR = 0x00004400,
	VM_EXIT_REASON = 0x00004402,
	VM_EXIT_INTR_INFO = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE = 0x00004406,
	IDT_VECTORING_INFO = 0x00004408,
	IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMX_INSTRUCTION_INFO = 0x0000440e,
	GUEST_ES_LIMIT = 0x00004800,
	GUEST_CS_LIMIT = 0x00004802,
	GUEST_SS_LIMIT = 0x00004804,
	GUEST_DS_LIMIT = 0x00004806,
	GUEST_FS_LIMIT = 0x00004808,
	GUEST_GS_LIMIT = 0x0000480a,
	GUEST_LDTR_LIMIT = 0x0000480c,
	GUEST_TR_LIMIT = 0x0000480e,
	GUEST_GDTR_LIMIT = 0x00004810,
	GUEST_IDTR_LIMIT = 0x00004812,
	GUEST_ES_AR_BYTES = 0x00004814,
	GUEST_CS_AR_BYTES = 0x00004816,
	GUEST_SS_AR_BYTES = 0x00004818,
	GUEST_DS_AR_BYTES = 0x0000481a,
	GUEST_FS_AR_BYTES = 0x0000481c,
	GUEST_GS_AR_BYTES = 0x0000481e,
	GUEST_LDTR_AR_BYTES = 0x00004820,
	GUEST_TR_AR_BYTES = 0x00004822,
	GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
	GUEST_ACTIVITY_STATE = 0x00004826,
	GUEST_SMBASE = 0x00004828,
	GUEST_SYSENTER_CS = 0x0000482a,
	GUEST_PREEMPTION_TIMER = 0x0000482e,
	HOST_SYSENTER_CS = 0x00004c00,
	CR0_GUEST_HOST_MASK = 0x00006000,
	CR4_GUEST_HOST_MASK = 0x00006002,
	CR0_READ_SHADOW = 0x00006004,
	CR4_READ_SHADOW = 0x00006006,
	CR3_TARGET_VALUE0 = 0x00006008,
	EXIT_QUALIFICATION = 0x00006400,
	GUEST_LINEAR_ADDRESS = 0x0000640a,
	GUEST_CR0 = 0x00006800,
	GUEST_CR3 = 0x00006802,
	GUEST_CR4 = 0x00006804,
	GUEST_ES_BASE = 0x00006806,
	GUEST_CS_BASE = 0x00006808,
	GUEST_SS_BASE = 0x0000680a,
	GUEST_DS_BASE = 0x0000680c,
	GUEST_FS_BASE = 0x0000680e,
	GUEST_GS_BASE = 0x00006810,
	GUEST_LDTR_BASE = 0x00006812,
	GUEST_TR_BASE = 0x00006814,
	GUEST_GDTR_BASE = 0x00006816,
	GUEST_IDTR_BASE = 0x00006818,
	GUEST_DR7 = 0x0000681a,
	GUEST_RSP = 0x0000681c,
	GUEST_RIP = 0x0000681e,
	GUEST_RFLAGS = 0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
	GUEST_SYSENTER_ESP = 0x00006824,
	GUEST_SYSENTER_EIP = 0x00006826,
	HOST_CR0 = 0x00006c00,
	HOST_CR3 = 0x00006c02,
	HOST_CR4 = 0x00006c04,
	HOST_FS_BASE = 0x00006c06,
	HOST_GS_BASE = 0x00006c08,
	HOST_TR_BASE = 0x00006c0a,
	HOST_GDTR_BASE = 0x00006c0c,
	HOST_IDTR_BASE = 0x00006c0e,
	HOST_SYSENTER_ESP = 0x00006c10,
	HOST_SYSENTER_EIP = 0x00006c12,
	HOST_RSP = 0x00006c14,
	HOST_RIP = 0x00006c16,
};

/** @name VMX Basic Exit Reasons.
* @{
*/
/** -1 Invalid exit code */
#define VMX_EXIT_INVALID                                        -1
/** 0 Exception or non-maskable interrupt (NMI). */
#define VMX_EXIT_XCPT_OR_NMI                                    0
/** 1 External interrupt. */
#define VMX_EXIT_EXT_INT                                        1
/** 2 Triple fault. */
#define VMX_EXIT_TRIPLE_FAULT                                   2
/** 3 INIT signal. */
#define VMX_EXIT_INIT_SIGNAL                                    3
/** 4 Start-up IPI (SIPI). */
#define VMX_EXIT_SIPI                                           4
/** 5 I/O system-management interrupt (SMI). */
#define VMX_EXIT_IO_SMI                                         5
/** 6 Other SMI. */
#define VMX_EXIT_SMI                                            6
/** 7 Interrupt window exiting. */
#define VMX_EXIT_INT_WINDOW                                     7
/** 8 NMI window exiting. */
#define VMX_EXIT_NMI_WINDOW                                     8
/** 9 Task switch. */
#define VMX_EXIT_TASK_SWITCH                                    9
/** 10 Guest software attempted to execute CPUID. */
#define VMX_EXIT_CPUID                                          10
/** 11 Guest software attempted to execute GETSEC. */
#define VMX_EXIT_GETSEC                                         11
/** 12 Guest software attempted to execute HLT. */
#define VMX_EXIT_HLT                                            12
/** 13 Guest software attempted to execute INVD. */
#define VMX_EXIT_INVD                                           13
/** 14 Guest software attempted to execute INVLPG. */
#define VMX_EXIT_INVLPG                                         14
/** 15 Guest software attempted to execute RDPMC. */
#define VMX_EXIT_RDPMC                                          15
/** 16 Guest software attempted to execute RDTSC. */
#define VMX_EXIT_RDTSC                                          16
/** 17 Guest software attempted to execute RSM in SMM. */
#define VMX_EXIT_RSM                                            17
/** 18 Guest software executed VMCALL. */
#define VMX_EXIT_VMCALL                                         18
/** 19 Guest software executed VMCLEAR. */
#define VMX_EXIT_VMCLEAR                                        19
/** 20 Guest software executed VMLAUNCH. */
#define VMX_EXIT_VMLAUNCH                                       20
/** 21 Guest software executed VMPTRLD. */
#define VMX_EXIT_VMPTRLD                                        21
/** 22 Guest software executed VMPTRST. */
#define VMX_EXIT_VMPTRST                                        22
/** 23 Guest software executed VMREAD. */
#define VMX_EXIT_VMREAD                                         23
/** 24 Guest software executed VMRESUME. */
#define VMX_EXIT_VMRESUME                                       24
/** 25 Guest software executed VMWRITE. */
#define VMX_EXIT_VMWRITE                                        25
/** 26 Guest software executed VMXOFF. */
#define VMX_EXIT_VMXOFF                                         26
/** 27 Guest software executed VMXON. */
#define VMX_EXIT_VMXON                                          27
/** 28 Control-register accesses. */
#define VMX_EXIT_MOV_CRX                                        28
/** 29 Debug-register accesses. */
#define VMX_EXIT_MOV_DRX                                        29
/** 30 I/O instruction. */
#define VMX_EXIT_IO_INSTR                                       30
/** 31 RDMSR. Guest software attempted to execute RDMSR. */
#define VMX_EXIT_RDMSR                                          31
/** 32 WRMSR. Guest software attempted to execute WRMSR. */
#define VMX_EXIT_WRMSR                                          32
/** 33 VM-entry failure due to invalid guest state. */
#define VMX_EXIT_ERR_INVALID_GUEST_STATE                        33
/** 34 VM-entry failure due to MSR loading. */
#define VMX_EXIT_ERR_MSR_LOAD                                   34
/** 36 Guest software executed MWAIT. */
#define VMX_EXIT_MWAIT                                          36
/** 37 VM-exit due to monitor trap flag. */
#define VMX_EXIT_MTF                                            37
/** 39 Guest software attempted to execute MONITOR. */
#define VMX_EXIT_MONITOR                                        39
/** 40 Guest software attempted to execute PAUSE. */
#define VMX_EXIT_PAUSE                                          40
/** 41 VM-entry failure due to machine-check. */
#define VMX_EXIT_ERR_MACHINE_CHECK                              41
/** 43 TPR below threshold. Guest software executed MOV to CR8. */
#define VMX_EXIT_TPR_BELOW_THRESHOLD                            43
/** 44 APIC access. Guest software attempted to access memory at a physical address on the APIC-access page. */
#define VMX_EXIT_APIC_ACCESS                                    44
/** 45 Virtualized EOI. EOI virtualization was performed for a virtual interrupt
whose vector indexed a bit set in the EOI-exit bitmap. */
#define VMX_EXIT_VIRTUALIZED_EOI                                45
/** 46 Access to GDTR or IDTR. Guest software attempted to execute LGDT, LIDT, SGDT, or SIDT. */
#define VMX_EXIT_XDTR_ACCESS                                    46
/** 47 Access to LDTR or TR. Guest software attempted to execute LLDT, LTR, SLDT, or STR. */
#define VMX_EXIT_TR_ACCESS                                      47
/** 48 EPT violation. An attempt to access memory with a guest-physical address was disallowed by the configuration of the EPT paging structures. */
#define VMX_EXIT_EPT_VIOLATION                                  48
/** 49 EPT misconfiguration. An attempt to access memory with a guest-physical address encountered a misconfigured EPT paging-structure entry. */
#define VMX_EXIT_EPT_MISCONFIG                                  49
/** 50 INVEPT. Guest software attempted to execute INVEPT. */
#define VMX_EXIT_INVEPT                                         50
/** 51 RDTSCP. Guest software attempted to execute RDTSCP. */
#define VMX_EXIT_RDTSCP                                         51
/** 52 VMX-preemption timer expired. The preemption timer counted down to zero. */
#define VMX_EXIT_PREEMPT_TIMER                                  52
/** 53 INVVPID. Guest software attempted to execute INVVPID. */
#define VMX_EXIT_INVVPID                                        53
/** 54 WBINVD. Guest software attempted to execute WBINVD. */
#define VMX_EXIT_WBINVD                                         54
/** 55 XSETBV. Guest software attempted to execute XSETBV. */
#define VMX_EXIT_XSETBV                                         55
/** 56 APIC write. Guest completed write to virtual-APIC. */
#define VMX_EXIT_APIC_WRITE                                     56
/** 57 RDRAND. Guest software attempted to execute RDRAND. */
#define VMX_EXIT_RDRAND                                         57
/** 58 INVPCID. Guest software attempted to execute INVPCID. */
#define VMX_EXIT_INVPCID                                        58
/** 59 VMFUNC. Guest software attempted to execute VMFUNC. */
#define VMX_EXIT_VMFUNC                                         59
/** 60 ENCLS. Guest software attempted to execute ENCLS. */
#define VMX_EXIT_ENCLS                                          60
/** 61 - RDSEED - Guest software attempted to executed RDSEED and exiting was
* enabled. */
#define VMX_EXIT_RDSEED                                         61
/** 62 - Page-modification log full. */
#define VMX_EXIT_PML_FULL                                       62
/** 63 - XSAVES - Guest software attempted to executed XSAVES and exiting was
* enabled (XSAVES/XRSTORS was enabled too, of course). */
#define VMX_EXIT_XSAVES                                         63
/** 63 - XRSTORS - Guest software attempted to executed XRSTORS and exiting
* was enabled (XSAVES/XRSTORS was enabled too, of course). */
#define VMX_EXIT_XRSTORS                                        64
/** The maximum exit value (inclusive). */
#define VMX_EXIT_MAX                                            (VMX_EXIT_XRSTORS)
/** @} */

/* MSRs */
#define IA32_FEATURE_CONTROL_CODE		0x03A
#define IA32_SYSENTER_CS                        0x174
#define IA32_SYSENTER_ESP                       0x175
#define IA32_SYSENTER_EIP                       0x176
#define IA32_DEBUGCTL                           0x1D9
#define IA32_VMX_BASIC_MSR_CODE			0x480
#define IA32_VMX_PINBASED_CTLS                  0x481
#define IA32_VMX_PROCBASED_CTLS                 0x482
#define IA32_VMX_EXIT_CTLS                      0x483
#define IA32_VMX_ENTRY_CTLS                     0x484
#define IA32_VMX_MISC                           0x485
#define IA32_VMX_CR0_FIXED0                     0x486
#define IA32_VMX_CR0_FIXED1                     0x487
#define IA32_VMX_CR4_FIXED0                     0x488
#define IA32_VMX_CR4_FIXED1                     0x489
#define	IA32_FS_BASE    		   0xc0000100
#define	IA32_GS_BASE	                   0xc0000101
#define IA32_VMX_PROCBASED_CTLS2				0x0000048b

#define MSR_IA32_VMX_BASIC                      0x480
#define MSR_IA32_VMX_PINBASED_CTLS              0x481
#define MSR_IA32_VMX_PROCBASED_CTLS             0x482
#define MSR_IA32_VMX_EXIT_CTLS                  0x483
#define MSR_IA32_VMX_ENTRY_CTLS                 0x484
#define MSR_IA32_VMX_MISC                       0x485
#define MSR_IA32_VMX_CR0_FIXED0                 0x486
#define MSR_IA32_VMX_CR0_FIXED1                 0x487
#define MSR_IA32_VMX_CR4_FIXED0                 0x488
#define MSR_IA32_VMX_CR4_FIXED1                 0x489
#define MSR_IA32_VMX_VMCS_ENUM                  0x48a
#define MSR_IA32_VMX_PROCBASED_CTLS2            0x48b
#define MSR_IA32_VMX_EPT_VPID_CAP               0x48c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS         0x48d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS        0x48e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS             0x48f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS            0x490

#define MSR_IA32_MTRRCAP			0xfe
#define MSR_IA32_MTRR_DEF_TYPE			0x2ff
#define MSR_IA32_MTRR_PHYSBASE(n)		(0x200 + 2*(n))
#define MSR_IA32_MTRR_PHYSMASK(n)		(0x200 + 2*(n) + 1)
#define MSR_IA32_MTRR_FIX64K_00000		0x250
#define MSR_IA32_MTRR_FIX16K_80000		0x258
#define MSR_IA32_MTRR_FIX16K_A0000		0x259
#define MSR_IA32_MTRR_FIX4K_C0000		0x268
#define MSR_IA32_MTRR_FIX4K_C8000		0x269
#define MSR_IA32_MTRR_FIX4K_D0000		0x26a
#define MSR_IA32_MTRR_FIX4K_D8000		0x26b
#define MSR_IA32_MTRR_FIX4K_E0000		0x26c
#define MSR_IA32_MTRR_FIX4K_E8000		0x26d
#define MSR_IA32_MTRR_FIX4K_F0000		0x26e
#define MSR_IA32_MTRR_FIX4K_F8000		0x26f
#define MSR_GS_BASE 0xC0000101

#define CPU_BASED_VIRTUAL_INTR_PENDING          0x00000004
#define CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define CPU_BASED_HLT_EXITING                   0x00000080
#define CPU_BASED_INVLPG_EXITING                0x00000200
#define CPU_BASED_MWAIT_EXITING                 0x00000400
#define CPU_BASED_RDPMC_EXITING                 0x00000800
#define CPU_BASED_RDTSC_EXITING                 0x00001000
#define CPU_BASED_CR3_LOAD_EXITING              0x00008000
#define CPU_BASED_CR3_STORE_EXITING             0x00010000
#define CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define CPU_BASED_CR8_STORE_EXITING             0x00100000
#define CPU_BASED_TPR_SHADOW                    0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING           0x00400000
#define CPU_BASED_MOV_DR_EXITING                0x00800000
#define CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP            0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG             0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP           0x10000000
#define CPU_BASED_MONITOR_EXITING               0x20000000
#define CPU_BASED_PAUSE_EXITING                 0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000

#define PIN_BASED_EXT_INTR_MASK                 0x00000001
#define PIN_BASED_NMI_EXITING                   0x00000008
#define PIN_BASED_VIRTUAL_NMIS                  0x00000020
#define PIN_BASED_PREEMPT_TIMER                 0x00000040
#define PIN_BASED_POSTED_INTERRUPT              0x00000080

#define VM_EXIT_SAVE_DEBUG_CNTRLS               0x00000004
#define VM_EXIT_IA32E_MODE                      0x00000200
#define VM_EXIT_LOAD_PERF_GLOBAL_CTRL           0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VM_EXIT_SAVE_GUEST_PAT                  0x00040000
#define VM_EXIT_LOAD_HOST_PAT                   0x00080000
#define VM_EXIT_SAVE_GUEST_EFER                 0x00100000
#define VM_EXIT_LOAD_HOST_EFER                  0x00200000
#define VM_EXIT_SAVE_PREEMPT_TIMER              0x00400000
#define VM_EXIT_CLEAR_BNDCFGS                   0x00800000

#define VM_ENTRY_IA32E_MODE                     0x00000200
#define VM_ENTRY_SMM                            0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR             0x00000800
#define VM_ENTRY_LOAD_PERF_GLOBAL_CTRL          0x00002000
#define VM_ENTRY_LOAD_GUEST_PAT                 0x00004000
#define VM_ENTRY_LOAD_GUEST_EFER                0x00008000
#define VM_ENTRY_LOAD_BNDCFGS                   0x00010000

#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define SECONDARY_EXEC_ENABLE_EPT               0x00000002
#define SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING 0x00000004
#define SECONDARY_EXEC_ENABLE_RDTSCP            0x00000008
#define SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE   0x00000010
#define SECONDARY_EXEC_ENABLE_VPID              0x00000020
#define SECONDARY_EXEC_WBINVD_EXITING           0x00000040
#define SECONDARY_EXEC_UNRESTRICTED_GUEST       0x00000080
#define SECONDARY_EXEC_APIC_REGISTER_VIRT       0x00000100
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY    0x00000200
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING       0x00000400
#define SECONDARY_EXEC_ENABLE_INVPCID           0x00001000
#define SECONDARY_EXEC_ENABLE_VM_FUNCTIONS      0x00002000
#define SECONDARY_EXEC_ENABLE_VMCS_SHADOWING    0x00004000
#define SECONDARY_EXEC_ENABLE_PML               0x00020000
#define SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS   0x00040000
#define SECONDARY_EXEC_XSAVES                   0x00100000
#define SECONDARY_EXEC_PCOMMIT                  0x00200000
#define SECONDARY_EXEC_TSC_SCALING              0x02000000

#pragma pack(push,1)

/////////////////////////////
//  SPECIAL MSR REGISTERS  //
/////////////////////////////
typedef struct _IA32_VMX_BASIC_MSR
{
	unsigned RevId : 32;	// Bits 31...0 contain the VMCS revision identifier
	unsigned szVmxOnRegion : 12;	// Bits 43...32 report # of bytes for VMXON region 
	unsigned RegionClear : 1;	// Bit 44 set only if bits 32-43 are clear
	unsigned Reserved1 : 3;	// Undefined
	unsigned PhyAddrWidth : 1;	// Physical address width for referencing VMXON, VMCS, etc.
	unsigned DualMon : 1;	// Reports whether the processor supports dual-monitor
							// treatment of SMI and SMM
	unsigned MemType : 4;	// Memory type that the processor uses to access the VMCS
	unsigned VmExitReport : 1;	// Reports weather the procesor reports info in the VM-exit
								// instruction information field on VM exits due to execution
								// of the INS and OUTS instructions
	unsigned Reserved2 : 9;	// Undefined
} IA32_VMX_BASIC_MSR;

typedef struct _IA32_FEATURE_CONTROL_MSR
{
	unsigned Lock : 1;	// Bit 0 is the lock bit - cannot be modified once lock is set
	unsigned Reserved1 : 1;	// Undefined
	unsigned EnableVmxon : 1;	// Bit 2. If this bit is clear, VMXON causes a general protection exception
	unsigned Reserved2 : 29;	// Undefined
	unsigned Reserved3 : 32;	// Undefined
} IA32_FEATURE_CONTROL_MSR;

#define FEATURE_CONTROL_LOCKED	(1 << 0)
#define FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX	(1 << 1)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1 << 2)

/* EPT Structures */
// {
typedef struct _VMX_EPTP
{
	union
	{
		struct
		{
			UINT64 Type : 3;
			UINT64 PageWalkLength : 3;
			UINT64 EnableAccessAndDirtyFlags : 1;
			UINT64 Reserved : 5;
			UINT64 PageFrameNumber : 36;
			UINT64 ReservedHigh : 16;
		};
		UINT64 AsUlonglong;
	};
} VMX_EPTP, *PVMX_EPTP;

typedef struct _VMX_EPML4E
{
	union
	{
		struct
		{
			UINT64 Read : 1;
			UINT64 Write : 1;
			UINT64 Execute : 1;
			UINT64 Reserved : 5;
			UINT64 Accessed : 1;
			UINT64 SoftwareUse : 1;
			UINT64 UserModeExecute : 1;
			UINT64 SoftwareUse2 : 1;
			UINT64 PageFrameNumber : 36;
			UINT64 ReservedHigh : 4;
			UINT64 SoftwareUseHigh : 12;
		};
		UINT64 AsUlonglong;
	};
} VMX_EPML4E, *PVMX_EPML4E;

typedef struct _VMX_HUGE_PDPTE
{
	union
	{
		struct
		{
			UINT64 Read : 1;
			UINT64 Write : 1;
			UINT64 Execute : 1;
			UINT64 Type : 3;
			UINT64 IgnorePat : 1;
			UINT64 Large : 1;
			UINT64 Accessed : 1;
			UINT64 Dirty : 1;
			UINT64 UserModeExecute : 1;
			UINT64 SoftwareUse : 1;
			UINT64 Reserved : 18;
			UINT64 PageFrameNumber : 18;
			UINT64 ReservedHigh : 4;
			UINT64 SoftwareUseHigh : 11;
			UINT64 SupressVme : 1;
		};
		UINT64 AsUlonglong;
	};
} VMX_HUGE_PDPTE, *PVMX_HUGE_PDPTE;

typedef struct _VMX_PDPTE
{
	union
	{
		struct
		{
			UINT64 Read : 1;
			UINT64 Write : 1;
			UINT64 Execute : 1;
			UINT64 Reserved : 5;
			UINT64 Accessed : 1;
			UINT64 SoftwareUse : 1;
			UINT64 UserModeExecute : 1;
			UINT64 SoftwareUse2 : 1;
			UINT64 PageFrameNumber : 36;
			UINT64 ReservedHigh : 4;
			UINT64 SoftwareUseHigh : 12;
		};
		UINT64 AsUlonglong;
	};
} VMX_PDPTE, *PVMX_PDPTE;

typedef struct _VMX_LARGE_PDE
{
	union
	{
		struct
		{
			UINT64 Read : 1;
			UINT64 Write : 1;
			UINT64 Execute : 1;
			UINT64 Type : 3;
			UINT64 IgnorePat : 1;
			UINT64 Large : 1;
			UINT64 Accessed : 1;
			UINT64 Dirty : 1;
			UINT64 UserModeExecute : 1;
			UINT64 SoftwareUse : 1;
			UINT64 Reserved : 9;
			UINT64 PageFrameNumber : 27;
			UINT64 ReservedHigh : 4;
			UINT64 SoftwareUseHigh : 11;
			UINT64 SupressVme : 1;
		};
		UINT64 AsUlonglong;
	};
} VMX_LARGE_PDE, *PVMX_LARGE_PDE;

static_assert(sizeof(VMX_EPTP) == sizeof(UINT64), "EPTP Size Mismatch");
static_assert(sizeof(VMX_EPML4E) == sizeof(UINT64), "EPML4E Size Mismatch");
static_assert(sizeof(VMX_PDPTE) == sizeof(UINT64), "EPDPTE Size Mismatch");

#define PML4E_ENTRY_COUNT   512
#define PDPTE_ENTRY_COUNT   512
#define PDE_ENTRY_COUNT     512

typedef struct _VMX_EPT {
	DECLSPEC_ALIGN(PAGE_SIZE) VMX_EPML4E Epml4[PML4E_ENTRY_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) VMX_PDPTE Epdpt[PDPTE_ENTRY_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) VMX_LARGE_PDE Epde[PDPTE_ENTRY_COUNT][PDE_ENTRY_COUNT];
} VMX_EPT, *PVMX_EPT;
// }

#define SELECTOR_TABLE_INDEX    0x04

typedef union _KGDTENTRY64
{
	struct
	{
		UINT16 LimitLow;
		UINT16 BaseLow;
		union
		{
			struct
			{
				UINT8 BaseMiddle;
				UINT8 Flags1;
				UINT8 Flags2;
				UINT8 BaseHigh;
			} Bytes;
			struct
			{
				UINT32 BaseMiddle : 8;
				UINT32 Type : 5;
				UINT32 Dpl : 2;
				UINT32 Present : 1;
				UINT32 LimitHigh : 4;
				UINT32 System : 1;
				UINT32 LongMode : 1;
				UINT32 DefaultBig : 1;
				UINT32 Granularity : 1;
				UINT32 BaseHigh : 8;
			} Bits;
		};
		UINT32 BaseUpper;
		UINT32 MustBeZero;
	};
	struct
	{
		INT64 DataLow;
		INT64 DataHigh;
	};
} KGDTENTRY64, *PKGDTENTRY64;

/* GDT */
typedef struct _GDT {
	USHORT wLimit;
	ULONG_PTR ulBase;
} GDT, *PGDT;

/* GDT Entry */
typedef struct _GDTENTRY {

	union {
		struct {
			ULONG64 LimitLo : 16;
			ULONG64 BaseLo : 16;
			ULONG64 BaseMid : 8;
			ULONG64 Type : 4;
			ULONG64 S : 1;
			ULONG64 DPL : 2;
			ULONG64 P : 1;
			ULONG64 LimitHi : 4;
			ULONG64 A : 1;
			ULONG64 Reserved_0 : 1;
			ULONG64 DB : 1;
			ULONG64 G : 1;
			ULONG64 BaseHi : 8;
		} AsFields;
		struct {
			UCHAR Low1;
			UCHAR Low2;
			UCHAR Low3;
			UCHAR Low4;
			UCHAR Hi1;
			UCHAR Hi2;
			UCHAR Hi3;
			UCHAR Hi4;
		} AsBytes;
	} u;
	ULONG32 BaseUpper;
	ULONG32 Reserved_1;
} GDTENTRY, *PGDTENTRY;

static_assert(sizeof(GDTENTRY) == 2 * sizeof(ULONG_PTR), "GdtEntry Size");
#pragma pack(pop)

/* lowlevel.asm */
// {
EXTERN_C ULONG_PTR __readcs(void);
EXTERN_C ULONG_PTR __reades(void);
EXTERN_C ULONG_PTR __readfs(void);
EXTERN_C ULONG_PTR __readds(void);
EXTERN_C ULONG_PTR __readgs(void);
EXTERN_C ULONG_PTR __readss(void);
EXTERN_C ULONG_PTR __sldt(void);
EXTERN_C ULONG_PTR __str(void);
EXTERN_C ULONG_PTR _StackPointer(void);
EXTERN_C ULONG_PTR __sgdt(PGDT gdtr);
EXTERN_C void __invd(void);
EXTERN_C ULONG_PTR _NextInstructionPointer(void);
EXTERN_C void __writeds(ULONG_PTR DS);
EXTERN_C void __writees(ULONG_PTR ES);
EXTERN_C void __writefs(ULONG_PTR FS);
// }

/* vmx.asm */
// {
EXTERN_C void _VMExitHandler(void);
// }

/* VMCS State */
typedef struct _GUEST_STATE {
	ULONG_PTR cs;
	ULONG_PTR ds;
	ULONG_PTR ss;
	ULONG_PTR es;
	ULONG_PTR fs;
	ULONG_PTR gs;
	GDT gdt;
	GDT idt;
	ULONG_PTR ldtr;
	ULONG_PTR tr;
	ULONG_PTR rsp;
	ULONG_PTR rip;
	ULONG_PTR rflags;
	ULONG_PTR cr0;
	ULONG_PTR cr4;
	ULONG_PTR cr3;
	ULONG_PTR dr7;
	ULONG_PTR msr_debugctl;
	ULONG_PTR msr_sysenter_cs;
	ULONG_PTR msr_sysenter_eip;
	ULONG_PTR msr_sysenter_esp;
	
	ULONG_PTR msr_perf_global_ctrl;
	ULONG_PTR msr_pat;
	ULONG_PTR msr_efer;
	ULONG_PTR msr_bndcfgs;
} GUEST_STATE, *PGUEST_STATE;

typedef struct _HOST_STATE {
	ULONG_PTR cr0;
	ULONG_PTR cr3;
	ULONG_PTR cr4;
	ULONG_PTR rsp;
	ULONG_PTR rip;
	ULONG_PTR cs;
	ULONG_PTR ds;
	ULONG_PTR ss;
	ULONG_PTR es;
	ULONG_PTR fs;
	ULONG_PTR gs;
	ULONG_PTR tr;
	ULONG_PTR fsbase;
	ULONG_PTR gsbase;
	ULONG_PTR trbase;
	GDT gdt;
	GDT idt;
	ULONG_PTR msr_sysenter_cs;
	ULONG_PTR msr_sysenter_esp;
	ULONG_PTR msr_sysenter_eip;
} HOST_STATE, *PHOST_STATE;

typedef struct _MTRR_CAPABILITIES
{
	union
	{
		struct
		{
			UINT64 VarCnt : 8;
			UINT64 FixedSupported : 1;
			UINT64 Reserved : 1;
			UINT64 WcSupported : 1;
			UINT64 SmrrSupported : 1;
			UINT64 Reserved_2 : 52;
		} u;
		UINT64 AsUlonglong;
	};
} MTRR_CAPABILITIES, *PMTRR_CAPABILITIES;
C_ASSERT(sizeof(MTRR_CAPABILITIES) == sizeof(UINT64));

typedef struct _MTRR_VARIABLE_BASE
{
	union
	{
		struct
		{
			UINT64 Type : 8;
			UINT64 Reserved : 4;
			UINT64 PhysBase : 36;
			UINT64 Reserved2 : 16;
		} u;
		UINT64 AsUlonglong;
	};
} MTRR_VARIABLE_BASE, *PMTRR_VARIABLE_BASE;
C_ASSERT(sizeof(MTRR_VARIABLE_BASE) == sizeof(UINT64));

typedef struct _MTRR_VARIABLE_MASK
{
	union
	{
		struct
		{
			UINT64 Reserved : 11;
			UINT64 Enabled : 1;
			UINT64 PhysMask : 36;
			UINT64 Reserved2 : 16;
		} u;
		UINT64 AsUlonglong;
	};
} MTRR_VARIABLE_MASK, *PMTRR_VARIABLE_MASK;
C_ASSERT(sizeof(MTRR_VARIABLE_MASK) == sizeof(UINT64));

#define _1GB                        (1 * 1024 * 1024 * 1024)
#define _2MB                        (2 * 1024 * 1024)
#define MTRR_TYPE_UC            0
#define MTRR_TYPE_USWC          1
#define MTRR_TYPE_WT            4
#define MTRR_TYPE_WP            5
#define MTRR_TYPE_WB            6
#define MTRR_TYPE_MAX           7

typedef struct _SHV_MTRR_RANGE
{
	UINT32 Enabled;
	UINT32 Type;
	UINT64 PhysicalAddressMin;
	UINT64 PhysicalAddressMax;
} SHV_MTRR_RANGE, *PSHV_MTRR_RANGE;

#define MTRR_MSR_CAPABILITIES   0x0fe
#define MTRR_MSR_DEFAULT        0x2ff
#define MTRR_MSR_VARIABLE_BASE  0x200
#define MTRR_MSR_VARIABLE_MASK  (MTRR_MSR_VARIABLE_BASE+1)
#define MTRR_PAGE_SIZE          4096
#define MTRR_PAGE_MASK          (~(MTRR_PAGE_SIZE-1))

#define ROUNDUP(x,align) ((x + align - 1) & ~(align - 1))
#define LODWORD(qword) (((ULONGLONG)(qword)) & 0xFFFFFFFF)
#define HIDWORD(qword) ((((ULONGLONG)(qword)) >> 32) & 0xFFFFFFFF)
#ifndef MAKEQWORD
#define MAKEQWORD(lo, hi) ((((ULONGLONG)lo) & 0xFFFFFFFF) | ((((ULONGLONG)hi) & 0xFFFFFFFF) << 32))
#endif 

#define R_RAX 0
#define R_RCX 1
#define R_RDX 2
#define R_RBX 3
#define R_RSP 4
#define R_RBP 5
#define R_RSI 6
#define R_RDI 7
#define R_R8 8
#define R_R9 9
#define R_R10 10
#define R_R11 11
#define R_R12 12
#define R_R13 13
#define R_R14 14
#define R_R15 15
#define R_MAX 16

class SimpleVT {
public:
	SimpleVT();
	BOOLEAN Install(void);
	VOID SetVMExitHandler(ULONG_PTR HandlerEntryPoint, ULONG_PTR HandlerStack);
	VOID SetRootmodeCR3(ULONG_PTR Cr3);

private:
	VOID GdtEntryToVmcsFormat(ULONG selector, ULONG_PTR * base, ULONG_PTR * limit, ULONG_PTR * rights);
	BOOLEAN InitializeEPT(void);
	BOOLEAN CheckVTSupported(void);
	BOOLEAN CheckVTEnabled(void);
	BOOLEAN InitVMCS(void);

	ULONG_PTR* m_VMXRegion;
	ULONG_PTR* m_VMCS;
	ULONG_PTR m_VMXRootStack;
	UINT8* m_MsrBitmap;

	/* EPT Stuff */
	PVMX_EPT m_Ept;

	GUEST_STATE m_GuestState;
	HOST_STATE m_HostState;
	ULONG_PTR m_VmxBasic;
	ULONG_PTR m_VmxFeatureControl;
	ULONG_PTR m_VmcsPhysAddr, m_VmxRegionPhysAddr, m_MsrBitmapPhysAddr;
	volatile BOOLEAN m_VMXOn;
};
