/** @file
  The compiler instrumentation routines for AddressSanitizer(ASan).

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
#ifndef _ASAN_H_
#define _ASAN_H_

#include <Guid/AsanInfo.h>

// These magic values are written to shadow for better error reporting.
#define kAsanHeapLeftRedzoneMagic  0xfa
#define kAsanHeapFreeMagic  0xfd
#define kAsanStackLeftRedzoneMagic  0xf1
#define kAsanStackMidRedzoneMagic  0xf2
#define kAsanStackRightRedzoneMagic  0xf3
#define kAsanStackAfterReturnMagic  0xf5
#define kAsanInitializationOrderMagic  0xf6
#define kAsanUserPoisonedMemoryMagic  0xf7
#define kAsanContiguousContainerOOBMagic  0xfc
//
// A protocol interface whose protocol has been uninstalled. The storage is still
// allocated and still readable, so nothing else describes it: the lifetime that ended
// is the protocol's, not the allocation's. Distinct from the free magic because a
// caller holding a stale interface and a caller holding freed memory are different
// mistakes with different fixes.
//
#define kAsanStaleInterfaceMagic  0xfb
#define kAsanStackUseAfterScopeMagic  0xf8
#define kAsanGlobalRedzoneMagic  0xf9
#define kAsanInternalHeapMagic  0xfe
#define kAsanArrayCookieMagic  0xac
#define kAsanIntraObjectRedzone  0xbb
#define kAsanAllocaLeftMagic  0xca
#define kAsanAllocaRightMagic  0xcb

#define ASAN_HEAP_LEFT_RZ_SIGNATURE   SIGNATURE_32('a','h','l','r')


void PoisonPages (
  IN const UINT64 Start,
  IN const UINTN  PageNum,
  IN const UINT8  Value
  ) ;

void UnpoisonPages (
  IN const UINT64 Start, 
  IN const UINTN  PageNum
  );

void 
PoisonPool(
  IN const UINTN aligned_addr, 
  IN UINTN Size,
  IN const UINT8 Value
  );

void 
UnpoisonPool(
  IN const UINTN aligned_addr,
  IN UINTN Size
  );

UINTN 
ComputePoolRightRedzoneSize(
  IN UINTN user_requested_size
  );

VOID
Num2Str64bit(
  IN  UINT64 Number,
  IN  CHAR8* NumStr
  );

RETURN_STATUS
EFIAPI
SetupAsanShadowMemory (
  VOID
  );
//
// The pool reports a double free itself: asan has no allocator-side hook here, and
// CoreFreePoolI was rejecting the second free with EFI_INVALID_PARAMETER in silence.
//
VOID
SerialOutput(
  IN  CONST CHAR8 *String
  );

//
// Opens and closes the window in which a finding is escalated to the fuzzer. Outside
// it a report is still logged, which is what a plain boot wants: this firmware raises
// hundreds of reports while it boots, and every one of them would otherwise end an
// iteration before the harness had run.
//
VOID
AsanSetFuzzingActive (
  IN BOOLEAN  Active
  );

//
// Memory a driver has no business reading, named rather than sized. ASan describes
// allocations, so it has nothing to say about a pointer into flash, MMIO or SMRAM:
// the access is in bounds of something real, it is simply in bounds of the wrong
// thing. That is the shape of an SMM callout, and it is the one firmware fault class
// a shadow of allocations cannot express.
//
// Policy lives in whoever calls Register -- this only holds the list and answers the
// question, because AsanLib is what the memory interceptors already link against.
//
VOID
AsanRegisterProtectedRegion (
  IN UINT64       Base,
  IN UINT64       Size,
  IN CONST CHAR8  *Name
  );

//
// Poison a pool allocation because the protocol it carried has been uninstalled. The
// extent comes from the shadow -- the allocator poisons a right redzone at the end of
// every allocation, so walking forward from the pointer finds it -- which means no
// caller has to know how large the interface was. Returns the number of bytes poisoned,
// or 0 when the pointer is not a bounded heap object: a protocol whose interface is a
// global has no redzone to find and must be left alone.
//
//
// Memory something outside the firmware can still change while a call is running.
// Register it around the call; a second read of a word already read during that call
// is a double fetch, and what the first read validated is not what the second used.
// Registering a size of 0 closes the window.
//
VOID
AsanRegisterUntrusted (
  IN UINT64  Base,
  IN UINT64  Size
  );

VOID
AsanNoteUntrustedRead (
  IN UINTN  Addr,
  IN UINTN  Size,
  IN UINTN  Ip
  );

UINTN
AsanPoisonStaleInterface (
  IN VOID  *Interface
  );

VOID
AsanSetRegionChecks (
  IN BOOLEAN  Active
  );

CONST CHAR8 *
AsanProtectedRegionName (
  IN UINT64  Address,
  IN UINT64  Size
  );

//
// Report a firmware-specific bug class -- one the compiler's own instrumentation cannot
// see, such as a double fetch or a use of a boot service after ExitBootServices. Goes
// through the same guards, counters and banner as a shadow finding, so a class that is
// suppressed stays quiet instead of announcing a detection whose report never arrives.
//
// DECLARED HERE, which it was not. Every caller wrote its own prototype and nothing made
// them agree: FwSanDxe's left `Detail` out, so for every FWSAN finding the address
// arrived where a CONST CHAR8 * was expected and the banner walked it as a string, Addr
// and Size arrived as 0, IsWrite got the return address, and Ip -- the dedup key and the
// ip in the crashes.csv row -- was never passed at all. It survived because a byte near
// the destination happened to be zero. With the declaration here the DEFINITION in
// AsanLib is checked against it, so the next disagreement is a compile error.
//
// The weak definitions in MdePkg's AsanMemoryLib and AsanMemoryLibRepStr cannot include
// this header -- MdePkg must not depend on MdeModulePkg, and an undefined weak leaves a
// relocation GenFw rejects, so they have to DEFINE rather than declare. Those two stay
// compared against this signature by scripts/fwsan_report_check.py instead.
//
VOID
AsanReportFirmwareClass (
  IN CONST CHAR8  *BugDescr,
  IN CONST CHAR8  *Detail,
  IN UINTN        Addr,
  IN UINTN        Size,
  IN UINTN        IsWrite,
  IN UINTN        Ip
  );

//
// Escalate the finding just reported into an objective the fuzzer sees. Separate from
// the report so a class can be announced on a plain boot and escalated only inside the
// fuzzing window.
//
// Declared here for the same reason as the call above. It is hand-written in eight
// places across this tree in two spellings -- `void` and `VOID` -- which happen to be
// the same type, so that set has never bitten; a no-argument function is the one shape
// drift cannot hurt. The declaration is here so a caller that includes this header does
// not have to add one more.
//
VOID
AsanSignalSolution (
  VOID
  );

extern UINTN __asan_shadow_memory_dynamic_address;
extern int __asan_option_detect_stack_use_after_return;
extern UINT64 mAsanShadowMemoryStart;
extern UINT64 mAsanShadowMemorySize;
extern UINT64 mShadowOffset;
extern int gSerialOutputSwitch;

#endif