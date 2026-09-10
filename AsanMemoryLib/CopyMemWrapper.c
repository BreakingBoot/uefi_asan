/** @file
  CopyMem() implementation.

  The following BaseMemoryLib instances contain the same copy of this file:

    BaseMemoryLib
    BaseMemoryLibMmx
    BaseMemoryLibSse2
    BaseMemoryLibRepStr
    BaseMemoryLibOptDxe
    BaseMemoryLibOptPei
    PeiMemoryLib
    UefiMemoryLib

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "MemLibInternals.h"

//
// The sanitizer runtime must never be instrumented. A DSC global
// "SAN_FLAGS ==" overrides an INF [BuildOptions], so this cannot be expressed
// in the build files -- at ASAN_SCOPE=full the platform flags reach this file
// whatever the INF says. Instrumenting it makes poisoning the shadow perform
// shadow-of-shadow checks and lets a report recurse into itself. Checking here
// is explicit (AsanInternal*/__asan_* call the shadow directly), so switching
// compiler instrumentation off costs no detection.
//
#if defined (__clang__)
#pragma clang attribute push (__attribute__((no_sanitize("address", "undefined"))), apply_to = function)
#endif

/**
  Copies a source buffer to a destination buffer, and returns the destination buffer.

  This function copies Length bytes from SourceBuffer to DestinationBuffer, and returns
  DestinationBuffer.  The implementation must be reentrant, and it must handle the case
  where SourceBuffer overlaps DestinationBuffer.

  If Length is greater than (MAX_ADDRESS - DestinationBuffer + 1), then ASSERT().
  If Length is greater than (MAX_ADDRESS - SourceBuffer + 1), then ASSERT().

  @param  DestinationBuffer   A pointer to the destination buffer of the memory copy.
  @param  SourceBuffer        A pointer to the source buffer of the memory copy.
  @param  Length              The number of bytes to copy from SourceBuffer to DestinationBuffer.

  @return DestinationBuffer.

**/
VOID *
EFIAPI
CopyMem (
  OUT VOID       *DestinationBuffer,
  IN CONST VOID  *SourceBuffer,
  IN UINTN       Length
  )
{
  if (Length == 0) {
    return DestinationBuffer;
  }

  ASSERT ((Length - 1) <= (MAX_ADDRESS - (UINTN)DestinationBuffer));
  ASSERT ((Length - 1) <= (MAX_ADDRESS - (UINTN)SourceBuffer));

  if (DestinationBuffer == SourceBuffer) {
    return DestinationBuffer;
  }

  return AsanInternalMemCopyMem (DestinationBuffer, SourceBuffer, Length, __FILE__, __LINE__);
}

#if defined (__clang__)
#pragma clang attribute pop
#endif
