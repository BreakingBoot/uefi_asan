/** @file
  ZeroMem() implementation.

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
  Fills a target buffer with zeros, and returns the target buffer.

  This function fills Length bytes of Buffer with zeros, and returns Buffer.

  If Length > 0 and Buffer is NULL, then ASSERT().
  If Length is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param  Buffer      The pointer to the target buffer to fill with zeros.
  @param  Length      The number of bytes in Buffer to fill with zeros.

  @return Buffer.

**/
VOID *
EFIAPI
ZeroMem (
  OUT VOID  *Buffer,
  IN UINTN  Length
  )
{
  if (Length == 0) {
    return Buffer;
  }

  ASSERT (Buffer != NULL);
  ASSERT (Length <= (MAX_ADDRESS - (UINTN)Buffer + 1));
  return AsanInternalMemZeroMem (Buffer, Length, __FILE__, __LINE__);
}

#if defined (__clang__)
#pragma clang attribute pop
#endif
