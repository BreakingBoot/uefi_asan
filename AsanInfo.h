/** @file
  GUID for an event that is signaled on the first attempt to check for a keystroke 
  from the ConIn device.

  Copyright (c) 2012, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __ASAN_INFO_GUID_H__
#define __ASAN_INFO_GUID_H__

#define ASAN_INFO_GUID \
          { 0xac0634da, 0x320e, 0x4f1d, { 0x8d, 0xc, 0x2e, 0x99, 0x1e, 0xab, 0xe5, 0xae } };

typedef struct {
  UINT64       AsanShadowMemorySize;
  UINT64       AsanShadowMemoryStart;
  UINT32       AsanInited;
  UINT32       AsanActivated;
  //
  // The fuzzing window, shared. AsanLib is a static library, so every instrumented
  // module has its own copy of every one of its variables: a harness opening the window
  // in its own copy leaves all 100-odd drivers with theirs still closed, and a finding
  // in the driver under test is printed to the serial port and never escalated. One run
  // against EFI_DEVICE_PATH_UTILITIES_PROTOCOL logged 714 findings and scored 4
  // solutions, none of them a sanitizer report. This field is in the HOB, which every
  // module reads through the same pointer.
  //
  UINT32       AsanFuzzingActive;
  //
  // Regions a driver has no business touching, shared for exactly the reason above.
  // FwSanDxe decides what belongs on the list and every instrumented module has to be
  // able to consult it -- registering into a per-module copy means the module that did
  // the registering is the only one that ever checks anything, which is a check that
  // passes everywhere it is not needed.
  //
  // Bases and ends rather than a descriptor with a name: a pointer to a string in one
  // image is not something another image should be dereferencing out of a HOB.
  //
  UINT32       AsanRegionChecksActive;
  UINT32       AsanProtectedRegionCount;
  UINT64       AsanProtectedRegionBase[8];
  UINT64       AsanProtectedRegionEnd[8];
  //
  // One buffer whose contents something outside the firmware can still change while a
  // call is running -- a communication buffer, a queue, or the buffer a fuzzer just
  // filled and handed to a protocol. Reading a length out of it, checking the length,
  // and then reading it again to use it means the value that passed the check is not
  // necessarily the value that acts.
  //
  // Shared, because the module that registers the buffer and the module that reads it
  // are never the same one. Seen[] is the addresses already read during this call; a
  // second read of one of them is the fault. Eight is enough -- a member that fetches
  // more than eight distinct words out of untrusted memory has a bigger problem than
  // this check.
  //
  // Four, not one. A harness hands several buffers to a single call and any of them can
  // be the one a driver reads twice, so registering the next would have discarded the
  // last and the check would only ever watch whichever argument happened to be built
  // most recently.
  UINT32       AsanUntrustedCount;
  UINT32       AsanUntrustedSeenCount;
  UINT64       AsanUntrustedBase[4];
  UINT64       AsanUntrustedEnd[4];
  UINT64       AsanUntrustedSeen[8];
  //
  // What the FIRST read of each of those words was. Seen[] alone records that the word
  // has been read, which names the SECOND fetch and loses the first -- and the first is
  // the read that validated. A developer handed only the re-read gets the line that used
  // the value and nothing pointing at the check it got past, which is the half of a
  // double fetch that has to be fixed.
  //
  // Parallel arrays rather than an array of structs, because the HOB is read through one
  // pointer by every instrumented module and everything above is laid out this way
  // already. The same fixed eight, and for the same reason: the snapshot restore rewinds
  // all of this with the rest of guest memory, so it is per-call state and a ninth entry
  // would never be read.
  //
  // Addr as well as Ip, because the two reads need not be the same access: the match is
  // by granule, so a 4-byte read of a length followed by an 8-byte read of the same word
  // is the case this check exists for, and the sizes are what say that is what happened.
  //
  UINT64       AsanUntrustedSeenIp[8];
  UINT64       AsanUntrustedSeenAddr[8];
  UINT32       AsanUntrustedSeenSize[8];
} ASAN_INFO;

extern EFI_GUID gAsanInfoGuid;

#endif
