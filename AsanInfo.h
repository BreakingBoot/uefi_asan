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
} ASAN_INFO;

extern EFI_GUID gAsanInfoGuid;

#endif
