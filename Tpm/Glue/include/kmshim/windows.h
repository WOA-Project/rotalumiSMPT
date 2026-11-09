// windows.h - kernel mode stand-in for the Windows-tree "windows.h" that SymCrypt's precomp.h
// includes. The SymCrypt library is compiled for kernel mode (ntifs.h) in this project.
#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include <intrin.h>

typedef int BOOL;

// SymCrypt's CPU detection uses the Windows-tree spelling of structured exception handling.
#ifndef try
#   define try      __try
#   define except   __except
#endif
