// stdint.h - the kernel mode CRT headers of the WDK do not ship one. Only the fixed width
// types that SymCrypt and ms-tpm-20-ref use.
#pragma once

#ifndef _FTPM_KMSHIM_STDINT_H
#define _FTPM_KMSHIM_STDINT_H

typedef signed char         int8_t;
typedef short               int16_t;
typedef int                 int32_t;
typedef long long           int64_t;
typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef unsigned long long  uint64_t;
typedef long long           intmax_t;
typedef unsigned long long  uintmax_t;

#ifdef _WIN64
typedef long long           intptr_t;
typedef unsigned long long  uintptr_t;
#else
typedef int                 intptr_t;
typedef unsigned int        uintptr_t;
#endif

#define INT8_MIN            (-127 - 1)
#define INT16_MIN           (-32767 - 1)
#define INT32_MIN           (-2147483647 - 1)
#define INT64_MIN           (-9223372036854775807LL - 1)
#define INT8_MAX            127
#define INT16_MAX           32767
#define INT32_MAX           2147483647
#define INT64_MAX           9223372036854775807LL
#define UINT8_MAX           0xffu
#define UINT16_MAX          0xffffu
#define UINT32_MAX          0xffffffffu
#define UINT64_MAX          0xffffffffffffffffULL

#endif
