// TpmToMsBnMath.h - big number back end ("MATH_LIB == MSBN") of ftpmsim.sys
//
// ms-tpm-20-ref names MSBN as the math library of the Windows build: the shipped
// binary contains the Windows glue (MsBnContextStart, MsBnPointToBnPoint, BnCurveInit,
// Root2, FindMetric ... see FunctionMap.csv) around SymCrypt's ARM64 Montgomery kernels
// and Microsoft's closed "msbignum" ECC code. That code is not public, so this
// header/TpmToMsBnMath.c pair is a *replacement adapter*: the same interface the TPM
// code needs (BnModMult, BnMult, BnDiv, BnGcd, BnModExp, BnModInverse, BnEccModMult,
// BnEccModMult2, BnEccAdd), written as portable word arithmetic. It is functionally
// equivalent, not instruction-equivalent, and not constant time.

#ifndef _TPM_TO_MSBN_MATH_H
#define _TPM_TO_MSBN_MATH_H

#if MATH_LIB == MSBN

// The curve is simply the TPM's ECC_CURVE_DATA, as in the wolfSSL back end.
typedef ECC_CURVE_DATA bnCurve_t;

typedef bnCurve_t  *bigCurve;

#define AccessCurveData(E)  (E)

#define CURVE_INITIALIZED(name, initializer)                        \
    bnCurve_t      *name = (ECC_CURVE_DATA *)GetCurveData(initializer)

#define CURVE_FREE(E)

#define MSBN_ENTER()
#define MSBN_LEAVE()

// Unlike the reference's empty macro the binary exports MathLibSimulationEnd() (ordinal
// 97); it prints the scratch usage statistics of the math code.
void MathLibSimulationEnd(void);

#endif // MATH_LIB == MSBN

#endif // _TPM_TO_MSBN_MATH_H
