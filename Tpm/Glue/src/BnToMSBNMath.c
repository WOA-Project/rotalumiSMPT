// TpmToMsBnMath.c - big number / ECC math adapter ("BN_MATH_LIB == MSBN") of ftpmsim.sys
//
// RE: In the shipped binary these entry points (BnModMult 0x1c0014060, BnMult
// 0x1c00141e0, BnDiv 0x1c0014350, BnGcd 0x1c0014530, BnModExp 0x1c0014660,
// BnModInverse 0x1c00147e0, BnEccModMult 0x1c0014af0, BnEccModMult2 0x1c0014b00,
// BnEccAdd 0x1c0014d60) are glue between the TPM's bigNum type and SymCrypt/msbignum
// (MsBnContextStart / MsBnPointToBnPoint ...). msbignum is not public, so this file is a
// clean replacement written against the same contracts (see TpmToOsslMath.c and
// TpmToWolfMath.c of ms-tpm-20-ref):
//
//   * all values are little-endian arrays of crypt_uword_t, exactly like bigNum->d;
//   * modular exponentiation and ECC use Montgomery multiplication for odd moduli
//     (all RSA moduli, RSA primes and ECC field primes are odd), with a slow
//     division based fallback for even moduli;
//   * scratch memory is on the stack only (MathLibSimulationEnd reports the peak).
//
// The code is variable time. The reference TPM libraries are not constant time either
// for most of these operations, but do not use this adapter where that matters.

#include "Tpm.h"

#if BN_MATH_LIB == MSBN

#include <intrin.h>
#include "BnConvert_fp.h"

#if RADIX_BITS != 64
#   error "TpmToMsBnMath.c is written for 64 bit words"
#endif

//*** Msb()
// This function returns the bit number of the most significant bit of a
// crypt_uword_t. The number for the least significant bit of any bigNum value is 0.
// The maximum return value is RADIX_BITS - 1,
//  Return Type: int
//      -1              the word was zero
//      n               the bit number of the most significant bit in the word
int Msb(crypt_uword_t word)
{
    int retVal = -1;
//
#if RADIX_BITS == 64
    if(word & 0xffffffff00000000)
    {
        retVal += 32;
        word >>= 32;
    }
#endif
    if(word & 0xffff0000)
    {
        retVal += 16;
        word >>= 16;
    }
    if(word & 0x0000ff00)
    {
        retVal += 8;
        word >>= 8;
    }
    if(word & 0x000000f0)
    {
        retVal += 4;
        word >>= 4;
    }
    if(word & 0x0000000c)
    {
        retVal += 2;
        word >>= 2;
    }
    if(word & 0x00000002)
    {
        retVal += 1;
        word >>= 1;
    }
    return retVal + (int)word;
}

typedef crypt_uword_t   W;

// Largest operand and product (in words) the TPM code ever hands to the math library.
#define OPW         ((crypt_uword_t)BITS_TO_CRYPT_WORDS(LARGEST_NUMBER_BITS))
#define PRODW       (2 * OPW + 2)
#define ECW         ((crypt_uword_t)BITS_TO_CRYPT_WORDS(MAX_ECC_KEY_BITS))

static crypt_uword_t     s_peakWords;        // statistics for MathLibSimulationEnd()
static crypt_uword_t     s_modExpCalls;
static crypt_uword_t     s_eccMultCalls;

//** Plain word array helpers

static crypt_uword_t
Len(const W *a, crypt_uword_t n)
{
    while(n > 0 && a[n - 1] == 0)
        n--;
    return n;
}

static void
Zero(W *a, crypt_uword_t n)
{
    crypt_uword_t i;
    for(i = 0; i < n; i++)
        a[i] = 0;
}

static void
Copy(W *d, const W *s, crypt_uword_t n)
{
    crypt_uword_t i;
    for(i = 0; i < n; i++)
        d[i] = s[i];
}

// Compare two normalised (no leading zero words) numbers.
static int
Cmp(const W *a, crypt_uword_t na, const W *b, crypt_uword_t nb)
{
    if(na != nb)
        return na > nb ? 1 : -1;
    while(na > 0)
    {
        na--;
        if(a[na] != b[na])
            return a[na] > b[na] ? 1 : -1;
    }
    return 0;
}

// r = a + b over n words, returns the carry
static W
AddN(W *r, const W *a, const W *b, crypt_uword_t n)
{
    W carry = 0;
    crypt_uword_t i;
    for(i = 0; i < n; i++)
    {
        W t = a[i] + carry;
        W c1 = t < carry;
        W s = t + b[i];
        carry = c1 + (s < t);
        r[i] = s;
    }
    return carry;
}

// r = a - b over n words, returns the borrow
static W
SubN(W *r, const W *a, const W *b, crypt_uword_t n)
{
    W borrow = 0;
    crypt_uword_t i;
    for(i = 0; i < n; i++)
    {
        W t = a[i] - borrow;
        W b1 = a[i] < borrow;
        W d = t - b[i];
        borrow = b1 + (t < b[i]);
        r[i] = d;
    }
    return borrow;
}

// 64x64 multiply-accumulate: returns the low word of a*b + acc + *carry and leaves the
// high word in *carry. Never overflows 128 bits.
static W
Mac(W a, W b, W acc, W *carry)
{
    W lo = a * b;
    W hi = __umulh(a, b);
    lo += acc;
    hi += (lo < acc);
    lo += *carry;
    hi += (lo < *carry);
    *carry = hi;
    return lo;
}

// r (na + nb words) = a * b
static void
Mul(W *r, const W *a, crypt_uword_t na, const W *b, crypt_uword_t nb)
{
    crypt_uword_t i, j;
    Zero(r, na + nb);
    for(i = 0; i < nb; i++)
    {
        W carry = 0;
        for(j = 0; j < na; j++)
            r[i + j] = Mac(a[j], b[i], r[i + j], &carry);
        r[i + na] = carry;
    }
}

static crypt_uword_t
BitLen(const W *a, crypt_uword_t n)
{
    if(n == 0)
        return 0;
    return (n - 1) * RADIX_BITS + (crypt_uword_t)Msb(a[n - 1]) + 1;
}

// In-place shift of n words by one bit, returns the bit shifted out
static W
Shr1(W *a, crypt_uword_t n)
{
    W out = 0;
    while(n > 0)
    {
        W t;
        n--;
        t = a[n] & 1;
        a[n] = (a[n] >> 1) | (out << (RADIX_BITS - 1));
        out = t;
    }
    return out;
}

// d (n + 1 words) = s (n words) << bits
static void
ShlTo(W *d, const W *s, crypt_uword_t n, crypt_uword_t bits)
{
    crypt_uword_t ws = bits / RADIX_BITS;
    crypt_uword_t bs = bits % RADIX_BITS;
    crypt_uword_t i;
    for(i = 0; i < n; i++)
    {
        d[i + ws] |= s[i] << bs;
        if(bs != 0)
            d[i + ws + 1] |= s[i] >> (RADIX_BITS - bs);
    }
}

// Division with remainder. a (na words) is divided by b (nb words, b != 0).
// q (optional) receives na words, r (optional) receives nb words (both zero padded).
// Shift-and-subtract aligned to the top bit, so the cost is proportional to the
// size of the quotient.
static void
DivMod(W *q, W *r, const W *a, crypt_uword_t na, const W *b, crypt_uword_t nb)
{
    W       rem[PRODW + 1];
    W       sh[PRODW + 2];
    crypt_uword_t la = Len(a, na);
    crypt_uword_t lb = Len(b, nb);
    crypt_uword_t ba = BitLen(a, la);
    crypt_uword_t bb = BitLen(b, lb);
    int      s;

    pAssert(lb != 0 && na <= PRODW);
    if(q != NULL)
        Zero(q, na);
    Copy(rem, a, la);
    Zero(rem + la, PRODW + 1 - la);
    if(ba >= bb)
    {
        crypt_uword_t wlen = la + 1;
        Zero(sh, PRODW + 2);
        ShlTo(sh, b, lb, ba - bb);
        for(s = (int)(ba - bb); s >= 0; s--)
        {
            if(Cmp(rem, Len(rem, wlen), sh, Len(sh, wlen)) >= 0)
            {
                SubN(rem, rem, sh, wlen);
                if(q != NULL)
                    q[s / RADIX_BITS] |= ((W)1) << (s % RADIX_BITS);
            }
            Shr1(sh, wlen);
        }
    }
    if(r != NULL)
    {
        Zero(r, nb);
        Copy(r, rem, nb < la ? nb : la);
    }
}

static void
NoteScratch(crypt_uword_t words)
{
    if(words > s_peakWords)
        s_peakWords = words;
}

//** Montgomery arithmetic for odd moduli

typedef struct
{
    crypt_uword_t    n;              // words in the modulus
    W           m[PRODW];       // modulus
    W           minv;           // -m^-1 mod 2^RADIX_BITS
    W           r2[PRODW];      // R^2 mod m, R = 2^(n * RADIX_BITS)
} MONT;

// r = a * b * R^-1 mod m, operands < m, n words each
static void
MontMul(W *r, const W *a, const W *b, const MONT *c)
{
    W           t[PRODW + 2];
    crypt_uword_t    n = c->n;
    crypt_uword_t    i, j;

    Zero(t, n + 2);
    for(i = 0; i < n; i++)
    {
        W carry = 0;
        W u, carry2, tmp;
        for(j = 0; j < n; j++)
            t[j] = Mac(a[j], b[i], t[j], &carry);
        tmp = t[n] + carry;
        t[n + 1] = (tmp < carry);
        t[n] = tmp;
        u = t[0] * c->minv;
        carry2 = 0;
        (void)Mac(u, c->m[0], t[0], &carry2);
        for(j = 1; j < n; j++)
            t[j - 1] = Mac(u, c->m[j], t[j], &carry2);
        tmp = t[n] + carry2;
        t[n - 1] = tmp;
        t[n] = t[n + 1] + (tmp < carry2);
    }
    if(t[n] != 0 || Cmp(t, Len(t, n), c->m, n) >= 0)
        SubN(t, t, c->m, n);
    Copy(r, t, n);
}

// Prepare a context for the odd modulus m (nm normalised words).
static void
MontInit(MONT *c, const W *m, crypt_uword_t nm)
{
    W           x;
    crypt_uword_t    i;
    W           t[PRODW + 1];
    crypt_uword_t    bitsR;

    c->n = nm;
    Copy(c->m, m, nm);
    // Newton iteration for m0^-1 mod 2^64
    x = m[0];
    for(i = 0; i < 6; i++)
        x *= 2 - m[0] * x;
    c->minv = (W)0 - x;
    // R^2 mod m by repeated doubling of 1
    Zero(t, nm + 1);
    t[0] = 1;
    bitsR = 2 * nm * RADIX_BITS;
    for(i = 0; i < bitsR; i++)
    {
        W top = t[nm - 1] >> (RADIX_BITS - 1);
        crypt_uword_t j;
        for(j = nm - 1; j > 0; j--)
            t[j] = (t[j] << 1) | (t[j - 1] >> (RADIX_BITS - 1));
        t[0] <<= 1;
        if(top != 0 || Cmp(t, Len(t, nm), m, nm) >= 0)
            SubN(t, t, m, nm);
    }
    Zero(c->r2, PRODW);
    Copy(c->r2, t, nm);
}

//** Variable time helpers on the TPM bigNum type

// Copy a word array into a bigNum, checking that it fits.
static BOOL
Store(bigNum bn, const W *a, crypt_uword_t n)
{
    crypt_uword_t l = Len(a, n);
    pAssert(bn->allocated >= l);
    if(bn->allocated < l)
        return FALSE;
    Copy(bn->d, a, l);
    BnSetTop(bn, l);
    return TRUE;
}

//*** MathLibraryCompatibilityCheck()
// Nothing to verify: the adapter uses the TPM word layout directly.
BOOL
BnMathLibraryCompatibilityCheck(
    void
    )
{
    return TRUE;
}

//*** SupportLibInit()
// RE: 0x1c0007850 is `mov w0, #1; ret`. The SymCrypt environment is initialised lazily
// from CryptHashInit() (LibHashInit == SymCryptInit()).
LIB_EXPORT int
BnSupportLibInit(
    void
    )
{
    return TRUE;
}

//*** MathLibSimulationEnd()
// RE: 0x1c0007860 prints "Memory usage statistics" of the MsBn allocator through
// DbgPrintEx. This adapter has no allocator; it reports its stack scratch peak instead.
extern void FtpmDebugPrint(const char *Format, ...);

void
MathLibSimulationEnd(
    void
    )
{
    FtpmDebugPrint("Memory usage statistics\n");
    FtpmDebugPrint("  peak scratch (words): %u\n", s_peakWords);
    FtpmDebugPrint("  BnModExp calls: %u\n", s_modExpCalls);
    FtpmDebugPrint("  BnEccModMult calls: %u\n", s_eccMultCalls);
}


//*** BnCurveInitialize()
// This function initializes the OpenSSL curve information structure. This
// structure points to the TPM-defined values for the curve, to the context for the
// number values in the frame, and to the OpenSSL-defined group values.
//  Return Type: bigCurveData*
//      NULL        the TPM_ECC_CURVE is not valid or there was a problem in
//                  in initializing the curve data
//      non-NULL    points to 'E'
LIB_EXPORT bigCurveData* BnCurveInitialize(
    bigCurveData*
        pDataE,  // IN: our implementation of bigCurveData is a pointer, so this is pointer-to-pointer.
    TPM_ECC_CURVE curveId  // IN: curve identifier
)
{
    *pDataE = BnGetCurveData(curveId);
    return pDataE;
}

//*** BnCurveFree()
// This function will free the allocated components of the curve and end the
// frame in which the curve data exists
LIB_EXPORT void BnCurveFree(bigCurveData* E)
{
    // nothing to clean up
}

//*** BnModMult()
// Does multiply and divide returning the remainder of the divide.
LIB_EXPORT BOOL
BnModMult(
    bigNum              result,
    bigConst            op1,
    bigConst            op2,
    bigConst            modulus
    )
{
    W           prod[PRODW];
    W           rem[PRODW];
    crypt_uword_t    lm = Len(modulus->d, modulus->size);
    crypt_uword_t    l1 = Len(op1->d, op1->size);
    crypt_uword_t    l2 = Len(op2->d, op2->size);

    pAssert(BnGetAllocated(result) >= BnGetSize(modulus));
    pAssert(l1 + l2 <= PRODW && lm != 0);
    Mul(prod, op1->d, l1, op2->d, l2);
    DivMod(NULL, rem, prod, l1 + l2, modulus->d, lm);
    NoteScratch(2 * PRODW);
    return Store(result, rem, lm);
}

//*** BnMult()
// Multiplies two numbers
LIB_EXPORT BOOL
BnMult(
    bigNum               result,
    bigConst             multiplicand,
    bigConst             multiplier
    )
{
    W           prod[PRODW];
    crypt_uword_t    l1 = Len(multiplicand->d, multiplicand->size);
    crypt_uword_t    l2 = Len(multiplier->d, multiplier->size);

    pAssert(result->allocated >=
            (BITS_TO_CRYPT_WORDS(BnSizeInBits(multiplicand)
                                 + BnSizeInBits(multiplier))));
    pAssert(l1 + l2 <= PRODW);
    Mul(prod, multiplicand->d, l1, multiplier->d, l2);
    NoteScratch(PRODW);
    return Store(result, prod, l1 + l2);
}

//*** BnDiv()
// This function divides two bigNum values. The function returns FALSE if
// there is an error in the operation.
LIB_EXPORT BOOL
BnDiv(
    bigNum               quotient,
    bigNum               remainder,
    bigConst             dividend,
    bigConst             divisor
    )
{
    W           q[PRODW];
    W           r[PRODW];
    crypt_uword_t    la = Len(dividend->d, dividend->size);
    crypt_uword_t    lb = Len(divisor->d, divisor->size);

    pAssert(!BnEqualZero(divisor));
    if(la < lb)
    {
        if(quotient)
            BnSetWord(quotient, 0);
        if(remainder)
            BnCopy(remainder, dividend);
        return TRUE;
    }
    pAssert((quotient == NULL)
            || (quotient->allocated >= (crypt_uword_t)(dividend->size - divisor->size)));
    pAssert((remainder == NULL) || (remainder->allocated >= divisor->size));
    DivMod(q, r, dividend->d, la, divisor->d, lb);
    NoteScratch(2 * PRODW);
    if(quotient != NULL && !Store(quotient, q, la))
        return FALSE;
    if(remainder != NULL && !Store(remainder, r, lb))
        return FALSE;
    return TRUE;
}

//*** BnGcd()
// Get the greatest common divisor of two numbers
LIB_EXPORT BOOL
BnGcd(
    bigNum      gcd,            // OUT: the common divisor
    bigConst    number1,        // IN:
    bigConst    number2         // IN:
    )
{
    W           a[PRODW];
    W           b[PRODW];
    W           r[PRODW];
    crypt_uword_t    la = Len(number1->d, number1->size);
    crypt_uword_t    lb = Len(number2->d, number2->size);

    pAssert(gcd != NULL);
    Copy(a, number1->d, la);
    Copy(b, number2->d, lb);
    while(lb != 0)
    {
        DivMod(NULL, r, a, la, b, lb);
        Copy(a, b, lb);
        la = lb;
        Copy(b, r, lb);
        lb = Len(b, lb);
    }
    NoteScratch(3 * PRODW);
    return Store(gcd, a, la);
}

// result = base^exp mod m for an odd modulus, Montgomery form, left to right.
static void
ModExpOdd(W *res, const W *base, crypt_uword_t nbase, const W *exp, crypt_uword_t nexp,
          const W *m, crypt_uword_t nm)
{
    MONT        c;
    W           b[PRODW];
    W           x[PRODW];
    W           one[PRODW];
    crypt_uword_t    i;
    int         bit;

    MontInit(&c, m, nm);
    // reduce the base
    Zero(b, PRODW);
    if(Cmp(base, nbase, m, nm) >= 0)
    {
        W r[PRODW];
        DivMod(NULL, r, base, nbase, m, nm);
        Copy(b, r, nm);
    }
    else
        Copy(b, base, nbase);
    // to Montgomery form
    MontMul(b, b, c.r2, &c);
    Zero(one, PRODW);
    one[0] = 1;
    MontMul(x, one, c.r2, &c);          // x = R mod m = 1 in Montgomery form
    for(bit = (int)BitLen(exp, nexp) - 1; bit >= 0; bit--)
    {
        MontMul(x, x, x, &c);
        if((exp[bit / RADIX_BITS] >> (bit % RADIX_BITS)) & 1)
            MontMul(x, x, b, &c);
    }
    MontMul(x, x, one, &c);             // out of Montgomery form
    Zero(res, nm);
    for(i = 0; i < nm; i++)
        res[i] = x[i];
    NoteScratch(5 * PRODW);
}

// Slow path for even moduli
static void
ModExpAny(W *res, const W *base, crypt_uword_t nbase, const W *exp, crypt_uword_t nexp,
          const W *m, crypt_uword_t nm)
{
    W           b[PRODW];
    W           x[PRODW];
    W           prod[PRODW];
    int         bit;
    crypt_uword_t    lx = 1;

    DivMod(NULL, b, base, nbase, m, nm);
    Zero(x, PRODW);
    x[0] = 1;
    if(nm == 1 && m[0] == 1)
        x[0] = 0;
    for(bit = (int)BitLen(exp, nexp) - 1; bit >= 0; bit--)
    {
        Mul(prod, x, nm, x, nm);
        DivMod(NULL, x, prod, 2 * nm, m, nm);
        if((exp[bit / RADIX_BITS] >> (bit % RADIX_BITS)) & 1)
        {
            Mul(prod, x, nm, b, nm);
            DivMod(NULL, x, prod, 2 * nm, m, nm);
        }
    }
    (void)lx;
    Zero(res, nm);
    Copy(res, x, nm);
    NoteScratch(4 * PRODW);
}

//***BnModExp()
// Do modular exponentiation using bigNum values.
LIB_EXPORT BOOL
BnModExp(
    bigNum               result,         // OUT: the result
    bigConst             number,         // IN: number to exponentiate
    bigConst             exponent,       // IN:
    bigConst             modulus         // IN:
    )
{
    W           res[PRODW];
    crypt_uword_t    lm = Len(modulus->d, modulus->size);
    crypt_uword_t    ln = Len(number->d, number->size);
    crypt_uword_t    le = Len(exponent->d, exponent->size);

    s_modExpCalls++;
    pAssert(lm != 0 && lm <= OPW && ln <= PRODW);
    if(lm == 0 || lm > OPW)
        return FALSE;
    if(lm == 1 && modulus->d[0] == 1)
    {
        BnSetWord(result, 0);
        return TRUE;
    }
    if(modulus->d[0] & 1)
        ModExpOdd(res, number->d, ln, exponent->d, le, modulus->d, lm);
    else
        ModExpAny(res, number->d, ln, exponent->d, le, modulus->d, lm);
    return Store(result, res, lm);
}

//*** BnModInverse()
// Modular multiplicative inverse (extended Euclid, works for any modulus).
LIB_EXPORT BOOL
BnModInverse(
    bigNum               result,
    bigConst             number,
    bigConst             modulus
    )
{
    W           r0[PRODW], r1[PRODW], r2[PRODW];
    W           t0[PRODW], t1[PRODW], t2[PRODW];
    W           q[PRODW], prod[PRODW], qt[PRODW];
    crypt_uword_t    lm = Len(modulus->d, modulus->size);
    crypt_uword_t    ln = Len(number->d, number->size);
    crypt_uword_t    l0, l1, lq;

    pAssert(lm != 0 && lm <= OPW);
    if(lm == 0 || lm > OPW)
        return FALSE;
    // r0 = m, r1 = number mod m, t0 = 0, t1 = 1
    Zero(r0, PRODW);
    Copy(r0, modulus->d, lm);
    l0 = lm;
    Zero(r1, PRODW);
    if(ln >= lm && Cmp(number->d, ln, modulus->d, lm) >= 0)
        DivMod(NULL, r1, number->d, ln, modulus->d, lm);
    else
        Copy(r1, number->d, ln);
    l1 = Len(r1, lm);
    Zero(t0, PRODW);
    Zero(t1, PRODW);
    t1[0] = 1;
    while(l1 != 0)
    {
        // q = r0 / r1; r2 = r0 mod r1
        Zero(r2, PRODW);
        DivMod(q, r2, r0, l0, r1, l1);
        lq = Len(q, l0);
        // t2 = (t0 - q * t1) mod m
        Mul(prod, q, lq, t1, lm);
        DivMod(NULL, qt, prod, lq + lm, modulus->d, lm);
        Zero(t2, PRODW);
        Copy(t2, t0, lm);
        if(Cmp(t2, Len(t2, lm), qt, Len(qt, lm)) < 0)
            AddN(t2, t2, modulus->d, lm);       // t0 + m, cannot carry out of lm words
        SubN(t2, t2, qt, lm);
        // shift
        Copy(r0, r1, lm);
        l0 = Len(r0, lm);
        Zero(r1, PRODW);
        Copy(r1, r2, lm);
        l1 = Len(r1, lm);
        Copy(t0, t1, lm);
        Copy(t1, t2, lm);
    }
    NoteScratch(9 * PRODW);
    if(!(l0 == 1 && r0[0] == 1))
        return FALSE;                           // not invertible
    return Store(result, t0, lm);
}

#if ALG_ECC

//** Elliptic curve arithmetic (short Weierstrass y^2 = x^3 + a x + b over GF(p))

typedef struct
{
    MONT        f;                  // field of the prime p
    W           a[ECW];             // curve a, Montgomery form
    W           one[ECW];           // 1 in Montgomery form
} FIELD;

typedef struct
{
    W           x[ECW];
    W           y[ECW];
    W           z[ECW];             // z == 0: point at infinity
} JPOINT;

static BOOL
FieldIsZero(const W *a, crypt_uword_t n)
{
    W acc = 0;
    crypt_uword_t i;
    for(i = 0; i < n; i++)
        acc |= a[i];
    return acc == 0;
}

static void
FeAdd(W *r, const W *a, const W *b, const FIELD *F)
{
    crypt_uword_t n = F->f.n;
    W t[ECW];
    W carry = AddN(t, a, b, n);
    if(carry != 0 || Cmp(t, Len(t, n), F->f.m, n) >= 0)
        SubN(t, t, F->f.m, n);
    Copy(r, t, n);
}

static void
FeSub(W *r, const W *a, const W *b, const FIELD *F)
{
    crypt_uword_t n = F->f.n;
    W t[ECW];
    if(SubN(t, a, b, n) != 0)
        AddN(t, t, F->f.m, n);
    Copy(r, t, n);
}

static void
FeMul(W *r, const W *a, const W *b, const FIELD *F)
{
    MontMul(r, a, b, &F->f);
}

static void
FeToMont(W *r, const W *a, crypt_uword_t na, const FIELD *F)
{
    W t[ECW];
    crypt_uword_t n = F->f.n;
    Zero(t, ECW);
    Copy(t, a, na < n ? na : n);
    MontMul(r, t, F->f.r2, &F->f);
}

static void
FeFromMont(W *r, const W *a, const FIELD *F)
{
    W one[ECW];
    Zero(one, ECW);
    one[0] = 1;
    MontMul(r, a, one, &F->f);
}

// a^(p-2) in Montgomery form (p is prime)
static void
FeInv(W *r, const W *a, const FIELD *F)
{
    crypt_uword_t n = F->f.n;
    W e[ECW];
    W x[ECW];
    int bit;
    Copy(e, F->f.m, n);
    // e = p - 2 (p is odd and > 2)
    e[0] -= 2;
    if(e[0] > F->f.m[0])
    {
        crypt_uword_t i = 1;
        while(i < n && e[i]-- == 0)
            i++;
    }
    Copy(x, F->one, n);
    for(bit = (int)BitLen(e, n) - 1; bit >= 0; bit--)
    {
        FeMul(x, x, x, F);
        if((e[bit / RADIX_BITS] >> (bit % RADIX_BITS)) & 1)
            FeMul(x, x, a, F);
    }
    Copy(r, x, n);
}

static BOOL
FieldInit(FIELD *F, bigConst prime, bigConst a)
{
    crypt_uword_t n = Len(prime->d, prime->size);
    W        t[ECW];
    pAssert(n != 0 && n <= ECW && (prime->d[0] & 1));
    if(n == 0 || n > ECW)
        return FALSE;
    MontInit(&F->f, prime->d, n);
    // 1 in Montgomery form is R mod p
    Zero(t, ECW);
    t[0] = 1;
    MontMul(F->one, t, F->f.r2, &F->f);
    Zero(F->a, ECW);
    FeToMont(F->a, a->d, Len(a->d, a->size), F);
    return TRUE;
}

static void
JSetInfinity(JPOINT *P, const FIELD *F)
{
    Zero(P->x, ECW);
    Zero(P->y, ECW);
    Zero(P->z, ECW);
    (void)F;
}

static BOOL
JIsInfinity(const JPOINT *P, const FIELD *F)
{
    return FieldIsZero(P->z, F->f.n);
}

static void
JFromAffine(JPOINT *P, pointConst S, const FIELD *F)
{
    if(BnEqualZero(S->z))
    {
        JSetInfinity(P, F);
        return;
    }
    Zero(P->x, ECW);
    Zero(P->y, ECW);
    Zero(P->z, ECW);
    FeToMont(P->x, S->x->d, Len(S->x->d, S->x->size), F);
    FeToMont(P->y, S->y->d, Len(S->y->d, S->y->size), F);
    Copy(P->z, F->one, F->f.n);
}

static void
JDouble(JPOINT *R, const JPOINT *P, const FIELD *F)
{
    crypt_uword_t n = F->f.n;
    W   yy[ECW], s[ECW], m[ECW], t[ECW], zz[ECW], x3[ECW], y3[ECW], z3[ECW];

    if(JIsInfinity(P, F) || FieldIsZero(P->y, n))
    {
        JSetInfinity(R, F);
        return;
    }
    FeMul(yy, P->y, P->y, F);               // yy = Y^2
    FeMul(s, P->x, yy, F);                  // S = 4 X Y^2
    FeAdd(s, s, s, F);
    FeAdd(s, s, s, F);
    FeMul(m, P->x, P->x, F);                // M = 3 X^2 + a Z^4
    FeAdd(t, m, m, F);
    FeAdd(m, t, m, F);
    FeMul(zz, P->z, P->z, F);
    FeMul(zz, zz, zz, F);
    FeMul(zz, zz, F->a, F);
    FeAdd(m, m, zz, F);
    FeMul(x3, m, m, F);                     // X3 = M^2 - 2S
    FeSub(x3, x3, s, F);
    FeSub(x3, x3, s, F);
    FeSub(t, s, x3, F);                     // Y3 = M (S - X3) - 8 Y^4
    FeMul(y3, m, t, F);
    FeMul(yy, yy, yy, F);
    FeAdd(yy, yy, yy, F);
    FeAdd(yy, yy, yy, F);
    FeAdd(yy, yy, yy, F);
    FeSub(y3, y3, yy, F);
    FeMul(z3, P->y, P->z, F);               // Z3 = 2 Y Z
    FeAdd(z3, z3, z3, F);
    Copy(R->x, x3, n);
    Copy(R->y, y3, n);
    Copy(R->z, z3, n);
}

static void
JAdd(JPOINT *R, const JPOINT *P, const JPOINT *Q, const FIELD *F)
{
    crypt_uword_t n = F->f.n;
    W   z1z1[ECW], z2z2[ECW], u1[ECW], u2[ECW], s1[ECW], s2[ECW], h[ECW], r[ECW];
    W   hh[ECW], hhh[ECW], v[ECW], x3[ECW], y3[ECW], z3[ECW], t[ECW];

    if(JIsInfinity(P, F))
    {
        *R = *Q;
        return;
    }
    if(JIsInfinity(Q, F))
    {
        *R = *P;
        return;
    }
    FeMul(z1z1, P->z, P->z, F);
    FeMul(z2z2, Q->z, Q->z, F);
    FeMul(u1, P->x, z2z2, F);
    FeMul(u2, Q->x, z1z1, F);
    FeMul(t, Q->z, z2z2, F);
    FeMul(s1, P->y, t, F);
    FeMul(t, P->z, z1z1, F);
    FeMul(s2, Q->y, t, F);
    FeSub(h, u2, u1, F);
    FeSub(r, s2, s1, F);
    if(FieldIsZero(h, n))
    {
        if(FieldIsZero(r, n))
            JDouble(R, P, F);
        else
            JSetInfinity(R, F);
        return;
    }
    FeMul(hh, h, h, F);
    FeMul(hhh, hh, h, F);
    FeMul(v, u1, hh, F);
    FeMul(x3, r, r, F);                     // X3 = R^2 - H^3 - 2 U1 H^2
    FeSub(x3, x3, hhh, F);
    FeSub(x3, x3, v, F);
    FeSub(x3, x3, v, F);
    FeSub(t, v, x3, F);                     // Y3 = R (V - X3) - S1 H^3
    FeMul(y3, r, t, F);
    FeMul(t, s1, hhh, F);
    FeSub(y3, y3, t, F);
    FeMul(z3, P->z, Q->z, F);               // Z3 = H Z1 Z2
    FeMul(z3, z3, h, F);
    Copy(R->x, x3, n);
    Copy(R->y, y3, n);
    Copy(R->z, z3, n);
}

static void
JScalarMul(JPOINT *R, const JPOINT *P, const W *k, crypt_uword_t nk, const FIELD *F)
{
    JPOINT  acc;
    int     bit;

    s_eccMultCalls++;
    JSetInfinity(&acc, F);
    for(bit = (int)BitLen(k, nk) - 1; bit >= 0; bit--)
    {
        JDouble(&acc, &acc, F);
        if((k[bit / RADIX_BITS] >> (bit % RADIX_BITS)) & 1)
            JAdd(&acc, &acc, P, F);
    }
    *R = acc;
    NoteScratch((crypt_uword_t)(sizeof(JPOINT) / sizeof(W)) * 4 + 12 * ECW);
}

// Convert to affine and store into R. Returns FALSE (and z = 0) for infinity.
static BOOL
JToAffine(bigPoint R, const JPOINT *P, const FIELD *F)
{
    crypt_uword_t n = F->f.n;
    W zi[ECW], zi2[ECW], zi3[ECW], x[ECW], y[ECW];

    if(JIsInfinity(P, F))
    {
        BnSetWord(R->z, 0);
        return FALSE;
    }
    FeInv(zi, P->z, F);
    FeMul(zi2, zi, zi, F);
    FeMul(zi3, zi2, zi, F);
    FeMul(x, P->x, zi2, F);
    FeMul(y, P->y, zi3, F);
    FeFromMont(x, x, F);
    FeFromMont(y, y, F);
    if(!Store(R->x, x, n) || !Store(R->y, y, n))
        return FALSE;
    BnSetWord(R->z, 1);
    return TRUE;
}

//*** BnEccModMult()
// This function does a point multiply of the form R = [d]S
// return type: BOOL
//  FALSE       failure in operation; treat as result being point at infinity
LIB_EXPORT BOOL
BnEccModMult(
    bigPoint             R,         // OUT: computed point
    pointConst           S,         // IN: point to multiply by 'd' (optional)
    bigConst             d,         // IN: scalar for [d]S
    const bigCurveData*  E
    )
{
    FIELD       F;
    JPOINT      P, Q;

    if(S == NULL)
        S = BnCurveGetG(AccessCurveConstants(E));
    if(!FieldInit(&F, BnCurveGetPrime(AccessCurveConstants(E)), BnCurveGet_a(AccessCurveConstants(E))))
        return FALSE;
    JFromAffine(&P, S, &F);
    JScalarMul(&Q, &P, d->d, Len(d->d, d->size), &F);
    return JToAffine(R, &Q, &F);
}

//*** BnEccModMult2()
// This function does a point multiply of the form R = [d]S + [u]Q
// return type: BOOL
//  FALSE       failure in operation; treat as result being point at infinity
LIB_EXPORT BOOL
BnEccModMult2(
    bigPoint             R,         // OUT: computed point
    pointConst           S,         // IN: optional point
    bigConst             d,         // IN: scalar for [d]S or [d]G
    pointConst           Q,         // IN: second point
    bigConst             u,         // IN: second scalar
    const bigCurveData*  E          // IN: curve
    )
{
    FIELD       F;
    JPOINT      PS, PQ, A, B;

    if(S == NULL)
        S = BnCurveGetG(AccessCurveConstants(E));
    if(!FieldInit(&F, BnCurveGetPrime(AccessCurveConstants(E)), BnCurveGet_a(AccessCurveConstants(E))))
        return FALSE;
    JFromAffine(&PS, S, &F);
    JFromAffine(&PQ, Q, &F);
    JScalarMul(&A, &PS, d->d, Len(d->d, d->size), &F);
    JScalarMul(&B, &PQ, u->d, Len(u->d, u->size), &F);
    JAdd(&A, &A, &B, &F);
    return JToAffine(R, &A, &F);
}

//** BnEccAdd()
// This function does addition of two points.
// return type: BOOL
//  FALSE       failure in operation; treat as result being point at infinity
LIB_EXPORT BOOL
BnEccAdd(
    bigPoint             R,         // OUT: computed point
    pointConst           S,         // IN: point to multiply by 'd'
    pointConst           Q,         // IN: second point
    const bigCurveData*  E          // IN: curve
    )
{
    FIELD       F;
    JPOINT      PS, PQ;

    if(!FieldInit(&F, BnCurveGetPrime(AccessCurveConstants(E)), BnCurveGet_a(AccessCurveConstants(E))))
        return FALSE;
    JFromAffine(&PS, S, &F);
    JFromAffine(&PQ, Q, &F);
    JAdd(&PS, &PS, &PQ, &F);
    return JToAffine(R, &PS, &F);
}

#endif // ALG_ECC

#endif // BN_MATH_LIB == MSBN
