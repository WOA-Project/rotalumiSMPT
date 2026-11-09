//** Introduction
// Provide vendor-specific version and identifiers to core TPM library for
// return in capabilities.  These may not be compile time constants and therefore
// are provided by platform callbacks.  These platform functions are expected to
// always be available, even in failure mode.
//
//** Includes
#include "FtpmSim.h"

// In this sample platform, these are compile time constants, but are not required to be.
#define MANUFACTURER    "XYZ "
#define VENDOR_STRING_1 "xCG "
#define VENDOR_STRING_2 "fTPM"
#define VENDOR_STRING_3 "\0\0\0\0"
#define VENDOR_STRING_4 "\0\0\0\0"
#define FIRMWARE_V1     (0x20240125)
#define FIRMWARE_V2     (0x00120000)
#define MAX_SVN         255

static ULONG currentHash = FIRMWARE_V2;
static USHORT currentSvn  = 10;

// Similar to the Core Library's ByteArrayToUint32, but usable in Platform code.
static ULONG StringToUint32(char s[4])
{
    UCHAR* b = (UCHAR*)s;  // AVOID promotion to a signed integer type
    return (((ULONG)b[0] << 8 | b[1]) << 8 | b[2]) << 8 | b[3];
}

// return the 4 character Manufacturer Capability code.  This
// should come from the platform library since that is provided by the manufacturer
ULONG _plat__GetManufacturerCapabilityCode()
{
    return StringToUint32(MANUFACTURER);
}

// return the 4 character VendorStrings for Capabilities.
// Index is ONE-BASED, and may be in the range [1,4] inclusive.
// Any other index returns all zeros. The return value will be interpreted
// as an array of 4 ASCII characters (with no null terminator)
ULONG _plat__GetVendorCapabilityCode(int index)
{
    switch(index)
    {
        case 1:
            return StringToUint32(VENDOR_STRING_1);
        case 2:
            return StringToUint32(VENDOR_STRING_2);
        case 3:
            return StringToUint32(VENDOR_STRING_3);
        case 4:
            return StringToUint32(VENDOR_STRING_4);
    }
    return 0;
}

// return the most-significant 32-bits of the TPM Firmware Version reported by
// getCapability.
ULONG _plat__GetTpmFirmwareVersionHigh()
{
    return FIRMWARE_V1;
}

// return the least-significant 32-bits of the TPM Firmware Version reported by
// getCapability.
ULONG _plat__GetTpmFirmwareVersionLow()
{
    return FIRMWARE_V2;
}

// return the TPM Firmware SVN reported by getCapability.
USHORT _plat__GetTpmFirmwareSvn(VOID)
{
    return currentSvn;
}

// return the TPM Firmware maximum SVN reported by getCapability.
USHORT _plat__GetTpmFirmwareMaxSvn(VOID)
{
    return MAX_SVN;
}

// Called by the simulator to set the TPM Firmware SVN reported by
// getCapability.
VOID _plat__SetTpmFirmwareHash(ULONG hash)
{
    currentHash = hash;
}

// Called by the simulator to set the TPM Firmware SVN reported by
// getCapability.
VOID _plat__SetTpmFirmwareSvn(USHORT svn)
{
    currentSvn = min(svn, MAX_SVN);
}

// Dummy implmenentation for obtaining a Firmware SVN Secret bound
// to the given SVN.
int _plat__GetTpmFirmwareSvnSecret(USHORT  svn,
                                              USHORT  secret_buf_size,
                                              UCHAR*  secret_buf,
                                              USHORT* secret_size)
{
    int i;

    if(svn > currentSvn)
    {
        return -1;
    }

    // INSECURE dummy implementation: repeat the SVN into the secret buffer.
    for(i = 0; i < secret_buf_size; ++i)
    {
        secret_buf[i] = ((UCHAR*)&svn)[i % sizeof(svn)];
    }

    *secret_size = secret_buf_size;

    return 0;
}

// Dummy implmenentation for obtaining a Firmware Secret bound
// to the current firmware image.
int _plat__GetTpmFirmwareSecret(
    USHORT secret_buf_size, UCHAR* secret_buf, USHORT* secret_size)
{
    int i;

    // INSECURE dummy implementation: repeat the firmware hash into the
    // secret buffer.
    for(i = 0; i < secret_buf_size; ++i)
    {
        secret_buf[i] = ((UCHAR*)&currentHash)[i % sizeof(currentHash)];
    }

    *secret_size = secret_buf_size;

    return 0;
}

// return the TPM Type returned by TPM_PT_VENDOR_TPM_TYPE
ULONG _plat__GetTpmType()
{
    return 1;  // just the value the reference code has returned in the past.
}
