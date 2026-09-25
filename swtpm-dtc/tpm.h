#ifndef TPM_VERIFY_H
#define TPM_VERIFY_H

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <tbs.h>
#include <fdi.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <wctype.h>
#include <limits.h>
#include <fcntl.h>
#include <strsafe.h>
#include <setupapi.h>


#ifdef _MSC_VER
    #pragma comment(lib, "winhttp.lib")
    #pragma comment(lib, "crypt32.lib")
    #pragma comment(lib, "cabinet.lib")
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "ncrypt.lib")
    #pragma comment(lib, "tbs.lib")
    #pragma comment(lib, "bcrypt.lib")
    #pragma comment(lib, "wintrust.lib")
#endif

#ifndef STATUS_SUCCESS
    #define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef MS_PLATFORM_CRYPTO_PROVIDER
    #define MS_PLATFORM_CRYPTO_PROVIDER L"Microsoft Platform Crypto Provider"
#endif

#ifndef BCRYPT_PCP_PLATFORM_TYPE_PROPERTY
    #define BCRYPT_PCP_PLATFORM_TYPE_PROPERTY L"PCP_PLATFORM_TYPE"
#endif
#ifndef BCRYPT_PCP_PROVIDER_VERSION_PROPERTY
    #define BCRYPT_PCP_PROVIDER_VERSION_PROPERTY L"PCP_PROVIDER_VERSION"
#endif
#ifndef NCRYPT_PCP_EKPUB_PROPERTY
    #define NCRYPT_PCP_EKPUB_PROPERTY L"PCP_EKPUB"
#endif
#ifndef NCRYPT_PCP_EKCERT_PROPERTY
    #define NCRYPT_PCP_EKCERT_PROPERTY L"PCP_EKCERT"
#endif

#ifndef _O_RDONLY
    #define _O_RDONLY 0x0000
#endif
#ifndef _O_WRONLY
    #define _O_WRONLY 0x0001
#endif
#ifndef _O_RDWR
    #define _O_RDWR   0x0002
#endif
#ifndef _O_CREAT
    #define _O_CREAT  0x0100
#endif
#ifndef _O_TRUNC
    #define _O_TRUNC  0x0200
#endif

#define CAB_HANDLE_MAGIC          0x54504D48 
#define MAX_EXTRACTED_FILE_SIZE   (64 * 1024 * 1024) 

#ifndef MAX_EXTRACTED_TOTAL_FILES
    #define MAX_EXTRACTED_TOTAL_FILES 65535
#endif
#ifndef MAX_EXTRACTED_TOTAL_SIZE
    #define MAX_EXTRACTED_TOTAL_SIZE  (128 * 1024 * 1024)
#endif

#ifndef CB_MAX_CAB_PATH
    #define CB_MAX_CAB_PATH 260
#endif

#define MAX_ACTIVE_CAB_HANDLES    16

#define MAX_CAB_DOWNLOAD_SIZE     (64 * 1024 * 1024) 
#define MAX_EXTENDED_PATH_LEN     4096

#ifdef TBS_TCGLOG_SRTM_CURRENT
    #undef TBS_TCGLOG_SRTM_CURRENT
#endif
#define TBS_TCGLOG_SRTM_CURRENT 0

#define MAX_ALG_PAIRS 32

#define TPM_ST_NO_SESSIONS         0x8001
#define TPM_ST_SESSIONS            0x8002
#define TPM_RS_PW                  0x40000009
#define TPM_RH_OWNER               0x40000001
#define TPM_RH_ENDORSEMENT         0x4000000B
#define TPM_RH_NULL                0x40000007

#define TPM_CC_CreatePrimary       0x00000131
#define TPM_CC_PolicySecret        0x00000151
#define TPM_CC_ActivateCredential  0x00000147
#define TPM_CC_StartAuthSession    0x00000176
#define TPM_CC_FlushContext        0x00000165
#define TPM_CC_ReadPublic          0x00000173
#define TPM_CC_GetCapability       0x0000017A
#define TPM_CC_NV_ReadPublic       0x00000169
#define TPM_CC_NV_Read             0x0000014E
#define TPM_CC_Quote               0x00000158
#define TPM_CC_PCR_Extend          0x00000182
#define TPM_CC_PCR_Reset           0x0000013D

#define TPM_ALG_RSA                0x0001
#ifndef TPM_ALG_SHA256
    #define TPM_ALG_SHA256         0x000B
#endif
#define TPM_ALG_NULL               0x0010
#define TPM_ALG_RSASSA             0x0014
#define TPM_ALG_ECC                0x0023
#define TPM_SE_POLICY              0x01

#define TCG_ET_NO_ACTION                      0x00000003U
#define TCG_ET_SEPARATOR                      0x00000004U
#define TCG_ET_EFI_VARIABLE_DRIVER_CONFIG     0x80000001U
#define TCG_ET_EFI_VARIABLE_AUTHORITY         0x800000E0U

#define EV_PREBOOT_CERT             0x00000000
#define EV_POST_CODE                0x00000001
#define EV_NO_ACTION                0x00000003
#define EV_SEPARATOR                0x00000004
#define EV_ACTION                   0x00000005
#define EV_EVENT_TAG                0x00000006
#define EV_S_CRTM_CONTENTS          0x00000007
#define EV_S_CRTM_VERSION           0x00000008
#define EV_CPU_MICROCODE            0x00000009
#define EV_PLATFORM_CONFIG_FLAGS    0x0000000A
#define EV_TABLE_OF_DEVICES         0x0000000B
#define EV_COMPACT_HASH             0x0000000C
#define EV_IPL                      0x0000000D
#define EV_IPL_PARTITION_DATA       0x0000000E
#define EV_NONHOST_CODE             0x0000000F
#define EV_NONHOST_CONFIG           0x00000010
#define EV_NONHOST_INFO             0x00000011
#define EV_OMIT_BOOT_DEVICE_EVENTS  0x00000012

#define EV_EFI_VARIABLE_DRIVER_CONFIG   0x800000E1
#define EV_EFI_VARIABLE_BOOT            0x800000E2
#define EV_EFI_BOOT_SERVICES_APPLICATION 0x80000003
#define EV_EFI_BOOT_SERVICES_DRIVER     0x80000004
#define EV_EFI_RUNTIME_SERVICES_DRIVER  0x80000005
#define EV_EFI_GPT_EVENT                0x80000006
#define EV_EFI_ACTION                   0x80000007
#define EV_EFI_PLATFORM_FIRMWARE_BLOB   0x80000008
#define EV_EFI_HANDOFF_TABLES           0x80000009
#define EV_EFI_PLATFORM_FIRMWARE_BLOB2  0x8000000A
#define EV_EFI_HANDOFF_TABLES2          0x8000000B
#define EV_EFI_VARIABLE_AUTHORITY       0x800000E0

typedef struct {
    const BYTE* data;
    DWORD size;
    DWORD pos;
} MEMSRC;

typedef struct {
    char* name;
    BYTE* data;
    DWORD size;
    DWORD cap;
} FILEBUF;

typedef struct {
    FILEBUF* items;
    size_t count;
    size_t cap;
} FILELIST;

typedef enum {
    CAB_HANDLE_TYPE_MEMSRC = 1,
    CAB_HANDLE_TYPE_FILEBUF = 2
} CAB_HANDLE_TYPE;

typedef enum {
    AUTHORITY_UNKNOWN = 0,
    AUTHORITY_WINDOWS_PRODUCTION_PCA,
    AUTHORITY_UEFI_CA
} pcr7_authority_type;

typedef struct {
    DWORD magic;
    CAB_HANDLE_TYPE type;
    union {
        MEMSRC* src;
        FILEBUF* buf;
    } u;
} CAB_HANDLE;

typedef struct {
    BOOL hasTpm;
    BOOL isTpm2;
    DWORD tpmVersionRaw;
    DWORD manufacturerId;
    char manufacturerIdText[5];
    char familyIndicatorText[5];
    char vendorString[17];
    ULONGLONG firmwareVersion;
    DWORD firmwareVersion1;
    DWORD firmwareVersion2;
    char providerType[128];
    char providerVersion[128];
    BYTE* ekPub;
    DWORD ekPubSize;
    char ekPubSha256[65];
    BOOL hasEkCertStore;
} TPMINFO;

typedef struct {
    WCHAR** items;
    size_t count;
    size_t cap;
} WSTRINGLIST;

typedef struct {
    const WCHAR* host;
    const WCHAR* path_prefix;
    BOOL allow_http;
    BOOL allow_https;
} TRUSTED_URL;

#pragma pack(push, 1)
    typedef struct {
        uint32_t PCRIndex;
        uint32_t EventType;
        uint8_t Digest[20];
        uint32_t EventSize;
    } TCG_PCR_EVENT_HEADER;

    typedef struct {
        uint64_t ImageLocationInMemory;
        uint64_t ImageLengthInMemory;
        uint64_t ImageLinkTimeAddress;
        uint64_t LengthOfDevicePath;
    } UEFI_IMAGE_LOAD_EVENT;

    typedef struct {
        uint8_t Type;
        uint8_t SubType;
        uint16_t Length;
    } EFI_DEVICE_PATH_HEADER;

    typedef struct {
        EFI_DEVICE_PATH_HEADER Header;
        uint32_t PartitionNumber;
        uint64_t PartitionStart;
        uint64_t PartitionSize;
        uint8_t Signature[16];
        uint8_t PartitionFormat;
        uint8_t SignatureType;
    } HARDDRIVE_DEVICE_PATH;
#pragma pack(pop)

typedef struct {
    uint32_t eventType;
    uint8_t digest[32];
    uint32_t digestSize;
} TrackedEvent;

typedef struct {
    TrackedEvent* items;
    uint32_t count;
    uint32_t capacity;
} PcrEventList;

typedef struct {
    uint16_t algId;
    uint16_t digestSize;
} AlgSizePair;

typedef struct {
    AlgSizePair pairs[MAX_ALG_PAIRS];
    uint32_t count;
} AlgSizeMap;

typedef struct {
    BYTE* buf;
    UINT32 capacity;
    UINT32 write_pos;
} buf_builder;

typedef struct {
    const BYTE* buf;
    UINT32 size;
    UINT32 read_pos;
} buf_parser;

extern FILELIST g_extracted;

BOOL extract_cab_from_memory(const BYTE* cabData, DWORD cabSize);

void print_last_error(const char* what);
BOOL ends_with_i(const char* s, const char* suffix);
const char* basename_a(const char* path);
const char* ext_a(const char* path);
BOOL is_cert_file_name(const char* path);

void free_filebuf(FILEBUF* f);
void free_filelist(FILELIST* list);
BOOL filelist_push(FILELIST* list, const char* name, const BYTE* data, DWORD size);

void free_wstringlist(WSTRINGLIST* list);
BOOL wstringlist_contains(const WSTRINGLIST* list, const WCHAR* s);
BOOL wstringlist_push(WSTRINGLIST* list, const WCHAR* s);
BOOL url_is_http(const WCHAR* url);
BOOL extract_aia_ca_issuers(PCCERT_CONTEXT cert, WSTRINGLIST* urls);

BOOL is_pem_data(const BYTE* data, DWORD size);
BOOL base64_decode_alloc(const char* s, BYTE** out, DWORD* outSize);
BOOL cert_equals(PCCERT_CONTEXT a, PCCERT_CONTEXT b);
BOOL store_contains_cert_exact(HCERTSTORE store, PCCERT_CONTEXT cert);
BOOL cert_is_self_signed(PCCERT_CONTEXT cert);
BOOL cert_is_trusted_root(PCCERT_CONTEXT cert, HCERTSTORE hRoots);
BOOL cert_signature_validates_against_issuer(PCCERT_CONTEXT subject, PCCERT_CONTEXT issuer);
BOOL blob_equals(const CRYPT_DATA_BLOB* a, const CRYPT_DATA_BLOB* b);
BOOL get_cert_subject_key_identifier(PCCERT_CONTEXT cert, CRYPT_DATA_BLOB* out);
BOOL get_cert_authority_key_identifier(PCCERT_CONTEXT cert, CRYPT_DATA_BLOB* out);
PCCERT_CONTEXT find_valid_issuer_in_store(HCERTSTORE store, PCCERT_CONTEXT subject);

BOOL parse_certs_from_extracted_files(HCERTSTORE* outStore);
BOOL build_cab_trust_stores(HCERTSTORE hCabStore, HCERTSTORE* outRoots, HCERTSTORE* outIntermediates, DWORD* outRootCount, DWORD* outIntermediateCount);
BOOL export_cert_public_key_blob(PCCERT_CONTEXT cert, BYTE** outBlob, DWORD* outBlobSize);
BOOL ekpub_matches_cert(PCCERT_CONTEXT cert, const BYTE* ekPub, DWORD ekPubSize);
BOOL is_trusted_manufacturer_url(const WCHAR* url);
BOOL check_issuer_basic_constraints_and_key_usage(PCCERT_CONTEXT cert);
BOOL check_cert_revocation(PCCERT_CONTEXT cert);
BOOL calculate_sha256(const uint8_t* data, uint32_t size, uint8_t outDigest[32]);
BOOL sha256_hex(const BYTE* data, DWORD size, char outHex[65]);

BOOL download_url_to_memory(const wchar_t* url, BYTE** outData, DWORD* outSize);
BOOL download_and_verify_trusted_tpm_cab(const wchar_t* url, BYTE** outData, DWORD* outSize);

BOOL get_tpm_info_via_ncrypt(TPMINFO* info);
BOOL get_ek_cert_store_from_nvram(HCERTSTORE* out_store);
BOOL get_pcp_ek_cert_store(NCRYPT_PROV_HANDLE hProv, HCERTSTORE* outStore);
BOOL build_candidate_issuer_store(HCERTSTORE h_cab_store, HCERTSTORE* out_store);
BOOL tpm_pcr_extend(TBS_HCONTEXT hContext, UINT32 pcrIndex, const BYTE* digest32);
BOOL tpm_generate_quote_and_verify(TBS_HCONTEXT hTbsContext, PCCERT_CONTEXT ekCert, const BYTE* expectedPcrDigest, BOOL* outQuoteVerified);

BOOL detect_tpm_passthrough(PCCERT_CONTEXT ekCert);

#endif