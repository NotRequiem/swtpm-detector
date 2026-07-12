#ifndef TPM_VERIFY_H
#define TPM_VERIFY_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <tbs.h>
#include <fdi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <strsafe.h>

#ifdef _MSC_VER
    #pragma comment(lib, "winhttp.lib")
    #pragma comment(lib, "crypt32.lib")
    #pragma comment(lib, "cabinet.lib")
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "ncrypt.lib")
    #pragma comment(lib, "tbs.lib")
    #pragma comment(lib, "bcrypt.lib")
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
#ifndef NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY
    #define NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY L"PCP_TPM12_IDACTIVATION"
#endif
#ifndef NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY
    #define NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY L"PCP_TPM12_IDACTIVATION"
#endif
#ifndef NCRYPT_PCP_TPM12_IDBINDING_PROPERTY
    #define NCRYPT_PCP_TPM12_IDBINDING_PROPERTY L"PCP_TPM12_IDBINDING"
#endif

typedef struct {
    ULONG cbHeader;
    ULONG cbIdObject;
    ULONG cbEncryptedSecret;
} PCP_20_IDACTIVATION_STRUCT;

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
    BOOL hasEk;
} TPMINFO;

typedef enum {
    TRUST_PATH_NONE = 0,
    TRUST_PATH_TPM_CAB = 1
} TRUST_PATH;

typedef struct {
    WCHAR** items;
    size_t count;
    size_t cap;
} WSTRINGLIST;

extern FILELIST g_extracted;

void print_last_error(const char* what);
void print_tbs_result(const char* what, TBS_RESULT r);
void print_ntstatus(const char* what, SECURITY_STATUS s);
void print_ascii4(const char* label, uint32_t val);
void print_utf8_or_unknown(const char* label, const char* s);

BOOL ends_with_i(const char* s, const char* suffix);
const char* basename_a(const char* path);
const char* ext_a(const char* path);
BOOL is_cert_file_name(const char* path);

void free_filebuf(FILEBUF* f);
void free_filelist(FILELIST* list);
BOOL filelist_push(FILELIST* list, const char* name, const BYTE* data, DWORD size);

BOOL is_pem_data(const BYTE* data, DWORD size);
BOOL base64_decode_alloc(const char* s, BYTE** out, DWORD* outSize);
BOOL sha256_hex(const BYTE* data, DWORD size, char outHex[65]);
BOOL parse_certs_from_extracted_files(HCERTSTORE* outStore);
BOOL build_cab_trust_stores(HCERTSTORE hCabStore, HCERTSTORE* outRoots, HCERTSTORE* outIntermediates, DWORD* outRootCount, DWORD* outIntermediateCount);
BOOL cert_equals(PCCERT_CONTEXT a, PCCERT_CONTEXT b);
BOOL store_contains_cert_exact(HCERTSTORE store, PCCERT_CONTEXT cert);
BOOL is_self_signed(PCCERT_CONTEXT c);
BOOL cert_is_self_signed(PCCERT_CONTEXT cert);
BOOL cert_is_trusted_root(PCCERT_CONTEXT cert, HCERTSTORE hRoots);
BOOL cert_public_key_info_der(PCCERT_CONTEXT cert, BYTE** out, DWORD* outSize);
BOOL export_cert_public_key_blob(PCCERT_CONTEXT cert, BYTE** outBlob, DWORD* outBlobSize);
BOOL ekpub_matches_cert(PCCERT_CONTEXT cert, const BYTE* ekPub, DWORD ekPubSize);
BOOL cert_signature_validates_against_issuer(PCCERT_CONTEXT subject, PCCERT_CONTEXT issuer);
BOOL blob_equals(const CRYPT_DATA_BLOB* a, const CRYPT_DATA_BLOB* b);
BOOL get_cert_subject_key_identifier(PCCERT_CONTEXT cert, CRYPT_DATA_BLOB* out);
BOOL get_cert_authority_key_identifier(PCCERT_CONTEXT cert, CRYPT_DATA_BLOB* out);
BOOL get_tpm_info_via_ncrypt(TPMINFO* info);
BOOL get_ek_cert_store_directly(HCERTSTORE* out_store);
PCCERT_CONTEXT find_valid_issuer_in_store(HCERTSTORE store, PCCERT_CONTEXT subject);

void free_wstringlist(WSTRINGLIST* list);
BOOL wstringlist_contains(const WSTRINGLIST* list, const WCHAR* s);
BOOL wstringlist_push(WSTRINGLIST* list, const WCHAR* s);
BOOL url_is_http(const WCHAR* url);
BOOL extract_aia_ca_issuers(PCCERT_CONTEXT cert, WSTRINGLIST* urls);

BOOL extract_cab_from_memory(const BYTE* cabData, DWORD cabSize);
BOOL read_file_to_memory(const wchar_t* filePath, BYTE** outData, DWORD* outSize);

BOOL download_url_to_memory(const wchar_t* url, BYTE** outData, DWORD* outSize);

BOOL read_ncrypt_property_bytes(NCRYPT_PROV_HANDLE hProv, LPCWSTR prop, BYTE** outBuf, DWORD* outSize);
BOOL read_ncrypt_property_string(NCRYPT_PROV_HANDLE hProv, LPCWSTR prop, char* out, size_t outChars);
BOOL get_tpm_info_via_tbs(TPMINFO* info);
BOOL get_pcp_info(TPMINFO* info);
BOOL get_pcp_ek_cert_store(NCRYPT_PROV_HANDLE hProv, HCERTSTORE* outStore);
void load_certs_from_registry(HKEY hKey, HCERTSTORE store, WCHAR* szValueName);
void load_tpm_intermediate_certs_from_registry(HCERTSTORE store);
void load_certs_from_pcp_property_store(NCRYPT_PROV_HANDLE hProv, LPCWSTR propName, HCERTSTORE hStoreToAddTo);
void load_pcp_intermediate_certs(HCERTSTORE store);
BOOL build_candidate_issuer_store(HCERTSTORE hCabStore, HCERTSTORE hRoots, HCERTSTORE hCaStore, HCERTSTORE* outStore);

BOOL perform_local_tpm_pop_challenge(PCCERT_CONTEXT ekCert);

BOOL manual_ek_chain_walk(PCCERT_CONTEXT leaf, HCERTSTORE hCabRoots, HCERTSTORE hCandidateStore, DWORD depth, TRUST_PATH* outPath, PCCERT_CONTEXT* outLeaf, FILE* out);
BOOL verify_ek_by_manual_chain(PCCERT_CONTEXT ekCert, const BYTE* ekPub, DWORD ekPubSize, HCERTSTORE hCabRoots, HCERTSTORE hCandidateStore, TRUST_PATH* outPath, PCCERT_CONTEXT* outLeaf);

BOOL is_trusted_manufacturer_url(const WCHAR* url);

#endif