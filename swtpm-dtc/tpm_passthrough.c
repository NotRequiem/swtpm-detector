#include "tpm_passthrough.h"

#include <bcrypt.h>
#include <ncrypt.h>
#include <tbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef _MSC_VER
    #pragma comment(lib, "tbs.lib")
    #pragma comment(lib, "bcrypt.lib")
    #pragma comment(lib, "ncrypt.lib")
#endif

#ifndef TBS_TCGLOG_SRTM_CURRENT
    #define TBS_TCGLOG_SRTM_CURRENT 1
#endif

#ifndef NCRYPT_CLAIM_PLATFORM
    #define NCRYPT_CLAIM_PLATFORM 0x00010000
#endif

#ifndef NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK
    #define NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK 82
#endif

#ifndef NCRYPTBUFFER_TPM_PLATFORM_CLAIM_NONCE
    #define NCRYPTBUFFER_TPM_PLATFORM_CLAIM_NONCE 81
#endif

#ifndef TPM_ALG_SHA256
    #define TPM_ALG_SHA256 0x000B
#endif

#ifndef STATUS_SUCCESS
    #define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef NCRYPTBUFFER_VERSION
    #define NCRYPTBUFFER_VERSION 0
#endif

#pragma pack(push, 1)
typedef struct {
    uint32_t PCRIndex;
    uint32_t EventType;
    uint8_t Digest[20];
    uint32_t EventSize;
} TCG_PCR_EVENT_HEADER;
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

#define MAX_ALG_PAIRS 16
typedef struct {
    AlgSizePair pairs[MAX_ALG_PAIRS];
    uint32_t count;
} AlgSizeMap;

static void pcreventlist_init(PcrEventList* list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static BOOL pcreventlist_push(PcrEventList* list, uint32_t eventType, const uint8_t* digest, uint32_t digestSize) {
    if (list->count == list->capacity) {
        uint32_t newCap = list->capacity ? list->capacity * 2 : 16;
        TrackedEvent* newItems = (TrackedEvent*)realloc(list->items, newCap * sizeof(TrackedEvent));
        if (!newItems) return FALSE;
        list->items = newItems;
        list->capacity = newCap;
    }
    list->items[list->count].eventType = eventType;
    list->items[list->count].digestSize = digestSize;
    memset(list->items[list->count].digest, 0, 32);
    memcpy(list->items[list->count].digest, digest, digestSize > 32 ? 32 : digestSize);
    list->count++;
    return TRUE;
}

static void pcreventlist_free(PcrEventList* list) {
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void algsizemap_init(AlgSizeMap* map) {
    map->count = 0;
}

static void algsizemap_set(AlgSizeMap* map, uint16_t algId, uint16_t digestSize) {
    for (uint32_t i = 0; i < map->count; i++) {
        if (map->pairs[i].algId == algId) {
            map->pairs[i].digestSize = digestSize;
            return;
        }
    }
    if (map->count < MAX_ALG_PAIRS) {
        map->pairs[map->count].algId = algId;
        map->pairs[map->count].digestSize = digestSize;
        map->count++;
    }
}

static uint16_t algsizemap_get(const AlgSizeMap* map, uint16_t algId, BOOL* found) {
    for (uint32_t i = 0; i < map->count; i++) {
        if (map->pairs[i].algId == algId) {
            if (found) *found = TRUE;
            return map->pairs[i].digestSize;
        }
    }
    if (found) *found = FALSE;
    return 0;
}

static BOOL calculate_sha256(const uint8_t* data, uint32_t size, uint8_t outDigest[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0;
    DWORD cbData = sizeof(DWORD);
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) return FALSE;

    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, cbData, &cbData, 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    BYTE* hashObject = (BYTE*)malloc(cbHashObject);
    if (!hashObject) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    status = BCryptCreateHash(hAlg, &hHash, hashObject, cbHashObject, NULL, 0, 0);
    if (status != STATUS_SUCCESS) {
        free(hashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    status = BCryptHashData(hHash, (PUCHAR)data, size, 0);
    if (status == STATUS_SUCCESS) {
        status = BCryptFinishHash(hHash, outDigest, 32, 0);
    }

    BCryptDestroyHash(hHash);
    free(hashObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return (status == STATUS_SUCCESS);
}

static BOOL read_tpm_pcr(TBS_HCONTEXT hContext, uint32_t pcrIndex, uint16_t algId, uint8_t* outDigest, uint32_t* outDigestSize) {
    uint8_t cmd[20] = { 0 };
    cmd[0] = 0x80; cmd[1] = 0x01;
    cmd[2] = 0x00; cmd[3] = 0x00; cmd[4] = 0x00; cmd[5] = 0x14;
    cmd[6] = 0x00; cmd[7] = 0x00; cmd[8] = 0x01; cmd[9] = 0x7E;
    cmd[10] = 0x00; cmd[11] = 0x00; cmd[12] = 0x00; cmd[13] = 0x01;

    cmd[14] = (algId >> 8) & 0xFF;
    cmd[15] = algId & 0xFF;
    cmd[16] = 0x03;
    cmd[17] = 0x00;
    cmd[18] = 0x00;
    cmd[19] = 0x00;
    cmd[17 + (pcrIndex / 8)] = 1 << (pcrIndex % 8);

    uint8_t resp[256];
    uint32_t respSize = sizeof(resp);

    TBS_RESULT hr = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmd, sizeof(cmd), resp, &respSize);
    if (hr != TBS_SUCCESS) return FALSE;

    if (respSize < 10) return FALSE;
    uint32_t code = ((uint32_t)resp[6] << 24) | ((uint32_t)resp[7] << 16) | ((uint32_t)resp[8] << 8) | resp[9];
    if (code != 0) return FALSE;

    uint32_t offset = 10;
    offset += 4; 

    if (offset + 4 > respSize) return FALSE;
    uint32_t selCount = ((uint32_t)resp[offset] << 24) | ((uint32_t)resp[offset + 1] << 16) | ((uint32_t)resp[offset + 2] << 8) | resp[offset + 3];
    offset += 4;
    if (selCount != 1) return FALSE;

    offset += 2; 
    if (offset + 1 > respSize) return FALSE;
    uint8_t retSizeofSelect = resp[offset];
    offset += 1 + retSizeofSelect;

    if (offset + 4 > respSize) return FALSE;
    uint32_t digestCount = ((uint32_t)resp[offset] << 24) | ((uint32_t)resp[offset + 1] << 16) | ((uint32_t)resp[offset + 2] << 8) | resp[offset + 3];
    offset += 4;
    if (digestCount != 1) return FALSE;

    if (offset + 2 > respSize) return FALSE;
    uint16_t digestSize = (resp[offset] << 8) | resp[offset + 1];
    offset += 2;

    if (offset + digestSize > respSize) return FALSE;
    if (outDigest) {
        memcpy(outDigest, resp + offset, digestSize > 32 ? 32 : digestSize);
    }
    if (outDigestSize) {
        *outDigestSize = digestSize;
    }
    return TRUE;
}

static void trace_pcr_reconstruction(const PcrEventList* list, const uint8_t* actualPCR, uint32_t actualPCRSize) {
    uint8_t currentPCR[32] = { 0 };
    printf("[Start] Initialization State       : ");
    for (int i = 0; i < 32; i++) printf("%02x", currentPCR[i]);
    printf("\n");

    for (uint32_t i = 0; i < list->count; i++) {
        const TrackedEvent* ev = &list->items[i];
        printf("[Event %3u] Type: 0x%08X", i + 1, ev->eventType);

        if (ev->eventType == 0x00000003) {
            printf(" - (EV_NO_ACTION)\n");
            continue;
        }
        else {
            printf(" - Extending...\n");
        }

        printf("Incoming Measurement Digest: ");
        for (uint32_t j = 0; j < ev->digestSize; j++) printf("%02x", ev->digest[j]);
        printf("\n");

        uint8_t concat[64];
        memcpy(concat, currentPCR, 32);
        memcpy(concat + 32, ev->digest, 32);
        calculate_sha256(concat, 64, currentPCR);

        printf("Resulting Register State: ");
        for (int j = 0; j < 32; j++) printf("%02x", currentPCR[j]);
        printf("\n");
    }

    printf("Reconstructed PCR: ");
    for (int i = 0; i < 32; i++) printf("%02x", currentPCR[i]);
    printf("\n");
    printf("Actual hardware PCR : ");
    for (uint32_t i = 0; i < actualPCRSize; i++) printf("%02x", actualPCR[i]);
    printf("\n");
}

static NCRYPT_KEY_HANDLE get_or_create_aik(NCRYPT_PROV_HANDLE hProv) {
    NCRYPT_KEY_HANDLE hKey = 0;
    SECURITY_STATUS status = NCryptOpenKey(hProv, &hKey, L"VMOwnedAttestationKey", 0, 0);
    if (status == ERROR_SUCCESS) {
        return hKey;
    }

    status = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, L"VMOwnedAttestationKey", 0, 0);
    if (status != ERROR_SUCCESS) {
        return 0;
    }

    status = NCryptFinalizeKey(hKey, 0);
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(hKey);
        return 0;
    }

    return hKey;
}

BOOL detect_tpm_passthrough(void) {
    TBS_CONTEXT_PARAMS2 params = { 0 };
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.asUINT32 = 0;
    params.requestRaw = 1;
    params.includeTpm20 = 1;

    TBS_HCONTEXT hTbsContext = 0;
    TBS_RESULT hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hTbsContext);
    if (hr != TBS_SUCCESS) {
        fprintf(stderr, "[-] Failed to establish TBS context. Code: 0x%08lX\n", (unsigned long)hr);
        return FALSE;
    }

    UINT32 logSize = 0;
    hr = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, NULL, &logSize);
    if (hr != TBS_E_INSUFFICIENT_BUFFER && hr != TBS_SUCCESS) {
        fprintf(stderr, "[-] Failed to retrieve log size. Code: 0x%08lX\n", (unsigned long)hr);
        Tbsip_Context_Close(hTbsContext);
        return FALSE;
    }

    BYTE* logBuffer = (BYTE*)malloc(logSize);
    if (!logBuffer) {
        Tbsip_Context_Close(hTbsContext);
        return FALSE;
    }

    hr = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, logBuffer, &logSize);
    if (hr != TBS_SUCCESS) {
        fprintf(stderr, "[-] Failed to download TCG log. Code: 0x%08lX\n", (unsigned long)hr);
        free(logBuffer);
        Tbsip_Context_Close(hTbsContext);
        return FALSE;
    }
    printf("[+] Downloaded TCG Log (" "%lu" " bytes).\n", (unsigned long)logSize);

    AlgSizeMap algToSize;
    algsizemap_init(&algToSize);
    algsizemap_set(&algToSize, 0x0004, 20); 
    algsizemap_set(&algToSize, TPM_ALG_SHA256, 32);

    PcrEventList pcrEvents[24] = { 0 };
    for (uint32_t i = 0; i < 24; ++i) {
        pcreventlist_init(&pcrEvents[i]);
    }

    size_t offset = 0;

    if (offset + sizeof(TCG_PCR_EVENT_HEADER) <= logSize) {
        const TCG_PCR_EVENT_HEADER* firstHeader = (const TCG_PCR_EVENT_HEADER*)(logBuffer + offset);
        offset += sizeof(TCG_PCR_EVENT_HEADER);

        if (offset + firstHeader->EventSize <= logSize) {
            const uint8_t* firstEventData = logBuffer + offset;
            offset += firstHeader->EventSize;

            if (firstHeader->EventType == 0x03 && firstHeader->EventSize >= 28) { 
                if (memcmp(firstEventData, "Spec ID Event03", 15) == 0) {
                    uint32_t numAlgs = *(const uint32_t*)(firstEventData + 24);
                    uint32_t algOffset = 28;
                    for (uint32_t i = 0; i < numAlgs; ++i) {
                        if (algOffset + 4 > firstHeader->EventSize) break;
                        uint16_t algId = *(const uint16_t*)(firstEventData + algOffset);
                        uint16_t digestSize = *(const uint16_t*)(firstEventData + algOffset + 2);
                        algsizemap_set(&algToSize, algId, digestSize);
                        algOffset += 4;
                    }
                }
            }
        }
    }

    while (offset < logSize) {
        if (offset + 8 > logSize) break;
        uint32_t pcrIndex = *(const uint32_t*)(logBuffer + offset);
        uint32_t eventType = *(const uint32_t*)(logBuffer + offset + 4);
        offset += 8;

        if (offset + 4 > logSize) break;
        uint32_t digestCount = *(const uint32_t*)(logBuffer + offset);
        offset += 4;

        typedef struct {
            uint16_t algId;
            uint8_t digest[64];
            uint32_t size;
        } TempDigest;

        TempDigest tempDigests[16] = { 0 };
        uint32_t tempDigestCount = 0;
        BOOL parseSuccess = TRUE;

        for (uint32_t i = 0; i < digestCount; ++i) {
            if (offset + 2 > logSize) { parseSuccess = FALSE; break; }
            uint16_t algId = *(const uint16_t*)(logBuffer + offset);
            offset += 2;

            BOOL found = FALSE;
            uint16_t size = algsizemap_get(&algToSize, algId, &found);
            if (!found) { parseSuccess = FALSE; break; }
            if (offset + size > logSize) { parseSuccess = FALSE; break; }

            if (tempDigestCount < 16) {
                tempDigests[tempDigestCount].algId = algId;
                tempDigests[tempDigestCount].size = size;
                memcpy(tempDigests[tempDigestCount].digest, logBuffer + offset, size);
                tempDigestCount++;
            }
            offset += size;
        }

        if (!parseSuccess) break;

        if (offset + 4 > logSize) break;
        uint32_t eventSize = *(const uint32_t*)(logBuffer + offset);
        offset += 4;

        if (offset + eventSize > logSize) break;
        offset += eventSize; 

        for (uint32_t i = 0; i < tempDigestCount; ++i) {
            if (tempDigests[i].algId == TPM_ALG_SHA256 && pcrIndex < 24) {
                pcreventlist_push(&pcrEvents[pcrIndex], eventType, tempDigests[i].digest, tempDigests[i].size);
            }
        }
    }

    uint8_t reconstructedPCRs[24][32];
    memset(reconstructedPCRs, 0, sizeof(reconstructedPCRs));

    for (uint32_t pcrIdx = 0; pcrIdx < 8; ++pcrIdx) {
        uint8_t currentPCR[32] = { 0 };
        for (uint32_t j = 0; j < pcrEvents[pcrIdx].count; ++j) {
            const TrackedEvent* ev = &pcrEvents[pcrIdx].items[j];
            if (ev->eventType == 0x00000003) {
                continue; 
            }
            uint8_t concat[64];
            memcpy(concat, currentPCR, 32);
            memcpy(concat + 32, ev->digest, 32);
            calculate_sha256(concat, 64, currentPCR);
        }
        memcpy(reconstructedPCRs[pcrIdx], currentPCR, 32);
    }

    BOOL passthroughDetected = FALSE;
    uint32_t mismatchingIdxs[8] = { 0 };
    uint32_t mismatchingCount = 0;

    for (uint32_t pcrIdx = 0; pcrIdx < 8; ++pcrIdx) {
        uint8_t actualPCR[32] = { 0 };
        uint32_t actualPCRSize = 0;
        if (read_tpm_pcr(hTbsContext, pcrIdx, TPM_ALG_SHA256, actualPCR, &actualPCRSize)) {
            if (actualPCRSize != 32 || memcmp(actualPCR, reconstructedPCRs[pcrIdx], 32) != 0) {
                mismatchingIdxs[mismatchingCount++] = pcrIdx;

                printf("[!] Mismatch detected on PCR [%u].\n", pcrIdx);
                printf("Reconstructed TCG: ");
                for (int j = 0; j < 32; ++j) printf("%02x", reconstructedPCRs[pcrIdx][j]);
                printf("\n");
                printf("Hardware response: ");
                for (uint32_t j = 0; j < actualPCRSize; ++j) printf("%02x", actualPCR[j]);
                printf("\n");

                if (pcrIdx != 0 && pcrIdx != 6) {
                    passthroughDetected = TRUE;
                }
            }
            else {
                printf("[+] PCR[%u] matches.\n", pcrIdx);
            }
        }
        else {
            fprintf(stderr, "[-] Failed to read actual PCR[%u]\n", pcrIdx);
        }
    }

    if (mismatchingCount > 0) {
        printf("\n[*] Tracing...\n");
        for (uint32_t i = 0; i < mismatchingCount; ++i) {
            uint32_t pcrIdx = mismatchingIdxs[i];
            uint8_t actualPCR[32] = { 0 };
            uint32_t actualPCRSize = 0;
            read_tpm_pcr(hTbsContext, pcrIdx, TPM_ALG_SHA256, actualPCR, &actualPCRSize);
            trace_pcr_reconstruction(&pcrEvents[pcrIdx], actualPCR, actualPCRSize);
        }
    }

    printf("[*] Quoting TPM...\n");
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status == ERROR_SUCCESS) {
        NCRYPT_KEY_HANDLE hAik = get_or_create_aik(hProv);
        if (hAik != 0) {
            uint8_t pcrMask[] = { 0xFF, 0x00, 0x00 }; 
            uint8_t nonce[20] = { 0 };
            NTSTATUS ntStatus = BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            (ntStatus);

            NCryptBuffer paramBuffers[2] = { 0 };
            paramBuffers[0].BufferType = NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK;
            paramBuffers[0].cbBuffer = sizeof(pcrMask);
            paramBuffers[0].pvBuffer = pcrMask;

            paramBuffers[1].BufferType = NCRYPTBUFFER_TPM_PLATFORM_CLAIM_NONCE;
            paramBuffers[1].cbBuffer = sizeof(nonce);
            paramBuffers[1].pvBuffer = nonce;

            NCryptBufferDesc paramList = { 0 };
            paramList.ulVersion = NCRYPTBUFFER_VERSION;
            paramList.cBuffers = 2;
            paramList.pBuffers = paramBuffers;

            DWORD cbClaim = 0;
            status = NCryptCreateClaim(0, hAik, NCRYPT_CLAIM_PLATFORM, &paramList, NULL, 0, &cbClaim, 0);
            if (status == ERROR_SUCCESS || status == NTE_BUFFER_TOO_SMALL) {
                BYTE* claimBlob = (BYTE*)malloc(cbClaim);
                if (claimBlob) {
                    status = NCryptCreateClaim(0, hAik, NCRYPT_CLAIM_PLATFORM, &paramList, claimBlob, cbClaim, &cbClaim, 0);
                    if (status == ERROR_SUCCESS) {
                        printf("[+] TPM platform claim generated (%lu bytes).\n", cbClaim);
                        printf("Header: ");
                        DWORD previewLen = cbClaim > 16 ? 16 : cbClaim;
                        for (DWORD j = 0; j < previewLen; ++j) printf("%02x", claimBlob[j]);
                        printf("\n");
                    }
                    else {
                        fprintf(stderr, "[-] NCryptCreateClaim failed. Code: 0x%08lX\n", (unsigned long)status);
                    }
                    free(claimBlob);
                }
            }
            NCryptFreeObject(hAik);
        }
        else {
            fprintf(stderr, "[-] Failed to open/create AIK.\n");
        }
        NCryptFreeObject(hProv);
    }
    else {
        fprintf(stderr, "[-] Failed to open Platform Crypto Provider.\n");
    }

    for (uint32_t i = 0; i < 24; ++i) {
        pcreventlist_free(&pcrEvents[i]);
    }
    free(logBuffer);
    Tbsip_Context_Close(hTbsContext);

    return !passthroughDetected;
}