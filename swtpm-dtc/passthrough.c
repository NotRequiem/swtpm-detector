#include "tpm.h"

static void pcreventlist_init(PcrEventList* list) {
    if (!list) return;
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static BOOL pcreventlist_push(PcrEventList* list, uint32_t eventType, const uint8_t* digest, uint32_t digestSize) {
    if (!list || !digest) return FALSE;
    if (list->count == list->capacity) {
        if (list->capacity > (UINT32_MAX / sizeof(TrackedEvent)) / 2) return FALSE;
        uint32_t newCap = list->capacity ? list->capacity * 2 : 16;
        TrackedEvent* newItems = (TrackedEvent*)realloc(list->items, newCap * sizeof(TrackedEvent));
        if (!newItems) return FALSE;
        list->items = newItems;
        list->capacity = newCap;
    }
    list->items[list->count].eventType = eventType;
    list->items[list->count].digestSize = (digestSize > 32) ? 32 : digestSize;
    memset(list->items[list->count].digest, 0, 32);
    memcpy(list->items[list->count].digest, digest, list->items[list->count].digestSize);
    list->count++;
    return TRUE;
}

static void pcreventlist_free(PcrEventList* list) {
    if (!list) return;
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void algsizemap_init(AlgSizeMap* map) {
    if (!map) return;
    map->count = 0;
}

static void algsizemap_set(AlgSizeMap* map, uint16_t algId, uint16_t digestSize) {
    if (!map || digestSize == 0 || digestSize > 64) return;
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
    if (!map) {
        if (found) *found = FALSE;
        return 0;
    }
    for (uint32_t i = 0; i < map->count; i++) {
        if (map->pairs[i].algId == algId) {
            if (found) *found = TRUE;
            return map->pairs[i].digestSize;
        }
    }
    if (found) *found = FALSE;
    return 0;
}

static BOOL read_tpm_pcr(TBS_HCONTEXT hContext, uint32_t pcrIndex, uint16_t algId, uint8_t* outDigest, uint32_t* outDigestSize) {
    if (pcrIndex >= 24) return FALSE;
    uint8_t cmd[20] = { 0 };
    cmd[0] = 0x80; cmd[1] = 0x01; // TPM_ST_NO_SESSIONS
    cmd[2] = 0x00; cmd[3] = 0x00; cmd[4] = 0x00; cmd[5] = 0x14; // 20 bytes
    cmd[6] = 0x00; cmd[7] = 0x00; cmd[8] = 0x01; cmd[9] = 0x7E; // TPM_CC_PCR_Read (0x0000017E)
    cmd[10] = 0x00; cmd[11] = 0x00; cmd[12] = 0x00; cmd[13] = 0x01; // TPML_PCR_SELECTION count = 1

    cmd[14] = (algId >> 8) & 0xFF;
    cmd[15] = algId & 0xFF;
    cmd[16] = 0x03; // sizeofSelect = 3 bytes (PCRs 0-23)
    cmd[17] = 0x00;
    cmd[18] = 0x00;
    cmd[19] = 0x00;
    cmd[17 + (pcrIndex / 8)] = (uint8_t)(1 << (pcrIndex % 8));

    uint8_t resp[256];
    uint32_t respSize = sizeof(resp);

    TBS_RESULT hr = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmd, sizeof(cmd), resp, &respSize);
    if (hr != TBS_SUCCESS || respSize < 10) return FALSE;

    uint32_t rc = ((uint32_t)resp[6] << 24) | ((uint32_t)resp[7] << 16) | ((uint32_t)resp[8] << 8) | resp[9];
    if (rc != 0) return FALSE;

    uint32_t offset = 14;
    if (respSize < offset || respSize - offset < 4) return FALSE;
    uint32_t selCount = ((uint32_t)resp[offset] << 24) | ((uint32_t)resp[offset + 1] << 16) | ((uint32_t)resp[offset + 2] << 8) | resp[offset + 3];
    offset += 4;
    if (selCount != 1) return FALSE;

    if (respSize - offset < 2) return FALSE;
    offset += 2;

    if (respSize - offset < 1) return FALSE;
    uint8_t retSizeofSelect = resp[offset++];

    if (respSize - offset < retSizeofSelect) return FALSE;
    offset += retSizeofSelect;

    if (respSize - offset < 4) return FALSE;
    uint32_t digestCount = ((uint32_t)resp[offset] << 24) | ((uint32_t)resp[offset + 1] << 16) | ((uint32_t)resp[offset + 2] << 8) | resp[offset + 3];
    offset += 4;
    if (digestCount != 1) return FALSE;

    if (respSize - offset < 2) return FALSE;
    uint16_t digestSize = ((uint16_t)resp[offset] << 8) | (uint16_t)resp[offset + 1];
    offset += 2;

    if (respSize - offset < digestSize) return FALSE;
    if (outDigest) {
        memcpy(outDigest, resp + offset, digestSize > 64 ? 64 : digestSize);
    }
    if (outDigestSize) {
        *outDigestSize = (digestSize > 64) ? 64 : digestSize;
    }
    return TRUE;
}

static void trace_pcr_reconstruction(const PcrEventList* list, const uint8_t* actualPCR, uint32_t actualPCRSize) {
    if (!list || !actualPCR || (list->count > 0 && !list->items)) return;
    uint8_t currentPCR[32] = { 0 };
    printf("[Start] Initialization State       : ");
    for (int i = 0; i < 32; i++) printf("%02x", currentPCR[i]);
    printf("\n");

    for (uint32_t i = 0; i < list->count; i++) {
        const TrackedEvent* ev = &list->items[i];
        printf("[Event %3u] Type: 0x%08X", i + 1, ev->eventType);

        if (ev->eventType == 0x00000003) {
            printf(" - (EV_NO_ACTION - not extended)\n");
            continue;
        }
        else {
            printf(" - Extending...\n");
        }

        uint8_t concat[64];
        memcpy(concat, currentPCR, 32);
        memcpy(concat + 32, ev->digest, 32);
        calculate_sha256(concat, 64, currentPCR);
    }

    printf("Reconstructed PCR : ");
    for (int i = 0; i < 32; i++) printf("%02x", currentPCR[i]);
    printf("\n");
    printf("Hardware Register : ");
    uint32_t printSize = (actualPCRSize > 64) ? 64 : actualPCRSize;
    for (uint32_t i = 0; i < printSize; i++) printf("%02x", actualPCR[i]);
    printf("\n");
}

static BOOL mem_contains_pattern(const uint8_t* haystack, uint32_t haystackLen, const void* needle, uint32_t needleLen) {
    if (!haystack || !needle || needleLen == 0 || haystackLen < needleLen) return FALSE;
    for (uint32_t k = 0; k <= haystackLen - needleLen; ++k) {
        BOOL match = TRUE;
        for (uint32_t m = 0; m < needleLen; ++m) {
            uint8_t b1 = haystack[k + m];
            uint8_t b2 = ((const uint8_t*)needle)[m];
            if (b1 >= 'A' && b1 <= 'Z') b1 += ('a' - 'A');
            if (b2 >= 'A' && b2 <= 'Z') b2 += ('a' - 'A');
            if (b1 != b2) {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

static BOOL query_boot_drive_gpt_guid(GUID* outGuid) {
    if (!outGuid) return FALSE;
    WCHAR drivePath[64] = L"\\\\.\\PhysicalDrive0";
    WCHAR sysDir[MAX_PATH] = { 0 };
    if (GetSystemWindowsDirectoryW(sysDir, MAX_PATH) >= 2 && sysDir[1] == L':') {
        WCHAR volPath[32];
        swprintf_s(volPath, 32, L"\\\\.\\%c:", sysDir[0]);
        HANDLE hVol = CreateFileW(volPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hVol != INVALID_HANDLE_VALUE) {
            VOLUME_DISK_EXTENTS extents = { 0 };
            DWORD br = 0;
            if (DeviceIoControl(hVol, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, &extents, sizeof(extents), &br, NULL) &&
                extents.NumberOfDiskExtents > 0) {
                swprintf_s(drivePath, 64, L"\\\\.\\PhysicalDrive%u", extents.Extents[0].DiskNumber);
            }
            CloseHandle(hVol);
        }
    }

    HANDLE hDisk = CreateFileW(drivePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        if (wcscmp(drivePath, L"\\\\.\\PhysicalDrive0") != 0) {
            hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        }
        if (hDisk == INVALID_HANDLE_VALUE) return FALSE;
    }

    DWORD bufSize = 64 * 1024;
    BYTE* buf = (BYTE*)malloc(bufSize);
    if (!buf) {
        CloseHandle(hDisk);
        return FALSE;
    }

    DWORD bytesReturned = 0;
    BOOL ok = FALSE;
    for (int retry = 0; retry < 4; ++retry) {
        if (DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, buf, bufSize, &bytesReturned, NULL)) {
            ok = TRUE;
            break;
        }
        DWORD err = GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER && err != ERROR_MORE_DATA) {
            break;
        }
        if (bufSize > (UINT32_MAX / 2)) {
            break;
        }
        bufSize *= 2;
        BYTE* newBuf = (BYTE*)realloc(buf, bufSize);
        if (!newBuf) {
            break;
        }
        buf = newBuf;
    }
    CloseHandle(hDisk);

    if (!ok || bytesReturned < (DWORD)FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry)) {
        free(buf);
        return FALSE;
    }

    PDRIVE_LAYOUT_INFORMATION_EX layout = (PDRIVE_LAYOUT_INFORMATION_EX)buf;
    if (layout->PartitionStyle != PARTITION_STYLE_GPT) {
        free(buf);
        return FALSE;
    }

    memcpy(outGuid, &layout->Gpt.DiskId, sizeof(GUID));
    free(buf);
    return TRUE;
}

static BOOL validate_uefi_bootmg_device_path(const uint8_t* payload, uint32_t size) {
    if (!payload || size < sizeof(UEFI_IMAGE_LOAD_EVENT)) return FALSE;

    const UEFI_IMAGE_LOAD_EVENT* loadEvent = (const UEFI_IMAGE_LOAD_EVENT*)payload;
    uint64_t dpLen = 0;
    memcpy(&dpLen, &loadEvent->LengthOfDevicePath, sizeof(dpLen));
    if (dpLen < sizeof(EFI_DEVICE_PATH_HEADER) || dpLen >(uint64_t)size - sizeof(UEFI_IMAGE_LOAD_EVENT)) {
        return FALSE;
    }

    const uint8_t* dpStart = payload + sizeof(UEFI_IMAGE_LOAD_EVENT);
    uint32_t offset = 0;
    BOOL hasHardDrive = FALSE;
    BOOL hasBootmgFile = FALSE;
    BOOL terminated = FALSE;

    while (dpLen - offset >= sizeof(EFI_DEVICE_PATH_HEADER)) {
        const EFI_DEVICE_PATH_HEADER* node = (const EFI_DEVICE_PATH_HEADER*)(dpStart + offset);
        uint16_t nodeLen = 0;
        memcpy(&nodeLen, &node->Length, sizeof(nodeLen));
        if (nodeLen < sizeof(EFI_DEVICE_PATH_HEADER) || (uint32_t)nodeLen > dpLen - offset) {
            return FALSE;
        }

        if (node->Type == 0x04) {
            if (node->SubType == 0x01 && nodeLen >= sizeof(HARDDRIVE_DEVICE_PATH)) {
                HARDDRIVE_DEVICE_PATH hd;
                memcpy(&hd, node, sizeof(HARDDRIVE_DEVICE_PATH));
                if ((hd.PartitionFormat == 0x01 || hd.PartitionFormat == 0x02) &&
                    (hd.SignatureType == 0x01 || hd.SignatureType == 0x02)) {
                    hasHardDrive = TRUE;
                }
            }
            else if (node->SubType == 0x04 && nodeLen > sizeof(EFI_DEVICE_PATH_HEADER)) {
                const uint8_t* filePathBytes = dpStart + offset + sizeof(EFI_DEVICE_PATH_HEADER);
                uint32_t filePathLen = (uint32_t)nodeLen - (uint32_t)sizeof(EFI_DEVICE_PATH_HEADER);
                if (mem_contains_pattern(filePathBytes, filePathLen, "bootmg", 6) ||
                    mem_contains_pattern(filePathBytes, filePathLen, "\x62\x00\x6F\x00\x6F\x00\x74\x00\x6D\x00\x67\x00", 12)) {
                    hasBootmgFile = TRUE;
                }
            }
        }
        else if (node->Type == 0x7F) {
            if (node->SubType == 0xFF || node->SubType == 0x01) {
                terminated = TRUE;
                break;
            }
        }

        offset += nodeLen;
    }

    return (hasHardDrive && hasBootmgFile && terminated);
}

BOOL detect_tpm_passthrough(PCCERT_CONTEXT ekCert) {
    if (!ekCert) return FALSE;
    TBS_CONTEXT_PARAMS2 params = { 0 };
    TBS_HCONTEXT hTbsContext = 0;
    TBS_RESULT hr = TBS_SUCCESS;
    UINT32 logSize = 0;
    BYTE* logBuffer = NULL;
    AlgSizeMap algToSize;
    PcrEventList pcrEvents[24] = { 0 };
    size_t offset = 0;

    uint8_t reconstructedPCRs[24][32];
    uint32_t mismatchingIdxs[16] = { 0 };
    uint32_t mismatchingCount = 0;

    const uint32_t selectedPCRs[] = { 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 16 };
    const uint32_t numSelectedPCRs = sizeof(selectedPCRs) / sizeof(selectedPCRs[0]);
    uint8_t concatenatedGuestPCRs[(sizeof(selectedPCRs) / sizeof(selectedPCRs[0])) * 32] = { 0 };
    uint32_t offset_concat = 0;
    uint8_t expectedPcrDigest[32] = { 0 };
    BOOL passthroughDetected = FALSE;
    BOOL quoteVerified = FALSE;

    BOOL pcr4HasBootManager = FALSE;
    BOOL pcr5GptGuidMatched = FALSE;
    GUID localBootDiskGuid = { 0 };
    BOOL haveLocalBootDiskGuid = query_boot_drive_gpt_guid(&localBootDiskGuid);

    uint8_t actualPCR[64] = { 0 };
    uint32_t actualPCRSize = 0;
    uint32_t i = 0;

    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;

    hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hTbsContext);
    if (hr != TBS_SUCCESS) {
        printf("[-] Failed to establish TBS context. Code: 0x%08lX\n", (unsigned long)hr);
        return FALSE;
    }

    hr = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, NULL, &logSize);
    if ((hr != TBS_E_INSUFFICIENT_BUFFER && hr != TBS_SUCCESS) || logSize == 0 || logSize > 32 * 1024 * 1024) {
        printf("[-] Failed to retrieve log size. Code: 0x%08lX\n", (unsigned long)hr);
        Tbsip_Context_Close(hTbsContext);
        return FALSE;
    }

    logBuffer = (BYTE*)malloc(logSize);
    if (!logBuffer) {
        Tbsip_Context_Close(hTbsContext);
        return FALSE;
    }

    hr = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, logBuffer, &logSize);
    if (hr != TBS_SUCCESS || logSize == 0) {
        printf("[-] Failed to download TCG log. Code: 0x%08lX\n", (unsigned long)hr);
        free(logBuffer);
        Tbsip_Context_Close(hTbsContext);
        return FALSE;
    }

    algsizemap_init(&algToSize);
    algsizemap_set(&algToSize, 0x0004, 20);         // TPM_ALG_SHA1
    algsizemap_set(&algToSize, TPM_ALG_SHA256, 32); // TPM_ALG_SHA256
    algsizemap_set(&algToSize, 0x000C, 48);         // TPM_ALG_SHA384
    algsizemap_set(&algToSize, 0x000D, 64);         // TPM_ALG_SHA512
    algsizemap_set(&algToSize, 0x0012, 32);         // TPM_ALG_SM3_256

    for (i = 0; i < 24; ++i) {
        pcreventlist_init(&pcrEvents[i]);
    }

    if (logSize - offset >= sizeof(TCG_PCR_EVENT_HEADER)) {
        TCG_PCR_EVENT_HEADER firstHeader;
        memcpy(&firstHeader, logBuffer + offset, sizeof(TCG_PCR_EVENT_HEADER));
        offset += sizeof(TCG_PCR_EVENT_HEADER);

        if (firstHeader.EventSize <= logSize - offset) {
            const uint8_t* firstEventData = logBuffer + offset;
            offset += firstHeader.EventSize;

            if (firstHeader.EventType == 0x03 && firstHeader.EventSize >= 28) {
                if (memcmp(firstEventData, "Spec ID Event03", 15) == 0) {
                    uint32_t numAlgs = 0;
                    memcpy(&numAlgs, firstEventData + 24, sizeof(numAlgs));
                    uint32_t algOffset = 28;
                    for (uint32_t j = 0; j < numAlgs; ++j) {
                        if (firstHeader.EventSize - algOffset < 4) break;
                        uint16_t algId = 0;
                        uint16_t digestSize = 0;
                        memcpy(&algId, firstEventData + algOffset, sizeof(algId));
                        memcpy(&digestSize, firstEventData + algOffset + 2, sizeof(digestSize));
                        algsizemap_set(&algToSize, algId, digestSize);
                        algOffset += 4;
                    }
                }
            }
        }
        else {
            passthroughDetected = TRUE;
            offset = logSize;
        }
    }

    while (offset < logSize) {
        if (logSize - offset < 8) {
            passthroughDetected = TRUE;
            break;
        }
        uint32_t pcrIndex = 0;
        uint32_t eventType = 0;
        memcpy(&pcrIndex, logBuffer + offset, sizeof(pcrIndex));
        memcpy(&eventType, logBuffer + offset + 4, sizeof(eventType));
        offset += 8;

        if (logSize - offset < 4) {
            passthroughDetected = TRUE;
            break;
        }
        uint32_t digestCount = 0;
        memcpy(&digestCount, logBuffer + offset, sizeof(digestCount));
        offset += 4;

        typedef struct {
            uint16_t algId;
            uint8_t digest[64];
            uint32_t size;
        } TempDigest;

        TempDigest tempDigests[32];
        memset(tempDigests, 0, sizeof(tempDigests));
        uint32_t tempDigestCount = 0;
        BOOL parseSuccess = TRUE;

        if (digestCount > (sizeof(tempDigests) / sizeof(tempDigests[0]))) {
            passthroughDetected = TRUE;
            break;
        }

        for (uint32_t j = 0; j < digestCount; ++j) {
            if (logSize - offset < 2) { parseSuccess = FALSE; break; }
            uint16_t algId = 0;
            memcpy(&algId, logBuffer + offset, sizeof(algId));
            offset += 2;

            BOOL found = FALSE;
            uint16_t size = algsizemap_get(&algToSize, algId, &found);
            if (!found || size == 0 || size > sizeof(tempDigests[0].digest) || size > logSize - offset) { parseSuccess = FALSE; break; }

            if (tempDigestCount < sizeof(tempDigests) / sizeof(tempDigests[0])) {
                tempDigests[tempDigestCount].algId = algId;
                tempDigests[tempDigestCount].size = size;
                memcpy(tempDigests[tempDigestCount].digest, logBuffer + offset, size);
                tempDigestCount++;
            }
            offset += size;
        }

        if (!parseSuccess) {
            passthroughDetected = TRUE;
            break;
        }

        if (logSize - offset < 4) {
            passthroughDetected = TRUE;
            break;
        }
        uint32_t eventSize = 0;
        memcpy(&eventSize, logBuffer + offset, sizeof(eventSize));
        offset += 4;

        if (eventSize > logSize - offset) {
            passthroughDetected = TRUE;
            break;
        }
        const uint8_t* eventPayload = logBuffer + offset;
        offset += eventSize;

        if (pcrIndex == 4) {
            BOOL hasBootmgPattern = mem_contains_pattern(eventPayload, eventSize, "bootmg", 6) ||
                mem_contains_pattern(eventPayload, eventSize, "\x62\x00\x6F\x00\x6F\x00\x74\x00\x6D\x00\x67\x00", 12);

            if (hasBootmgPattern) {
                if (eventType == 0x00000003) {
                    passthroughDetected = TRUE;
                }
                else if (eventType == 0x80000003) {
                    if (validate_uefi_bootmg_device_path(eventPayload, eventSize)) {
                        pcr4HasBootManager = TRUE;
                    }
                    else {
                        passthroughDetected = TRUE;
                    }
                }
                else {
                    passthroughDetected = TRUE;
                }
            }
        }
        else if (pcrIndex == 5 && haveLocalBootDiskGuid) {
            if (eventType == 0x00000003) {
                if (mem_contains_pattern(eventPayload, eventSize, "EFI PART", 8)) {
                    passthroughDetected = TRUE;
                }
            }
            else {
                for (uint32_t pos = 0; eventSize >= 72 && pos <= eventSize - 72; ++pos) {
                    if (memcmp(eventPayload + pos, "EFI PART", 8) == 0) {
                        if (memcmp(eventPayload + pos + 56, &localBootDiskGuid, sizeof(GUID)) == 0) {
                            pcr5GptGuidMatched = TRUE;
                            break;
                        }
                    }
                }
            }
        }

        for (uint32_t j = 0; j < tempDigestCount; ++j) {
            if (tempDigests[j].algId == TPM_ALG_SHA256 && pcrIndex < 24) {
                if (!pcreventlist_push(&pcrEvents[pcrIndex], eventType, tempDigests[j].digest, tempDigests[j].size)) {
                    passthroughDetected = TRUE;
                }
            }
        }
    }

    if (!pcr4HasBootManager) {
        printf("[!] PCR 4 event log lacks valid UEFI Windows Boot Manager device path records.\n");
        passthroughDetected = TRUE;
    }
    if (haveLocalBootDiskGuid && !pcr5GptGuidMatched) {
        printf("[!] PCR 5 GPT Disk GUID mismatch with local boot drive.\n");
        passthroughDetected = TRUE;
    }
    if (pcrEvents[7].count == 0) {
        printf("[!] Event log lacks Secure Boot (PCR 7) records.\n");
        passthroughDetected = TRUE;
    }
    if (pcrEvents[12].count == 0 || pcrEvents[13].count == 0 || pcrEvents[14].count == 0) {
        printf("[!] Event log lacks Windows OS Boot Manager/Loader (PCR 12/13/14) records.\n");
        passthroughDetected = TRUE;
    }

    memset(reconstructedPCRs, 0, sizeof(reconstructedPCRs));
    for (uint32_t pcrIdx = 0; pcrIdx < 24; ++pcrIdx) {
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

    uint8_t oldPcr16[64] = { 0 };
    uint32_t oldPcr16Size = 0;
    if (!read_tpm_pcr(hTbsContext, 16, TPM_ALG_SHA256, oldPcr16, &oldPcr16Size) || oldPcr16Size != 32) {
        passthroughDetected = TRUE;
    }

    uint8_t dynamicNonce[32] = { 0 };
    if (BCryptGenRandom(NULL, dynamicNonce, sizeof(dynamicNonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        passthroughDetected = TRUE;
    }

    if (!tpm_pcr_extend(hTbsContext, 16, dynamicNonce)) {
        passthroughDetected = TRUE;
    }

    uint8_t pcr16ExtendInput[64];
    memcpy(pcr16ExtendInput, oldPcr16, 32);
    memcpy(pcr16ExtendInput + 32, dynamicNonce, 32);
    if (!calculate_sha256(pcr16ExtendInput, sizeof(pcr16ExtendInput), reconstructedPCRs[16])) {
        passthroughDetected = TRUE;
    }

    for (i = 0; i < numSelectedPCRs; ++i) {
        if (selectedPCRs[i] < 24 && (unsigned long long)(offset_concat) + 32 <= sizeof(concatenatedGuestPCRs)) {
            memcpy(concatenatedGuestPCRs + offset_concat, reconstructedPCRs[selectedPCRs[i]], 32);
            offset_concat += 32;
        }
    }

    BYTE zeroPcr[32] = { 0 };
    if (memcmp(reconstructedPCRs[12], zeroPcr, 32) == 0 ||
        memcmp(reconstructedPCRs[13], zeroPcr, 32) == 0 ||
        memcmp(reconstructedPCRs[14], zeroPcr, 32) == 0) {
        printf("[!] OS Measured Boot PCRs (12/13/14) are unextended/zero.\n");
        passthroughDetected = TRUE;
    }

    BYTE allZeroCheck[sizeof(concatenatedGuestPCRs)] = { 0 };
    if (memcmp(concatenatedGuestPCRs, allZeroCheck, sizeof(allZeroCheck)) == 0) {
        printf("[!] Warning: Reconstructed guest PCR bank is completely zero/unextended.\n");
        passthroughDetected = TRUE;
    }

    if (calculate_sha256(concatenatedGuestPCRs, sizeof(concatenatedGuestPCRs), expectedPcrDigest)) {
        if (tpm_generate_quote_and_verify(hTbsContext, ekCert, expectedPcrDigest, &quoteVerified)) {
            if (!quoteVerified) {
                printf("[!] Reconstructed guest digest does NOT match signed TPM quote.\n");
                passthroughDetected = TRUE;
            }
        }
        else {
            printf("[!] Failed to perform TPM Signed Quote verification.\n");
            passthroughDetected = TRUE;
        }
    }
    else {
        printf("[-] Failed to calculate expected guest PCR digest.\n");
        passthroughDetected = TRUE;
    }

    for (i = 0; i < numSelectedPCRs; ++i) {
        uint32_t checkIdx = selectedPCRs[i];
        if (checkIdx == 0 || checkIdx >= 24) continue;

        memset(actualPCR, 0, sizeof(actualPCR));
        actualPCRSize = 0;
        if (read_tpm_pcr(hTbsContext, checkIdx, TPM_ALG_SHA256, actualPCR, &actualPCRSize)) {
            if (actualPCRSize != 32 || memcmp(actualPCR, reconstructedPCRs[checkIdx], 32) != 0) {
                if (mismatchingCount < sizeof(mismatchingIdxs) / sizeof(mismatchingIdxs[0])) {
                    mismatchingIdxs[mismatchingCount++] = checkIdx;
                }
                printf("[!] Mismatch detected on PCR [%u].\n", checkIdx);
                printf("  Reconstructed: ");
                for (int j = 0; j < 32; ++j) printf("%02x", reconstructedPCRs[checkIdx][j]);
                printf("\n  Hardware Read: ");
                uint32_t printSize = (actualPCRSize > sizeof(actualPCR)) ? sizeof(actualPCR) : actualPCRSize;
                for (uint32_t j = 0; j < printSize; ++j) printf("%02x", actualPCR[j]);
                printf("\n");
                passthroughDetected = TRUE;
            }
        }
        else {
            printf("[-] Failed to read actual PCR[%u] from hardware.\n", checkIdx);
            passthroughDetected = TRUE;
        }
    }

    if (mismatchingCount > 0) {
        for (i = 0; i < mismatchingCount; ++i) {
            uint32_t badPcrIdx = mismatchingIdxs[i];
            if (badPcrIdx == 0 || badPcrIdx >= 24) continue;

            memset(actualPCR, 0, sizeof(actualPCR));
            actualPCRSize = 0;
            read_tpm_pcr(hTbsContext, badPcrIdx, TPM_ALG_SHA256, actualPCR, &actualPCRSize);
            trace_pcr_reconstruction(&pcrEvents[badPcrIdx], actualPCR, actualPCRSize);
        }
    }

    for (i = 0; i < 24; ++i) {
        pcreventlist_free(&pcrEvents[i]);
    }
    free(logBuffer);
    Tbsip_Context_Close(hTbsContext);

    return (!passthroughDetected);
}