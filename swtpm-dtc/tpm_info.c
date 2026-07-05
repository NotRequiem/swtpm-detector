#include "tpm_verify.h"

static void dump_hex_prefix(const char* label, const BYTE* data, DWORD size, DWORD maxBytes) {
    DWORD n = size < maxBytes ? size : maxBytes;
    DWORD i;
    if (!label) label = "(null)";
    printf("%s (%lu bytes):", label, (unsigned long)size);
    for (i = 0; i < n; ++i) {
        printf(" %02X", data ? data[i] : 0);
    }
    if (size > n) printf(" ...");
    printf("\n");
}

static BOOL write_u16_be(BYTE* dst, size_t dstSize, size_t offset, USHORT value) {
    if (!dst || offset > dstSize || (dstSize - offset) < 2) return FALSE;
    dst[offset + 0] = (BYTE)((value >> 8) & 0xFF);
    dst[offset + 1] = (BYTE)(value & 0xFF);
    return TRUE;
}

BOOL read_ncrypt_property_bytes(NCRYPT_PROV_HANDLE hProv, LPCWSTR prop, BYTE** outBuf, DWORD* outSize) {
    DWORD size = 0;
    SECURITY_STATUS s;
    BYTE* buf;

    if (!outBuf || !outSize) return FALSE;
    *outBuf = NULL;
    *outSize = 0;

    s = NCryptGetProperty(hProv, prop, NULL, 0, &size, 0);
    if (s != ERROR_SUCCESS && s != NTE_BUFFER_TOO_SMALL) {
        print_ntstatus("NCryptGetProperty(size)", s);
        return FALSE;
    }

    buf = (BYTE*)malloc(size ? size : 1);
    if (!buf) return FALSE;

    s = NCryptGetProperty(hProv, prop, buf, size, &size, 0);
    if (s != ERROR_SUCCESS) {
        print_ntstatus("NCryptGetProperty(data)", s);
        free(buf);
        return FALSE;
    }

    *outBuf = buf;
    *outSize = size;
    return TRUE;
}

BOOL read_ncrypt_property_string(NCRYPT_PROV_HANDLE hProv, LPCWSTR prop, char* out, size_t outChars) {
    DWORD size = 0;
    SECURITY_STATUS s;
    WCHAR* wbuf = NULL;

    if (!out || outChars == 0) return FALSE;
    out[0] = '\0';

    s = NCryptGetProperty(hProv, prop, NULL, 0, &size, 0);
    if (s != ERROR_SUCCESS && s != NTE_BUFFER_TOO_SMALL) {
        return FALSE;
    }

    wbuf = (WCHAR*)calloc(1, size + sizeof(WCHAR));
    if (!wbuf) return FALSE;

    s = NCryptGetProperty(hProv, prop, (PBYTE)wbuf, size, &size, 0);
    if (s != ERROR_SUCCESS) {
        free(wbuf);
        return FALSE;
    }

    wbuf[size / sizeof(WCHAR)] = L'\0';
    if (!WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, (int)outChars, NULL, NULL)) {
        free(wbuf);
        return FALSE;
    }

    free(wbuf);
    return TRUE;
}

void load_certs_from_registry_recursive(HKEY hKey, HCERTSTORE store, WCHAR* szValueName) {
    DWORD dwIndex = 0;
    DWORD cbValueName = 16384;
    DWORD dwType = 0;
    BYTE* lpData = NULL;
    DWORD cbData = 0;

    if (!hKey || !store || !szValueName) return;

    while (TRUE) {
        cbValueName = 16384;
        cbData = 0;

        LONG lResult = RegEnumValueW(hKey, dwIndex, szValueName, &cbValueName, NULL, &dwType, NULL, &cbData);
        if (lResult == ERROR_NO_MORE_ITEMS) {
            break;
        }

        if (lResult == ERROR_SUCCESS || lResult == ERROR_MORE_DATA) {
            if (dwType == REG_BINARY && cbData > 0) {
                lpData = (BYTE*)malloc(cbData);
                if (lpData) {
                    cbValueName = 16384;
                    lResult = RegEnumValueW(hKey, dwIndex, szValueName, &cbValueName, NULL, &dwType, lpData, &cbData);
                    if (lResult == ERROR_SUCCESS) {
                        PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, lpData, cbData);
                        if (ctx) {
                            CertAddCertificateContextToStore(store, ctx, CERT_STORE_ADD_NEW, NULL);
                            CertFreeCertificateContext(ctx);
                        }
                    }
                    free(lpData);
                    lpData = NULL;
                }
            }
        }
        dwIndex++;
    }

    dwIndex = 0;
    WCHAR szSubKeyName[256];
    DWORD cbSubKeyName = _countof(szSubKeyName);
    while (TRUE) {
        cbSubKeyName = _countof(szSubKeyName);
        LONG lResult = RegEnumKeyExW(hKey, dwIndex, szSubKeyName, &cbSubKeyName, NULL, NULL, NULL, NULL);
        if (lResult == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (lResult == ERROR_SUCCESS) {
            HKEY hSubKey = NULL;
            if (RegOpenKeyExW(hKey, szSubKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                load_certs_from_registry_recursive(hSubKey, store, szValueName);
                RegCloseKey(hSubKey);
            }
        }
        dwIndex++;
    }
}

void load_tpm_intermediate_certs_from_registry(HCERTSTORE store) {
    HKEY hKey = NULL;
    WCHAR* szValueName = (WCHAR*)malloc(16384 * sizeof(WCHAR));
    if (!szValueName) return;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        load_certs_from_registry_recursive(hKey, store, szValueName);
        RegCloseKey(hKey);
    }
    free(szValueName);
}

void load_certs_from_pcp_property_store(NCRYPT_PROV_HANDLE hProv, LPCWSTR propName, HCERTSTORE hStoreToAddTo) {
    HCERTSTORE hPcpStore = NULL;
    DWORD cbStore = sizeof(hPcpStore);
    SECURITY_STATUS s = NCryptGetProperty(hProv, propName, (PBYTE)&hPcpStore, sizeof(hPcpStore), &cbStore, 0);
    if (s == ERROR_SUCCESS && hPcpStore) {
        PCCERT_CONTEXT c = NULL;
        DWORD loadedCount = 0;
        while ((c = CertEnumCertificatesInStore(hPcpStore, c)) != NULL) {
            if (CertAddCertificateContextToStore(hStoreToAddTo, c, CERT_STORE_ADD_NEW, NULL)) {
                loadedCount++;
            }
        }
        CertCloseStore(hPcpStore, 0);
        if (loadedCount > 0) {
            wprintf(L"  Loaded %lu intermediate certificate(s) from PCP property: %s\n", loadedCount, propName);
        }
    }
}

void load_pcp_intermediate_certs(HCERTSTORE store) {
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS s = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (s == ERROR_SUCCESS) {
        load_certs_from_pcp_property_store(hProv, L"PCP_RSA_EKNVCERT", store);
        load_certs_from_pcp_property_store(hProv, L"PCP_ECC_EKNVCERT", store);
        load_certs_from_pcp_property_store(hProv, L"PCP_EKNVCERT", store);
        load_certs_from_pcp_property_store(hProv, L"PCP_INTERMEDIATE_CA_EKCERT", store);
        NCryptFreeObject(hProv);
    }
}

BOOL build_candidate_issuer_store(HCERTSTORE hCabStore, HCERTSTORE hRoots, HCERTSTORE hCaStore, HCERTSTORE* outStore) {
    HCERTSTORE hStore = NULL;
    HCERTSTORE hLmRoots = NULL;
    HCERTSTORE hLmCa = NULL;
    PCCERT_CONTEXT c = NULL;

    if (!outStore) return FALSE;
    *outStore = NULL;

    hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!hStore) {
        print_last_error("CertOpenStore(candidate)");
        return FALSE;
    }

    if (hCabStore) {
        while ((c = CertEnumCertificatesInStore(hCabStore, c)) != NULL) {
            CertAddCertificateContextToStore(hStore, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    c = NULL;
    if (hRoots) {
        while ((c = CertEnumCertificatesInStore(hRoots, c)) != NULL) {
            CertAddCertificateContextToStore(hStore, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    c = NULL;
    if (hCaStore) {
        while ((c = CertEnumCertificatesInStore(hCaStore, c)) != NULL) {
            CertAddCertificateContextToStore(hStore, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    hLmRoots = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
        "ROOT");
    if (hLmRoots) {
        c = NULL;
        while ((c = CertEnumCertificatesInStore(hLmRoots, c)) != NULL) {
            CertAddCertificateContextToStore(hStore, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    hLmCa = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
        "CA");
    if (hLmCa) {
        c = NULL;
        while ((c = CertEnumCertificatesInStore(hLmCa, c)) != NULL) {
            CertAddCertificateContextToStore(hStore, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    {
        HCERTSTORE hEntRoot = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
            "Enterprise Root");
        if (hEntRoot) {
            c = NULL;
            while ((c = CertEnumCertificatesInStore(hEntRoot, c)) != NULL) {
                CertAddCertificateContextToStore(hStore, c, CERT_STORE_ADD_ALWAYS, NULL);
            }
            CertCloseStore(hEntRoot, 0);
        }
    }

    load_tpm_intermediate_certs_from_registry(hStore);
    load_pcp_intermediate_certs(hStore);

    if (hLmRoots) CertCloseStore(hLmRoots, 0);
    if (hLmCa) CertCloseStore(hLmCa, 0);

    *outStore = hStore;
    return TRUE;
}

BOOL get_tpm_info_via_tbs(TPMINFO* info) {
    ZeroMemory(info, sizeof(*info));

    TBS_CONTEXT_PARAMS2 params;
    ZeroMemory(&params, sizeof(params));
    params.version = TPM_VERSION_20;
    params.includeTpm20 = 1;
    params.includeTpm12 = 1;

    TBS_HCONTEXT hContext = 0;
    TBS_RESULT r = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hContext);
    if (r != TBS_SUCCESS) {
        print_tbs_result("Tbsi_Context_Create", r);
        return FALSE;
    }

    TPM_DEVICE_INFO deviceInfo;
    ZeroMemory(&deviceInfo, sizeof(deviceInfo));
    deviceInfo.structVersion = TPM_VERSION_20;

    r = Tbsi_GetDeviceInfo(sizeof(deviceInfo), &deviceInfo);
    if (r == TBS_SUCCESS) {
        info->hasTpm = TRUE;
        info->tpmVersionRaw = deviceInfo.tpmVersion;
        info->isTpm2 = (deviceInfo.tpmVersion == TPM_VERSION_20);
    }
    else {
        print_tbs_result("Tbsi_GetDeviceInfo", r);
    }

    if (info->isTpm2) {
        BYTE cmd[22] = { 0 };
        BYTE rsp[512];
        UINT32 cbRsp = sizeof(rsp);
        const uint16_t tag = 0x8001;
        const uint32_t cc = 0x0000017A;
        const uint32_t capability = 0x00000006;
        const uint32_t property = 0x00000105;
        const uint32_t count = 8;

    #define WRITE16(p,v) do { (p)[0] = (BYTE)(((v) >> 8) & 0xFF); (p)[1] = (BYTE)((v) & 0xFF); } while (0)
    #define WRITE32(p,v) do { (p)[0] = (BYTE)(((v) >> 24) & 0xFF); (p)[1] = (BYTE)(((v) >> 16) & 0xFF); (p)[2] = (BYTE)(((v) >> 8) & 0xFF); (p)[3] = (BYTE)((v) & 0xFF); } while (0)

        WRITE16(cmd + 0, tag);
        WRITE32(cmd + 2, sizeof(cmd));
        WRITE32(cmd + 6, cc);
        WRITE32(cmd + 10, capability);
        WRITE32(cmd + 14, property);
        WRITE32(cmd + 18, count);

    #undef WRITE16
    #undef WRITE32

        r = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_HIGH,
            cmd, sizeof(cmd), rsp, &cbRsp);
        if (r == TBS_SUCCESS && cbRsp >= 22) {
            uint32_t respCode = ((uint32_t)rsp[6] << 24) | ((uint32_t)rsp[7] << 16) |
                ((uint32_t)rsp[8] << 8) | rsp[9];
            if (respCode == 0) {
                size_t off = 10;
                BYTE moreData = rsp[off++];
                uint32_t returnedCapability = ((uint32_t)rsp[off] << 24) | ((uint32_t)rsp[off + 1] << 16) |
                    ((uint32_t)rsp[off + 2] << 8) | rsp[off + 3];
                off += 4;
                uint32_t propertyCount = ((uint32_t)rsp[off] << 24) | ((uint32_t)rsp[off + 1] << 16) |
                    ((uint32_t)rsp[off + 2] << 8) | rsp[off + 3];
                off += 4;
                (void)moreData;

                if (returnedCapability == capability) {
                    for (uint32_t i = 0; i < propertyCount && off + 8 <= cbRsp; ++i) {
                        uint32_t prop = ((uint32_t)rsp[off] << 24) | ((uint32_t)rsp[off + 1] << 16) |
                            ((uint32_t)rsp[off + 2] << 8) | rsp[off + 3];
                        uint32_t val = ((uint32_t)rsp[off + 4] << 24) | ((uint32_t)rsp[off + 5] << 16) |
                            ((uint32_t)rsp[off + 6] << 8) | rsp[off + 7];
                        off += 8;

                        if (prop == 0x00000105) {
                            info->manufacturerId = val;
                        }
                        else if (prop == 0x00000100) {
                            info->familyIndicatorText[0] = (char)((val >> 24) & 0xFF);
                            info->familyIndicatorText[1] = (char)((val >> 16) & 0xFF);
                            info->familyIndicatorText[2] = (char)((val >> 8) & 0xFF);
                            info->familyIndicatorText[3] = (char)(val & 0xFF);
                            info->familyIndicatorText[4] = '\0';
                        }
                        else if (prop >= 0x00000106 && prop <= 0x00000109) {
                            size_t base = (size_t)(prop - 0x00000106) * 4;
                            if (base + 4 <= 16) {
                                info->vendorString[base + 0] = (char)((val >> 24) & 0xFF);
                                info->vendorString[base + 1] = (char)((val >> 16) & 0xFF);
                                info->vendorString[base + 2] = (char)((val >> 8) & 0xFF);
                                info->vendorString[base + 3] = (char)(val & 0xFF);
                                info->vendorString[16] = '\0';
                            }
                        }
                        else if (prop == 0x0000010B) {
                            info->firmwareVersion1 = val;
                        }
                        else if (prop == 0x0000010C) {
                            info->firmwareVersion2 = val;
                        }
                    }
                }
            }
        }
        else if (r != TBS_SUCCESS) {
            print_tbs_result("Tbsip_Submit_Command(GetCapability)", r);
        }

        if (info->manufacturerId) {
            info->manufacturerIdText[0] = (char)((info->manufacturerId >> 24) & 0xFF);
            info->manufacturerIdText[1] = (char)((info->manufacturerId >> 16) & 0xFF);
            info->manufacturerIdText[2] = (char)((info->manufacturerId >> 8) & 0xFF);
            info->manufacturerIdText[3] = (char)(info->manufacturerId & 0xFF);
            info->manufacturerIdText[4] = '\0';
        }
        else {
            StringCchCopyA(info->manufacturerIdText, _countof(info->manufacturerIdText), "----");
        }

        if (!info->familyIndicatorText[0]) StringCchCopyA(info->familyIndicatorText, _countof(info->familyIndicatorText), "----");
        if (!info->vendorString[0]) StringCchCopyA(info->vendorString, _countof(info->vendorString), "(unknown)");
        info->firmwareVersion = ((ULONGLONG)info->firmwareVersion1 << 32) | info->firmwareVersion2;
    }
    else {
        StringCchCopyA(info->manufacturerIdText, _countof(info->manufacturerIdText), "----");
        StringCchCopyA(info->familyIndicatorText, _countof(info->familyIndicatorText), "----");
        StringCchCopyA(info->vendorString, _countof(info->vendorString), "(unknown)");
    }

    Tbsip_Context_Close(hContext);
    return TRUE;
}

BOOL get_pcp_info(TPMINFO* info) {
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS s;

    s = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (s != ERROR_SUCCESS) {
        print_ntstatus("NCryptOpenStorageProvider", s);
        return FALSE;
    }

    if (!read_ncrypt_property_string(hProv, BCRYPT_PCP_PLATFORM_TYPE_PROPERTY, info->providerType, sizeof(info->providerType))) {
        StringCchCopyA(info->providerType, _countof(info->providerType), "(unknown)");
    }
    if (!read_ncrypt_property_string(hProv, BCRYPT_PCP_PROVIDER_VERSION_PROPERTY, info->providerVersion, sizeof(info->providerVersion))) {
        StringCchCopyA(info->providerVersion, _countof(info->providerVersion), "(unknown)");
    }

    if (!read_ncrypt_property_bytes(hProv, NCRYPT_PCP_EKPUB_PROPERTY, &info->ekPub, &info->ekPubSize)) {
        info->ekPub = NULL;
        info->ekPubSize = 0;
    }
    else {
        sha256_hex(info->ekPub, info->ekPubSize, info->ekPubSha256);
    }

    info->hasEkCertStore = TRUE;
    NCryptFreeObject(hProv);
    return TRUE;
}

BOOL get_pcp_ek_cert_store(NCRYPT_PROV_HANDLE hProv, HCERTSTORE* outStore) {
    HCERTSTORE hStore = NULL;
    DWORD size = sizeof(hStore);
    SECURITY_STATUS s;
    if (!outStore) return FALSE;
    *outStore = NULL;

    s = NCryptGetProperty(hProv, NCRYPT_PCP_EKCERT_PROPERTY, (PBYTE)&hStore, sizeof(hStore), &size, 0);
    if (s != ERROR_SUCCESS) {
        print_ntstatus("NCryptGetProperty(PCP_EKCERT)", s);
        return FALSE;
    }

    if (!hStore) return FALSE;
    *outStore = hStore;
    return TRUE;
}

static BOOL tpm_namealg_to_bcrypt_alg(USHORT nameAlg, LPCWSTR* algId, DWORD* digestLen) {
    if (!algId || !digestLen) return FALSE;

    switch (nameAlg) {
    case 0x0004: 
        *algId = BCRYPT_SHA1_ALGORITHM;
        *digestLen = 20;
        return TRUE;
    case 0x000B: 
        *algId = BCRYPT_SHA256_ALGORITHM;
        *digestLen = 32;
        return TRUE;
    case 0x000C: 
        *algId = BCRYPT_SHA384_ALGORITHM;
        *digestLen = 48;
        return TRUE;
    case 0x000D: 
        *algId = BCRYPT_SHA512_ALGORITHM;
        *digestLen = 64;
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL KDFa_Generic(USHORT hashAlg, const BYTE* key, DWORD keySize, const char* label, const BYTE* contextU, DWORD contextUSize, DWORD bits, BYTE* outBuf) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE pbHashObject[1024];
    DWORD cbHashObject = sizeof(pbHashObject);
    DWORD bytesNeeded = (bits + 7) / 8;
    DWORD bytesGenerated = 0;
    DWORD counter = 1;
    BYTE digest[64];
    NTSTATUS status;
    LPCWSTR bcryptAlg = NULL;
    DWORD digestLen = 0;

    if (!key || keySize == 0 || !label || !outBuf) return FALSE;

    if (!tpm_namealg_to_bcrypt_alg(hashAlg, &bcryptAlg, &digestLen)) {
        return FALSE;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, bcryptAlg, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != STATUS_SUCCESS) {
        return FALSE;
    }

    while (bytesGenerated < bytesNeeded) {
        BYTE ctrBytes[4] = { 0 };
        BYTE bitsBytes[4] = { 0 };
        DWORD toCopy;

        ctrBytes[0] = (BYTE)((counter >> 24) & 0xFF);
        ctrBytes[1] = (BYTE)((counter >> 16) & 0xFF);
        ctrBytes[2] = (BYTE)((counter >> 8) & 0xFF);
        ctrBytes[3] = (BYTE)(counter & 0xFF);

        bitsBytes[0] = (BYTE)((bits >> 24) & 0xFF);
        bitsBytes[1] = (BYTE)((bits >> 16) & 0xFF);
        bitsBytes[2] = (BYTE)((bits >> 8) & 0xFF);
        bitsBytes[3] = (BYTE)(bits & 0xFF);

        hHash = NULL;
        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, (PUCHAR)key, keySize, 0);
        if (status != STATUS_SUCCESS) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return FALSE;
        }

        status = BCryptHashData(hHash, ctrBytes, sizeof(ctrBytes), 0);
        if (status == STATUS_SUCCESS) {
            status = BCryptHashData(hHash, (PUCHAR)label, (ULONG)strlen(label), 0);
        }
        if (status == STATUS_SUCCESS) {
            BYTE zeroByte = 0x00;
            status = BCryptHashData(hHash, &zeroByte, 1, 0);
        }
        if (status == STATUS_SUCCESS && contextU && contextUSize > 0) {
            status = BCryptHashData(hHash, (PUCHAR)contextU, contextUSize, 0);
        }
        if (status == STATUS_SUCCESS) {
            status = BCryptHashData(hHash, bitsBytes, sizeof(bitsBytes), 0);
        }
        if (status == STATUS_SUCCESS) {
            status = BCryptFinishHash(hHash, digest, digestLen, 0);
        }

        BCryptDestroyHash(hHash);
        hHash = NULL;

        if (status != STATUS_SUCCESS) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return FALSE;
        }

        toCopy = bytesNeeded - bytesGenerated;
        if (toCopy > digestLen) toCopy = digestLen;
        memcpy(outBuf + bytesGenerated, digest, toCopy);
        bytesGenerated += toCopy;
        counter++;
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}

static BOOL compute_tpm_name_from_binding(const BYTE* pbIdBinding, DWORD cbIdBinding, BYTE** outName, DWORD* outNameSize) {
    BYTE* pbRawPublic = NULL;
    DWORD cbRawPublic = 0;
    USHORT nameAlg = 0;
    LPCWSTR bcryptAlg = NULL;
    DWORD digestLen = 0;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbRes = 0;
    BYTE* pbHashObject = NULL;
    BYTE* name = NULL;
    BOOL ok = FALSE;
    NTSTATUS status;

    if (!pbIdBinding || cbIdBinding < 2 || !outName || !outNameSize) return FALSE;
    *outName = NULL;
    *outNameSize = 0;

    {
        DWORD publicSize = ((DWORD)pbIdBinding[0] << 8) | pbIdBinding[1];
        if (cbIdBinding < 2 + publicSize || publicSize < 4) return FALSE;
        pbRawPublic = (BYTE*)(pbIdBinding + 2);
        cbRawPublic = publicSize;
        nameAlg = (USHORT)(((USHORT)pbRawPublic[2] << 8) | pbRawPublic[3]);
    }

    if (!tpm_namealg_to_bcrypt_alg(nameAlg, &bcryptAlg, &digestLen)) {
        return FALSE;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, bcryptAlg, NULL, 0);
    if (status != STATUS_SUCCESS) {
        return FALSE;
    }

    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(cbHashObject), &cbRes, 0);
    if (status != STATUS_SUCCESS || cbHashObject == 0) {
        goto cleanup;
    }

    pbHashObject = (BYTE*)malloc(cbHashObject);
    if (!pbHashObject) goto cleanup;

    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
    if (status != STATUS_SUCCESS) goto cleanup;

    status = BCryptHashData(hHash, pbRawPublic, cbRawPublic, 0);
    if (status != STATUS_SUCCESS) goto cleanup;

    name = (BYTE*)malloc(2 + (size_t)(digestLen));
    if (!name) goto cleanup;
    name[0] = (BYTE)((nameAlg >> 8) & 0xFF);
    name[1] = (BYTE)(nameAlg & 0xFF);

    status = BCryptFinishHash(hHash, name + 2, digestLen, 0);
    if (status != STATUS_SUCCESS) goto cleanup;

    *outName = name;
    *outNameSize = 2 + digestLen;
    name = NULL;
    ok = TRUE;

cleanup:
    if (name) free(name);
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) free(pbHashObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static BOOL build_tpm2b_id_object(const BYTE* hmac, DWORD hmacLen, const BYTE* encIdentity, DWORD encIdentityLen, BYTE** outBlob, DWORD* outBlobSize) {
    size_t innerSize;
    size_t totalSize;
    BYTE* blob = NULL;

    if (!outBlob || !outBlobSize || !hmac || !encIdentity) return FALSE;
    *outBlob = NULL;
    *outBlobSize = 0;

    if (hmacLen > 0xFFFFu || encIdentityLen > 0xFFFFu) return FALSE;

    innerSize = 2u + (size_t)hmacLen + 2u + (size_t)encIdentityLen;
    totalSize = 2u + innerSize;

    if (innerSize > 0xFFFFu || totalSize > 0xFFFFu) return FALSE;
    if (totalSize < 6u) return FALSE;

    blob = (BYTE*)calloc(1, totalSize);
    if (!blob) return FALSE;

    if (!write_u16_be(blob, totalSize, 0, (USHORT)innerSize)) goto fail;
    if (!write_u16_be(blob, totalSize, 2, (USHORT)hmacLen)) goto fail;
    memcpy(blob + 4, hmac, hmacLen);

    if (!write_u16_be(blob, totalSize, 4u + (size_t)hmacLen, (USHORT)encIdentityLen)) goto fail;
    memcpy(blob + 6u + (size_t)hmacLen, encIdentity, encIdentityLen);

    *outBlob = blob;
    *outBlobSize = (DWORD)totalSize;
    return TRUE;

fail:
    free(blob);
    return FALSE;
}

static BOOL aes_cfb128_encrypt(const BYTE* key, DWORD keySize, const BYTE* plaintext, DWORD plaintextLen, BYTE* ciphertext) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject = 0, cbRes = 0;
    NTSTATUS status;
    BOOL ok = FALSE;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) return FALSE;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != STATUS_SUCCESS) goto cleanup;

    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(cbKeyObject), &cbRes, 0);
    if (status != STATUS_SUCCESS) goto cleanup;

    pbKeyObject = (PBYTE)malloc(cbKeyObject);
    if (!pbKeyObject) goto cleanup;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PUCHAR)key, keySize, 0);
    if (status != STATUS_SUCCESS) goto cleanup;

    BYTE iv[16] = { 0 };
    BYTE outBlock[16];
    DWORD cbOut = 0;
    DWORD bytesProcessed = 0;

    while (bytesProcessed < plaintextLen) {
        status = BCryptEncrypt(hKey, iv, 16, NULL, NULL, 0, outBlock, 16, &cbOut, 0);
        if (status != STATUS_SUCCESS) goto cleanup;

        DWORD toProcess = plaintextLen - bytesProcessed;
        if (toProcess > 16) toProcess = 16;

        for (DWORD i = 0; i < toProcess; ++i) {
            ciphertext[bytesProcessed + i] = plaintext[bytesProcessed + i] ^ outBlock[i];
            iv[i] = ciphertext[bytesProcessed + i];
        }

        bytesProcessed += toProcess;
    }

    ok = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (pbKeyObject) free(pbKeyObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

BOOL perform_local_tpm_pop_challenge(PCCERT_CONTEXT ekCert) {
    BOOL ok = FALSE;
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE hAIK = 0;
    SECURITY_STATUS s;
    BYTE* rsaKeyBlob = NULL;
    DWORD rsaKeyBlobSize = 0;
    BCRYPT_ALG_HANDLE hRng = NULL;

    BYTE* pbIdBinding = NULL;
    DWORD cbIdBinding = 0;
    BYTE* name = NULL;
    DWORD cbName = 0;
    BYTE* idObjectBytes = NULL;
    DWORD idObjectSize = 0;
    BYTE* encSecretBytes = NULL;
    DWORD encSecretSize = 0;
    BYTE* activationBlob = NULL;
    DWORD activationBlobSize = 0;
    BYTE* nonce = NULL;
    BYTE* encNonce = NULL;
    DWORD challengeLen = 0;
    DWORD cbHashObject = 0;

    printf("Executing Cryptographic Proof-of-Possession of Endorsement Key.\n");

    if (BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0) == STATUS_SUCCESS) {
        printf("  RNG: BCryptGenRandom available.\n");
        BCryptCloseAlgorithmProvider(hRng, 0);
        hRng = NULL;
    }
    else {
        printf("  [!] BCrypt RNG provider unavailable; will fall back to rand().\n");
    }

    s = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (s != ERROR_SUCCESS) {
        print_ntstatus("NCryptOpenStorageProvider", s);
        return FALSE;
    }
    printf("  Opened provider: %ws\n", MS_PLATFORM_CRYPTO_PROVIDER);

    s = NCryptCreatePersistedKey(hProv, &hAIK, BCRYPT_RSA_ALGORITHM, L"PoPAttestationKey", 0, NCRYPT_OVERWRITE_KEY_FLAG);
    if (s == ERROR_SUCCESS) {
        DWORD dwUsagePolicy = NCRYPT_PCP_IDENTITY_KEY;
        DWORD dwKeyBits = 2048;
        SECURITY_STATUS s2;

        s2 = NCryptSetProperty(hAIK, NCRYPT_LENGTH_PROPERTY, (PBYTE)&dwKeyBits, sizeof(dwKeyBits), 0);
        if (s2 != ERROR_SUCCESS) {
            print_ntstatus("NCryptSetProperty(NCRYPT_LENGTH_PROPERTY)", s2);
        }

        s2 = NCryptSetProperty(hAIK, L"PCP_KEY_USAGE_POLICY", (PBYTE)&dwUsagePolicy, sizeof(dwUsagePolicy), 0);
        if (s2 != ERROR_SUCCESS) {
            print_ntstatus("NCryptSetProperty(PCP_KEY_USAGE_POLICY)", s2);
        }

        s = NCryptFinalizeKey(hAIK, 0);
    }

    if (s != ERROR_SUCCESS) {
        print_ntstatus("NCryptCreatePersistedKey / NCryptFinalizeKey (AIK)", s);
        NCryptFreeObject(hProv);
        return FALSE;
    }

    if (!export_cert_public_key_blob(ekCert, &rsaKeyBlob, &rsaKeyBlobSize)) {
        printf("  Failed to export validated EK public key from certificate.\n");
        NCryptDeleteKey(hAIK, 0);
        NCryptFreeObject(hProv);
        return FALSE;
    }

    printf("  EK public key blob size: %lu bytes\n", (unsigned long)rsaKeyBlobSize);

    if (!read_ncrypt_property_bytes(hAIK, L"PCP_TPM12_IDBINDING", &pbIdBinding, &cbIdBinding)) {
        printf("  Failed to read AIK binding.\n");
        free(rsaKeyBlob);
        NCryptDeleteKey(hAIK, 0);
        NCryptFreeObject(hProv);
        return FALSE;
    }

    dump_hex_prefix("  AIK binding", pbIdBinding, cbIdBinding, 64);

    if (!compute_tpm_name_from_binding(pbIdBinding, cbIdBinding, &name, &cbName)) {
        printf("  Failed to compute TPM Name from AIK binding.\n");
        free(pbIdBinding);
        free(rsaKeyBlob);
        NCryptDeleteKey(hAIK, 0);
        NCryptFreeObject(hProv);
        return FALSE;
    }

    {
        USHORT nameAlg = 0;
        if (cbIdBinding >= 2 + 4) {
            DWORD publicSize = ((DWORD)pbIdBinding[0] << 8) | pbIdBinding[1];
            if (cbIdBinding >= 2 + publicSize && publicSize >= 4) {
                BYTE* pbRawPublic = (BYTE*)(pbIdBinding + 2);
                nameAlg = (USHORT)(((USHORT)pbRawPublic[2] << 8) | pbRawPublic[3]);
            }
        }

        if (cbName < 3) {
            printf("  [-] AIK Name blob is too small.\n");
            free(pbIdBinding);
            free(rsaKeyBlob);
            free(name);
            NCryptDeleteKey(hAIK, 0);
            NCryptFreeObject(hProv);
            return FALSE;
        }

        challengeLen = cbName - 2;
        printf("  AIK nameAlg: 0x%04X\n", nameAlg);
        printf("  AIK Name size: %lu bytes\n", (unsigned long)cbName);
        printf("  Credential / POP nonce size: %lu bytes\n", (unsigned long)challengeLen);

        if (challengeLen != 32) {
            printf("  [!] This TPM Name digest size is not 32 bytes. The attestation profile usually expects the nonce to match the Name hash size.\n");
        }
    }

    free(pbIdBinding);
    pbIdBinding = NULL;

    nonce = (BYTE*)malloc(challengeLen);
    encNonce = (BYTE*)malloc(challengeLen);
    if (!nonce || !encNonce) {
        printf("  [-] Out of memory allocating challenge buffers.\n");
        free(nonce);
        free(encNonce);
        free(rsaKeyBlob);
        free(name);
        NCryptDeleteKey(hAIK, 0);
        NCryptFreeObject(hProv);
        return FALSE;
    }

    {
        BCRYPT_ALG_HANDLE hSeedRng = NULL;
        if (BCryptOpenAlgorithmProvider(&hSeedRng, BCRYPT_RNG_ALGORITHM, NULL, 0) == STATUS_SUCCESS) {
            if (BCryptGenRandom(hSeedRng, nonce, challengeLen, 0) != STATUS_SUCCESS) {
                printf("  [!] BCryptGenRandom failed; falling back to rand().\n");
                for (DWORD i = 0; i < challengeLen; ++i) nonce[i] = (BYTE)(rand() & 0xFF);
            }
            BCryptCloseAlgorithmProvider(hSeedRng, 0);
        }
        else {
            printf("  [!] RNG provider unavailable for challenge; falling back to rand().\n");
            for (DWORD i = 0; i < challengeLen; ++i) nonce[i] = (BYTE)(rand() & 0xFF);
        }
    }

    {
        BCRYPT_ALG_HANDLE hRsaAlg = NULL;
        BCRYPT_KEY_HANDLE hRsaKey = NULL;
        NTSTATUS status;

        status = BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
        if (status != STATUS_SUCCESS) {
            printf("  [-] BCryptOpenAlgorithmProvider(RSA) failed: 0x%08X\n", status);
            goto cleanup;
        }

        status = BCryptImportKeyPair(hRsaAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hRsaKey, rsaKeyBlob, rsaKeyBlobSize, 0);
        if (status != STATUS_SUCCESS) {
            printf("  [-] BCryptImportKeyPair failed: 0x%08X\n", status);
            goto cleanup_rsa;
        }

        DWORD seedSize = 32;
        BYTE* seed = (BYTE*)malloc(seedSize);
        if (!seed) {
            printf("  [-] Out of memory allocating seed.\n");
            goto cleanup_rsa;
        }

        if (BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0) == STATUS_SUCCESS) {
            if (BCryptGenRandom(hRng, seed, seedSize, 0) != STATUS_SUCCESS) {
                printf("  [!] BCryptGenRandom(seed) failed; using rand().\n");
                for (size_t i = 0; i < seedSize; ++i) seed[i] = (BYTE)(rand() & 0xFF);
            }
            BCryptCloseAlgorithmProvider(hRng, 0);
            hRng = NULL;
        }
        else {
            for (size_t i = 0; i < seedSize; ++i) seed[i] = (BYTE)(rand() & 0xFF);
        }

        BCRYPT_OAEP_PADDING_INFO oaepInfo;
        ZeroMemory(&oaepInfo, sizeof(oaepInfo));
        oaepInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        oaepInfo.pbLabel = (PUCHAR)"IDENTITY";
        oaepInfo.cbLabel = 8; 

        DWORD encSecretAlloc = 0;
        status = BCryptEncrypt(hRsaKey, seed, seedSize, &oaepInfo, NULL, 0, NULL, 0, &encSecretAlloc, BCRYPT_PAD_OAEP);
        if (status != STATUS_SUCCESS || encSecretAlloc == 0) {
            printf("  [-] BCryptEncrypt(RSA size query) failed: 0x%08X\n", status);
            free(seed);
            goto cleanup_rsa;
        }

        BYTE* rawEnc = (BYTE*)malloc(encSecretAlloc);
        if (!rawEnc) {
            printf("  [-] Out of memory allocating wrapped seed buffer.\n");
            free(seed);
            goto cleanup_rsa;
        }

        DWORD encOut = 0;
        status = BCryptEncrypt(hRsaKey, seed, seedSize, &oaepInfo, NULL, 0, rawEnc, encSecretAlloc, &encOut, BCRYPT_PAD_OAEP);
        if (status != STATUS_SUCCESS) {
            printf("  [-] BCryptEncrypt(RSA seed encryption) failed: 0x%08X\n", status);
            free(rawEnc);
            free(seed);
            goto cleanup_rsa;
        }

        encSecretSize = 2 + encOut;
        encSecretBytes = (BYTE*)malloc(encSecretSize);
        if (!encSecretBytes) {
            printf("  [-] Out of memory allocating EK-wrapped seed.\n");
            free(rawEnc);
            free(seed);
            goto cleanup_rsa;
        }

        encSecretBytes[0] = (BYTE)((encOut >> 8) & 0xFF);
        encSecretBytes[1] = (BYTE)(encOut & 0xFF);
        memcpy(encSecretBytes + 2, rawEnc, encOut);
        dump_hex_prefix("  EK-wrapped seed", encSecretBytes, encSecretSize, 64);

        free(rawEnc);

        {
            BYTE symKey[16];
            BYTE hmacKey[32];

            if (!KDFa_Generic(0x000B, seed, seedSize, "STORAGE", name, cbName, 128, symKey)) {
                printf("  [-] KDFa(STORAGE) failed.\n");
                free(seed);
                goto cleanup_rsa;
            }

            if (!KDFa_Generic(0x000B, seed, seedSize, "INTEGRITY", NULL, 0, 256, hmacKey)) {
                printf("  [-] KDFa(INTEGRITY) failed.\n");
                free(seed);
                goto cleanup_rsa;
            }

            dump_hex_prefix("  Derived STORAGE key", symKey, sizeof(symKey), 32);
            dump_hex_prefix("  Derived INTEGRITY key", hmacKey, sizeof(hmacKey), 32);

            if (!aes_cfb128_encrypt(symKey, sizeof(symKey), nonce, challengeLen, encNonce)) {
                printf("  [-] AES_CFB128_Encrypt failed.\n");
                free(seed);
                goto cleanup_rsa;
            }

            dump_hex_prefix("  Encrypted identity", encNonce, challengeLen, 64);

            {
                BCRYPT_ALG_HANDLE hHmacAlg = NULL;
                BCRYPT_HASH_HANDLE hHmac = NULL;
                BYTE hmacOut[32];
                DWORD cbRes = 0;

                status = BCryptOpenAlgorithmProvider(&hHmacAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
                if (status != STATUS_SUCCESS) {
                    printf("  [-] BCryptOpenAlgorithmProvider(HMAC) failed: 0x%08X\n", status);
                    free(seed);
                    goto cleanup_rsa;
                }

                status = BCryptGetProperty(hHmacAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(cbHashObject), &cbRes, 0);
                if (status != STATUS_SUCCESS || cbHashObject == 0) {
                    printf("  [-] BCryptGetProperty(HMAC Object length) failed: 0x%08X\n", status);
                    BCryptCloseAlgorithmProvider(hHmacAlg, 0);
                    free(seed);
                    goto cleanup_rsa;
                }

                PBYTE pbHashObject = (PBYTE)malloc(cbHashObject);
                if (!pbHashObject) {
                    printf("  [-] Out of memory allocating HMAC hash object.\n");
                    BCryptCloseAlgorithmProvider(hHmacAlg, 0);
                    free(seed);
                    goto cleanup_rsa;
                }

                status = BCryptCreateHash(hHmacAlg, &hHmac, pbHashObject, cbHashObject, hmacKey, sizeof(hmacKey), 0);
                if (status != STATUS_SUCCESS) {
                    printf("  [-] BCryptCreateHash failed: 0x%08X\n", status);
                    free(pbHashObject);
                    BCryptCloseAlgorithmProvider(hHmacAlg, 0);
                    free(seed);
                    goto cleanup_rsa;
                }

                if (BCryptHashData(hHmac, encNonce, challengeLen, 0) != STATUS_SUCCESS ||
                    BCryptHashData(hHmac, name, cbName, 0) != STATUS_SUCCESS ||
                    BCryptFinishHash(hHmac, hmacOut, sizeof(hmacOut), 0) != STATUS_SUCCESS) {
                    printf("  [-] HMAC computation failed.\n");
                    BCryptDestroyHash(hHmac);
                    free(pbHashObject);
                    BCryptCloseAlgorithmProvider(hHmacAlg, 0);
                    free(seed);
                    goto cleanup_rsa;
                }

                BCryptDestroyHash(hHmac);
                free(pbHashObject);
                BCryptCloseAlgorithmProvider(hHmacAlg, 0);

                if (!build_tpm2b_id_object(hmacOut, sizeof(hmacOut), encNonce, challengeLen, &idObjectBytes, &idObjectSize)) {
                    printf("  [-] build_tpm2b_id_object failed.\n");
                    free(seed);
                    goto cleanup_rsa;
                }

                dump_hex_prefix("  ID object", idObjectBytes, idObjectSize, 96);

                activationBlobSize = idObjectSize + encSecretSize;
                activationBlob = (BYTE*)malloc(activationBlobSize);
                if (!activationBlob) {
                    printf("  [-] Out of memory allocating activation blob.\n");
                    free(seed);
                    goto cleanup_rsa;
                }

                memcpy(activationBlob, idObjectBytes, idObjectSize);
                memcpy(activationBlob + idObjectSize, encSecretBytes, encSecretSize);
                dump_hex_prefix("  Activation blob", activationBlob, activationBlobSize, 128);

                printf("  [DEBUG] Setting PCP_TPM12_IDACTIVATION on AIK handle.\n");
                s = NCryptSetProperty(hAIK,
                    NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
                    activationBlob,
                    activationBlobSize,
                    0);
                if (s != ERROR_SUCCESS) {
                    print_ntstatus("  [-] NCryptSetProperty(PCP_TPM12_IDACTIVATION)", s);
                    printf("  [DEBUG] The provider rejected the blob before any returned credential existed.\n");
                    goto cleanup_rsa;
                }

                {
                    DWORD cbUnwrapped = 0;
                    printf("  [DEBUG] Querying returned credential size via PCP_TPM12_IDACTIVATION.\n");
                    s = NCryptGetProperty(hAIK,
                        NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
                        NULL,
                        0,
                        &cbUnwrapped,
                        0);
                    printf("  [DEBUG] NCryptGetProperty(size) status=0x%08X size=%lu\n",
                        s, (unsigned long)cbUnwrapped);

                    if (s == TPM_20_E_VALUE || s == 0x80280084) {
                        printf("  [DEBUG] PCP_TPM12_IDACTIVATION route is unsupported for TPM 2.0 activation.\n");
                        goto cleanup_rsa;
                    }

                    if (s != NTE_BUFFER_TOO_SMALL && s != ERROR_SUCCESS) {
                        print_ntstatus("  [-] NCryptGetProperty(PCP_TPM12_IDACTIVATION) - Size query failed", s);
                        goto cleanup_rsa;
                    }

                    BYTE* unwrapped = (BYTE*)malloc(cbUnwrapped ? cbUnwrapped : 1);
                    if (!unwrapped) {
                        printf("  [-] Out of memory allocating returned credential buffer.\n");
                        goto cleanup_rsa;
                    }

                    s = NCryptGetProperty(hAIK,
                        NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
                        unwrapped,
                        cbUnwrapped,
                        &cbUnwrapped,
                        0);
                    if (s == ERROR_SUCCESS) {
                        dump_hex_prefix("  Returned credential", unwrapped, cbUnwrapped, 64);

                        if (cbUnwrapped == challengeLen &&
                            memcmp(unwrapped, nonce, challengeLen) == 0) {
                            printf("  [SUCCESS] Local TPM decrypted the challenge. Possession of the verified EK private key is validated.\n");
                            ok = TRUE;
                        }
                        else {
                            printf("  [-] Decrypted credential mismatch. Expected %lu bytes.\n",
                                (unsigned long)challengeLen);
                        }
                    }
                    else {
                        print_ntstatus("  [-] NCryptGetProperty(PCP_TPM12_IDACTIVATION) - Decryption denied", s);
                        printf("  [DEBUG] Provider accepted SetProperty but refused to return any credential.\n");
                    }

                    free(unwrapped);
                }

                free(activationBlob);
                activationBlob = NULL;
            }
        }

        free(seed);

    cleanup_rsa:
        if (hRsaKey) BCryptDestroyKey(hRsaKey);
        if (hRsaAlg) BCryptCloseAlgorithmProvider(hRsaAlg, 0);
    }

cleanup:
    free(pbIdBinding);
    free(rsaKeyBlob);
    free(encSecretBytes);
    free(idObjectBytes);
    free(name);
    free(nonce);
    free(encNonce);

    if (hAIK) NCryptDeleteKey(hAIK, 0);
    if (hProv) NCryptFreeObject(hProv);

    return ok;
}