#include "tpm.h"

BOOL ends_with_i(const char* s, const char* suffix) {
    size_t ls, lt;
    if (!s || !suffix) return FALSE;
    ls = strlen(s);
    lt = strlen(suffix);
    if (lt > ls) return FALSE;
    return _stricmp(s + (ls - lt), suffix) == 0;
}

const char* basename_a(const char* path) {
    if (!path) return "";
    const char* p1 = strrchr(path, '\\');
    const char* p2 = strrchr(path, '/');
    const char* p = (p1 && p2) ? (p1 > p2 ? p1 : p2) : (p1 ? p1 : p2);
    return p ? p + 1 : path;
}

const char* ext_a(const char* path) {
    if (!path) return "";
    const char* b = basename_a(path);
    const char* dot = strrchr(b, '.');
    return dot ? dot + 1 : "";
}

BOOL is_cert_file_name(const char* path) {
    if (!path) return FALSE;
    const char* e = ext_a(path);
    return (_stricmp(e, "cer") == 0) || (_stricmp(e, "crt") == 0) ||
        (_stricmp(e, "der") == 0) || (_stricmp(e, "pem") == 0);
}

void free_filebuf(FILEBUF* f) {
    if (!f) return;
    free(f->name);
    free(f->data);
    memset(f, 0, sizeof(*f));
}

void free_filelist(FILELIST* list) {
    if (!list) return;
    if (list->items) {
        for (size_t i = 0; i < list->count; ++i) {
            free_filebuf(&list->items[i]);
        }
        free(list->items);
    }
    memset(list, 0, sizeof(*list));
}

BOOL filelist_push(FILELIST* list, const char* name, const BYTE* data, DWORD size) {
    if (!list || !name || (!data && size != 0)) return FALSE;

    if (list->count >= list->cap) {
        if (list->cap > (SIZE_MAX / 2) / sizeof(FILEBUF)) return FALSE;
        size_t newcap = list->cap ? list->cap * 2 : 32;
        FILEBUF* p = (FILEBUF*)realloc(list->items, newcap * sizeof(FILEBUF));
        if (!p) return FALSE;
        memset(p + list->cap, 0, (newcap - list->cap) * sizeof(FILEBUF));
        list->items = p;
        list->cap = newcap;
    }

    FILEBUF* out = &list->items[list->count];
    out->name = _strdup(name);
    if (!out->name) return FALSE;

    out->data = (BYTE*)malloc(size ? size : 1);
    if (!out->data) {
        free(out->name);
        out->name = NULL;
        return FALSE;
    }

    if (size && data) {
        memcpy(out->data, data, size);
    }
    out->size = size;
    out->cap = size ? size : 1;
    list->count++;
    return TRUE;
}

void free_wstringlist(WSTRINGLIST* list) {
    if (!list) return;
    if (list->items) {
        for (size_t i = 0; i < list->count; ++i) {
            free(list->items[i]);
        }
        free(list->items);
    }
    memset(list, 0, sizeof(*list));
}

BOOL wstringlist_contains(const WSTRINGLIST* list, const WCHAR* s) {
    if (!list || !s || !list->items) return FALSE;
    for (size_t i = 0; i < list->count; ++i) {
        if (list->items[i] && _wcsicmp(list->items[i], s) == 0) return TRUE;
    }
    return FALSE;
}

BOOL wstringlist_push(WSTRINGLIST* list, const WCHAR* s) {
    if (!list || !s || !s[0]) return FALSE;
    if (wstringlist_contains(list, s)) return TRUE;

    WCHAR* copy = _wcsdup(s);
    if (!copy) return FALSE;

    if (list->count >= list->cap) {
        if (list->cap > (SIZE_MAX / 2) / sizeof(WCHAR*)) {
            free(copy);
            return FALSE;
        }
        size_t newcap = list->cap ? list->cap * 2 : 8;
        WCHAR** p = (WCHAR**)realloc(list->items, newcap * sizeof(WCHAR*));
        if (!p) {
            free(copy);
            return FALSE;
        }
        list->items = p;
        list->cap = newcap;
    }

    list->items[list->count++] = copy;
    return TRUE;
}

BOOL url_is_http(const WCHAR* url) {
    return url && ((_wcsnicmp(url, L"http://", 7) == 0) || (_wcsnicmp(url, L"https://", 8) == 0));
}

BOOL extract_aia_ca_issuers(PCCERT_CONTEXT cert, WSTRINGLIST* urls) {
    if (!cert || !cert->pCertInfo || !urls) return FALSE;

    PCERT_EXTENSION ext = CertFindExtension(szOID_AUTHORITY_INFO_ACCESS,
        cert->pCertInfo->cExtension,
        cert->pCertInfo->rgExtension);
    if (!ext) return TRUE;
    if (!ext->Value.pbData || ext->Value.cbData == 0) return TRUE;

    DWORD cb = 0;
    PCERT_AUTHORITY_INFO_ACCESS aia = NULL;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        X509_AUTHORITY_INFO_ACCESS,
        ext->Value.pbData,
        ext->Value.cbData,
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &aia,
        &cb)) {
        return FALSE;
    }

    if (aia) {
        for (DWORD i = 0; i < aia->cAccDescr; ++i) {
            CERT_ACCESS_DESCRIPTION* ad = &aia->rgAccDescr[i];
            if (ad->pszAccessMethod &&
                strcmp(ad->pszAccessMethod, szOID_PKIX_CA_ISSUERS) == 0 &&
                ad->AccessLocation.dwAltNameChoice == CERT_ALT_NAME_URL &&
                ad->AccessLocation.pwszURL) {
                if (url_is_http(ad->AccessLocation.pwszURL)) {
                    wstringlist_push(urls, ad->AccessLocation.pwszURL);
                }
            }
        }
        LocalFree(aia);
    }
    return TRUE;
}

void print_last_error(const char* what) {
    DWORD e = GetLastError();
    fprintf(stderr, "%s failed: %lu\n", what ? what : "Operation", (unsigned long)e);
}

BOOL is_pem_data(const BYTE* data, DWORD size) {
    const char prefix[] = "-----BEGIN";
    DWORD offset = 0;
    if (!data || size < sizeof(prefix) - 1) return FALSE;
    if (size >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
        offset = 3;
    }
    while (offset < size && (data[offset] == ' ' || data[offset] == '\r' ||
        data[offset] == '\n' || data[offset] == '\t')) {
        offset++;
    }
    if ((unsigned long long)(size) - offset < sizeof(prefix) - 1) return FALSE;
    return memcmp(data + offset, prefix, sizeof(prefix) - 1) == 0;
}

BOOL base64_decode_alloc(const char* s, BYTE** out, DWORD* outSize) {
    if (!s || !out || !outSize) return FALSE;
    *out = NULL;
    *outSize = 0;

    DWORD needed = 0;
    if (!CryptStringToBinaryA(s, 0, CRYPT_STRING_BASE64_ANY, NULL, &needed, NULL, NULL) || needed == 0) {
        return FALSE;
    }
    *out = (BYTE*)malloc(needed);
    if (!*out) return FALSE;

    if (!CryptStringToBinaryA(s, 0, CRYPT_STRING_BASE64_ANY, *out, &needed, NULL, NULL)) {
        free(*out);
        *out = NULL;
        return FALSE;
    }
    *outSize = needed;
    return TRUE;
}

BOOL parse_certs_from_extracted_files(HCERTSTORE* outStore) {
    if (!outStore) return FALSE;
    *outStore = NULL;

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!store) return FALSE;

    if (g_extracted.items) {
        for (size_t i = 0; i < g_extracted.count; ++i) {
            FILEBUF* f = &g_extracted.items[i];
            if (!f || !f->data || f->size == 0) continue;

            PCCERT_CONTEXT cc = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, f->data, f->size);
            if (!cc && is_pem_data(f->data, f->size)) {
                DWORD derSize = 0;
                if (CryptStringToBinaryA((LPCSTR)f->data, f->size, CRYPT_STRING_BASE64HEADER, NULL, &derSize, NULL, NULL) && derSize > 0) {
                    BYTE* derBuf = (BYTE*)malloc(derSize);
                    if (derBuf) {
                        if (CryptStringToBinaryA((LPCSTR)f->data, f->size, CRYPT_STRING_BASE64HEADER, derBuf, &derSize, NULL, NULL)) {
                            cc = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBuf, derSize);
                        }
                        free(derBuf);
                    }
                }
            }

            if (cc) {
                CertAddCertificateContextToStore(store, cc, CERT_STORE_ADD_ALWAYS, NULL);
                CertFreeCertificateContext(cc);
            }
        }
    }
    *outStore = store;
    return TRUE;
}

BOOL cert_equals(PCCERT_CONTEXT a, PCCERT_CONTEXT b) {
    if (!a || !b) return FALSE;
    if (a == b) return TRUE;
    if (a->cbCertEncoded != b->cbCertEncoded) return FALSE;
    if (a->cbCertEncoded == 0) return TRUE;
    if (!a->pbCertEncoded || !b->pbCertEncoded) return FALSE;
    return memcmp(a->pbCertEncoded, b->pbCertEncoded, a->cbCertEncoded) == 0;
}

BOOL store_contains_cert_exact(HCERTSTORE store, PCCERT_CONTEXT cert) {
    if (!store || !cert) return FALSE;
    PCCERT_CONTEXT c = NULL;
    while ((c = CertEnumCertificatesInStore(store, c)) != NULL) {
        if (cert_equals(c, cert)) {
            CertFreeCertificateContext(c);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL cert_signature_validates_against_issuer(PCCERT_CONTEXT subject, PCCERT_CONTEXT issuer) {
    if (!subject || !issuer) return FALSE;
    return CryptVerifyCertificateSignatureEx(
        0,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
        (void*)subject,
        CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
        (void*)issuer,
        0,
        NULL);
}

BOOL cert_is_self_signed(PCCERT_CONTEXT cert) {
    return (cert && cert->pCertInfo &&
        CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &cert->pCertInfo->Subject,
            &cert->pCertInfo->Issuer) &&
        cert_signature_validates_against_issuer(cert, cert));
}

BOOL cert_is_trusted_root(PCCERT_CONTEXT cert, HCERTSTORE hRoots) {
    return (cert && hRoots && store_contains_cert_exact(hRoots, cert));
}

BOOL blob_equals(const CRYPT_DATA_BLOB* a, const CRYPT_DATA_BLOB* b) {
    if (!a || !b) return FALSE;
    if (a->cbData != b->cbData) return FALSE;
    if (a->cbData == 0) return TRUE;
    if (!a->pbData || !b->pbData) return FALSE;
    return memcmp(a->pbData, b->pbData, a->cbData) == 0;
}

BOOL get_cert_subject_key_identifier(PCCERT_CONTEXT cert, CRYPT_DATA_BLOB* out) {
    if (!out) return FALSE;
    out->pbData = NULL;
    out->cbData = 0;
    if (!cert || !cert->pCertInfo) return FALSE;

    PCERT_EXTENSION ext = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER,
        cert->pCertInfo->cExtension,
        cert->pCertInfo->rgExtension);
    if (ext && ext->Value.pbData && ext->Value.cbData > 0) {
        PCRYPT_DATA_BLOB skiBlob = NULL;
        DWORD cb = 0;
        if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            szOID_SUBJECT_KEY_IDENTIFIER,
            ext->Value.pbData,
            ext->Value.cbData,
            CRYPT_DECODE_ALLOC_FLAG,
            NULL,
            &skiBlob,
            &cb)) {
            if (skiBlob && skiBlob->cbData > 0 && skiBlob->pbData) {
                out->pbData = (BYTE*)malloc(skiBlob->cbData);
                if (out->pbData) {
                    memcpy(out->pbData, skiBlob->pbData, skiBlob->cbData);
                    out->cbData = skiBlob->cbData;
                    LocalFree(skiBlob);
                    return TRUE;
                }
            }
            if (skiBlob) LocalFree(skiBlob);
        }
    }
    return FALSE;
}

BOOL get_cert_authority_key_identifier(PCCERT_CONTEXT cert, CRYPT_DATA_BLOB* out) {
    if (!out) return FALSE;
    out->pbData = NULL;
    out->cbData = 0;
    if (!cert || !cert->pCertInfo) return FALSE;

    PCERT_EXTENSION ext = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2,
        cert->pCertInfo->cExtension,
        cert->pCertInfo->rgExtension);
    if (ext && ext->Value.pbData && ext->Value.cbData > 0) {
        PCERT_AUTHORITY_KEY_ID2_INFO aki2 = NULL;
        DWORD cb = 0;
        if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_AUTHORITY_KEY_ID2,
            ext->Value.pbData,
            ext->Value.cbData,
            CRYPT_DECODE_ALLOC_FLAG,
            NULL,
            &aki2,
            &cb)) {
            if (aki2 && aki2->KeyId.cbData > 0 && aki2->KeyId.pbData) {
                out->pbData = (BYTE*)malloc(aki2->KeyId.cbData);
                if (out->pbData) {
                    memcpy(out->pbData, aki2->KeyId.pbData, aki2->KeyId.cbData);
                    out->cbData = aki2->KeyId.cbData;
                    LocalFree(aki2);
                    return TRUE;
                }
            }
            if (aki2) LocalFree(aki2);
        }
    }
    return FALSE;
}

PCCERT_CONTEXT find_valid_issuer_in_store(HCERTSTORE store, PCCERT_CONTEXT subject) {
    if (!store || !subject) return NULL;
    PCCERT_CONTEXT c = NULL;

    while ((c = CertFindCertificateInStore(store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_ISSUER_OF,
        subject,
        c)) != NULL) {
        if (cert_signature_validates_against_issuer(subject, c)) {
            return c;
        }
    }
    return NULL;
}

BOOL build_cab_trust_stores(HCERTSTORE hCabStore,
    HCERTSTORE* outRoots,
    HCERTSTORE* outIntermediates,
    DWORD* outRootCount,
    DWORD* outIntermediateCount) {
    if (outRoots) *outRoots = NULL;
    if (outIntermediates) *outIntermediates = NULL;
    if (outRootCount) *outRootCount = 0;
    if (outIntermediateCount) *outIntermediateCount = 0;

    if (!hCabStore) return FALSE;

    HCERTSTORE roots = NULL;
    if (outRoots || outRootCount) {
        roots = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
        if (!roots) return FALSE;
    }

    HCERTSTORE intermediates = NULL;
    if (outIntermediates || outIntermediateCount) {
        intermediates = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
        if (!intermediates) {
            if (roots) CertCloseStore(roots, 0);
            return FALSE;
        }
    }

    DWORD rootCount = 0;
    DWORD intermediateCount = 0;
    PCCERT_CONTEXT c = NULL;

    while ((c = CertEnumCertificatesInStore(hCabStore, c)) != NULL) {
        if (cert_is_self_signed(c)) {
            if (roots) {
                if (CertAddCertificateContextToStore(roots, c, CERT_STORE_ADD_ALWAYS, NULL)) {
                    rootCount++;
                }
            }
        }
        else {
            if (intermediates) {
                if (CertAddCertificateContextToStore(intermediates, c, CERT_STORE_ADD_ALWAYS, NULL)) {
                    intermediateCount++;
                }
            }
        }
    }

    if (outRoots) {
        *outRoots = roots;
    }
    else if (roots) {
        CertCloseStore(roots, 0);
    }

    if (outIntermediates) {
        *outIntermediates = intermediates;
    }
    else if (intermediates) {
        CertCloseStore(intermediates, 0);
    }

    if (outRootCount) *outRootCount = rootCount;
    if (outIntermediateCount) *outIntermediateCount = intermediateCount;
    return TRUE;
}

BOOL export_cert_public_key_blob(PCCERT_CONTEXT cert, BYTE** outBlob, DWORD* outBlobSize) {
    if (!outBlob || !outBlobSize) return FALSE;
    *outBlob = NULL;
    *outBlobSize = 0;

    if (!cert || !cert->pCertInfo) return FALSE;
    if (!cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId) return FALSE;

    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cb = 0;

    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
        &cert->pCertInfo->SubjectPublicKeyInfo,
        0,
        NULL,
        &hKey)) {
        return FALSE;
    }

    LPCWSTR blobType = (strcmp(cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA) == 0)
        ? BCRYPT_RSAPUBLIC_BLOB
        : BCRYPT_ECCPUBLIC_BLOB;

    if (BCryptExportKey(hKey, NULL, blobType, NULL, 0, &cb, 0) != STATUS_SUCCESS || cb == 0) {
        BCryptDestroyKey(hKey);
        return FALSE;
    }

    *outBlob = (BYTE*)malloc(cb);
    if (!*outBlob) {
        BCryptDestroyKey(hKey);
        return FALSE;
    }

    if (BCryptExportKey(hKey, NULL, blobType, *outBlob, cb, outBlobSize, 0) != STATUS_SUCCESS) {
        free(*outBlob);
        *outBlob = NULL;
        *outBlobSize = 0;
        BCryptDestroyKey(hKey);
        return FALSE;
    }

    BCryptDestroyKey(hKey);
    return TRUE;
}

BOOL ekpub_matches_cert(PCCERT_CONTEXT cert, const BYTE* ekPub, DWORD ekPubSize) {
    if (!cert || !ekPub || ekPubSize == 0) return FALSE;

    BYTE* certBlob = NULL;
    DWORD certBlobSize = 0;
    BOOL ok = FALSE;

    if (export_cert_public_key_blob(cert, &certBlob, &certBlobSize)) {
        if (certBlob && certBlobSize == ekPubSize) {
            ok = (memcmp(certBlob, ekPub, ekPubSize) == 0);
        }
        free(certBlob);
    }
    return ok;
}

BOOL calculate_sha256(const uint8_t* data, uint32_t size, uint8_t outDigest[32]) {
    if (!outDigest || (!data && size != 0)) return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbObj = 0, cbData = sizeof(DWORD);
    BOOL success = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != STATUS_SUCCESS) {
        return FALSE;
    }

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbObj, cbData, &cbData, 0) == STATUS_SUCCESS && cbObj > 0) {
        BYTE* hashObject = (BYTE*)malloc(cbObj);
        if (hashObject) {
            if (BCryptCreateHash(hAlg, &hHash, hashObject, cbObj, NULL, 0, 0) == STATUS_SUCCESS) {
                NTSTATUS status = STATUS_SUCCESS;
                if (data && size > 0) {
                    status = BCryptHashData(hHash, (PUCHAR)data, size, 0);
                }
                if (status == STATUS_SUCCESS &&
                    BCryptFinishHash(hHash, outDigest, 32, 0) == STATUS_SUCCESS) {
                    success = TRUE;
                }
                BCryptDestroyHash(hHash);
            }
            free(hashObject);
        }
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}

BOOL sha256_hex(const BYTE* data, DWORD size, char outHex[65]) {
    if (!outHex) return FALSE;
    BYTE hash[32];
    if (!calculate_sha256((const uint8_t*)data, (uint32_t)size, hash)) {
        outHex[0] = '\0';
        return FALSE;
    }
    for (int i = 0; i < 32; ++i) {
        StringCchPrintfA(outHex + (i * 2), 3, "%02x", hash[i]);
    }
    outHex[64] = '\0';
    return TRUE;
}

static const TRUSTED_URL kTrustedManufacturerUrls[] = {
    { L"ekop.intel.com", L"/ekcertservice", FALSE, TRUE },
    { L"ekcert.intel.com", L"/ekcertservice", FALSE, TRUE },
    { L"ftpm.amd.com", L"/pki/aia", TRUE, TRUE },
    { L"ekcert.spserv.microsoft.com", L"/EKCertificate/GetEKCertificate/v1", FALSE, TRUE },
    { L"pki.infineon.com", L"/", TRUE, TRUE },
    { L"tpm.nuvoton.com", L"/", TRUE, TRUE }
};

BOOL is_trusted_manufacturer_url(const WCHAR* url) {
    if (!url || !url_is_http(url)) return FALSE;

    const WCHAR* sep = wcsstr(url, L"://");
    if (!sep) return FALSE;
    const WCHAR* host = sep + 3;
    const WCHAR* path = wcschr(host, L'/');
    if (!path) return FALSE;

    const WCHAR* host_end = host;
    while (host_end < path && *host_end != L':') {
        host_end++;
    }
    size_t host_len = (size_t)(host_end - host);
    if (host_len == 0) return FALSE;

    for (size_t i = 0; i < sizeof(kTrustedManufacturerUrls) / sizeof(kTrustedManufacturerUrls[0]); i++) {
        size_t trusted_host_len = wcslen(kTrustedManufacturerUrls[i].host);
        if (host_len != trusted_host_len) continue;
        if (_wcsnicmp(host, kTrustedManufacturerUrls[i].host, host_len) != 0) continue;

        size_t prefix_len = wcslen(kTrustedManufacturerUrls[i].path_prefix);
        if (_wcsnicmp(path, kTrustedManufacturerUrls[i].path_prefix, prefix_len) == 0) {
            if (kTrustedManufacturerUrls[i].path_prefix[prefix_len - 1] == L'/' ||
                path[prefix_len] == L'\0' ||
                path[prefix_len] == L'/' ||
                path[prefix_len] == L'?') {
                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOL check_issuer_basic_constraints_and_key_usage(PCCERT_CONTEXT cert) {
    if (!cert || !cert->pCertInfo) return FALSE;

    PCERT_EXTENSION ext = CertFindExtension(szOID_BASIC_CONSTRAINTS2,
        cert->pCertInfo->cExtension,
        cert->pCertInfo->rgExtension);
    if (!ext || !ext->Value.pbData || ext->Value.cbData == 0) return FALSE;

    CERT_BASIC_CONSTRAINTS2_INFO bc = { 0 };
    DWORD cb = sizeof(bc);
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        X509_BASIC_CONSTRAINTS2,
        ext->Value.pbData,
        ext->Value.cbData,
        0,
        NULL,
        &bc,
        &cb)) {
        return FALSE;
    }
    if (!bc.fCA) return FALSE;

    BYTE keyUsage[2] = { 0 };
    SetLastError(0);
    if (CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        cert->pCertInfo,
        keyUsage,
        sizeof(keyUsage))) {
        if ((keyUsage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE) == 0) {
            return FALSE;
        }
    }
    else {
        if (GetLastError() != 0) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL check_cert_revocation(PCCERT_CONTEXT cert) {
    if (!cert) return FALSE;

    CERT_REVOCATION_STATUS rev = { sizeof(rev) };
    PVOID rgpvContext[1] = { (PVOID)cert };

    if (CertVerifyRevocation(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        CERT_CONTEXT_REVOCATION_TYPE,
        1,
        rgpvContext,
        0,
        NULL,
        &rev)) {
        return TRUE;
    }

    if (rev.dwError == CRYPT_E_REVOKED) {
        return FALSE;
    }

    return TRUE;
}