#include "tpm_verify.h"

BOOL ends_with_i(const char* s, const char* suffix) {
    size_t ls, lt;
    if (!s || !suffix) return FALSE;
    ls = strlen(s);
    lt = strlen(suffix);
    if (lt > ls) return FALSE;
    return _stricmp(s + (ls - lt), suffix) == 0;
}

const char* basename_a(const char* path) {
    const char* p1 = strrchr(path, '\\');
    const char* p2 = strrchr(path, '/');
    const char* p = (p1 && p2) ? (p1 > p2 ? p1 : p2) : (p1 ? p1 : p2);
    return p ? p + 1 : path;
}

const char* ext_a(const char* path) {
    const char* b = basename_a(path);
    const char* dot = strrchr(b, '.');
    return dot ? dot + 1 : "";
}

BOOL is_cert_file_name(const char* path) {
    const char* e = ext_a(path);
    return (_stricmp(e, "cer") == 0) ||
        (_stricmp(e, "crt") == 0) ||
        (_stricmp(e, "der") == 0) ||
        (_stricmp(e, "pem") == 0);
}

void free_filebuf(FILEBUF* f) {
    if (!f) return;
    free(f->name);
    free(f->data);
    memset(f, 0, sizeof(*f));
}

void free_filelist(FILELIST* list) {
    if (!list) return;
    for (size_t i = 0; i < list->count; ++i) {
        free_filebuf(&list->items[i]);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

BOOL filelist_push(FILELIST* list, const char* name, const BYTE* data, DWORD size) {
    if (!list || !name || (!data && size != 0)) return FALSE;

    if (list->count == list->cap) {
        size_t newcap = list->cap ? list->cap * 2 : 32;
        FILEBUF* p = (FILEBUF*)realloc(list->items, newcap * sizeof(FILEBUF));
        if (!p) return FALSE;
        memset(p + list->cap, 0, (newcap - list->cap) * sizeof(FILEBUF));
        list->items = p;
        list->cap = newcap;
    }

    FILEBUF* out = &list->items[list->count];
    memset(out, 0, sizeof(*out));
    out->name = _strdup(name);
    if (!out->name) return FALSE;

    out->data = (BYTE*)malloc(size ? size : 1);
    if (!out->data) {
        free(out->name);
        memset(out, 0, sizeof(*out));
        return FALSE;
    }

    if (size) memcpy(out->data, data, size);
    out->size = size;
    out->cap = size;
    list->count++;
    return TRUE;
}

void free_wstringlist(WSTRINGLIST* list) {
    if (!list) return;
    for (size_t i = 0; i < list->count; ++i) free(list->items[i]);
    free(list->items);
    memset(list, 0, sizeof(*list));
}

BOOL wstringlist_contains(const WSTRINGLIST* list, const WCHAR* s) {
    if (!list || !s) return FALSE;
    for (size_t i = 0; i < list->count; ++i) {
        if (_wcsicmp(list->items[i], s) == 0) return TRUE;
    }
    return FALSE;
}

BOOL wstringlist_push(WSTRINGLIST* list, const WCHAR* s) {
    WCHAR* copy;
    WCHAR** p;
    if (!list || !s || !s[0]) return FALSE;
    if (wstringlist_contains(list, s)) return TRUE;
    if (list->count == list->cap) {
        size_t newcap = list->cap ? list->cap * 2 : 8;
        p = (WCHAR**)realloc(list->items, newcap * sizeof(WCHAR*));
        if (!p) return FALSE;
        list->items = p;
        list->cap = newcap;
    }
    copy = _wcsdup(s);
    if (!copy) return FALSE;
    list->items[list->count++] = copy;
    return TRUE;
}

BOOL url_is_http(const WCHAR* url) {
    return url && ((_wcsnicmp(url, L"http://", 7) == 0) || (_wcsnicmp(url, L"https://", 8) == 0));
}

BOOL extract_aia_ca_issuers(PCCERT_CONTEXT cert, WSTRINGLIST* urls) {
    PCCERT_EXTENSION ext;
    DWORD cb = 0;
    PCERT_AUTHORITY_INFO_ACCESS aia = NULL;

    if (!cert || !urls) return FALSE;
    ext = CertFindExtension(szOID_AUTHORITY_INFO_ACCESS, cert->pCertInfo->cExtension, cert->pCertInfo->rgExtension);
    if (!ext) return TRUE;

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

    for (DWORD i = 0; i < aia->cAccDescr; ++i) {
        CERT_ACCESS_DESCRIPTION* ad = &aia->rgAccDescr[i];
        if (ad->pszAccessMethod && strcmp(ad->pszAccessMethod, szOID_PKIX_CA_ISSUERS) == 0) {
            if (ad->AccessLocation.dwAltNameChoice == CERT_ALT_NAME_URL && ad->AccessLocation.pwszURL) {
                if (url_is_http(ad->AccessLocation.pwszURL)) {
                    wstringlist_push(urls, ad->AccessLocation.pwszURL);
                }
            }
        }
    }

    LocalFree(aia);
    return TRUE;
}

void print_ascii4(const char* label, uint32_t val) {
    char s[5] = { 0 };
    s[0] = (char)((val >> 24) & 0xFF);
    s[1] = (char)((val >> 16) & 0xFF);
    s[2] = (char)((val >> 8) & 0xFF);
    s[3] = (char)(val & 0xFF);
    s[4] = '\0';
    printf("%s: %lu (ASCII '%s')\n", label, (unsigned long)val, s);
}

void print_utf8_or_unknown(const char* label, const char* s) {
    printf("%s: %s\n", label, (s && s[0]) ? s : "(unknown)");
}

BOOL is_pem_data(const BYTE* data, DWORD size) {
    const char prefix[] = "-----BEGIN";
    return data && size >= sizeof(prefix) - 1 && memcmp(data, prefix, sizeof(prefix) - 1) == 0;
}

BOOL cert_equals(PCCERT_CONTEXT a, PCCERT_CONTEXT b) {
    if (!a || !b) return FALSE;
    return CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, a->pCertInfo, b->pCertInfo);
}

BOOL store_contains_cert_exact(HCERTSTORE store, PCCERT_CONTEXT cert) {
    PCCERT_CONTEXT c = NULL;
    if (!store || !cert) return FALSE;
    while ((c = CertEnumCertificatesInStore(store, c)) != NULL) {
        if (cert_equals(c, cert)) {
            CertFreeCertificateContext(c);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL is_self_signed(PCCERT_CONTEXT c) {
    if (!c) return FALSE;
    return CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        &c->pCertInfo->Subject,
        &c->pCertInfo->Issuer);
}

BOOL cert_is_self_signed(PCCERT_CONTEXT cert) {
    if (!cert) return FALSE;
    if (!CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        &cert->pCertInfo->Subject,
        &cert->pCertInfo->Issuer)) {
        return FALSE;
    }
    return cert_signature_validates_against_issuer(cert, cert);
}

BOOL cert_is_trusted_root(PCCERT_CONTEXT cert, HCERTSTORE hRoots) {
    if (!cert || !hRoots) return FALSE;
    return store_contains_cert_exact(hRoots, cert);
}

BOOL base64_decode_alloc(const char* s, BYTE** out, DWORD* outSize) {
    DWORD needed = 0;
    BYTE* buf = NULL;
    *out = NULL;
    *outSize = 0;

    if (!CryptStringToBinaryA(s, 0, CRYPT_STRING_BASE64HEADER, NULL, &needed, NULL, NULL) &&
        !CryptStringToBinaryA(s, 0, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &needed, NULL, NULL)) {
        return FALSE;
    }

    buf = (BYTE*)malloc(needed ? needed : 1);
    if (!buf) return FALSE;

    if (!CryptStringToBinaryA(s, 0, CRYPT_STRING_BASE64HEADER, buf, &needed, NULL, NULL) &&
        !CryptStringToBinaryA(s, 0, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buf, &needed, NULL, NULL)) {
        free(buf);
        return FALSE;
    }

    *out = buf;
    *outSize = needed;
    return TRUE;
}

BOOL parse_certs_from_extracted_files(HCERTSTORE* outStore) {
    HCERTSTORE store = NULL;
    *outStore = NULL;

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!store) {
        print_last_error("CertOpenStore(memory)");
        return FALSE;
    }

    for (size_t i = 0; i < g_extracted.count; ++i) {
        FILEBUF* f = &g_extracted.items[i];
        BYTE* der = NULL;
        DWORD derSize = 0;
        BOOL decoded = FALSE;
        PCCERT_CONTEXT cc = NULL;

        if (is_pem_data(f->data, f->size)) {
            char* tmp = (char*)malloc((size_t)(f->size) + 1);
            if (!tmp) continue;
            memcpy(tmp, f->data, f->size);
            tmp[f->size] = '\0';
            decoded = base64_decode_alloc(tmp, &der, &derSize);
            free(tmp);
        }
        else {
            der = (BYTE*)malloc(f->size ? f->size : 1);
            if (der) {
                if (f->size) memcpy(der, f->data, f->size);
                derSize = f->size;
                decoded = TRUE;
            }
        }

        if (!decoded || !der || derSize == 0) {
            free(der);
            continue;
        }

        cc = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der, derSize);
        if (!cc) {
            free(der);
            continue;
        }

        if (!CertAddCertificateContextToStore(store, cc, CERT_STORE_ADD_ALWAYS, NULL)) {
            CertFreeCertificateContext(cc);
            free(der);
            continue;
        }

        CertFreeCertificateContext(cc);
        free(der);
    }

    *outStore = store;
    return TRUE;
}

PCCERT_CONTEXT find_valid_issuer_in_store(HCERTSTORE store, PCCERT_CONTEXT subject) {
    PCCERT_CONTEXT c = NULL;
    CRYPT_DATA_BLOB subjectAki = { 0 };
    BOOL haveAki = FALSE;

    if (!store || !subject) return NULL;

    haveAki = get_cert_authority_key_identifier(subject, &subjectAki);

    c = NULL;
    while ((c = CertFindCertificateInStore(store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_ISSUER_OF,
        subject,
        c)) != NULL) {
        if (cert_signature_validates_against_issuer(subject, c)) {
            if (haveAki) free(subjectAki.pbData);
            PCCERT_CONTEXT duplicated = CertDuplicateCertificateContext(c);
            CertFreeCertificateContext(c);
            return duplicated;
        }
    }

    if (haveAki) {
        c = NULL;
        while ((c = CertEnumCertificatesInStore(store, c)) != NULL) {
            CRYPT_DATA_BLOB ski = { 0 };
            BOOL matched = FALSE;
            if (get_cert_subject_key_identifier(c, &ski)) {
                matched = blob_equals(&subjectAki, &ski);
                free(ski.pbData);
            }
            if (matched && cert_signature_validates_against_issuer(subject, c)) {
                free(subjectAki.pbData);
                PCCERT_CONTEXT duplicated = CertDuplicateCertificateContext(c);
                CertFreeCertificateContext(c);
                return duplicated;
            }
        }
        free(subjectAki.pbData);
    }

    c = NULL;
    while ((c = CertEnumCertificatesInStore(store, c)) != NULL) {
        if (cert_signature_validates_against_issuer(subject, c)) {
            PCCERT_CONTEXT duplicated = CertDuplicateCertificateContext(c);
            CertFreeCertificateContext(c);
            return duplicated;
        }
    }
    return NULL;
}

BOOL build_cab_trust_stores(HCERTSTORE hCabStore, HCERTSTORE* outRoots, HCERTSTORE* outIntermediates,
    DWORD* outRootCount, DWORD* outIntermediateCount) {
    PCCERT_CONTEXT c = NULL;
    HCERTSTORE roots = NULL, inters = NULL;
    DWORD rootCount = 0, intermediateCount = 0;

    roots = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    inters = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!roots || !inters) {
        if (roots) CertCloseStore(roots, 0);
        if (inters) CertCloseStore(inters, 0);
        return FALSE;
    }

    while ((c = CertEnumCertificatesInStore(hCabStore, c)) != NULL) {
        if (is_self_signed(c)) {
            if (CertAddCertificateContextToStore(roots, c, CERT_STORE_ADD_ALWAYS, NULL)) rootCount++;
        }
        else {
            if (CertAddCertificateContextToStore(inters, c, CERT_STORE_ADD_ALWAYS, NULL)) intermediateCount++;
        }
    }

    if (outRoots) *outRoots = roots; else CertCloseStore(roots, 0);
    if (outIntermediates) *outIntermediates = inters; else CertCloseStore(inters, 0);
    if (outRootCount) *outRootCount = rootCount;
    if (outIntermediateCount) *outIntermediateCount = intermediateCount;
    return TRUE;
}

BOOL cert_public_key_info_der(PCCERT_CONTEXT cert, BYTE** out, DWORD* outSize) {
    if (!cert || !out || !outSize) return FALSE;
    *out = NULL;
    *outSize = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        X509_PUBLIC_KEY_INFO,
        &cert->pCertInfo->SubjectPublicKeyInfo,
        CRYPT_ENCODE_ALLOC_FLAG,
        NULL,
        out,
        outSize)) {
        print_last_error("CryptEncodeObjectEx(X509_PUBLIC_KEY_INFO)");
        return FALSE;
    }
    return TRUE;
}

BOOL export_cert_public_key_blob(PCCERT_CONTEXT cert, BYTE** outBlob, DWORD* outBlobSize) {
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cb = 0;
    LPCWSTR blobType = NULL;
    BYTE* blob = NULL;

    if (!cert || !outBlob || !outBlobSize) return FALSE;
    *outBlob = NULL;
    *outBlobSize = 0;

    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
        &cert->pCertInfo->SubjectPublicKeyInfo,
        0,
        NULL,
        &hKey)) {
        print_last_error("CryptImportPublicKeyInfoEx2");
        return FALSE;
    }

    if (cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId &&
        strcmp(cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA) == 0) {
        blobType = BCRYPT_RSAPUBLIC_BLOB;
    }
    else if (cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId &&
        strcmp(cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) == 0) {
        blobType = BCRYPT_ECCPUBLIC_BLOB;
    }
    else {
        BCryptDestroyKey(hKey);
        return FALSE;
    }

    if (BCryptExportKey(hKey, NULL, blobType, NULL, 0, &cb, 0) != STATUS_SUCCESS || cb == 0) {
        print_last_error("BCryptExportKey");
        BCryptDestroyKey(hKey);
        return FALSE;
    }

    blob = (BYTE*)malloc(cb);
    if (!blob) {
        BCryptDestroyKey(hKey);
        return FALSE;
    }

    if (BCryptExportKey(hKey, NULL, blobType, blob, cb, &cb, 0) != STATUS_SUCCESS) {
        print_last_error("BCryptExportKey");
        free(blob);
        BCryptDestroyKey(hKey);
        return FALSE;
    }

    BCryptDestroyKey(hKey);
    *outBlob = blob;
    *outBlobSize = cb;
    return TRUE;
}

BOOL ekpub_matches_cert(PCCERT_CONTEXT cert, const BYTE* ekPub, DWORD ekPubSize) {
    BYTE* certBlob = NULL;
    DWORD certBlobSize = 0;
    BOOL ok = FALSE;

    if (!cert || !ekPub || ekPubSize == 0) return FALSE;

    if (export_cert_public_key_blob(cert, &certBlob, &certBlobSize)) {
        if (certBlobSize == ekPubSize && memcmp(certBlob, ekPub, ekPubSize) == 0) {
            ok = TRUE;
        }
        free(certBlob);
        if (ok) return TRUE;
    }

    {
        BYTE* der = NULL;
        DWORD derSize = 0;
        if (cert_public_key_info_der(cert, &der, &derSize)) {
            char a[65] = { 0 }, b[65] = { 0 };
            if (sha256_hex(der, derSize, a) && sha256_hex(ekPub, ekPubSize, b) && strcmp(a, b) == 0) {
                ok = TRUE;
            }
            free(der);
        }
    }

    return ok;
}

BOOL cert_signature_validates_against_issuer(PCCERT_CONTEXT subject, PCCERT_CONTEXT issuer) {
    if (!subject || !issuer) return FALSE;
    return CryptVerifyCertificateSignature(0,
        X509_ASN_ENCODING,
        subject->pbCertEncoded,
        subject->cbCertEncoded,
        &issuer->pCertInfo->SubjectPublicKeyInfo);
}

BOOL blob_equals(const CRYPT_DATA_BLOB* a, const CRYPT_DATA_BLOB* b) {
    if (!a || !b) return FALSE;
    return a->cbData == b->cbData && a->cbData > 0 && memcmp(a->pbData, b->pbData, a->cbData) == 0;
}

BOOL get_cert_subject_key_identifier(PCCERT_CONTEXT cert, CRYPT_DATA_BLOB* out) {
    DWORD cb = 0;
    BYTE* pb = NULL;
    if (!cert || !out) return FALSE;
    ZeroMemory(out, sizeof(*out));

    if (CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, NULL, &cb) && cb) {
        pb = (BYTE*)malloc(cb);
        if (!pb) return FALSE;
        if (CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, pb, &cb)) {
            out->pbData = pb;
            out->cbData = cb;
            return TRUE;
        }
        free(pb);
        return FALSE;
    }
    return FALSE;
}

BOOL get_cert_authority_key_identifier(PCCERT_CONTEXT cert, CRYPT_DATA_BLOB* out) {
    PCCERT_EXTENSION ext = NULL;
    PCERT_AUTHORITY_KEY_ID_INFO aki = NULL;
    DWORD cb = 0;

    if (!cert || !out) return FALSE;
    ZeroMemory(out, sizeof(*out));

    ext = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER,
        cert->pCertInfo->cExtension,
        cert->pCertInfo->rgExtension);
    if (!ext) {
        ext = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2,
            cert->pCertInfo->cExtension,
            cert->pCertInfo->rgExtension);
    }
    if (!ext) return FALSE;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        X509_AUTHORITY_KEY_ID,
        ext->Value.pbData,
        ext->Value.cbData,
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &aki,
        &cb)) {
        return FALSE;
    }

    if (aki->KeyId.cbData && aki->KeyId.pbData) {
        out->pbData = (BYTE*)malloc(aki->KeyId.cbData);
        if (!out->pbData) {
            LocalFree(aki);
            return FALSE;
        }
        memcpy(out->pbData, aki->KeyId.pbData, aki->KeyId.cbData);
        out->cbData = aki->KeyId.cbData;
        LocalFree(aki);
        return TRUE;
    }

    LocalFree(aki);
    return FALSE;
}

void print_last_error(const char* what) {
    DWORD e = GetLastError();
    char* msg = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, e, 0, (LPSTR)&msg, 0, NULL);
    fprintf(stderr, "%s failed: %lu%s%s\n", what, (unsigned long)e, msg ? ": " : "", msg ? msg : "");
    if (msg) LocalFree(msg);
}

void print_tbs_result(const char* what, TBS_RESULT r) {
    fprintf(stderr, "%s failed: 0x%08lx\n", what, (unsigned long)r);
}

void print_ntstatus(const char* what, SECURITY_STATUS s) {
    fprintf(stderr, "%s failed: 0x%08lx\n", what, (unsigned long)s);
}

BOOL sha256_hex(const BYTE* data, DWORD size, char outHex[65]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE hash[32];
    DWORD cbRes = 0, objLen = 0;
    PUCHAR obj = NULL;
    NTSTATUS st;

    outHex[0] = '\0';

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st < 0) return FALSE;

    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbRes, 0);
    if (st < 0 || objLen == 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    obj = (PUCHAR)malloc(objLen);
    if (!obj) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    st = BCryptCreateHash(hAlg, &hHash, obj, objLen, NULL, 0, 0);
    if (st < 0) {
        free(obj);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    st = BCryptHashData(hHash, (PUCHAR)data, size, 0);
    if (st < 0) goto Fail;

    st = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
    if (st < 0) goto Fail;

    for (DWORD i = 0; i < sizeof(hash); ++i) {
        StringCchPrintfA(outHex + (i * 2), 65 - ((size_t)(i) * 2), "%02x", hash[i]);
    }
    outHex[64] = '\0';
    BCryptDestroyHash(hHash);
    free(obj);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;

Fail:
    BCryptDestroyHash(hHash);
    free(obj);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return FALSE;
}

BOOL is_trusted_manufacturer_url(const WCHAR* url) {
    if (!url) return FALSE;

    size_t len = wcslen(url);
    WCHAR* lower = (WCHAR*)malloc((len + 1) * sizeof(WCHAR));
    if (!lower) return FALSE;
    for (size_t i = 0; i <= len; i++) {
        lower[i] = (WCHAR)towlower(url[i]);
    }

    BOOL trusted = FALSE;
    const WCHAR* trusted_domains[] = {
        L"ftpm.amd.com",
        L"download.amd.com",
        L"intel.com",
        L"trustedservices.intel.com",
        L"ekop.intel.com",
        L"tpmsec.microsoft.com",
        L"microsoftaik.azure.net",
        L"spserv.microsoft.com",
        L"nuvoton.com",
        L"infineon.com",
        L"st.com",
        L"globalsign.com",
        L"globalsign.net",
        L"qualcomm.com",
        L"qcom.com",
        L"nxp.com"
    };

    for (size_t i = 0; i < sizeof(trusted_domains) / sizeof(trusted_domains[0]); i++) {
        if (wcsstr(lower, trusted_domains[i]) != NULL) {
            trusted = TRUE;
            break;
        }
    }

    free(lower);
    return trusted;
}