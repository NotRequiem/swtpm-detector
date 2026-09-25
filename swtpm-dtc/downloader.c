#include "tpm.h"

static const BYTE MS_ROOT_2010_SHA1[20] = {
    0x3B, 0x1E, 0xFD, 0x3A, 0x66, 0xEA, 0x28, 0xB1, 0x66, 0x97,
    0x39, 0x47, 0x03, 0xA7, 0x2C, 0xA3, 0x40, 0xA0, 0x5B, 0xD5
};
static const BYTE MS_ROOT_2011_SHA1[20] = {
    0x8F, 0x43, 0x28, 0x8A, 0xD2, 0x72, 0xF3, 0x10, 0x3B, 0x6F,
    0xB1, 0x42, 0x84, 0x85, 0xEA, 0x30, 0x14, 0xC0, 0xBC, 0xFE
};
static const BYTE MS_ROOT_2001_SHA1[20] = {
    0xCD, 0xD4, 0xEE, 0x20, 0x20, 0x0D, 0x4C, 0x28, 0x80, 0x1E,
    0x62, 0x4E, 0xBA, 0x7A, 0x42, 0x96, 0x3D, 0x1A, 0x0B, 0x37
};
static const BYTE MS_ROOT_1997_SHA1[20] = {
    0xA9, 0x46, 0xBF, 0x02, 0x11, 0xEA, 0x42, 0xA7, 0x49, 0x26,
    0xDF, 0x3F, 0xA3, 0xB4, 0x0D, 0x23, 0xDF, 0x61, 0x8F, 0x23
};

BOOL download_url_to_memory(const wchar_t* url, BYTE** outData, DWORD* outSize) {
    BOOL ok = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    URL_COMPONENTS uc;
    WCHAR host[256];
    WCHAR path[2048];
    WCHAR extra[1024];
    WCHAR fullPath[4096];
    BYTE* buf = NULL;
    DWORD cap = 0, size = 0;
    DWORD dwFlags = 0;
    DWORD status = 0, statusSize = sizeof(status);

    if (!url || !outData || !outSize) {
        return FALSE;
    }
    *outData = NULL;
    *outSize = 0;

    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    ZeroMemory(host, sizeof(host));
    ZeroMemory(path, sizeof(path));
    ZeroMemory(extra, sizeof(extra));
    ZeroMemory(fullPath, sizeof(fullPath));

    uc.lpszHostName = host;
    uc.dwHostNameLength = _countof(host) - 1;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = _countof(path) - 1;
    uc.lpszExtraInfo = extra;
    uc.dwExtraInfoLength = _countof(extra) - 1;

    if (!WinHttpCrackUrl(url, 0, 0, &uc)) {
        print_last_error("WinHttpCrackUrl");
        goto cleanup;
    }

    if (uc.dwHostNameLength == 0 || host[0] == L'\0') {
        goto cleanup;
    }

    if (uc.dwHostNameLength >= _countof(host) ||
        uc.dwUrlPathLength >= _countof(path) ||
        uc.dwExtraInfoLength >= _countof(extra)) {
        goto cleanup;
    }

    host[uc.dwHostNameLength] = L'\0';
    path[uc.dwUrlPathLength] = L'\0';
    extra[uc.dwExtraInfoLength] = L'\0';

    WCHAR* fragment = wcschr(extra, L'#');
    if (fragment) {
        *fragment = L'\0';
        uc.dwExtraInfoLength = (DWORD)(fragment - extra);
    }

    if (uc.nScheme == INTERNET_SCHEME_HTTPS) {
        dwFlags |= WINHTTP_FLAG_SECURE;
    }
    else if (uc.nScheme == INTERNET_SCHEME_HTTP) {
        dwFlags = 0;
    }
    else {
        fprintf(stderr, "[!] Unsupported protocol scheme. Only HTTP and HTTPS are supported.\n");
        goto cleanup;
    }

    if (uc.dwUrlPathLength == 0 || path[0] == L'\0') {
        if (FAILED(StringCchCopyW(fullPath, _countof(fullPath), L"/"))) goto cleanup;
    }
    else {
        if (path[0] != L'/') {
            if (FAILED(StringCchCopyW(fullPath, _countof(fullPath), L"/"))) goto cleanup;
            if (FAILED(StringCchCatW(fullPath, _countof(fullPath), path))) goto cleanup;
        }
        else {
            if (FAILED(StringCchCopyW(fullPath, _countof(fullPath), path))) goto cleanup;
        }
    }

    if (uc.dwExtraInfoLength > 0 && extra[0] != L'\0') {
        if (FAILED(StringCchCatW(fullPath, _countof(fullPath), extra))) goto cleanup;
    }

    hSession = WinHttpOpen(L"TPMTrustCheck/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        print_last_error("WinHttpOpen");
        goto cleanup;
    }

    WinHttpSetTimeouts(hSession, 10000, 10000, 15000, 30000);

    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#if defined(WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
    protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

    hConnect = WinHttpConnect(hSession, host, uc.nPort, 0);
    if (!hConnect) {
        print_last_error("WinHttpConnect");
        goto cleanup;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"GET", fullPath, NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
    if (!hRequest) {
        print_last_error("WinHttpOpenRequest");
        goto cleanup;
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy))) {
        print_last_error("WinHttpSetOption: redirect policy");
        goto cleanup;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        print_last_error("WinHttpSendRequest");
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        print_last_error("WinHttpReceiveResponse");
        goto cleanup;
    }

    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
        print_last_error("WinHttpQueryHeaders");
        goto cleanup;
    }

    if (status != HTTP_STATUS_OK) {
        fprintf(stderr, "[!] HTTP server responded with status: %lu\n", (unsigned long)status);
        goto cleanup;
    }

    DWORD contentLength = 0;
    DWORD clSize = sizeof(contentLength);
    BOOL hasContentLength = WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &contentLength, &clSize, WINHTTP_NO_HEADER_INDEX);

    if (hasContentLength) {
        if (contentLength == 0 || contentLength > MAX_CAB_DOWNLOAD_SIZE) {
            fprintf(stderr, "[!] Content-Length invalid or exceeds limit (%lu bytes)\n", contentLength);
            goto cleanup;
        }
        cap = contentLength;
    }
    else {
        cap = 65536;
    }

    buf = (BYTE*)malloc(cap);
    if (!buf) {
        goto cleanup;
    }

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) {
            print_last_error("WinHttpQueryDataAvailable");
            goto cleanup;
        }
        if (avail == 0) {
            break;
        }

        if (avail > MAX_CAB_DOWNLOAD_SIZE || size > MAX_CAB_DOWNLOAD_SIZE - avail) {
            fprintf(stderr, "[!] Download exceeded maximum allowable memory limit.\n");
            goto cleanup;
        }

        if (hasContentLength && (size > contentLength || avail > contentLength - size)) {
            fprintf(stderr, "[!] Server transmitted more bytes than declared in Content-Length.\n");
            goto cleanup;
        }

        if (size + avail > cap) {
            DWORD newcap = (cap > (MAX_CAB_DOWNLOAD_SIZE / 2)) ? MAX_CAB_DOWNLOAD_SIZE : (cap * 2);
            if (newcap < size + avail) {
                newcap = size + avail;
            }
            if (newcap > MAX_CAB_DOWNLOAD_SIZE) {
                newcap = MAX_CAB_DOWNLOAD_SIZE;
            }
            BYTE* newbuf = (BYTE*)realloc(buf, newcap);
            if (!newbuf) {
                goto cleanup;
            }
            buf = newbuf;
            cap = newcap;
        }

        DWORD bytesRead = 0;
        if (!WinHttpReadData(hRequest, buf + size, avail, &bytesRead)) {
            print_last_error("WinHttpReadData");
            goto cleanup;
        }

        if (bytesRead == 0) {
            fprintf(stderr, "[!] Connection dropped prematurely.\n");
            goto cleanup;
        }

        size += bytesRead;
    }

    if (size == 0) {
        goto cleanup;
    }

    if (hasContentLength && size != contentLength) {
        fprintf(stderr, "[!] Incomplete download: expected %lu bytes, got %lu bytes.\n", contentLength, size);
        goto cleanup;
    }

    BYTE* shrunk = (BYTE*)realloc(buf, size);
    if (shrunk) {
        buf = shrunk;
    }

    *outData = buf;
    *outSize = size;
    buf = NULL;
    ok = TRUE;

cleanup:
    if (buf) {
        free(buf);
    }
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return ok;
}

static BOOL is_authentic_microsoft_root(PCCERT_CONTEXT pCert, const wchar_t* subject) {
    if (!pCert || !subject) {
        return FALSE;
    }

    BOOL validSubject = (_wcsicmp(subject, L"Microsoft Root Certificate Authority 2010") == 0 ||
        _wcsicmp(subject, L"Microsoft Root Certificate Authority 2011") == 0 ||
        _wcsicmp(subject, L"Microsoft Root Certificate Authority") == 0 ||
        _wcsicmp(subject, L"Microsoft Root Authority") == 0);
    if (!validSubject) {
        return FALSE;
    }

    BYTE certThumbprint[20];
    DWORD cbThumbprint = sizeof(certThumbprint);
    if (!CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, certThumbprint, &cbThumbprint) ||
        cbThumbprint != sizeof(certThumbprint)) {
        return FALSE;
    }

    if (memcmp(certThumbprint, MS_ROOT_2010_SHA1, 20) == 0 ||
        memcmp(certThumbprint, MS_ROOT_2011_SHA1, 20) == 0 ||
        memcmp(certThumbprint, MS_ROOT_2001_SHA1, 20) == 0 ||
        memcmp(certThumbprint, MS_ROOT_1997_SHA1, 20) == 0) {
        return TRUE;
    }

    return FALSE;
}

static BOOL verify_file_authenticode(const wchar_t* filePath, HANDLE hFile) {
    if (!filePath || hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath;
    fileInfo.hFile = hFile;

    WINTRUST_DATA trustData;
    ZeroMemory(&trustData, sizeof(trustData));
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_CHAIN | WTD_DISABLE_MD2_MD4;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGuid, &trustData);
    BOOL verified = FALSE;

    if (status == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA* pProvData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
        if (pProvData && pProvData->csSigners > 0 && pProvData->pasSigners) {
            CRYPT_PROVIDER_SGNR* pSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);

            if (pSigner && pSigner->dwError == ERROR_SUCCESS &&
                pSigner->pasCertChain && pSigner->csCertChain >= 2) {

                CRYPT_PROVIDER_CERT* pLeafCert = WTHelperGetProvCertFromChain(pSigner, 0);
                CRYPT_PROVIDER_CERT* pRootCert = WTHelperGetProvCertFromChain(pSigner, pSigner->csCertChain - 1);

                WCHAR leafSubject[512] = { 0 };
                WCHAR rootSubject[512] = { 0 };

                if (pLeafCert && pLeafCert->pCert) {
                    CertGetNameStringW(pLeafCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, leafSubject, _countof(leafSubject));
                }

                if (pRootCert && pRootCert->pCert) {
                    CertGetNameStringW(pRootCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, rootSubject, _countof(rootSubject));
                }

                BOOL validLeaf = (_wcsicmp(leafSubject, L"Microsoft Corporation") == 0 ||
                    _wcsicmp(leafSubject, L"Microsoft Windows") == 0);

                BOOL validRoot = (pRootCert && pRootCert->fTrustedRoot &&
                    is_authentic_microsoft_root(pRootCert->pCert, rootSubject));

                BOOL validIntermediate = TRUE;
                if (pSigner->csCertChain >= 3) {
                    CRYPT_PROVIDER_CERT* pInterCert = WTHelperGetProvCertFromChain(pSigner, 1);
                    WCHAR interSubject[512] = { 0 };
                    if (pInterCert && pInterCert->pCert) {
                        CertGetNameStringW(pInterCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, interSubject, _countof(interSubject));
                        if (wcsstr(interSubject, L"Microsoft") == NULL) {
                            validIntermediate = FALSE;
                        }
                    }
                    else {
                        validIntermediate = FALSE;
                    }
                }

                if (validLeaf && validRoot && validIntermediate) {
                    verified = TRUE;
                }
                else {
                    if (!validLeaf) {
                        fwprintf(stderr, L"[!] Untrusted signer publisher: %ls\n", leafSubject);
                    }
                    if (!validRoot) {
                        fwprintf(stderr, L"[!] Certificate does not chain to an authentic Microsoft Root CA: %ls\n", rootSubject);
                    }
                    if (!validIntermediate) {
                        fwprintf(stderr, L"[!] Intermediate certificate failed provenance validation.\n");
                    }
                }
            }
        }
    }
    else {
        fprintf(stderr, "[!] Authenticode verification failed with error: 0x%08lX\n", (unsigned long)status);
    }

    if (trustData.hWVTStateData != NULL) {
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGuid, &trustData);
        trustData.hWVTStateData = NULL;
    }

    return verified;
}

BOOL download_and_verify_trusted_tpm_cab(const wchar_t* url, BYTE** outData, DWORD* outSize) {
    BYTE* downloaded = NULL;
    DWORD downloadedSize = 0;
    WCHAR tempPath[MAX_EXTENDED_PATH_LEN] = { 0 };
    WCHAR tempFile[MAX_EXTENDED_PATH_LEN] = { 0 };
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BOOL success = FALSE;

    if (!url || !outData || !outSize) {
        return FALSE;
    }
    *outData = NULL;
    *outSize = 0;
    tempFile[0] = L'\0';

    if (!download_url_to_memory(url, &downloaded, &downloadedSize)) {
        return FALSE;
    }

    if (downloadedSize < 32 || memcmp(downloaded, "MSCF", 4) != 0) {
        fprintf(stderr, "[!] Downloaded payload does not contain a valid cabinet header.\n");
        goto cleanup;
    }

    DWORD tLen = GetTempPathW(_countof(tempPath), tempPath);
    if (tLen == 0 || tLen >= _countof(tempPath)) {
        fprintf(stderr, "[!] Failed to query system temporary directory.\n");
        goto cleanup;
    }

    if (tempPath[tLen - 1] != L'\\' && tempPath[tLen - 1] != L'/') {
        if (FAILED(StringCchCatW(tempPath, _countof(tempPath), L"\\"))) {
            goto cleanup;
        }
    }

    for (int retry = 0; retry < 10; ++retry) {
        BYTE randBytes[8];
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, randBytes, sizeof(randBytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            goto cleanup;
        }

        if (FAILED(StringCchPrintfW(tempFile, _countof(tempFile),
            L"%sTPM_%02X%02X%02X%02X%02X%02X%02X%02X.cab",
            tempPath,
            randBytes[0], randBytes[1], randBytes[2], randBytes[3],
            randBytes[4], randBytes[5], randBytes[6], randBytes[7]))) {
            tempFile[0] = L'\0';
            goto cleanup;
        }

        hFile = CreateFileW(
            tempFile,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT,
            NULL
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            break;
        }

        if (GetLastError() != ERROR_FILE_EXISTS) {
            tempFile[0] = L'\0';
            goto cleanup;
        }
    }

    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Failed to securely create temporary file.\n");
        tempFile[0] = L'\0';
        goto cleanup;
    }

    DWORD totalWritten = 0;
    while (totalWritten < downloadedSize) {
        DWORD written = 0;
        if (!WriteFile(hFile, downloaded + totalWritten, downloadedSize - totalWritten, &written, NULL) || written == 0) {
            fprintf(stderr, "[!] Failed writing to temporary file.\n");
            goto cleanup;
        }
        totalWritten += written;
    }

    if (!FlushFileBuffers(hFile)) {
        fprintf(stderr, "[!] Failed to flush file buffers.\n");
        goto cleanup;
    }

    LARGE_INTEGER zero = { 0 };
    if (!SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN)) {
        fprintf(stderr, "[!] Failed to rewind file pointer.\n");
        goto cleanup;
    }

    if (!verify_file_authenticode(tempFile, hFile)) {
        fprintf(stderr, "[!] Downloaded TrustedTpm.cab has an INVALID or untrusted Microsoft signature.\n");
        goto cleanup;
    }

    if (!SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN)) {
        fprintf(stderr, "[!] Failed to rewind file pointer for integrity check.\n");
        goto cleanup;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart != (LONGLONG)downloadedSize) {
        fprintf(stderr, "[!] File size corrupted during verification.\n");
        goto cleanup;
    }

    BYTE verifyChunk[8192] = { 0 };
    DWORD bytesVerified = 0;
    while (bytesVerified < downloadedSize) {
        DWORD toRead = sizeof(verifyChunk);
        if (downloadedSize - bytesVerified < toRead) {
            toRead = downloadedSize - bytesVerified;
        }
        DWORD read = 0;
        if (!ReadFile(hFile, verifyChunk, toRead, &read, NULL) || read != toRead) {
            fprintf(stderr, "[!] Failed reading back temporary file.\n");
            goto cleanup;
        }
        if (memcmp(verifyChunk, downloaded + bytesVerified, toRead) != 0) {
            fprintf(stderr, "[!] Memory and disk contents differ; integrity check failed.\n");
            goto cleanup;
        }
        bytesVerified += read;
    }

    *outData = downloaded;
    *outSize = downloadedSize;
    downloaded = NULL;
    success = TRUE;

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    if (tempFile[0] != L'\0') {
        BOOL deleted = FALSE;
        for (int i = 0; i < 5; ++i) {
            if (DeleteFileW(tempFile)) {
                deleted = TRUE;
                break;
            }
            Sleep(20);
        }
        if (!deleted) {
            MoveFileExW(tempFile, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }
    if (downloaded) {
        free(downloaded);
    }
    return success;
}