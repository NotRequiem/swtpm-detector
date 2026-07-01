#include "tpm_verify.h"

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

    host[uc.dwHostNameLength] = L'\0';
    path[uc.dwUrlPathLength] = L'\0';
    extra[uc.dwExtraInfoLength] = L'\0';

    if (FAILED(StringCchCopyW(fullPath, _countof(fullPath), path))) goto cleanup;
    if (uc.dwExtraInfoLength > 0 && extra[0]) {
        if (FAILED(StringCchCatW(fullPath, _countof(fullPath), extra))) goto cleanup;
    }

    hSession = WinHttpOpen(L"TPMTrustCheck/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        print_last_error("WinHttpOpen");
        goto cleanup;
    }

    if (uc.nScheme == INTERNET_SCHEME_HTTPS) dwFlags |= WINHTTP_FLAG_SECURE;

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

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        print_last_error("WinHttpSendRequest");
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        print_last_error("WinHttpReceiveResponse");
        goto cleanup;
    }

    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
        if (status != 200) {
            fprintf(stderr, "HTTP status %lu\n", (unsigned long)status);
            goto cleanup;
        }
    }

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) {
            print_last_error("WinHttpQueryDataAvailable");
            goto cleanup;
        }
        if (avail == 0) break;

        if (size + avail > cap) {
            DWORD newcap = cap ? cap * 2 : 65536;
            while (newcap < size + avail) newcap *= 2;
            BYTE* newbuf = (BYTE*)realloc(buf, newcap);
            if (!newbuf) goto cleanup;
            buf = newbuf;
            cap = newcap;
        }

        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf + size, avail, &read)) {
            print_last_error("WinHttpReadData");
            goto cleanup;
        }
        size += read;
        if (read == 0) break;
    }

    if (size == 0) goto cleanup;

    *outData = buf;
    *outSize = size;
    buf = NULL;
    ok = TRUE;

cleanup:
    if (buf) free(buf);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return ok;
}