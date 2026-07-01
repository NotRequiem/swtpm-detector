#include "tpm_verify.h"

FILELIST g_extracted = { 0 };
static const BYTE* g_cab_data = NULL;
static DWORD g_cab_size = 0;

static INT_PTR DIAMONDAPI mem_open(char* pszFile, int oflag, int pmode) {
    (void)oflag;
    (void)pmode;
    if (!pszFile || !g_cab_data || g_cab_size == 0) return -1;

    const char* base = basename_a(pszFile);
    if (ends_with_i(base, "TrustedTpm.cab") || ends_with_i(pszFile, ".cab")) {
        MEMSRC* s = (MEMSRC*)calloc(1, sizeof(MEMSRC));
        if (!s) return -1;
        s->data = g_cab_data;
        s->size = g_cab_size;
        s->pos = 0;
        return (INT_PTR)s;
    }
    return -1;
}

static UINT DIAMONDAPI mem_read(INT_PTR hf, void* pv, UINT cb) {
    MEMSRC* s = (MEMSRC*)hf;
    UINT remain;
    if (!s || !pv) return (UINT)-1;
    if (s->pos >= s->size) return 0;
    remain = s->size - s->pos;
    if (cb > remain) cb = remain;
    memcpy(pv, s->data + s->pos, cb);
    s->pos += cb;
    return cb;
}

static UINT DIAMONDAPI mem_write(INT_PTR hf, void* pv, UINT cb) {
    FILEBUF* f = (FILEBUF*)hf;
    BYTE* p;
    if (!f || !pv) return (UINT)-1;

    if (f->size + cb > f->cap) {
        DWORD newcap = f->cap ? f->cap : 4096;
        while (newcap < f->size + cb) {
            newcap *= 2;
            if (newcap < f->cap) return (UINT)-1;
        }
        p = (BYTE*)realloc(f->data, newcap);
        if (!p) return (UINT)-1;
        f->data = p;
        f->cap = newcap;
    }

    memcpy(f->data + f->size, pv, cb);
    f->size += cb;
    return cb;
}

static long DIAMONDAPI mem_seek(INT_PTR hf, long dist, int seektype) {
    MEMSRC* s = (MEMSRC*)hf;
    LONG64 newpos = 0;
    if (!s) return -1;

    switch (seektype) {
    case SEEK_SET: newpos = dist; break;
    case SEEK_CUR: newpos = (LONG64)s->pos + dist; break;
    case SEEK_END: newpos = (LONG64)s->size + dist; break;
    default: return -1;
    }

    if (newpos < 0) newpos = 0;
    if ((ULONGLONG)newpos > s->size) newpos = s->size;
    s->pos = (DWORD)newpos;
    return (long)s->pos;
}

static int DIAMONDAPI mem_close(INT_PTR hf) {
    free((void*)hf);
    return 0;
}

static void* DIAMONDAPI mem_alloc(ULONG cb) {
    return malloc(cb ? cb : 1);
}

static void DIAMONDAPI mem_free(void* pv) {
    free(pv);
}

static FILEBUF* create_output_filebuf(const char* name) {
    FILEBUF* f = (FILEBUF*)calloc(1, sizeof(FILEBUF));
    if (!f) return NULL;
    f->name = _strdup(name ? name : "");
    if (!f->name) {
        free(f);
        return NULL;
    }
    f->cap = 4096;
    f->data = (BYTE*)malloc(f->cap);
    if (!f->data) {
        free(f->name);
        free(f);
        return NULL;
    }
    return f;
}

static INT_PTR DIAMONDAPI fdi_notify(FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin) {
    switch (fdint) {
    case fdintCOPY_FILE:
        if (pfdin && pfdin->psz1 && is_cert_file_name(pfdin->psz1)) {
            FILEBUF* out = create_output_filebuf(pfdin->psz1);
            if (!out) return -1;
            return (INT_PTR)out;
        }
        return 0;

    case fdintCLOSE_FILE_INFO: {
        FILEBUF* out = pfdin ? (FILEBUF*)(INT_PTR)pfdin->hf : NULL;
        if (!out) return FALSE;
        if (is_cert_file_name(out->name)) {
            if (!filelist_push(&g_extracted, out->name, out->data, out->size)) {
                free_filebuf(out);
                free(out);
                return FALSE;
            }
        }
        free_filebuf(out);
        free(out);
        return TRUE;
    }
    case fdintCABINET_INFO:
        return 0;
    case fdintNEXT_CABINET:
        return -1;
    default:
        return 0;
    }
}

BOOL extract_cab_from_memory(const BYTE* cabData, DWORD cabSize) {
    ERF erf;
    HFDI hfdi;
    BOOL ok;

    ZeroMemory(&erf, sizeof(erf));
    g_cab_data = cabData;
    g_cab_size = cabSize;

    hfdi = FDICreate(mem_alloc, mem_free, mem_open, mem_read, mem_write, mem_close, mem_seek, cpuUNKNOWN, &erf);
    if (!hfdi) {
        fprintf(stderr, "FDICreate failed: op=%d type=%d\n", erf.erfOper, erf.erfType);
        return FALSE;
    }

    ok = FDICopy(hfdi, "TrustedTpm.cab", "", 0, fdi_notify, NULL, NULL);
    if (!ok) {
        fprintf(stderr, "FDICopy failed: op=%d type=%d\n", erf.erfOper, erf.erfType);
    }

    FDIDestroy(hfdi);
    return ok;
}

BOOL read_file_to_memory(const wchar_t* filePath, BYTE** outData, DWORD* outSize) {
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD read = 0;
    if (!ReadFile(hFile, buf, size, &read, NULL) || read != size) {
        free(buf);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    *outData = buf;
    *outSize = size;
    return TRUE;
}