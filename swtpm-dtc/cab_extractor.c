#include "tpm.h"

FILELIST g_extracted = { 0 };

static const BYTE* g_cab_data = NULL;
static DWORD g_cab_size = 0;
static DWORD g_total_extracted_files = 0;
static DWORD g_total_extracted_bytes = 0;

static CAB_HANDLE* g_active_handles[MAX_ACTIVE_CAB_HANDLES] = { 0 };

static BOOL track_handle(CAB_HANDLE* h) {
    if (!h) return FALSE;
    for (size_t i = 0; i < MAX_ACTIVE_CAB_HANDLES; i++) {
        if (g_active_handles[i] == NULL) {
            g_active_handles[i] = h;
            return TRUE;
        }
    }
    return FALSE; 
}

static BOOL untrack_handle(CAB_HANDLE* h) {
    if (!h) return FALSE;
    for (size_t i = 0; i < MAX_ACTIVE_CAB_HANDLES; i++) {
        if (g_active_handles[i] == h) {
            g_active_handles[i] = NULL;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL is_active_handle(const CAB_HANDLE* h) {
    if (!h) return FALSE;
    for (size_t i = 0; i < MAX_ACTIVE_CAB_HANDLES; i++) {
        if (g_active_handles[i] == h) {
            return TRUE;
        }
    }
    return FALSE;
}

static __inline BOOL is_valid_handle_ptr(INT_PTR hf) {
    if (hf == 0 || hf == -1) return FALSE;
    return is_active_handle((const CAB_HANDLE*)hf);
}

static void destroy_output_filebuf(FILEBUF* f) {
    if (!f) return;
    if (f->data) {
        if (f->cap > 0) {
            SecureZeroMemory(f->data, f->cap);
        }
        free(f->data);
        f->data = NULL;
    }
    if (f->name) {
        free(f->name);
        f->name = NULL;
    }
    memset(f, 0, sizeof(*f));
    free(f);
}

static BOOL has_path_traversal(const char* name) {
    if (!name || *name == '\0') return TRUE;

    size_t total_len = strnlen(name, 260);
    if (total_len >= 260) return TRUE;

    if (strchr(name, ':') != NULL) return TRUE;

    if (name[0] == '/' || name[0] == '\\') return TRUE;

    if (name[total_len - 1] == '/' || name[total_len - 1] == '\\') return TRUE;

    const char* p = name;
    while (*p != '\0') {
        const char* seg_start = p;
        while (*p != '\0' && *p != '/' && *p != '\\') {
            unsigned char c = (unsigned char)*p;
            if (c < 32 || c == 0x7F || c == '"' || c == '<' || c == '>' ||
                c == '|' || c == '?' || c == '*' || c == 0xC0 || c == 0xC1 || c >= 0xF5) {
                return TRUE;
            }
            p++;
        }

        size_t seg_len = (size_t)(p - seg_start);
        if (seg_len == 0) {
            return TRUE;
        }

        BOOL all_dots = TRUE;
        for (size_t i = 0; i < seg_len; i++) {
            if (seg_start[i] != '.') {
                all_dots = FALSE;
                break;
            }
        }
        if (all_dots) return TRUE;

        if (seg_start[seg_len - 1] == ' ' || seg_start[seg_len - 1] == '.') {
            return TRUE;
        }

        size_t base_len = 0;
        while (base_len < seg_len && seg_start[base_len] != '.') {
            base_len++;
        }
        while (base_len > 0 && seg_start[base_len - 1] == ' ') {
            base_len--;
        }

        if (base_len == 3) {
            if (_strnicmp(seg_start, "CON", 3) == 0 ||
                _strnicmp(seg_start, "PRN", 3) == 0 ||
                _strnicmp(seg_start, "AUX", 3) == 0 ||
                _strnicmp(seg_start, "NUL", 3) == 0) {
                return TRUE;
            }
        }
        else if (base_len == 4) {
            if ((_strnicmp(seg_start, "COM", 3) == 0 || _strnicmp(seg_start, "LPT", 3) == 0) &&
                (seg_start[3] >= '0' && seg_start[3] <= '9')) {
                return TRUE;
            }
        }
        else if (base_len == 6) {
            if (_strnicmp(seg_start, "CONIN$", 6) == 0 ||
                _strnicmp(seg_start, "CLOCK$", 6) == 0) {
                return TRUE;
            }
        }
        else if (base_len == 7) {
            if (_strnicmp(seg_start, "CONOUT$", 7) == 0) {
                return TRUE;
            }
        }

        if (*p == '/' || *p == '\\') {
            p++;
        }
    }

    return FALSE;
}

static int DIAMONDAPI mem_close(INT_PTR hf) {
    if (!is_valid_handle_ptr(hf)) return -1;

    CAB_HANDLE* h = (CAB_HANDLE*)hf;
    untrack_handle(h);

    if (h->magic == CAB_HANDLE_MAGIC) {
        if (h->type == CAB_HANDLE_TYPE_MEMSRC) {
            if (h->u.src) {
                free(h->u.src);
                h->u.src = NULL;
            }
        }
        else if (h->type == CAB_HANDLE_TYPE_FILEBUF) {
            if (h->u.buf) {
                destroy_output_filebuf(h->u.buf);
                h->u.buf = NULL;
            }
        }
    }

    h->magic = 0;
    memset(h, 0, sizeof(*h));
    free(h);
    return 0;
}

static void cleanup_all_active_handles(void) {
    for (size_t i = 0; i < MAX_ACTIVE_CAB_HANDLES; i++) {
        CAB_HANDLE* h = g_active_handles[i];
        if (h) {
            mem_close((INT_PTR)h);
        }
    }
}

static INT_PTR DIAMONDAPI mem_open(char* pszFile, int oflag, int pmode) {
    (void)pmode;
    if (!pszFile || !g_cab_data || g_cab_size == 0) return -1;

    if ((oflag & 0x0003) != _O_RDONLY || (oflag & (_O_CREAT | _O_TRUNC)) != 0) {
        return -1;
    }

    const char* base = basename_a(pszFile);
    if (!base) base = pszFile;

    if (_stricmp(base, "TrustedTpm.cab") == 0) {
        MEMSRC* s = (MEMSRC*)calloc(1, sizeof(MEMSRC));
        if (!s) return -1;

        CAB_HANDLE* h = (CAB_HANDLE*)calloc(1, sizeof(CAB_HANDLE));
        if (!h) {
            free(s);
            return -1;
        }

        s->data = g_cab_data;
        s->size = g_cab_size;
        s->pos = 0;

        h->magic = CAB_HANDLE_MAGIC;
        h->type = CAB_HANDLE_TYPE_MEMSRC;
        h->u.src = s;

        if (!track_handle(h)) {
            free(s);
            free(h);
            return -1;
        }

        return (INT_PTR)h;
    }

    return -1;
}

static UINT DIAMONDAPI mem_read(INT_PTR hf, void* pv, UINT cb) {
    if (!is_valid_handle_ptr(hf) || !pv) return (UINT)-1;
    if (cb == 0) return 0;

    CAB_HANDLE* h = (CAB_HANDLE*)hf;
    if (h->magic != CAB_HANDLE_MAGIC || h->type != CAB_HANDLE_TYPE_MEMSRC || !h->u.src) {
        return (UINT)-1;
    }

    MEMSRC* s = h->u.src;
    if (!s->data) return (UINT)-1;
    if (s->pos >= s->size) return 0;

    UINT remain = s->size - s->pos;
    if (cb > remain) cb = remain;

    memcpy(pv, s->data + s->pos, cb);
    s->pos += cb;
    return cb;
}

static UINT DIAMONDAPI mem_write(INT_PTR hf, void* pv, UINT cb) {
    if (!is_valid_handle_ptr(hf) || !pv) return (UINT)-1;
    if (cb == 0) return 0;

    CAB_HANDLE* h = (CAB_HANDLE*)hf;
    if (h->magic != CAB_HANDLE_MAGIC || h->type != CAB_HANDLE_TYPE_FILEBUF || !h->u.buf) {
        return (UINT)-1;
    }

    FILEBUF* f = h->u.buf;

    if ((UINT64)f->size + (UINT64)cb > MAX_EXTRACTED_FILE_SIZE) {
        return (UINT)-1;
    }

    if ((UINT64)g_total_extracted_bytes + (UINT64)f->size + (UINT64)cb > MAX_EXTRACTED_TOTAL_SIZE) {
        return (UINT)-1;
    }

    DWORD required_cap = f->size + cb;
    if (required_cap > f->cap) {
        DWORD newcap = f->cap ? f->cap : 4096;
        while (newcap < required_cap) {
            if (newcap >= MAX_EXTRACTED_FILE_SIZE / 2 || newcap > ((DWORD)-1) / 2) {
                newcap = required_cap;
                break;
            }
            newcap *= 2;
        }

        if (newcap < required_cap || newcap > MAX_EXTRACTED_FILE_SIZE) {
            newcap = required_cap;
        }

        BYTE* p = (BYTE*)realloc(f->data, newcap);
        if (!p) return (UINT)-1;

        f->data = p;
        f->cap = newcap;
    }

    if (!f->data) return (UINT)-1;

    memcpy(f->data + f->size, pv, cb);
    f->size += cb;
    return cb;
}

static long DIAMONDAPI mem_seek(INT_PTR hf, long dist, int seektype) {
    if (!is_valid_handle_ptr(hf)) return -1;

    CAB_HANDLE* h = (CAB_HANDLE*)hf;
    if (h->magic != CAB_HANDLE_MAGIC || h->type != CAB_HANDLE_TYPE_MEMSRC || !h->u.src) {
        return -1;
    }

    MEMSRC* s = h->u.src;
    if (!s->data) return -1;

    LONG64 newpos = 0;
    switch (seektype) {
    case SEEK_SET:
        newpos = dist;
        break;
    case SEEK_CUR:
        newpos = (LONG64)s->pos + dist;
        break;
    case SEEK_END:
        newpos = (LONG64)s->size + dist;
        break;
    default:
        return -1;
    }

    if (newpos < 0 || (ULONGLONG)newpos > s->size || newpos > 0x7FFFFFFFL) {
        return -1;
    }

    s->pos = (DWORD)newpos;
    return (long)s->pos;
}

static void* DIAMONDAPI mem_alloc(ULONG cb) {
    if (cb == 0) return malloc(1);
    if (cb > 32 * 1024 * 1024) return NULL;
    return malloc(cb);
}

static void DIAMONDAPI mem_free(void* pv) {
    if (pv) {
        free(pv);
    }
}

static FILEBUF* create_output_filebuf(const char* name, DWORD expected_size) {
    FILEBUF* f = (FILEBUF*)calloc(1, sizeof(FILEBUF));
    if (!f) return NULL;

    f->name = _strdup(name ? name : "");
    if (!f->name) {
        free(f);
        return NULL;
    }

    DWORD initial_cap = 4096;
    if (expected_size > initial_cap) {
        DWORD remaining_budget = (g_total_extracted_bytes < MAX_EXTRACTED_TOTAL_SIZE) ?
            (MAX_EXTRACTED_TOTAL_SIZE - g_total_extracted_bytes) : 0;
        DWORD max_allowed = (MAX_EXTRACTED_FILE_SIZE < remaining_budget) ?
            MAX_EXTRACTED_FILE_SIZE : remaining_budget;
        DWORD initial_ceiling = (max_allowed < 65536) ? max_allowed : 65536;

        initial_cap = (expected_size < initial_ceiling) ? expected_size : initial_ceiling;
        if (initial_cap < 4096 && max_allowed >= 4096) {
            initial_cap = 4096;
        }
    }

    f->cap = initial_cap ? initial_cap : 4096;
    f->data = (BYTE*)malloc(f->cap);
    if (!f->data) {
        free(f->name);
        free(f);
        return NULL;
    }
    f->size = 0;
    return f;
}

static INT_PTR DIAMONDAPI fdi_notify(FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin) {
    if (!pfdin) return -1;

    switch (fdint) {
    case fdintCOPY_FILE: {
        if (has_path_traversal(pfdin->psz1)) {
            return 0; 
        }

        if (!is_cert_file_name(pfdin->psz1)) {
            return 0; 
        }

        if (pfdin->cb <= 0 || (DWORD)pfdin->cb > MAX_EXTRACTED_FILE_SIZE) {
            return 0;
        }

        if (g_total_extracted_files >= MAX_EXTRACTED_TOTAL_FILES) {
            return -1;
        }

        if (g_total_extracted_bytes >= MAX_EXTRACTED_TOTAL_SIZE ||
            (UINT64)g_total_extracted_bytes + (DWORD)pfdin->cb > MAX_EXTRACTED_TOTAL_SIZE) {
            return -1;
        }

        FILEBUF* out = create_output_filebuf(pfdin->psz1, (DWORD)pfdin->cb);
        if (!out) return -1;

        CAB_HANDLE* h = (CAB_HANDLE*)calloc(1, sizeof(CAB_HANDLE));
        if (!h) {
            destroy_output_filebuf(out);
            return -1;
        }

        h->magic = CAB_HANDLE_MAGIC;
        h->type = CAB_HANDLE_TYPE_FILEBUF;
        h->u.buf = out;

        if (!track_handle(h)) {
            destroy_output_filebuf(out);
            free(h);
            return -1;
        }

        return (INT_PTR)h;
    }

    case fdintCLOSE_FILE_INFO: {
        if (!is_valid_handle_ptr(pfdin->hf)) return -1;

        CAB_HANDLE* h = (CAB_HANDLE*)pfdin->hf;
        if (h->magic != CAB_HANDLE_MAGIC || h->type != CAB_HANDLE_TYPE_FILEBUF || !h->u.buf) {
            mem_close(pfdin->hf);
            return -1;
        }

        FILEBUF* out = h->u.buf;
        BOOL push_ok = TRUE;

        FILELIST* list_dst = pfdin->pv ? (FILELIST*)pfdin->pv : &g_extracted;

        if (out->name && is_cert_file_name(out->name) && out->data && out->size > 0) {
            if (!filelist_push(list_dst, out->name, out->data, out->size)) {
                push_ok = FALSE;
            }
            else {
                g_total_extracted_files++;
                g_total_extracted_bytes += out->size;
            }
        }
        else {
            push_ok = FALSE;
        }

        mem_close(pfdin->hf);

        return push_ok ? TRUE : -1;
    }

    case fdintCABINET_INFO:
        return 0;

    case fdintNEXT_CABINET:
        return -1;

    case fdintPARTIAL_FILE:
        return 0;

    default:
        return 0;
    }
}

BOOL extract_cab_from_memory(const BYTE* cabData, DWORD cabSize) {
    ERF erf;
    HFDI hfdi = NULL;
    BOOL ok = FALSE;

    if (!cabData || cabSize < 36 || cabSize > 0x7FFFFFFFL) {
        return FALSE;
    }

    if (memcmp(cabData, "MSCF", 4) != 0) {
        return FALSE;
    }

    cleanup_all_active_handles();

    ZeroMemory(&erf, sizeof(erf));
    g_cab_data = cabData;
    g_cab_size = cabSize;
    g_total_extracted_files = 0;
    g_total_extracted_bytes = 0;

    char szCabName[CB_MAX_CAB_PATH] = "TrustedTpm.cab";
    char szCabPath[CB_MAX_CAB_PATH] = "";

    hfdi = FDICreate(mem_alloc, mem_free, mem_open, mem_read, mem_write, mem_close, mem_seek, cpuUNKNOWN, &erf);
    if (hfdi) {
        ok = FDICopy(hfdi, szCabName, szCabPath, 0, fdi_notify, NULL, &g_extracted);
        FDIDestroy(hfdi);
    }

    cleanup_all_active_handles();

    g_cab_data = NULL;
    g_cab_size = 0;
    g_total_extracted_files = 0;
    g_total_extracted_bytes = 0;

    return ok;
}