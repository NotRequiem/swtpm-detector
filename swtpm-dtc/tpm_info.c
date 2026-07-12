#include "tpm_verify.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <strsafe.h>
#include <tbs.h>
#include <time.h>

#pragma comment(lib, "tbs.lib")

#define TPM_ST_NO_SESSIONS         0x8001
#define TPM_ST_SESSIONS            0x8002
#define TPM_RS_PW                  0x40000009
#define TPM_RH_OWNER               0x40000001
#define TPM_RH_ENDORSEMENT         0x4000000B
#define TPM_RH_NULL                0x40000007

#define TPM_CC_CreatePrimary       0x00000131
#define TPM_CC_PolicySecret        0x00000151
#define TPM_CC_ActivateCredential  0x00000147
#define TPM_CC_MakeCredential      0x00000168
#define TPM_CC_StartAuthSession    0x00000176
#define TPM_CC_FlushContext        0x00000165
#define TPM_CC_ReadPublic          0x00000173
#define TPM_CC_GetCapability       0x0000017A
#define TPM_CC_NV_ReadPublic       0x00000169
#define TPM_CC_NV_Read             0x0000014E

#define TPM_ALG_RSA                0x0001
#define TPM_ALG_SHA256             0x000B
#define TPM_ALG_NULL               0x0010
#define TPM_ALG_RSASSA             0x0014
#define TPM_ALG_ECC                0x0023

#define TPM_SE_POLICY              0x01

#ifndef NCRYPT_PCP_TPM_VERSION_PROPERTY
#define NCRYPT_PCP_TPM_VERSION_PROPERTY L"PCP_TPM_VERSION"
#endif

#ifndef NCRYPT_PCP_TPM_MANUFACTURER_ID_PROPERTY
#define NCRYPT_PCP_TPM_MANUFACTURER_ID_PROPERTY L"PCP_TPM_MANUFACTURER_ID"
#endif

#ifndef NCRYPT_PCP_TPM_FW_VERSION_PROPERTY
#define NCRYPT_PCP_TPM_FW_VERSION_PROPERTY L"PCP_TPM_FW_VERSION"
#endif

typedef struct {
    BYTE* buf;
    UINT32 capacity;
    UINT32 write_pos;
} buf_builder;

typedef struct {
    const BYTE* buf;
    UINT32 size;
    UINT32 read_pos;
} buf_parser;

static void init_builder(buf_builder* b, BYTE* buf, UINT32 cap) {
    b->buf = buf;
    b->capacity = cap;
    b->write_pos = 0;
}

static void write_8(buf_builder* b, BYTE val) {
    if (b->write_pos < b->capacity) b->buf[b->write_pos++] = val;
}

static void write_16(buf_builder* b, UINT16 val) {
    if (b->write_pos + 2 <= b->capacity) {
        b->buf[b->write_pos++] = (val >> 8) & 0xFF;
        b->buf[b->write_pos++] = val & 0xFF;
    }
}

static void write_32(buf_builder* b, UINT32 val) {
    if (b->write_pos + 4 <= b->capacity) {
        b->buf[b->write_pos++] = (val >> 24) & 0xFF;
        b->buf[b->write_pos++] = (val >> 16) & 0xFF;
        b->buf[b->write_pos++] = (val >> 8) & 0xFF;
        b->buf[b->write_pos++] = val & 0xFF;
    }
}

static void write_buf(buf_builder* b, const BYTE* src, UINT32 len) {
    if (b->write_pos + len <= b->capacity) {
        memcpy(b->buf + b->write_pos, src, len);
        b->write_pos += len;
    }
}

static void write_2b(buf_builder* b, const BYTE* src, UINT16 len) {
    write_16(b, len);
    write_buf(b, src, len);
}

static void patch_32(BYTE* buf, UINT32 offset, UINT32 val) {
    buf[offset] = (val >> 24) & 0xFF;
    buf[offset + 1] = (val >> 16) & 0xFF;
    buf[offset + 2] = (val >> 8) & 0xFF;
    buf[offset + 3] = val & 0xFF;
}

static void init_parser(buf_parser* p, const BYTE* buf, UINT32 size) {
    p->buf = buf;
    p->size = size;
    p->read_pos = 0;
}

static BYTE read_8(buf_parser* p) {
    if (p->read_pos < p->size) return p->buf[p->read_pos++];
    return 0;
}

static UINT16 read_16(buf_parser* p) {
    if (p->read_pos + 2 <= p->size) {
        UINT16 val = (p->buf[p->read_pos] << 8) | p->buf[p->read_pos + 1];
        p->read_pos += 2;
        return val;
    }
    return 0;
}

static UINT32 read_32(buf_parser* p) {
    if (p->read_pos + 4 <= p->size) {
        UINT32 val = ((UINT32)p->buf[p->read_pos] << 24) |
            ((UINT32)p->buf[p->read_pos + 1] << 16) |
            ((UINT32)p->buf[p->read_pos + 2] << 8) |
            ((UINT32)p->buf[p->read_pos + 3]);
        p->read_pos += 4;
        return val;
    }
    return 0;
}

static void read_buf(buf_parser* p, BYTE* dst, UINT32 len) {
    if (p->read_pos + len <= p->size) {
        memcpy(dst, p->buf + p->read_pos, len);
        p->read_pos += len;
    }
}

static UINT16 read_2b(buf_parser* p, BYTE* dst, UINT16 max_len) {
    UINT16 len = read_16(p);
    if (len > max_len || p->read_pos + len > p->size) return 0;
    read_buf(p, dst, len);
    return len;
}

static void generate_stack_random(BYTE* out_buf, UINT32 len) {
    ULONG_PTR stack_addr = (ULONG_PTR)&stack_addr;
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    UINT64 seed = (UINT64)stack_addr ^ (UINT64)qpc.QuadPart;
    for (UINT32 i = 0; i < len; i++) {
        seed ^= (seed << 13);
        seed ^= (seed >> 7);
        seed ^= (seed << 17);
        out_buf[i] = (BYTE)(seed & 0xFF);
    }
}

static BOOL send_tpm_command(TBS_HCONTEXT h_tbs_context, const BYTE* cmd_buf, UINT32 cmd_size, BYTE* resp_buf, UINT32* resp_size) {
    TBS_RESULT hr = Tbsip_Submit_Command(
        h_tbs_context,
        TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL,
        cmd_buf,
        cmd_size,
        resp_buf,
        resp_size
    );
    if (hr != TBS_SUCCESS) {
        printf("[!] TBS Submit failed: 0x%08X\n", hr);
        return FALSE;
    }
    return TRUE;
}

static BOOL tpm_read_public(TBS_HCONTEXT h_tbs_context, UINT32 handle, BYTE* out_name, UINT16* out_name_size) {
    BYTE cmd[128];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_NO_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_ReadPublic);
    write_32(&b, handle);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[4096];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    UINT32 rc = read_32(&p);
    if (rc != 0) {
        printf("[!] ReadPublic failed on handle 0x%08X with RC: 0x%08X\n", handle, rc);
        return FALSE;
    }

    UINT16 out_public_size = read_16(&p);
    p.read_pos += out_public_size;

    *out_name_size = read_2b(&p, out_name, 128);
    return (*out_name_size > 0);
}

static BOOL tpm_read_public_area(TBS_HCONTEXT h_tbs_context, UINT32 handle, BYTE** out_public, DWORD* out_public_size) {
    if (!out_public || !out_public_size) return FALSE;
    *out_public = NULL;
    *out_public_size = 0;

    BYTE cmd[128];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_NO_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_ReadPublic);
    write_32(&b, handle);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[4096];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p);
    read_32(&p);
    UINT32 rc = read_32(&p);
    if (rc != 0) {
        return FALSE;
    }

    UINT32 public_area_start_offset = p.read_pos;
    UINT16 public_size = read_16(&p);
    if (public_size == 0 || p.read_pos + public_size > resp_size) {
        return FALSE;
    }

    DWORD total_tpm2b_public_size = 2 + public_size;
    BYTE* buf = (BYTE*)malloc(total_tpm2b_public_size);
    if (!buf) return FALSE;

    memcpy(buf, resp + public_area_start_offset, total_tpm2b_public_size);
    *out_public = buf;
    *out_public_size = total_tpm2b_public_size;
    return TRUE;
}

static BOOL parse_tpm2b_public_rsa(const BYTE* tpm2b, DWORD tpm2b_size, UINT32* out_exponent, BYTE** out_modulus, UINT16* out_modulus_size) {
    if (!tpm2b || tpm2b_size < 12) return FALSE;

    buf_parser p;
    init_parser(&p, tpm2b, tpm2b_size);

    UINT16 size = read_16(&p);
    if (size == 0 || p.read_pos + size > tpm2b_size) return FALSE;

    UINT16 type = read_16(&p);
    if (type != TPM_ALG_RSA) return FALSE;

    read_16(&p);
    read_32(&p);

    UINT16 auth_policy_size = read_16(&p);
    p.read_pos += auth_policy_size;

    UINT16 sym_alg = read_16(&p);
    if (sym_alg != 0x0010) {
        read_16(&p);
        read_16(&p);
    }

    UINT16 scheme_alg = read_16(&p);
    if (scheme_alg != 0x0010) {
        read_16(&p);
    }

    UINT16 key_bits = read_16(&p);
    UINT32 exponent = read_32(&p);
    if (exponent == 0) {
        exponent = 65537;
    }

    UINT16 modulus_size = read_16(&p);
    if (modulus_size == 0 || p.read_pos + modulus_size > tpm2b_size) return FALSE;

    BYTE* modulus = (BYTE*)malloc(modulus_size);
    if (!modulus) return FALSE;

    read_buf(&p, modulus, modulus_size);

    *out_exponent = exponent;
    *out_modulus = modulus;
    *out_modulus_size = modulus_size;
    return TRUE;
}

static BOOL parse_tpm2b_public_ecc(const BYTE* tpm2b, DWORD tpm2b_size, UINT16* out_curve_id, BYTE** out_x, UINT16* out_x_size, BYTE** out_y, UINT16* out_y_size) {
    if (!tpm2b || tpm2b_size < 12) return FALSE;

    buf_parser p;
    init_parser(&p, tpm2b, tpm2b_size);

    UINT16 size = read_16(&p);
    if (size == 0 || p.read_pos + size > tpm2b_size) return FALSE;

    UINT16 type = read_16(&p);
    if (type != TPM_ALG_ECC) return FALSE;

    read_16(&p);
    read_32(&p);

    UINT16 auth_policy_size = read_16(&p);
    p.read_pos += auth_policy_size;

    UINT16 sym_alg = read_16(&p);
    if (sym_alg != 0x0010) {
        read_16(&p);
        read_16(&p);
    }

    UINT16 scheme_alg = read_16(&p);
    if (scheme_alg != 0x0010) {
        read_16(&p);
    }

    UINT16 curve_id = read_16(&p);

    UINT16 kdf_alg = read_16(&p);
    if (kdf_alg != 0x0010) {
        read_16(&p);
    }

    UINT16 x_size = read_16(&p);
    if (x_size == 0 || p.read_pos + x_size > tpm2b_size) return FALSE;
    BYTE* x = (BYTE*)malloc(x_size);
    if (!x) return FALSE;
    read_buf(&p, x, x_size);

    UINT16 y_size = read_16(&p);
    if (y_size == 0 || p.read_pos + y_size > tpm2b_size) {
        free(x);
        return FALSE;
    }
    BYTE* y = (BYTE*)malloc(y_size);
    if (!y) {
        free(x);
        return FALSE;
    }
    read_buf(&p, y, y_size);

    *out_curve_id = curve_id;
    *out_x = x;
    *out_x_size = x_size;
    *out_y = y;
    *out_y_size = y_size;
    return TRUE;
}

static BYTE* rsa_to_bcrypt_blob(UINT32 exponent, const BYTE* modulus, UINT16 modulus_size, DWORD* out_blob_size) {
    BYTE exp_bytes[4];
    exp_bytes[0] = (exponent >> 24) & 0xFF;
    exp_bytes[1] = (exponent >> 16) & 0xFF;
    exp_bytes[2] = (exponent >> 8) & 0xFF;
    exp_bytes[3] = exponent & 0xFF;

    DWORD exp_start = 0;
    while (exp_start < 3 && exp_bytes[exp_start] == 0) {
        exp_start++;
    }
    DWORD exp_len = 4 - exp_start;

    DWORD total_size = sizeof(BCRYPT_RSAKEY_BLOB) + exp_len + modulus_size;
    BYTE* blob = (BYTE*)malloc(total_size);
    if (!blob) return NULL;

    BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)blob;
    header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    header->BitLength = modulus_size * 8;
    header->cbPublicExp = exp_len;
    header->cbModulus = modulus_size;
    header->cbPrime1 = 0;
    header->cbPrime2 = 0;

    BYTE* dest = blob + sizeof(BCRYPT_RSAKEY_BLOB);
    memcpy(dest, exp_bytes + exp_start, exp_len);
    dest += exp_len;
    memcpy(dest, modulus, modulus_size);

    *out_blob_size = total_size;
    return blob;
}

static BYTE* ecc_to_bcrypt_blob(UINT16 curve_id, const BYTE* x, UINT16 x_size, const BYTE* y, UINT16 y_size, DWORD* out_blob_size) {
    DWORD magic = 0;
    if (curve_id == 0x0003) {
        magic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    }
    else if (curve_id == 0x0004) {
        magic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
    }
    else {
        return NULL;
    }

    DWORD total_size = sizeof(BCRYPT_ECCKEY_BLOB) + x_size + y_size;
    BYTE* blob = (BYTE*)malloc(total_size);
    if (!blob) return NULL;

    BCRYPT_ECCKEY_BLOB* header = (BCRYPT_ECCKEY_BLOB*)blob;
    header->dwMagic = magic;
    header->cbKey = x_size;

    BYTE* dest = blob + sizeof(BCRYPT_ECCKEY_BLOB);
    memcpy(dest, x, x_size);
    dest += x_size;
    memcpy(dest, y, y_size);

    *out_blob_size = total_size;
    return blob;
}

static BYTE* tpm_public_to_bcrypt_blob(const BYTE* tpm2b, DWORD tpm2b_size, DWORD* out_blob_size) {
    if (!tpm2b || tpm2b_size < 6) return NULL;

    UINT16 type = (tpm2b[2] << 8) | tpm2b[3];
    if (type == TPM_ALG_RSA) {
        UINT32 exponent = 0;
        BYTE* modulus = NULL;
        UINT16 modulus_size = 0;
        if (parse_tpm2b_public_rsa(tpm2b, tpm2b_size, &exponent, &modulus, &modulus_size)) {
            BYTE* blob = rsa_to_bcrypt_blob(exponent, modulus, modulus_size, out_blob_size);
            free(modulus);
            return blob;
        }
    }
    else if (type == TPM_ALG_ECC) {
        UINT16 curve_id = 0;
        BYTE* x = NULL;
        UINT16 x_size = 0;
        BYTE* y = NULL;
        UINT16 y_size = 0;
        if (parse_tpm2b_public_ecc(tpm2b, tpm2b_size, &curve_id, &x, &x_size, &y, &y_size)) {
            BYTE* blob = ecc_to_bcrypt_blob(curve_id, x, x_size, y, y_size, out_blob_size);
            free(x);
            free(y);
            return blob;
        }
    }
    return NULL;
}

static BOOL tpm_nv_read_public(TBS_HCONTEXT h_tbs_context, UINT32 nv_index, UINT16* out_data_size) {
    BYTE cmd[128];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_NO_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_NV_ReadPublic);
    write_32(&b, nv_index);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[4096];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p);
    read_32(&p);
    UINT32 rc = read_32(&p);
    if (rc != 0) {
        return FALSE;
    }

    UINT16 total_nv_pub_size = read_16(&p);
    if (total_nv_pub_size == 0) return FALSE;

    read_32(&p);
    read_16(&p);
    read_32(&p);

    UINT16 auth_policy_size = read_16(&p);
    p.read_pos += auth_policy_size;

    *out_data_size = read_16(&p);
    return TRUE;
}

static BOOL tpm_nv_read(TBS_HCONTEXT h_tbs_context, UINT32 auth_handle, UINT32 nv_index, UINT16 size, UINT16 offset, BYTE* out_data, UINT16* out_size) {
    BYTE cmd[256];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_NV_Read);
    write_32(&b, auth_handle);
    write_32(&b, nv_index);

    write_32(&b, 9);
    write_32(&b, TPM_RS_PW);
    write_16(&b, 0);
    write_8(&b, 0);
    write_16(&b, 0);

    write_16(&b, size);
    write_16(&b, offset);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[2048];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    UINT16 tag = read_16(&p);
    read_32(&p);
    UINT32 rc = read_32(&p);
    if (rc != 0) {
        return FALSE;
    }

    if (tag == TPM_ST_SESSIONS) {
        read_32(&p);
    }

    *out_size = read_2b(&p, out_data, size);
    return (*out_size > 0);
}

static BYTE* tpm_read_full_nv_index(TBS_HCONTEXT h_tbs_context, UINT32 auth_handle, UINT32 nv_index, DWORD* out_total_size) {
    UINT16 data_size = 0;
    if (!tpm_nv_read_public(h_tbs_context, nv_index, &data_size)) {
        return NULL;
    }
    if (data_size == 0 || data_size > 8192) {
        return NULL;
    }

    BYTE* cert_buf = (BYTE*)malloc(data_size);
    if (!cert_buf) return NULL;

    UINT16 bytes_read = 0;
    UINT16 chunk_size = 256;

    while (bytes_read < data_size) {
        UINT16 to_read = data_size - bytes_read;
        if (to_read > chunk_size) {
            to_read = chunk_size;
        }

        BYTE chunk[256];
        UINT16 read_len = 0;
        if (!tpm_nv_read(h_tbs_context, auth_handle, nv_index, to_read, bytes_read, chunk, &read_len)) {
            if (auth_handle == TPM_RH_OWNER) {
                if (tpm_nv_read(h_tbs_context, TPM_RH_ENDORSEMENT, nv_index, to_read, bytes_read, chunk, &read_len)) {
                    goto chunk_ok;
                }
            }
            free(cert_buf);
            return NULL;
        }

    chunk_ok:
        if (read_len == 0) {
            free(cert_buf);
            return NULL;
        }
        memcpy(cert_buf + bytes_read, chunk, read_len);
        bytes_read += read_len;
    }

    *out_total_size = data_size;
    return cert_buf;
}

BOOL get_ek_cert_store_directly(HCERTSTORE* out_store) {
    if (!out_store) return FALSE;
    *out_store = NULL;

    HCERTSTORE h_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!h_store) return FALSE;

    TBS_CONTEXT_PARAMS2 params;
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm12 = 0;
    params.includeTpm20 = 1;
    TBS_HCONTEXT h_tbs_context = 0;

    TBS_RESULT tr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &h_tbs_context);
    if (tr != TBS_SUCCESS) {
        CertCloseStore(h_store, 0);
        return FALSE;
    }

    UINT32 indices[] = { 0x01c00002, 0x01c0000a };
    BOOL found = FALSE;

    for (int i = 0; i < 2; i++) {
        DWORD cert_size = 0;
        BYTE* cert_bytes = tpm_read_full_nv_index(h_tbs_context, TPM_RH_OWNER, indices[i], &cert_size);
        if (!cert_bytes) {
            cert_bytes = tpm_read_full_nv_index(h_tbs_context, TPM_RH_ENDORSEMENT, indices[i], &cert_size);
        }

        if (cert_bytes) {
            PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_bytes, cert_size);
            if (ctx) {
                if (CertAddCertificateContextToStore(h_store, ctx, CERT_STORE_ADD_ALWAYS, NULL)) {
                    found = TRUE;
                }
                CertFreeCertificateContext(ctx);
            }
            free(cert_bytes);
        }
    }

    Tbsip_Context_Close(h_tbs_context);

    if (!found) {
        CertCloseStore(h_store, 0);
        return FALSE;
    }

    *out_store = h_store;
    return TRUE;
}

static BOOL tpm_create_primary_ak(TBS_HCONTEXT h_tbs_context, UINT32* out_ak_handle) {
    BYTE in_public[128];
    buf_builder pb;
    init_builder(&pb, in_public, sizeof(in_public));
    write_16(&pb, TPM_ALG_RSA);
    write_16(&pb, TPM_ALG_SHA256);
    write_32(&pb, 0x00050072);
    write_16(&pb, 0);
    write_16(&pb, TPM_ALG_NULL);
    write_16(&pb, TPM_ALG_RSASSA);
    write_16(&pb, TPM_ALG_SHA256);
    write_16(&pb, 2048);
    write_32(&pb, 0);
    write_16(&pb, 0);
    UINT16 in_public_size = (UINT16)pb.write_pos;

    BYTE cmd[1024];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));
    write_16(&b, TPM_ST_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_CreatePrimary);
    write_32(&b, TPM_RH_OWNER);

    write_32(&b, 9);
    write_32(&b, TPM_RS_PW);
    write_16(&b, 0);
    write_8(&b, 0);
    write_16(&b, 0);

    write_16(&b, 4);
    write_16(&b, 0);
    write_16(&b, 0);

    write_16(&b, in_public_size);
    write_buf(&b, in_public, in_public_size);
    write_16(&b, 0);
    write_32(&b, 0);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[4096];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    UINT32 rc = read_32(&p);
    if (rc != 0) {
        printf("[!] CreatePrimary (AK) failed with RC: 0x%08X\n", rc);
        return FALSE;
    }

    *out_ak_handle = read_32(&p);
    return TRUE;
}

static BOOL tpm_start_auth_session(TBS_HCONTEXT h_tbs_context, UINT32* out_session_handle) {
    BYTE cmd[256];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_NO_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_StartAuthSession);
    write_32(&b, TPM_RH_NULL);
    write_32(&b, TPM_RH_NULL);

    BYTE dummy_nonce[20] = { 0 };
    write_2b(&b, dummy_nonce, 20);
    write_16(&b, 0);
    write_8(&b, TPM_SE_POLICY);
    write_16(&b, TPM_ALG_NULL);
    write_16(&b, TPM_ALG_SHA256);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[512];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    UINT32 rc = read_32(&p);
    if (rc != 0) {
        printf("[!] StartAuthSession failed with RC: 0x%08X\n", rc);
        return FALSE;
    }

    *out_session_handle = read_32(&p);
    return TRUE;
}

static BOOL tpm_policy_secret(TBS_HCONTEXT h_tbs_context, UINT32 session_handle) {
    BYTE cmd[256];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_PolicySecret);
    write_32(&b, TPM_RH_ENDORSEMENT);
    write_32(&b, session_handle);

    write_32(&b, 9);
    write_32(&b, TPM_RS_PW);
    write_16(&b, 0);
    write_8(&b, 0);
    write_16(&b, 0);

    write_16(&b, 0);
    write_16(&b, 0);
    write_16(&b, 0);
    write_32(&b, 0);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[512];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    UINT32 rc = read_32(&p);
    if (rc != 0) {
        printf("[!] PolicySecret failed with RC: 0x%08X\n", rc);
        return FALSE;
    }
    return TRUE;
}

static BOOL tpm_make_credential(TBS_HCONTEXT h_tbs_context, UINT32 ek_handle, const BYTE* challenge, UINT16 challenge_size,
    const BYTE* ak_name, UINT16 ak_name_size,
    BYTE* out_blob, UINT16* out_blob_size,
    BYTE* out_secret, UINT16* out_secret_size) {
    BYTE cmd[2048];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_NO_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_MakeCredential);
    write_32(&b, ek_handle);

    write_2b(&b, challenge, challenge_size);
    write_2b(&b, ak_name, ak_name_size);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[4096];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    UINT32 rc = read_32(&p);
    if (rc != 0) {
        printf("[!] MakeCredential failed with RC: 0x%08X\n", rc);
        return FALSE;
    }

    *out_blob_size = read_2b(&p, out_blob, 1024);
    *out_secret_size = read_2b(&p, out_secret, 1024);
    return (*out_blob_size > 0 && *out_secret_size > 0);
}

static BOOL tpm_activate_credential(TBS_HCONTEXT h_tbs_context, UINT32 ak_handle, UINT32 ek_handle, UINT32 policy_session_handle,
    const BYTE* blob, UINT16 blob_size,
    const BYTE* secret, UINT16 secret_size,
    BYTE* out_decrypted, UINT16* out_decrypted_size) {
    BYTE cmd[4096];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_ActivateCredential);
    write_32(&b, ak_handle);
    write_32(&b, ek_handle);

    write_32(&b, 18);

    write_32(&b, TPM_RS_PW);
    write_16(&b, 0);
    write_8(&b, 0);
    write_16(&b, 0);

    write_32(&b, policy_session_handle);
    write_16(&b, 0);
    write_8(&b, 0);
    write_16(&b, 0);

    write_2b(&b, blob, blob_size);
    write_2b(&b, secret, secret_size);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[2048];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    UINT16 tag = read_16(&p);
    read_32(&p);
    UINT32 rc = read_32(&p);
    if (rc != 0) {
        printf("[!] ActivateCredential failed with RC: 0x%08X\n", rc);
        return FALSE;
    }

    if (tag == TPM_ST_SESSIONS) {
        read_32(&p);
    }

    *out_decrypted_size = read_2b(&p, out_decrypted, 128);
    return (*out_decrypted_size > 0);
}

static void tpm_flush_context(TBS_HCONTEXT h_tbs_context, UINT32 handle) {
    BYTE cmd[64];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_NO_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_FlushContext);
    write_32(&b, handle);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[64];
    UINT32 resp_size = sizeof(resp);
    send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size);
}

static BOOL tpm_enumerate_persistent_handles(TBS_HCONTEXT h_tbs_context, UINT32* out_handles, UINT32* out_count) {
    BYTE cmd[128];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_NO_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_GetCapability);
    write_32(&b, 0x00000001);
    write_32(&b, 0x81000000);
    write_32(&b, 64);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[4096];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    UINT32 rc = read_32(&p);
    if (rc != 0) return FALSE;

    read_8(&p);
    UINT32 returned_cap = read_32(&p);
    if (returned_cap != 0x00000001) return FALSE;

    UINT32 count = read_32(&p);
    if (count > 64) count = 64;
    *out_count = count;

    for (UINT32 i = 0; i < count; i++) {
        out_handles[i] = read_32(&p);
    }
    return TRUE;
}

static BOOL execute_possession_challenge(TBS_HCONTEXT h_tbs_context, UINT32 ek_handle, UINT32 ak_handle) {
    BYTE ek_name[128];
    UINT16 ek_name_size = 0;
    BYTE ak_name[128];
    UINT16 ak_name_size = 0;

    if (!tpm_read_public(h_tbs_context, ek_handle, ek_name, &ek_name_size)) return FALSE;
    if (!tpm_read_public(h_tbs_context, ak_handle, ak_name, &ak_name_size)) return FALSE;

    printf("[*] Initiating Auth Policy Session...\n");
    UINT32 policy_session = 0;
    if (!tpm_start_auth_session(h_tbs_context, &policy_session)) return FALSE;

    printf("[*] Satisfying EK policy context...\n");
    if (!tpm_policy_secret(h_tbs_context, policy_session)) {
        tpm_flush_context(h_tbs_context, policy_session);
        return FALSE;
    }

    BYTE challenge[16];
    generate_stack_random(challenge, 16);
    printf("[*] Formulating challenge payload: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X", challenge[i]);
    }
    printf("\n");

    printf("[*] Wrapping challenge payload (MakeCredential)...\n");
    BYTE blob[1024];
    UINT16 blob_size = 0;
    BYTE secret[1024];
    UINT16 secret_size = 0;
    if (!tpm_make_credential(h_tbs_context, ek_handle, challenge, 16, ak_name, ak_name_size, blob, &blob_size, secret, &secret_size)) {
        tpm_flush_context(h_tbs_context, policy_session);
        return FALSE;
    }

    printf("[*] Requesting decryption validation (ActivateCredential)...\n");
    BYTE decrypted_challenge[128];
    UINT16 decrypted_size = 0;
    BOOL validated = tpm_activate_credential(h_tbs_context, ak_handle, ek_handle, policy_session, blob, blob_size, secret, secret_size, decrypted_challenge, &decrypted_size);

    tpm_flush_context(h_tbs_context, policy_session);

    if (validated && decrypted_size == 16 && memcmp(challenge, decrypted_challenge, 16) == 0) {
        printf("[+] Success: Returned bytes match the challenge.\n");
        return TRUE;
    }
    printf("[-] Decrypted credential mismatch.\n");
    return FALSE;
}

BOOL perform_local_tpm_pop_challenge(PCCERT_CONTEXT ek_cert) {
    if (!ek_cert) {
        printf("[!] Error: No validated EK certificate provided for challenge binding.\n");
        return FALSE;
    }

    TBS_CONTEXT_PARAMS2 params;
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm12 = 0;
    params.includeTpm20 = 1;
    TBS_HCONTEXT h_tbs_context = 0;

    printf("[*] Connecting to TPM...\n");
    TBS_RESULT tr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &h_tbs_context);
    if (tr != TBS_SUCCESS) {
        printf("[!] TBS connection failed: 0x%08X\n", tr);
        return FALSE;
    }
    printf("[+] TBS connected.\n");

    UINT32 handles[64] = { 0 };
    UINT32 handle_count = 0;
    UINT32 preinstalled_ek_handle = 0;

    if (tpm_enumerate_persistent_handles(h_tbs_context, handles, &handle_count)) {
        for (UINT32 i = 0; i < handle_count; i++) {
            if (handles[i] >= 0x81010000 && handles[i] <= 0x810100FF) {
                BYTE* ek_pub_tpm2b = NULL;
                DWORD ek_pub_tpm2b_size = 0;
                if (tpm_read_public_area(h_tbs_context, handles[i], &ek_pub_tpm2b, &ek_pub_tpm2b_size)) {
                    DWORD bcrypt_blob_size = 0;
                    BYTE* bcrypt_blob = tpm_public_to_bcrypt_blob(ek_pub_tpm2b, ek_pub_tpm2b_size, &bcrypt_blob_size);
                    if (bcrypt_blob) {
                        if (ekpub_matches_cert(ek_cert, bcrypt_blob, bcrypt_blob_size)) {
                            preinstalled_ek_handle = handles[i];
                            free(bcrypt_blob);
                            free(ek_pub_tpm2b);
                            break;
                        }
                        free(bcrypt_blob);
                    }
                    free(ek_pub_tpm2b);
                }
            }
        }
    }

    if (preinstalled_ek_handle == 0) {
        printf("[!] Error: No persistent EK handle matching the validated EK certificate was found. The TPM is not trusted.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }
    printf("[+] Target EK handle located: 0x%08X\n", preinstalled_ek_handle);

    printf("[*] Loading transient AK into your TPM under Owner hierarchy...\n");
    UINT32 ak_handle = 0;
    if (!tpm_create_primary_ak(h_tbs_context, &ak_handle)) {
        printf("[!] Failed to load transient AK.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }
    printf("[+] Transient AK loaded: 0x%08X\n", ak_handle);

    BOOL path_success = execute_possession_challenge(h_tbs_context, preinstalled_ek_handle, ak_handle);

    tpm_flush_context(h_tbs_context, ak_handle);
    Tbsip_Context_Close(h_tbs_context);

    return path_success;
}

BOOL read_ncrypt_property_bytes(NCRYPT_PROV_HANDLE h_prov, LPCWSTR prop, BYTE** out_buf, DWORD* out_size) {
    DWORD size = 0;
    SECURITY_STATUS s;
    BYTE* buf;

    if (!out_buf || !out_size) return FALSE;
    *out_buf = NULL;
    *out_size = 0;

    s = NCryptGetProperty(h_prov, prop, NULL, 0, &size, 0);
    if (s != ERROR_SUCCESS && s != NTE_BUFFER_TOO_SMALL) {
        return FALSE;
    }

    buf = (BYTE*)malloc(size ? size : 1);
    if (!buf) return FALSE;

    s = NCryptGetProperty(h_prov, prop, buf, size, &size, 0);
    if (s != ERROR_SUCCESS) {
        free(buf);
        return FALSE;
    }

    *out_buf = buf;
    *out_size = size;
    return TRUE;
}

BOOL read_ncrypt_property_string(NCRYPT_PROV_HANDLE h_prov, LPCWSTR prop, char* out, size_t out_chars) {
    DWORD size = 0;
    SECURITY_STATUS s;
    WCHAR* w_buf = NULL;

    if (!out || out_chars == 0) return FALSE;
    out[0] = '\0';

    s = NCryptGetProperty(h_prov, prop, NULL, 0, &size, 0);
    if (s != ERROR_SUCCESS && s != NTE_BUFFER_TOO_SMALL) {
        return FALSE;
    }

    w_buf = (WCHAR*)calloc(1, size + sizeof(WCHAR));
    if (!w_buf) return FALSE;

    s = NCryptGetProperty(h_prov, prop, (PBYTE)w_buf, size, &size, 0);
    if (s != ERROR_SUCCESS) {
        free(w_buf);
        return FALSE;
    }

    w_buf[size / sizeof(WCHAR)] = L'\0';
    if (!WideCharToMultiByte(CP_UTF8, 0, w_buf, -1, out, (int)out_chars, NULL, NULL)) {
        free(w_buf);
        return FALSE;
    }

    free(w_buf);
    return TRUE;
}

static void parse_platform_type_string(TPMINFO* info) {
    const char* p_version = strstr(info->providerType, "TPM-Version:");
    if (p_version) {
        p_version += 12;
        if (strncmp(p_version, "2.0", 3) == 0) {
            info->isTpm2 = TRUE;
            info->tpmVersionRaw = 2;
        }
        else if (strncmp(p_version, "1.2", 3) == 0) {
            info->isTpm2 = FALSE;
            info->tpmVersionRaw = 1;
        }
    }

    const char* p_vendor = strstr(info->providerType, "VendorID:'");
    if (p_vendor) {
        p_vendor += 10;
        char vendor[5] = { 0 };
        int i = 0;
        while (p_vendor[i] && p_vendor[i] != '\'' && i < 4) {
            vendor[i] = p_vendor[i];
            i++;
        }
        vendor[i] = '\0';
        if (i > 0) {
            StringCchCopyA(info->manufacturerIdText, _countof(info->manufacturerIdText), vendor);
            DWORD mfg_id = 0;
            for (int k = 0; k < i; k++) {
                mfg_id = (mfg_id << 8) | (BYTE)vendor[k];
            }
            for (int k = i; k < 4; k++) {
                mfg_id = (mfg_id << 8);
            }
            info->manufacturerId = mfg_id;
        }
    }

    if (!info->vendorString[0] || strcmp(info->vendorString, "----") == 0) {
        StringCchCopyA(info->vendorString, _countof(info->vendorString), info->manufacturerIdText);
    }
}

BOOL get_tpm_info_via_ncrypt(TPMINFO* info) {
    ZeroMemory(info, sizeof(*info));
    NCRYPT_PROV_HANDLE h_prov = 0;
    SECURITY_STATUS s;

    s = NCryptOpenStorageProvider(&h_prov, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (s != ERROR_SUCCESS) {
        return FALSE;
    }

    if (!read_ncrypt_property_string(h_prov, BCRYPT_PCP_PLATFORM_TYPE_PROPERTY, info->providerType, sizeof(info->providerType))) {
        StringCchCopyA(info->providerType, _countof(info->providerType), "(unknown)");
    }

    if (!read_ncrypt_property_string(h_prov, BCRYPT_PCP_PROVIDER_VERSION_PROPERTY, info->providerVersion, sizeof(info->providerVersion))) {
        StringCchCopyA(info->providerVersion, _countof(info->providerVersion), "(unknown)");
    }

    DWORD tpm_ver = 0;
    DWORD cb_read = sizeof(tpm_ver);
    s = NCryptGetProperty(h_prov, NCRYPT_PCP_TPM_VERSION_PROPERTY, (PBYTE)&tpm_ver, sizeof(tpm_ver), &cb_read, 0);
    if (s == ERROR_SUCCESS) {
        info->hasTpm = TRUE;
        info->isTpm2 = (tpm_ver == 2);
        info->tpmVersionRaw = tpm_ver;
    }

    DWORD mfg_id = 0;
    cb_read = sizeof(mfg_id);
    s = NCryptGetProperty(h_prov, NCRYPT_PCP_TPM_MANUFACTURER_ID_PROPERTY, (PBYTE)&mfg_id, sizeof(mfg_id), &cb_read, 0);
    if (s == ERROR_SUCCESS) {
        info->manufacturerId = mfg_id;
        info->manufacturerIdText[0] = (char)((mfg_id >> 24) & 0xFF);
        info->manufacturerIdText[1] = (char)((mfg_id >> 16) & 0xFF);
        info->manufacturerIdText[2] = (char)((mfg_id >> 8) & 0xFF);
        info->manufacturerIdText[3] = (char)(mfg_id & 0xFF);
        info->manufacturerIdText[4] = '\0';
    }
    else {
        StringCchCopyA(info->manufacturerIdText, _countof(info->manufacturerIdText), "----");
    }

    ULONGLONG fw_ver = 0;
    cb_read = sizeof(fw_ver);
    s = NCryptGetProperty(h_prov, NCRYPT_PCP_TPM_FW_VERSION_PROPERTY, (PBYTE)&fw_ver, sizeof(fw_ver), &cb_read, 0);
    if (s == ERROR_SUCCESS) {
        info->firmwareVersion = fw_ver;
        info->firmwareVersion1 = (DWORD)(fw_ver >> 32);
        info->firmwareVersion2 = (DWORD)(fw_ver & 0xFFFFFFFF);
    }

    if (!info->familyIndicatorText[0]) {
        StringCchCopyA(info->familyIndicatorText, _countof(info->familyIndicatorText), info->isTpm2 ? "2.0" : "1.2");
    }
    if (!info->vendorString[0]) {
        StringCchCopyA(info->vendorString, _countof(info->vendorString), info->manufacturerIdText);
    }

    parse_platform_type_string(info);

    info->ekPub = NULL;
    info->ekPubSize = 0;

    TBS_CONTEXT_PARAMS2 params;
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm12 = 0;
    params.includeTpm20 = 1;
    TBS_HCONTEXT h_tbs_context = 0;
    BOOL direct_success = FALSE;

    if (Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &h_tbs_context) == TBS_SUCCESS) {
        UINT32 handles[64] = { 0 };
        UINT32 handle_count = 0;
        UINT32 ek_handle = 0;
        if (tpm_enumerate_persistent_handles(h_tbs_context, handles, &handle_count)) {
            for (UINT32 i = 0; i < handle_count; i++) {
                if (handles[i] >= 0x81010000 && handles[i] <= 0x810100FF) {
                    ek_handle = handles[i];
                    break;
                }
            }
        }
        if (ek_handle != 0) {
            BYTE* ek_pub_tpm2b = NULL;
            DWORD ek_pub_tpm2b_size = 0;
            if (tpm_read_public_area(h_tbs_context, ek_handle, &ek_pub_tpm2b, &ek_pub_tpm2b_size)) {
                DWORD bcrypt_blob_size = 0;
                BYTE* bcrypt_blob = tpm_public_to_bcrypt_blob(ek_pub_tpm2b, ek_pub_tpm2b_size, &bcrypt_blob_size);
                if (bcrypt_blob) {
                    info->ekPub = bcrypt_blob;
                    info->ekPubSize = bcrypt_blob_size;
                    sha256_hex(info->ekPub, info->ekPubSize, info->ekPubSha256);
                    direct_success = TRUE;
                }
                free(ek_pub_tpm2b);
            }
        }
        Tbsip_Context_Close(h_tbs_context);
    }

    if (!direct_success) {
        printf("[!] Direct TPM public EK query failed. Reverting to original PCP property query...\n");
        if (!read_ncrypt_property_bytes(h_prov, NCRYPT_PCP_EKPUB_PROPERTY, &info->ekPub, &info->ekPubSize)) {
            info->ekPub = NULL;
            info->ekPubSize = 0;
        }
        else {
            sha256_hex(info->ekPub, info->ekPubSize, info->ekPubSha256);
        }
    }

    info->hasEkCertStore = TRUE;
    NCryptFreeObject(h_prov);
    return TRUE;
}

BOOL get_pcp_ek_cert_store(NCRYPT_PROV_HANDLE h_prov, HCERTSTORE* out_store) {
    HCERTSTORE h_store = NULL;
    DWORD size = sizeof(h_store);
    SECURITY_STATUS s;
    if (!out_store) return FALSE;
    *out_store = NULL;

    s = NCryptGetProperty(h_prov, NCRYPT_PCP_EKCERT_PROPERTY, (PBYTE)&h_store, sizeof(h_store), &size, 0);
    if (s != ERROR_SUCCESS) {
        return FALSE;
    }

    if (!h_store) return FALSE;
    *out_store = h_store;
    return TRUE;
}

void load_certs_from_registry_recursive(HKEY h_key, HCERTSTORE store, WCHAR* sz_value_name) {
    DWORD dw_index = 0;
    DWORD cb_value_name = 16384;
    DWORD dw_type = 0;
    BYTE* lp_data = NULL;
    DWORD cb_data = 0;

    if (!h_key || !store || !sz_value_name) return;

    while (TRUE) {
        cb_value_name = 16384;
        cb_data = 0;

        LONG l_result = RegEnumValueW(h_key, dw_index, sz_value_name, &cb_value_name, NULL, &dw_type, NULL, &cb_data);
        if (l_result == ERROR_NO_MORE_ITEMS) {
            break;
        }

        if (l_result == ERROR_SUCCESS || l_result == ERROR_MORE_DATA) {
            if (dw_type == REG_BINARY && cb_data > 0) {
                lp_data = (BYTE*)malloc(cb_data);
                if (lp_data) {
                    cb_value_name = 16384;
                    l_result = RegEnumValueW(h_key, dw_index, sz_value_name, &cb_value_name, NULL, &dw_type, lp_data, &cb_data);
                    if (l_result == ERROR_SUCCESS) {
                        PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, lp_data, cb_data);
                        if (ctx) {
                            CertAddCertificateContextToStore(store, ctx, CERT_STORE_ADD_NEW, NULL);
                            CertFreeCertificateContext(ctx);
                        }
                    }
                    free(lp_data);
                    lp_data = NULL;
                }
            }
        }
        dw_index++;
    }

    dw_index = 0;
    WCHAR sz_sub_key_name[256];
    DWORD cb_sub_key_name = _countof(sz_sub_key_name);
    while (TRUE) {
        cb_sub_key_name = _countof(sz_sub_key_name);
        LONG l_result = RegEnumKeyExW(h_key, dw_index, sz_sub_key_name, &cb_sub_key_name, NULL, NULL, NULL, NULL);
        if (l_result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (l_result == ERROR_SUCCESS) {
            HKEY h_sub_key = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sz_sub_key_name, 0, KEY_READ, &h_sub_key) == ERROR_SUCCESS) {
                load_certs_from_registry_recursive(h_sub_key, store, sz_value_name);
                RegCloseKey(h_sub_key);
            }
        }
        dw_index++;
    }
}

void load_tpm_intermediate_certs_from_registry(HCERTSTORE store) {
    HKEY h_key = NULL;
    WCHAR* sz_value_name = (WCHAR*)malloc(16384 * sizeof(WCHAR));
    if (!sz_value_name) return;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement", 0, KEY_READ, &h_key) == ERROR_SUCCESS) {
        load_certs_from_registry_recursive(h_key, store, sz_value_name);
        RegCloseKey(h_key);
    }
    free(sz_value_name);
}

void load_certs_from_pcp_property_store(NCRYPT_PROV_HANDLE h_prov, LPCWSTR prop_name, HCERTSTORE h_store_to_add_to) {
    HCERTSTORE h_pcp_store = NULL;
    DWORD cb_store = sizeof(h_pcp_store);
    SECURITY_STATUS s = NCryptGetProperty(h_prov, prop_name, (PBYTE)&h_pcp_store, sizeof(h_pcp_store), &cb_store, 0);
    if (s == ERROR_SUCCESS && h_pcp_store) {
        PCCERT_CONTEXT c = NULL;
        DWORD loaded_count = 0;
        while ((c = CertEnumCertificatesInStore(h_pcp_store, c)) != NULL) {
            if (CertAddCertificateContextToStore(h_store_to_add_to, c, CERT_STORE_ADD_NEW, NULL)) {
                loaded_count++;
            }
        }
        CertCloseStore(h_pcp_store, 0);
        if (loaded_count > 0) {
            wprintf(L"  Loaded %lu intermediate certificate(s) from PCP property: %s\n", loaded_count, prop_name);
        }
    }
}

void load_pcp_intermediate_certs(HCERTSTORE store) {
    NCRYPT_PROV_HANDLE h_prov = 0;
    SECURITY_STATUS s = NCryptOpenStorageProvider(&h_prov, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (s == ERROR_SUCCESS) {
        load_certs_from_pcp_property_store(h_prov, L"PCP_RSA_EKNVCERT", store);
        load_certs_from_pcp_property_store(h_prov, L"PCP_ECC_EKNVCERT", store);
        load_certs_from_pcp_property_store(h_prov, L"PCP_EKNVCERT", store);
        load_certs_from_pcp_property_store(h_prov, L"PCP_INTERMEDIATE_CA_EKCERT", store);
        NCryptFreeObject(h_prov);
    }
}

BOOL build_candidate_issuer_store(HCERTSTORE h_cab_store, HCERTSTORE h_roots, HCERTSTORE h_ca_store, HCERTSTORE* out_store) {
    HCERTSTORE h_store = NULL;
    HCERTSTORE h_lm_roots = NULL;
    HCERTSTORE h_lm_ca = NULL;
    PCCERT_CONTEXT c = NULL;

    if (!out_store) return FALSE;
    *out_store = NULL;

    h_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!h_store) {
        return FALSE;
    }

    if (h_cab_store) {
        while ((c = CertEnumCertificatesInStore(h_cab_store, c)) != NULL) {
            CertAddCertificateContextToStore(h_store, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    c = NULL;
    if (h_roots) {
        while ((c = CertEnumCertificatesInStore(h_roots, c)) != NULL) {
            CertAddCertificateContextToStore(h_store, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    c = NULL;
    if (h_ca_store) {
        while ((c = CertEnumCertificatesInStore(h_ca_store, c)) != NULL) {
            CertAddCertificateContextToStore(h_store, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    h_lm_roots = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
        "ROOT");
    if (h_lm_roots) {
        c = NULL;
        while ((c = CertEnumCertificatesInStore(h_lm_roots, c)) != NULL) {
            CertAddCertificateContextToStore(h_store, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    h_lm_ca = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
        "CA");
    if (h_lm_ca) {
        c = NULL;
        while ((c = CertEnumCertificatesInStore(h_lm_ca, c)) != NULL) {
            CertAddCertificateContextToStore(h_store, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    {
        HCERTSTORE h_ent_root = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
            "Enterprise Root");
        if (h_ent_root) {
            c = NULL;
            while ((c = CertEnumCertificatesInStore(h_ent_root, c)) != NULL) {
                CertAddCertificateContextToStore(h_store, c, CERT_STORE_ADD_ALWAYS, NULL);
            }
            CertCloseStore(h_ent_root, 0);
        }
    }

    load_tpm_intermediate_certs_from_registry(h_store);
    load_pcp_intermediate_certs(h_store);

    if (h_lm_roots) CertCloseStore(h_lm_roots, 0);
    if (h_lm_ca) CertCloseStore(h_lm_ca, 0);

    *out_store = h_store;
    return TRUE;
}