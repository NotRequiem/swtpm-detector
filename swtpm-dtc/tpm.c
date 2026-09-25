#include "tpm.h"

static void init_builder(buf_builder* b, BYTE* buf, UINT32 cap) {
    if (!b) return;
    b->buf = buf;
    b->capacity = cap;
    b->write_pos = 0;
}

static void write_8(buf_builder* b, BYTE val) {
    if (b && b->buf && b->write_pos < b->capacity) b->buf[b->write_pos++] = val;
}

static void write_16(buf_builder* b, UINT16 val) {
    if (b && b->buf && b->capacity >= b->write_pos && b->capacity - b->write_pos >= 2) {
        b->buf[b->write_pos++] = (val >> 8) & 0xFF;
        b->buf[b->write_pos++] = val & 0xFF;
    }
}

static void write_32(buf_builder* b, UINT32 val) {
    if (b && b->buf && b->capacity >= b->write_pos && b->capacity - b->write_pos >= 4) {
        b->buf[b->write_pos++] = (val >> 24) & 0xFF;
        b->buf[b->write_pos++] = (val >> 16) & 0xFF;
        b->buf[b->write_pos++] = (val >> 8) & 0xFF;
        b->buf[b->write_pos++] = val & 0xFF;
    }
}

static void write_buf(buf_builder* b, const BYTE* src, UINT32 len) {
    if (b && b->buf && src && len > 0 && b->capacity >= b->write_pos && b->capacity - b->write_pos >= len) {
        memcpy(b->buf + b->write_pos, src, len);
        b->write_pos += len;
    }
}

static void write_2b(buf_builder* b, const BYTE* src, UINT16 len) {
    write_16(b, len);
    if (len > 0 && src) {
        write_buf(b, src, len);
    }
}

static void patch_32(BYTE* buf, UINT32 offset, UINT32 val) {
    if (!buf) return;
    buf[offset] = (val >> 24) & 0xFF;
    buf[offset + 1] = (val >> 16) & 0xFF;
    buf[offset + 2] = (val >> 8) & 0xFF;
    buf[offset + 3] = val & 0xFF;
}

static void init_parser(buf_parser* p, const BYTE* buf, UINT32 size) {
    if (!p) return;
    p->buf = buf;
    p->size = size;
    p->read_pos = 0;
}

static BYTE read_8(buf_parser* p) {
    return (p && p->buf && p->read_pos < p->size) ? p->buf[p->read_pos++] : 0;
}

static UINT16 read_16(buf_parser* p) {
    if (p && p->buf && p->size >= p->read_pos && p->size - p->read_pos >= 2) {
        UINT16 val = ((UINT16)p->buf[p->read_pos] << 8) | (UINT16)p->buf[p->read_pos + 1];
        p->read_pos += 2;
        return val;
    }
    return 0;
}

static UINT32 read_32(buf_parser* p) {
    if (p && p->buf && p->size >= p->read_pos && p->size - p->read_pos >= 4) {
        UINT32 val = ((UINT32)p->buf[p->read_pos] << 24) |
            ((UINT32)p->buf[p->read_pos + 1] << 16) |
            ((UINT32)p->buf[p->read_pos + 2] << 8) |
            ((UINT32)p->buf[p->read_pos + 3]);
        p->read_pos += 4;
        return val;
    }
    return 0;
}

static UINT64 read_64(buf_parser* p) {
    if (p && p->buf && p->size >= p->read_pos && p->size - p->read_pos >= 8) {
        UINT64 val = ((UINT64)p->buf[p->read_pos] << 56) |
            ((UINT64)p->buf[p->read_pos + 1] << 48) |
            ((UINT64)p->buf[p->read_pos + 2] << 40) |
            ((UINT64)p->buf[p->read_pos + 3] << 32) |
            ((UINT64)p->buf[p->read_pos + 4] << 24) |
            ((UINT64)p->buf[p->read_pos + 5] << 16) |
            ((UINT64)p->buf[p->read_pos + 6] << 8) |
            ((UINT64)p->buf[p->read_pos + 7]);
        p->read_pos += 8;
        return val;
    }
    return 0;
}

static void read_buf(buf_parser* p, BYTE* dst, UINT32 len) {
    if (p && p->buf && dst && len > 0 && p->size >= p->read_pos && p->size - p->read_pos >= len) {
        memcpy(dst, p->buf + p->read_pos, len);
        p->read_pos += len;
    }
}

static UINT16 read_2b(buf_parser* p, BYTE* dst, UINT16 max_len) {
    if (!p || !dst || max_len == 0) return 0;
    UINT16 len = read_16(p);
    if (len == 0 || len > max_len || p->size - p->read_pos < len) return 0;
    read_buf(p, dst, len);
    return len;
}

static BOOL send_tpm_command(TBS_HCONTEXT h_tbs_context, const BYTE* cmd_buf, UINT32 cmd_size, BYTE* resp_buf, UINT32* resp_size) {
    if (!h_tbs_context || !cmd_buf || cmd_size == 0 || !resp_buf || !resp_size || *resp_size == 0) return FALSE;
    TBS_RESULT hr = Tbsip_Submit_Command(
        h_tbs_context,
        TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL,
        cmd_buf,
        cmd_size,
        resp_buf,
        resp_size
    );
    return (hr == TBS_SUCCESS);
}

static BOOL tpm_read_public(TBS_HCONTEXT h_tbs_context, UINT32 handle, BYTE* out_name, UINT16* out_name_size, BYTE* out_qn, UINT16* out_qn_size) {
    if (!h_tbs_context || handle == 0 || !out_name || !out_name_size) return FALSE;
    *out_name_size = 0;
    if (out_qn_size) *out_qn_size = 0;

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
    if (resp_size < 10) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    if (read_32(&p) != 0) return FALSE;

    UINT16 out_public_size = read_16(&p);
    if (out_public_size == 0 || p.size - p.read_pos < out_public_size) return FALSE;
    p.read_pos += out_public_size;
    *out_name_size = read_2b(&p, out_name, 128);
    if (out_qn && out_qn_size) {
        *out_qn_size = read_2b(&p, out_qn, 128);
    }
    return (*out_name_size > 0);
}

static BOOL tpm_read_public_area(TBS_HCONTEXT h_tbs_context, UINT32 handle, BYTE** out_public, DWORD* out_public_size) {
    if (!h_tbs_context || handle == 0 || !out_public || !out_public_size) return FALSE;
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
    if (resp_size < 10) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    if (read_32(&p) != 0) return FALSE;

    UINT32 start_off = p.read_pos;
    UINT16 pub_size = read_16(&p);
    if (pub_size == 0 || p.size - p.read_pos < pub_size) return FALSE;

    DWORD total_size = 2 + pub_size;
    BYTE* buf = (BYTE*)malloc(total_size);
    if (!buf) return FALSE;

    memcpy(buf, resp + start_off, total_size);
    *out_public = buf;
    *out_public_size = total_size;
    return TRUE;
}

static BOOL parse_tpm2b_public_rsa(const BYTE* tpm2b, DWORD tpm2b_size, UINT32* out_exponent, BYTE** out_modulus, UINT16* out_modulus_size) {
    if (!tpm2b || tpm2b_size < 12 || !out_exponent || !out_modulus || !out_modulus_size) return FALSE;
    *out_exponent = 0;
    *out_modulus = NULL;
    *out_modulus_size = 0;

    buf_parser p;
    init_parser(&p, tpm2b, tpm2b_size);
    UINT16 size = read_16(&p);
    if (size == 0 || p.size - p.read_pos < size) return FALSE;
    UINT32 max_end = p.read_pos + size;

    if (read_16(&p) != TPM_ALG_RSA) return FALSE;

    read_16(&p); read_32(&p);
    UINT16 auth_policy_size = read_16(&p);
    if (p.size - p.read_pos < auth_policy_size || p.read_pos + auth_policy_size > max_end) return FALSE;
    p.read_pos += auth_policy_size;

    if (p.read_pos >= max_end) return FALSE;
    if (read_16(&p) != 0x0010) { read_16(&p); read_16(&p); }
    if (p.read_pos >= max_end) return FALSE;
    if (read_16(&p) != 0x0010) { read_16(&p); }

    if (p.read_pos + 6 > max_end) return FALSE;
    read_16(&p);
    UINT32 exponent = read_32(&p);
    if (exponent == 0) exponent = 65537;

    if (p.read_pos + 2 > max_end) return FALSE;
    UINT16 modulus_size = read_16(&p);
    if (modulus_size == 0 || p.read_pos + modulus_size > max_end) return FALSE;

    BYTE* modulus = (BYTE*)malloc(modulus_size);
    if (!modulus) return FALSE;
    read_buf(&p, modulus, modulus_size);

    *out_exponent = exponent;
    *out_modulus = modulus;
    *out_modulus_size = modulus_size;
    return TRUE;
}

static BOOL parse_tpm2b_public_ecc(const BYTE* tpm2b, DWORD tpm2b_size, UINT16* out_curve_id, BYTE** out_x, UINT16* out_x_size, BYTE** out_y, UINT16* out_y_size) {
    if (!tpm2b || tpm2b_size < 12 || !out_curve_id || !out_x || !out_x_size || !out_y || !out_y_size) return FALSE;
    *out_curve_id = 0;
    *out_x = NULL;
    *out_x_size = 0;
    *out_y = NULL;
    *out_y_size = 0;

    buf_parser p;
    init_parser(&p, tpm2b, tpm2b_size);
    UINT16 size = read_16(&p);
    if (size == 0 || p.size - p.read_pos < size) return FALSE;
    UINT32 max_end = p.read_pos + size;

    if (read_16(&p) != TPM_ALG_ECC) return FALSE;

    read_16(&p); read_32(&p);
    UINT16 auth_policy_size = read_16(&p);
    if (p.size - p.read_pos < auth_policy_size || p.read_pos + auth_policy_size > max_end) return FALSE;
    p.read_pos += auth_policy_size;

    if (p.read_pos >= max_end) return FALSE;
    if (read_16(&p) != 0x0010) { read_16(&p); read_16(&p); }
    if (p.read_pos >= max_end) return FALSE;
    if (read_16(&p) != 0x0010) { read_16(&p); }

    if (p.read_pos + 4 > max_end) return FALSE;
    UINT16 curve_id = read_16(&p);
    if (read_16(&p) != 0x0010) { read_16(&p); }

    if (p.read_pos + 2 > max_end) return FALSE;
    UINT16 x_size = read_16(&p);
    if (x_size == 0 || p.read_pos + x_size > max_end) return FALSE;
    BYTE* x = (BYTE*)malloc(x_size);
    if (!x) return FALSE;
    read_buf(&p, x, x_size);

    if (p.read_pos + 2 > max_end) {
        free(x);
        return FALSE;
    }
    UINT16 y_size = read_16(&p);
    if (y_size == 0 || p.read_pos + y_size > max_end) {
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
    if (!modulus || modulus_size == 0 || !out_blob_size) return NULL;
    *out_blob_size = 0;

    if (exponent == 0) exponent = 65537;

    BYTE exp_bytes[4] = { (BYTE)((exponent >> 24) & 0xFF), (BYTE)((exponent >> 16) & 0xFF), (BYTE)((exponent >> 8) & 0xFF), (BYTE)(exponent & 0xFF) };
    DWORD exp_start = 0;
    while (exp_start < 3 && exp_bytes[exp_start] == 0) exp_start++;
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
    if (!x || !y || !out_blob_size || x_size == 0 || y_size == 0 || x_size != y_size) return NULL;
    *out_blob_size = 0;

    DWORD magic = 0;
    if (curve_id == 0x0003 && x_size == 32) {
        magic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    }
    else if (curve_id == 0x0004 && x_size == 48) {
        magic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
    }
    if (!magic) return NULL;

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
    if (!tpm2b || tpm2b_size < 6 || !out_blob_size) return NULL;
    *out_blob_size = 0;

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
    if (!h_tbs_context || !out_data_size) return FALSE;
    *out_data_size = 0;

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
    if (resp_size < 10) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    if (read_32(&p) != 0) return FALSE;
    if (read_16(&p) == 0) return FALSE;

    read_32(&p); read_16(&p); read_32(&p);
    UINT16 auth_policy_size = read_16(&p);
    if (p.size - p.read_pos < (UINT32)auth_policy_size + 2) return FALSE;
    p.read_pos += auth_policy_size;
    *out_data_size = read_16(&p);
    return TRUE;
}

static BOOL tpm_nv_read(TBS_HCONTEXT h_tbs_context, UINT32 auth_handle, UINT32 nv_index, UINT16 size, UINT16 offset, BYTE* out_data, UINT16* out_size) {
    if (!h_tbs_context || !out_data || !out_size || size == 0) return FALSE;
    *out_size = 0;

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
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);

    write_16(&b, size);
    write_16(&b, offset);
    patch_32(cmd, 2, b.write_pos);

    BYTE resp[2048];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;
    if (resp_size < 10) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    UINT16 tag = read_16(&p);
    read_32(&p);
    if (read_32(&p) != 0) return FALSE;
    if (tag == TPM_ST_SESSIONS) read_32(&p);

    *out_size = read_2b(&p, out_data, size);
    return (*out_size > 0);
}

static BYTE* tpm_read_full_nv_index(TBS_HCONTEXT h_tbs_context, UINT32 auth_handle, UINT32 nv_index, DWORD* out_total_size) {
    if (!h_tbs_context || !out_total_size) return NULL;
    *out_total_size = 0;

    UINT16 data_size = 0;
    if (!tpm_nv_read_public(h_tbs_context, nv_index, &data_size) || data_size == 0 || data_size > 8192) {
        return NULL;
    }

    BYTE* cert_buf = (BYTE*)malloc(data_size);
    if (!cert_buf) return NULL;

    UINT16 bytes_read = 0;
    UINT16 chunk_size = 256;

    while (bytes_read < data_size) {
        UINT16 to_read = data_size - bytes_read;
        if (to_read > chunk_size) to_read = chunk_size;

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
        if (read_len == 0 || read_len > to_read) {
            free(cert_buf);
            return NULL;
        }
        memcpy(cert_buf + bytes_read, chunk, read_len);
        bytes_read += read_len;
    }

    *out_total_size = data_size;
    return cert_buf;
}

BOOL get_ek_cert_store_from_nvram(HCERTSTORE* out_store) {
    if (!out_store) return FALSE;
    *out_store = NULL;

    HCERTSTORE h_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!h_store) return FALSE;

    TBS_CONTEXT_PARAMS2 params = { 0 };
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm12 = 0;
    params.includeTpm20 = 1;
    TBS_HCONTEXT h_tbs_context = 0;

    if (Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &h_tbs_context) != TBS_SUCCESS) {
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

static BOOL tpm_start_auth_session(TBS_HCONTEXT h_tbs_context, UINT32* out_session_handle) {
    if (!h_tbs_context || !out_session_handle) return FALSE;
    *out_session_handle = 0;

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
    if (resp_size < 14) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    if (read_32(&p) != 0) return FALSE;

    *out_session_handle = read_32(&p);
    return (*out_session_handle != 0);
}

static BOOL tpm_policy_secret(TBS_HCONTEXT h_tbs_context, UINT32 session_handle) {
    if (!h_tbs_context || session_handle == 0) return FALSE;

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
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);

    write_16(&b, 0); write_16(&b, 0); write_16(&b, 0); write_32(&b, 0);
    patch_32(cmd, 2, b.write_pos);

    BYTE resp[512];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;
    if (resp_size < 10) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    return (read_32(&p) == 0);
}

static void tpm_flush_context(TBS_HCONTEXT h_tbs_context, UINT32 handle) {
    if (!h_tbs_context || handle == 0) return;

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

static BOOL tpm_create_primary_ak(TBS_HCONTEXT h_tbs_context, UINT32* out_ak_handle) {
    if (!h_tbs_context || !out_ak_handle) return FALSE;
    *out_ak_handle = 0;

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
    write_32(&b, TPM_RH_ENDORSEMENT);

    write_32(&b, 9);
    write_32(&b, TPM_RS_PW);
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);

    write_16(&b, 4); write_16(&b, 0); write_16(&b, 0);
    write_16(&b, in_public_size);
    write_buf(&b, in_public, in_public_size);
    write_16(&b, 0); write_32(&b, 0);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[4096];
    UINT32 resp_size = sizeof(resp);
    if (send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) {
        if (resp_size >= 14) {
            buf_parser p;
            init_parser(&p, resp, resp_size);
            read_16(&p); read_32(&p);
            if (read_32(&p) == 0) {
                *out_ak_handle = read_32(&p);
                if (*out_ak_handle != 0) return TRUE;
            }
        }
    }

    UINT32 policy_session = 0;
    if (!tpm_start_auth_session(h_tbs_context, &policy_session)) return FALSE;
    if (!tpm_policy_secret(h_tbs_context, policy_session)) {
        tpm_flush_context(h_tbs_context, policy_session);
        return FALSE;
    }

    init_builder(&b, cmd, sizeof(cmd));
    write_16(&b, TPM_ST_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_CreatePrimary);
    write_32(&b, TPM_RH_ENDORSEMENT);

    write_32(&b, 9);
    write_32(&b, policy_session);
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);

    write_16(&b, 4); write_16(&b, 0); write_16(&b, 0);
    write_16(&b, in_public_size);
    write_buf(&b, in_public, in_public_size);
    write_16(&b, 0); write_32(&b, 0);

    patch_32(cmd, 2, b.write_pos);

    resp_size = sizeof(resp);
    BOOL ok = send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size);
    tpm_flush_context(h_tbs_context, policy_session);
    if (!ok || resp_size < 14) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    if (read_32(&p) != 0) return FALSE;

    *out_ak_handle = read_32(&p);
    return (*out_ak_handle != 0);
}

static BOOL tpm_create_primary_ek_attempt(TBS_HCONTEXT h_tbs_context, UINT16 unique_size, UINT32* out_ek_handle) {
    if (!h_tbs_context || !out_ek_handle) return FALSE;
    *out_ek_handle = 0;

    const BYTE ek_policy[32] = {
        0x83, 0x71, 0xAC, 0x02, 0xBB, 0x52, 0x4E, 0x3E,
        0x8A, 0xAC, 0x14, 0x8E, 0xB3, 0xCD, 0x5F, 0x80,
        0x0E, 0x6E, 0xEC, 0xE1, 0x89, 0x2F, 0x79, 0x66,
        0x80, 0xC8, 0xDA, 0x42, 0xDA, 0xC1, 0xBE, 0x3D
    };

    BYTE in_public[512];
    buf_builder pb;
    init_builder(&pb, in_public, sizeof(in_public));
    write_16(&pb, TPM_ALG_RSA);
    write_16(&pb, TPM_ALG_SHA256);
    write_32(&pb, 0x000300B2);
    write_2b(&pb, ek_policy, sizeof(ek_policy));
    write_16(&pb, 0x0006);
    write_16(&pb, 128);
    write_16(&pb, 0x0043);
    write_16(&pb, TPM_ALG_NULL);
    write_16(&pb, 2048);
    write_32(&pb, 0);

    if (unique_size > 0) {
        BYTE zero_unique[256] = { 0 };
        write_2b(&pb, zero_unique, unique_size);
    }
    else {
        write_16(&pb, 0);
    }
    UINT16 in_public_size = (UINT16)pb.write_pos;

    BYTE cmd[1024];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));
    write_16(&b, TPM_ST_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_CreatePrimary);
    write_32(&b, TPM_RH_ENDORSEMENT);

    write_32(&b, 9);
    write_32(&b, TPM_RS_PW);
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);

    write_16(&b, 4); write_16(&b, 0); write_16(&b, 0);
    write_16(&b, in_public_size);
    write_buf(&b, in_public, in_public_size);
    write_16(&b, 0); write_32(&b, 0);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[4096];
    UINT32 resp_size = sizeof(resp);
    if (send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) {
        if (resp_size >= 14) {
            buf_parser p;
            init_parser(&p, resp, resp_size);
            read_16(&p); read_32(&p);
            if (read_32(&p) == 0) {
                *out_ek_handle = read_32(&p);
                if (*out_ek_handle != 0) return TRUE;
            }
        }
    }

    UINT32 policy_session = 0;
    if (!tpm_start_auth_session(h_tbs_context, &policy_session)) return FALSE;
    if (!tpm_policy_secret(h_tbs_context, policy_session)) {
        tpm_flush_context(h_tbs_context, policy_session);
        return FALSE;
    }

    init_builder(&b, cmd, sizeof(cmd));
    write_16(&b, TPM_ST_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_CreatePrimary);
    write_32(&b, TPM_RH_ENDORSEMENT);

    write_32(&b, 9);
    write_32(&b, policy_session);
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);

    write_16(&b, 4); write_16(&b, 0); write_16(&b, 0);
    write_16(&b, in_public_size);
    write_buf(&b, in_public, in_public_size);
    write_16(&b, 0); write_32(&b, 0);

    patch_32(cmd, 2, b.write_pos);

    resp_size = sizeof(resp);
    BOOL ok = send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size);
    tpm_flush_context(h_tbs_context, policy_session);
    if (!ok || resp_size < 14) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    if (read_32(&p) != 0) return FALSE;

    *out_ek_handle = read_32(&p);
    return (*out_ek_handle != 0);
}

static BOOL tpm_create_primary_ek(TBS_HCONTEXT h_tbs_context, UINT32* out_ek_handle) {
    if (tpm_create_primary_ek_attempt(h_tbs_context, 256, out_ek_handle)) {
        return TRUE;
    }
    return tpm_create_primary_ek_attempt(h_tbs_context, 0, out_ek_handle);
}

static BOOL hmac_sha256(const BYTE* key, DWORD key_len, const BYTE* data, DWORD data_len, BYTE out_mac[32]) {
    if (!key || key_len == 0 || !data || data_len == 0 || !out_mac) return FALSE;
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_HASH_HANDLE h_hash = NULL;
    DWORD cb_obj = 0, cb_data = sizeof(DWORD);
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != STATUS_SUCCESS) return FALSE;
    status = BCryptGetProperty(h_alg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cb_obj, cb_data, &cb_data, 0);
    if (status != STATUS_SUCCESS || cb_obj == 0) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return FALSE;
    }
    BYTE* obj = (BYTE*)malloc(cb_obj);
    if (!obj) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return FALSE;
    }
    status = BCryptCreateHash(h_alg, &h_hash, obj, cb_obj, (PUCHAR)key, key_len, 0);
    if (status == STATUS_SUCCESS) {
        status = BCryptHashData(h_hash, (PUCHAR)data, data_len, 0);
        if (status == STATUS_SUCCESS) {
            status = BCryptFinishHash(h_hash, out_mac, 32, 0);
        }
        BCryptDestroyHash(h_hash);
    }
    free(obj);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    return (status == STATUS_SUCCESS);
}

static BOOL aes_128_ecb_encrypt_block(const BYTE key[16], const BYTE in[16], BYTE out[16]) {
    if (!key || !in || !out) return FALSE;
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_KEY_HANDLE h_key = NULL;
    DWORD cb_obj = 0, cb_data = sizeof(DWORD);
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) return FALSE;
    status = BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return FALSE;
    }
    status = BCryptGetProperty(h_alg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cb_obj, cb_data, &cb_data, 0);
    if (status != STATUS_SUCCESS || cb_obj == 0) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return FALSE;
    }
    BYTE* obj = (BYTE*)malloc(cb_obj);
    if (!obj) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return FALSE;
    }
    status = BCryptGenerateSymmetricKey(h_alg, &h_key, obj, cb_obj, (PUCHAR)key, 16, 0);
    if (status == STATUS_SUCCESS) {
        DWORD res = 0;
        status = BCryptEncrypt(h_key, (PUCHAR)in, 16, NULL, NULL, 0, out, 16, &res, 0);
        BCryptDestroyKey(h_key);
    }
    free(obj);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    return (status == STATUS_SUCCESS);
}

static BOOL local_software_make_credential(
    PCCERT_CONTEXT ek_cert,
    const BYTE* challenge,
    UINT16 challenge_size,
    const BYTE* ak_name,
    UINT16 ak_name_size,
    BYTE* out_blob,
    UINT16* out_blob_size,
    BYTE* out_secret,
    UINT16* out_secret_size)
{
    if (!ek_cert || !ek_cert->pCertInfo || !challenge || challenge_size == 0 || challenge_size > 32 ||
        !ak_name || ak_name_size == 0 || ak_name_size > 64 ||
        !out_blob || !out_blob_size || !out_secret || !out_secret_size) {
        return FALSE;
    }
    *out_blob_size = 0;
    *out_secret_size = 0;

    BCRYPT_KEY_HANDLE h_ek_key = NULL;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &ek_cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &h_ek_key)) {
        return FALSE;
    }

    BYTE seed[32];
    if (BCryptGenRandom(NULL, seed, sizeof(seed), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        BCryptDestroyKey(h_ek_key);
        return FALSE;
    }

    BCRYPT_OAEP_PADDING_INFO oaep = { 0 };
    oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    oaep.pbLabel = (PUCHAR)"IDENTITY";
    oaep.cbLabel = 9;

    DWORD enc_secret_len = 0;
    NTSTATUS status = BCryptEncrypt(h_ek_key, seed, sizeof(seed), &oaep, NULL, 0, out_secret, 1024, &enc_secret_len, BCRYPT_PAD_OAEP);
    BCryptDestroyKey(h_ek_key);
    if (status != STATUS_SUCCESS || enc_secret_len == 0 || enc_secret_len > 1024) {
        SecureZeroMemory(seed, sizeof(seed));
        return FALSE;
    }
    *out_secret_size = (UINT16)enc_secret_len;

    BYTE hmac_input[18];
    patch_32(hmac_input, 0, 1);
    memcpy(hmac_input + 4, "INTEGRITY", 10);
    patch_32(hmac_input, 14, 256);
    BYTE hmac_key[32];
    if (!hmac_sha256(seed, sizeof(seed), hmac_input, sizeof(hmac_input), hmac_key)) {
        SecureZeroMemory(seed, sizeof(seed));
        return FALSE;
    }

    BYTE storage_input[128];
    patch_32(storage_input, 0, 1);
    memcpy(storage_input + 4, "STORAGE", 8);
    memcpy(storage_input + 12, ak_name, ak_name_size);
    patch_32(storage_input, 12 + ak_name_size, 128);
    BYTE sym_key_full[32];
    if (!hmac_sha256(seed, sizeof(seed), storage_input, 16 + ak_name_size, sym_key_full)) {
        SecureZeroMemory(seed, sizeof(seed));
        SecureZeroMemory(hmac_key, sizeof(hmac_key));
        return FALSE;
    }

    BYTE sym_key[16];
    memcpy(sym_key, sym_key_full, 16);
    SecureZeroMemory(seed, sizeof(seed));
    SecureZeroMemory(sym_key_full, sizeof(sym_key_full));

    BYTE pt[64] = { 0 };
    pt[0] = (challenge_size >> 8) & 0xFF;
    pt[1] = challenge_size & 0xFF;
    memcpy(pt + 2, challenge, challenge_size);
    UINT32 pt_len = 2 + challenge_size;

    BYTE ct[64] = { 0 };
    BYTE iv[16] = { 0 };
    BYTE pad[16] = { 0 };
    UINT32 pos = 0;
    while (pos < pt_len) {
        if (!aes_128_ecb_encrypt_block(sym_key, iv, pad)) {
            SecureZeroMemory(sym_key, sizeof(sym_key));
            SecureZeroMemory(hmac_key, sizeof(hmac_key));
            return FALSE;
        }
        UINT32 chunk = pt_len - pos;
        if (chunk > 16) chunk = 16;
        for (UINT32 k = 0; k < chunk; k++) {
            ct[pos + k] = pt[pos + k] ^ pad[k];
            iv[k] = ct[pos + k];
        }
        pos += chunk;
    }
    SecureZeroMemory(sym_key, sizeof(sym_key));

    BYTE hmac_target[128];
    memcpy(hmac_target, ct, pt_len);
    memcpy(hmac_target + pt_len, ak_name, ak_name_size);
    BYTE outer_hmac[32];
    if (!hmac_sha256(hmac_key, sizeof(hmac_key), hmac_target, pt_len + ak_name_size, outer_hmac)) {
        SecureZeroMemory(hmac_key, sizeof(hmac_key));
        return FALSE;
    }
    SecureZeroMemory(hmac_key, sizeof(hmac_key));

    out_blob[0] = 0x00;
    out_blob[1] = 0x20;
    memcpy(out_blob + 2, outer_hmac, 32);
    memcpy(out_blob + 34, ct, pt_len);
    *out_blob_size = (UINT16)(34 + pt_len);
    return TRUE;
}

static BOOL validate_and_compute_ak_names(
    const BYTE* ak_pub_tpm2b,
    DWORD ak_pub_tpm2b_size,
    const BYTE* reported_ak_name,
    UINT16 reported_ak_name_size,
    const BYTE* reported_ak_qn,
    UINT16 reported_ak_qn_size,
    BYTE out_ak_name[34],
    BYTE out_expected_qn[34])
{
    if (!ak_pub_tpm2b || ak_pub_tpm2b_size < 14 || !reported_ak_name || !out_ak_name || !out_expected_qn) return FALSE;

    buf_parser p;
    init_parser(&p, ak_pub_tpm2b, ak_pub_tpm2b_size);
    UINT16 pub_size = read_16(&p);
    if (pub_size == 0 || p.size - p.read_pos < pub_size) return FALSE;
    UINT32 max_end = p.read_pos + pub_size;

    UINT16 type = read_16(&p);
    UINT16 name_alg = read_16(&p);
    if (type != TPM_ALG_RSA || name_alg != TPM_ALG_SHA256) return FALSE;

    UINT32 attrs = read_32(&p);
    if (attrs != 0x00050072) {
        return FALSE;
    }

    UINT16 auth_policy_size = read_16(&p);
    if (auth_policy_size != 0 || p.size - p.read_pos < auth_policy_size || p.read_pos + auth_policy_size > max_end) return FALSE;
    p.read_pos += auth_policy_size;

    if (p.read_pos + 12 > max_end) return FALSE;
    if (read_16(&p) != TPM_ALG_NULL) return FALSE;
    if (read_16(&p) != TPM_ALG_RSASSA) return FALSE;
    if (read_16(&p) != TPM_ALG_SHA256) return FALSE;
    if (read_16(&p) != 2048) return FALSE;
    UINT32 exp = read_32(&p);
    if (exp != 0 && exp != 65537) return FALSE;

    if (p.read_pos + 2 > max_end) return FALSE;
    UINT16 mod_size = read_16(&p);
    if (mod_size != 256 || p.read_pos + mod_size > max_end) return FALSE;

    out_ak_name[0] = 0x00;
    out_ak_name[1] = 0x0B;
    calculate_sha256(ak_pub_tpm2b + 2, pub_size, out_ak_name + 2);

    if (reported_ak_name_size != 34 || memcmp(reported_ak_name, out_ak_name, 34) != 0) {
        return FALSE;
    }

    BYTE qn_seed_concat[38] = { 0 };
    qn_seed_concat[0] = 0x40;
    qn_seed_concat[1] = 0x00;
    qn_seed_concat[2] = 0x00;
    qn_seed_concat[3] = 0x0B;
    memcpy(qn_seed_concat + 4, out_ak_name, 34);

    out_expected_qn[0] = 0x00;
    out_expected_qn[1] = 0x0B;
    calculate_sha256(qn_seed_concat, sizeof(qn_seed_concat), out_expected_qn + 2);

    if (reported_ak_qn && reported_ak_qn_size > 0) {
        if (reported_ak_qn_size != 34 || memcmp(reported_ak_qn, out_expected_qn, 34) != 0) {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOL tpm_activate_credential(TBS_HCONTEXT h_tbs_context, UINT32 ak_handle, UINT32 ek_handle, UINT32 policy_session_handle,
    const BYTE* blob, UINT16 blob_size,
    const BYTE* secret, UINT16 secret_size,
    BYTE* out_decrypted, UINT16* out_decrypted_size) {
    if (!h_tbs_context || ak_handle == 0 || ek_handle == 0 || !blob || blob_size == 0 || !secret || secret_size == 0 || !out_decrypted || !out_decrypted_size) return FALSE;
    *out_decrypted_size = 0;

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
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);
    write_32(&b, policy_session_handle);
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);

    write_2b(&b, blob, blob_size);
    write_2b(&b, secret, secret_size);
    patch_32(cmd, 2, b.write_pos);

    BYTE resp[2048];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;
    if (resp_size < 10) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    UINT16 tag = read_16(&p);
    read_32(&p);
    if (read_32(&p) != 0) return FALSE;
    if (tag == TPM_ST_SESSIONS) read_32(&p);

    *out_decrypted_size = read_2b(&p, out_decrypted, 128);
    return (*out_decrypted_size > 0);
}

static BOOL tpm_enumerate_persistent_handles(TBS_HCONTEXT h_tbs_context, UINT32* out_handles, UINT32* out_count) {
    if (!h_tbs_context || !out_handles || !out_count) return FALSE;
    *out_count = 0;

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
    if (resp_size < 10) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    read_16(&p); read_32(&p);
    if (read_32(&p) != 0) return FALSE;

    read_8(&p);
    if (read_32(&p) != 0x00000001) return FALSE;

    UINT32 count = read_32(&p);
    if (count > 64) count = 64;
    if (p.size - p.read_pos < count * 4) return FALSE;
    *out_count = count;

    for (UINT32 i = 0; i < count; i++) {
        out_handles[i] = read_32(&p);
    }
    return TRUE;
}

static BOOL execute_possession_challenge(
    TBS_HCONTEXT h_tbs_context,
    PCCERT_CONTEXT ek_cert,
    UINT32 ek_handle,
    UINT32 ak_handle,
    const BYTE* ak_name,
    UINT16 ak_name_size,
    BYTE out_secret[32])
{
    if (!h_tbs_context || !ek_cert || ek_handle == 0 || ak_handle == 0 || !ak_name || ak_name_size == 0) return FALSE;

    UINT32 policy_session = 0;
    if (!tpm_start_auth_session(h_tbs_context, &policy_session)) return FALSE;

    if (!tpm_policy_secret(h_tbs_context, policy_session)) {
        tpm_flush_context(h_tbs_context, policy_session);
        return FALSE;
    }

    BYTE challenge[32];
    if (BCryptGenRandom(NULL, challenge, sizeof(challenge), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        tpm_flush_context(h_tbs_context, policy_session);
        return FALSE;
    }

    BYTE blob[1024];
    UINT16 blob_size = 0;
    BYTE secret[1024];
    UINT16 secret_size = 0;
    if (!local_software_make_credential(ek_cert, challenge, sizeof(challenge), ak_name, ak_name_size, blob, &blob_size, secret, &secret_size)) {
        SecureZeroMemory(challenge, sizeof(challenge));
        tpm_flush_context(h_tbs_context, policy_session);
        return FALSE;
    }

    BYTE decrypted_challenge[128];
    UINT16 decrypted_size = 0;
    BOOL validated = tpm_activate_credential(h_tbs_context, ak_handle, ek_handle, policy_session, blob, blob_size, secret, secret_size, decrypted_challenge, &decrypted_size);

    tpm_flush_context(h_tbs_context, policy_session);

    BOOL match = (validated && decrypted_size == 32 && memcmp(challenge, decrypted_challenge, 32) == 0);
    if (match && out_secret) {
        memcpy(out_secret, challenge, 32);
    }
    SecureZeroMemory(challenge, sizeof(challenge));
    SecureZeroMemory(decrypted_challenge, sizeof(decrypted_challenge));
    return match;
}

static BOOL read_ncrypt_property_bytes(NCRYPT_PROV_HANDLE h_prov, LPCWSTR prop, BYTE** out_buf, DWORD* out_size) {
    DWORD size = 0;
    SECURITY_STATUS s;
    BYTE* buf;

    if (!h_prov || !prop || !out_buf || !out_size) return FALSE;
    *out_buf = NULL;
    *out_size = 0;

    s = NCryptGetProperty(h_prov, prop, NULL, 0, &size, 0);
    if (s != ERROR_SUCCESS && s != NTE_BUFFER_TOO_SMALL) return FALSE;
    if (size == 0) return FALSE;

    buf = (BYTE*)malloc(size);
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

static BOOL read_ncrypt_property_string(NCRYPT_PROV_HANDLE h_prov, LPCWSTR prop, char* out, size_t out_chars) {
    DWORD size = 0;
    SECURITY_STATUS s;
    WCHAR* w_buf = NULL;

    if (!h_prov || !prop || !out || out_chars == 0) return FALSE;
    out[0] = '\0';

    s = NCryptGetProperty(h_prov, prop, NULL, 0, &size, 0);
    if (s != ERROR_SUCCESS && s != NTE_BUFFER_TOO_SMALL) return FALSE;
    if (size == 0) return TRUE;

    w_buf = (WCHAR*)calloc(1, size + sizeof(WCHAR));
    if (!w_buf) return FALSE;

    s = NCryptGetProperty(h_prov, prop, (PBYTE)w_buf, size, &size, 0);
    if (s != ERROR_SUCCESS) {
        free(w_buf);
        return FALSE;
    }

    w_buf[size / sizeof(WCHAR)] = L'\0';
    int cb_out = (out_chars > 0x7FFFFFFF) ? 0x7FFFFFFF : (int)out_chars;
    if (!WideCharToMultiByte(CP_UTF8, 0, w_buf, -1, out, cb_out, NULL, NULL)) {
        free(w_buf);
        out[0] = '\0';
        return FALSE;
    }

    free(w_buf);
    return TRUE;
}

static void parse_platform_type_string(TPMINFO* info) {
    if (!info) return;

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
    if (!info) return FALSE;
    if (info->ekPub) {
        free(info->ekPub);
        info->ekPub = NULL;
    }
    ZeroMemory(info, sizeof(*info));
    NCRYPT_PROV_HANDLE h_prov = 0;
    SECURITY_STATUS s;

    s = NCryptOpenStorageProvider(&h_prov, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (s != ERROR_SUCCESS) return FALSE;

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

    TBS_CONTEXT_PARAMS2 params = { 0 };
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;
    TBS_HCONTEXT h_tbs_context = 0;
    BOOL nvram_success = FALSE;

    if (Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &h_tbs_context) == TBS_SUCCESS) {
        UINT32 handles[64] = { 0 };
        UINT32 handle_count = 0;
        UINT32 ek_handle = 0;
        if (tpm_enumerate_persistent_handles(h_tbs_context, handles, &handle_count)) {
            for (UINT32 i = 0; i < handle_count; i++) {
                if (handles[i] >= 0x81010000 && handles[i] <= 0x810100FF) {
                    BYTE* ek_pub_tpm2b = NULL;
                    DWORD ek_pub_tpm2b_size = 0;
                    if (tpm_read_public_area(h_tbs_context, handles[i], &ek_pub_tpm2b, &ek_pub_tpm2b_size)) {
                        if (ek_pub_tpm2b_size >= 4 && ((ek_pub_tpm2b[2] << 8) | ek_pub_tpm2b[3]) == TPM_ALG_RSA) {
                            ek_handle = handles[i];
                            DWORD bcrypt_blob_size = 0;
                            BYTE* bcrypt_blob = tpm_public_to_bcrypt_blob(ek_pub_tpm2b, ek_pub_tpm2b_size, &bcrypt_blob_size);
                            if (bcrypt_blob) {
                                info->ekPub = bcrypt_blob;
                                info->ekPubSize = bcrypt_blob_size;
                                sha256_hex(info->ekPub, info->ekPubSize, info->ekPubSha256);
                                nvram_success = TRUE;
                            }
                            free(ek_pub_tpm2b);
                            break;
                        }
                        free(ek_pub_tpm2b);
                    }
                }
            }
        }
        if (!nvram_success) {
            UINT32 dynamic_ek_handle = 0;
            if (tpm_create_primary_ek(h_tbs_context, &dynamic_ek_handle)) {
                BYTE* ek_pub_tpm2b = NULL;
                DWORD ek_pub_tpm2b_size = 0;
                if (tpm_read_public_area(h_tbs_context, dynamic_ek_handle, &ek_pub_tpm2b, &ek_pub_tpm2b_size)) {
                    DWORD bcrypt_blob_size = 0;
                    BYTE* bcrypt_blob = tpm_public_to_bcrypt_blob(ek_pub_tpm2b, ek_pub_tpm2b_size, &bcrypt_blob_size);
                    if (bcrypt_blob) {
                        info->ekPub = bcrypt_blob;
                        info->ekPubSize = bcrypt_blob_size;
                        sha256_hex(info->ekPub, info->ekPubSize, info->ekPubSha256);
                        nvram_success = TRUE;
                    }
                    free(ek_pub_tpm2b);
                }
                tpm_flush_context(h_tbs_context, dynamic_ek_handle);
            }
        }
        Tbsip_Context_Close(h_tbs_context);
    }

    if (!nvram_success) {
        if (read_ncrypt_property_bytes(h_prov, NCRYPT_PCP_EKPUB_PROPERTY, &info->ekPub, &info->ekPubSize)) {
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
    if (!h_prov || !out_store) return FALSE;
    *out_store = NULL;

    s = NCryptGetProperty(h_prov, NCRYPT_PCP_EKCERT_PROPERTY, (PBYTE)&h_store, sizeof(h_store), &size, 0);
    if (s != ERROR_SUCCESS || !h_store) return FALSE;

    *out_store = h_store;
    return TRUE;
}

static void load_certs_from_pcp_property_store(NCRYPT_PROV_HANDLE h_prov, LPCWSTR prop_name, HCERTSTORE h_store_to_add_to) {
    if (!h_prov || !prop_name || !h_store_to_add_to) return;
    HCERTSTORE h_pcp_store = NULL;
    DWORD cb_store = sizeof(h_pcp_store);
    SECURITY_STATUS s = NCryptGetProperty(h_prov, prop_name, (PBYTE)&h_pcp_store, sizeof(h_pcp_store), &cb_store, 0);
    if (s == ERROR_SUCCESS && h_pcp_store) {
        PCCERT_CONTEXT c = NULL;
        while ((c = CertEnumCertificatesInStore(h_pcp_store, c)) != NULL) {
            CertAddCertificateContextToStore(h_store_to_add_to, c, CERT_STORE_ADD_NEW, NULL);
        }
        CertCloseStore(h_pcp_store, 0);
    }
}

static void load_pcp_intermediate_certs(HCERTSTORE store) {
    if (!store) return;
    NCRYPT_PROV_HANDLE h_prov = 0;
    if (NCryptOpenStorageProvider(&h_prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) == ERROR_SUCCESS) {
        load_certs_from_pcp_property_store(h_prov, L"PCP_RSA_EKNVCERT", store);
        load_certs_from_pcp_property_store(h_prov, L"PCP_ECC_EKNVCERT", store);
        load_certs_from_pcp_property_store(h_prov, L"PCP_EKNVCERT", store);
        load_certs_from_pcp_property_store(h_prov, L"PCP_INTERMEDIATE_CA_EKCERT", store);
        NCryptFreeObject(h_prov);
    }
}

static void load_certs_from_registry_recursive(HKEY h_key, HCERTSTORE store, WCHAR* sz_value_name, int depth) {
    DWORD dw_index = 0;
    DWORD cb_value_name = 16384;
    DWORD dw_type = 0;
    BYTE* lp_data = NULL;
    DWORD cb_data = 0;

    if (!h_key || !store || !sz_value_name || depth > 16) return;

    while (TRUE) {
        cb_value_name = 16384;
        cb_data = 0;
        LONG l_result = RegEnumValueW(h_key, dw_index, sz_value_name, &cb_value_name, NULL, &dw_type, NULL, &cb_data);
        if (l_result == ERROR_NO_MORE_ITEMS) break;

        if (l_result == ERROR_SUCCESS || l_result == ERROR_MORE_DATA) {
            if (dw_type == REG_BINARY && cb_data > 0 && cb_data <= 65536) {
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
    while (TRUE) {
        DWORD cb_sub_key_name = _countof(sz_sub_key_name);
        LONG l_result = RegEnumKeyExW(h_key, dw_index, sz_sub_key_name, &cb_sub_key_name, NULL, NULL, NULL, NULL);
        if (l_result == ERROR_NO_MORE_ITEMS) break;
        if (l_result == ERROR_SUCCESS) {
            HKEY h_sub_key = NULL;
            if (RegOpenKeyExW(h_key, sz_sub_key_name, 0, KEY_READ, &h_sub_key) == ERROR_SUCCESS) {
                load_certs_from_registry_recursive(h_sub_key, store, sz_value_name, depth + 1);
                RegCloseKey(h_sub_key);
            }
        }
        dw_index++;
    }
}

static void load_tpm_intermediate_certs_from_registry(HCERTSTORE store) {
    if (!store) return;
    HKEY h_key = NULL;
    WCHAR* sz_value_name = (WCHAR*)malloc(16384 * sizeof(WCHAR));
    if (!sz_value_name) return;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement", 0, KEY_READ, &h_key) == ERROR_SUCCESS) {
        load_certs_from_registry_recursive(h_key, store, sz_value_name, 0);
        RegCloseKey(h_key);
    }
    free(sz_value_name);
}

BOOL build_candidate_issuer_store(HCERTSTORE h_cab_store, HCERTSTORE* out_store) {
    if (!out_store) return FALSE;
    *out_store = NULL;

    HCERTSTORE h_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!h_store) return FALSE;

    if (h_cab_store) {
        PCCERT_CONTEXT c = NULL;
        while ((c = CertEnumCertificatesInStore(h_cab_store, c)) != NULL) {
            CertAddCertificateContextToStore(h_store, c, CERT_STORE_ADD_ALWAYS, NULL);
        }
    }

    load_tpm_intermediate_certs_from_registry(h_store);
    load_pcp_intermediate_certs(h_store);

    *out_store = h_store;
    return TRUE;
}

static BOOL tpm_quote(TBS_HCONTEXT h_tbs_context, UINT32 ak_handle, const BYTE* nonce, UINT16 nonce_size, BYTE* out_attest, UINT16* out_attest_size, BYTE* out_sig, UINT16* out_sig_size) {
    if (!h_tbs_context || ak_handle == 0 || !nonce || nonce_size == 0) return FALSE;
    if (out_attest_size) *out_attest_size = 0;
    if (out_sig_size) *out_sig_size = 0;

    BYTE cmd[1024];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_Quote);
    write_32(&b, ak_handle);

    write_32(&b, 9);
    write_32(&b, TPM_RS_PW);
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);

    write_2b(&b, nonce, nonce_size);
    write_16(&b, TPM_ALG_NULL);

    write_32(&b, 1);
    write_16(&b, TPM_ALG_SHA256);
    write_8(&b, 3);
    write_8(&b, 0xFE);
    write_8(&b, 0x78);
    write_8(&b, 0x00);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[4096];
    UINT32 resp_size = sizeof(resp);
    if (!send_tpm_command(h_tbs_context, cmd, b.write_pos, resp, &resp_size)) return FALSE;
    if (resp_size < 10) return FALSE;

    buf_parser p;
    init_parser(&p, resp, resp_size);
    UINT16 tag = read_16(&p);
    read_32(&p);
    if (read_32(&p) != 0) return FALSE;
    if (tag == TPM_ST_SESSIONS) read_32(&p);

    UINT16 attest_size = read_16(&p);
    if (attest_size == 0 || attest_size > 1024 || p.size - p.read_pos < attest_size) return FALSE;
    if (out_attest && out_attest_size) {
        memcpy(out_attest, p.buf + p.read_pos, attest_size);
        *out_attest_size = attest_size;
    }
    p.read_pos += attest_size;

    if (p.size - p.read_pos < 6) return FALSE;
    if (read_16(&p) != TPM_ALG_RSASSA || read_16(&p) != TPM_ALG_SHA256) return FALSE;

    UINT16 sig_size = read_16(&p);
    if (sig_size == 0 || sig_size > 512 || p.size - p.read_pos < sig_size) return FALSE;
    if (out_sig && out_sig_size) {
        memcpy(out_sig, p.buf + p.read_pos, sig_size);
        *out_sig_size = sig_size;
    }
    return TRUE;
}

static BOOL verify_quote_signature(const BYTE* attest_bytes, UINT16 attest_size, const BYTE* sig_bytes, UINT16 sig_size, const BYTE* ak_pub_tpm2b, DWORD ak_pub_tpm2b_size) {
    if (!attest_bytes || attest_size == 0 || !sig_bytes || sig_size == 0 || !ak_pub_tpm2b || ak_pub_tpm2b_size == 0) return FALSE;

    DWORD bcrypt_blob_size = 0;
    BYTE* bcrypt_blob = tpm_public_to_bcrypt_blob(ak_pub_tpm2b, ak_pub_tpm2b_size, &bcrypt_blob_size);
    if (!bcrypt_blob) return FALSE;

    BCRYPT_ALG_HANDLE h_rsa_alg = NULL;
    BCRYPT_KEY_HANDLE h_key = NULL;
    BYTE attest_hash[32];

    if (!calculate_sha256(attest_bytes, attest_size, attest_hash)) {
        free(bcrypt_blob);
        return FALSE;
    }

    if (BCryptOpenAlgorithmProvider(&h_rsa_alg, BCRYPT_RSA_ALGORITHM, NULL, 0) != STATUS_SUCCESS) {
        free(bcrypt_blob);
        return FALSE;
    }

    if (BCryptImportKeyPair(h_rsa_alg, NULL, BCRYPT_RSAPUBLIC_BLOB, &h_key, bcrypt_blob, bcrypt_blob_size, 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(h_rsa_alg, 0);
        free(bcrypt_blob);
        return FALSE;
    }

    BCRYPT_PKCS1_PADDING_INFO pad_info = { 0 };
    pad_info.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    NTSTATUS status = BCryptVerifySignature(h_key, &pad_info, attest_hash, sizeof(attest_hash), (PUCHAR)sig_bytes, sig_size, BCRYPT_PAD_PKCS1);

    BCryptDestroyKey(h_key);
    BCryptCloseAlgorithmProvider(h_rsa_alg, 0);
    free(bcrypt_blob);
    return (status == STATUS_SUCCESS);
}

static BOOL parse_and_verify_attest_structure(
    const BYTE* attest_bytes, UINT16 attest_size,
    const BYTE* expected_nonce, UINT16 expected_nonce_size,
    const BYTE* expected_qn, UINT16 expected_qn_size,
    BYTE* out_pcr_digest, UINT16* out_pcr_digest_size)
{
    if (!attest_bytes || attest_size < 37 || !expected_nonce || expected_nonce_size == 0) return FALSE;
    if (out_pcr_digest_size) *out_pcr_digest_size = 0;

    buf_parser p;
    init_parser(&p, attest_bytes, attest_size);

    if (read_32(&p) != 0xFF544347) return FALSE;
    if (read_16(&p) != 0x8018) return FALSE;

    UINT16 qualified_signer_size = read_16(&p);
    if (p.size - p.read_pos < qualified_signer_size) return FALSE;
    if (expected_qn && expected_qn_size > 0) {
        if (qualified_signer_size != expected_qn_size || memcmp(p.buf + p.read_pos, expected_qn, qualified_signer_size) != 0) {
            printf("[!] Quote verification failed: Qualified Signer mismatch.\n");
            return FALSE;
        }
    }
    p.read_pos += qualified_signer_size;

    UINT16 extra_data_size = read_16(&p);
    if (p.size - p.read_pos < extra_data_size) return FALSE;
    if (extra_data_size != expected_nonce_size || memcmp(p.buf + p.read_pos, expected_nonce, extra_data_size) != 0) {
        printf("[!] Quote verification failed: Nonce mismatch.\n");
        return FALSE;
    }
    p.read_pos += extra_data_size;

    if (p.size - p.read_pos < 25) return FALSE;
    UINT64 tpm_clock = read_64(&p);
    read_32(&p);
    read_32(&p);
    BYTE safe = read_8(&p);

    if (tpm_clock == 0 || safe != 1) {
        printf("[!] Quote rejected: TPM hardware clock is non-functional (zero).\n");
        return FALSE;
    }

    read_64(&p);

    if (p.size - p.read_pos < 12) return FALSE;
    if (read_32(&p) != 1) return FALSE;
    if (read_16(&p) != TPM_ALG_SHA256) return FALSE;
    if (read_8(&p) != 3) return FALSE;
    if (read_8(&p) != 0xFE) return FALSE;
    if (read_8(&p) != 0x78) return FALSE;
    if (read_8(&p) != 0x00) return FALSE;

    UINT16 digest_size = read_16(&p);
    if (digest_size != 32 || p.size - p.read_pos < digest_size) return FALSE;

    if (out_pcr_digest && out_pcr_digest_size) {
        memcpy(out_pcr_digest, p.buf + p.read_pos, digest_size);
        *out_pcr_digest_size = digest_size;
    }
    return TRUE;
}

BOOL tpm_generate_quote_and_verify(TBS_HCONTEXT h_tbs_context, PCCERT_CONTEXT ek_cert, const BYTE* expected_pcr_digest, BOOL* out_quote_verified) {
    if (!h_tbs_context || !ek_cert || !expected_pcr_digest || !out_quote_verified) return FALSE;
    *out_quote_verified = FALSE;

    UINT32 handles[64] = { 0 };
    UINT32 handle_count = 0;
    UINT32 ek_handle = 0;
    BOOL ek_is_transient = FALSE;

    if (tpm_enumerate_persistent_handles(h_tbs_context, handles, &handle_count)) {
        for (UINT32 i = 0; i < handle_count; i++) {
            if (handles[i] >= 0x81010000 && handles[i] <= 0x810100FF) {
                BYTE* ek_pub_tpm2b = NULL;
                DWORD ek_pub_tpm2b_size = 0;
                if (tpm_read_public_area(h_tbs_context, handles[i], &ek_pub_tpm2b, &ek_pub_tpm2b_size)) {
                    if (ek_pub_tpm2b_size >= 4 && ((ek_pub_tpm2b[2] << 8) | ek_pub_tpm2b[3]) == TPM_ALG_RSA) {
                        DWORD bcrypt_blob_size = 0;
                        BYTE* bcrypt_blob = tpm_public_to_bcrypt_blob(ek_pub_tpm2b, ek_pub_tpm2b_size, &bcrypt_blob_size);
                        if (bcrypt_blob) {
                            if (ekpub_matches_cert(ek_cert, bcrypt_blob, bcrypt_blob_size)) {
                                ek_handle = handles[i];
                                ek_is_transient = FALSE;
                                free(bcrypt_blob);
                                free(ek_pub_tpm2b);
                                break;
                            }
                            free(bcrypt_blob);
                        }
                    }
                    free(ek_pub_tpm2b);
                }
            }
        }
    }

    if (ek_handle == 0) {
        UINT32 dynamic_ek_handle = 0;
        if (tpm_create_primary_ek(h_tbs_context, &dynamic_ek_handle)) {
            BYTE* ek_pub_tpm2b = NULL;
            DWORD ek_pub_tpm2b_size = 0;
            if (tpm_read_public_area(h_tbs_context, dynamic_ek_handle, &ek_pub_tpm2b, &ek_pub_tpm2b_size)) {
                DWORD bcrypt_blob_size = 0;
                BYTE* bcrypt_blob = tpm_public_to_bcrypt_blob(ek_pub_tpm2b, ek_pub_tpm2b_size, &bcrypt_blob_size);
                if (bcrypt_blob) {
                    if (ekpub_matches_cert(ek_cert, bcrypt_blob, bcrypt_blob_size)) {
                        ek_handle = dynamic_ek_handle;
                        ek_is_transient = TRUE;
                    }
                    free(bcrypt_blob);
                }
                free(ek_pub_tpm2b);
            }
            if (ek_handle == 0) {
                tpm_flush_context(h_tbs_context, dynamic_ek_handle);
            }
        }
    }

    if (ek_handle == 0) return FALSE;

    UINT32 ak_handle = 0;
    if (!tpm_create_primary_ak(h_tbs_context, &ak_handle)) {
        if (ek_is_transient) tpm_flush_context(h_tbs_context, ek_handle);
        return FALSE;
    }

    BYTE* ak_pub_tpm2b = NULL;
    DWORD ak_pub_tpm2b_size = 0;
    if (!tpm_read_public_area(h_tbs_context, ak_handle, &ak_pub_tpm2b, &ak_pub_tpm2b_size)) {
        tpm_flush_context(h_tbs_context, ak_handle);
        if (ek_is_transient) tpm_flush_context(h_tbs_context, ek_handle);
        return FALSE;
    }

    BYTE reported_ak_name[128];
    UINT16 reported_ak_name_size = 0;
    BYTE reported_ak_qn[128];
    UINT16 reported_ak_qn_size = 0;
    if (!tpm_read_public(h_tbs_context, ak_handle, reported_ak_name, &reported_ak_name_size, reported_ak_qn, &reported_ak_qn_size)) {
        free(ak_pub_tpm2b);
        tpm_flush_context(h_tbs_context, ak_handle);
        if (ek_is_transient) tpm_flush_context(h_tbs_context, ek_handle);
        return FALSE;
    }

    BYTE computed_ak_name[34];
    BYTE expected_ak_qn[34];
    if (!validate_and_compute_ak_names(ak_pub_tpm2b, ak_pub_tpm2b_size, reported_ak_name, reported_ak_name_size, reported_ak_qn, reported_ak_qn_size, computed_ak_name, expected_ak_qn)) {
        free(ak_pub_tpm2b);
        tpm_flush_context(h_tbs_context, ak_handle);
        if (ek_is_transient) tpm_flush_context(h_tbs_context, ek_handle);
        return FALSE;
    }

    BYTE decrypted_secret[32];
    if (!execute_possession_challenge(h_tbs_context, ek_cert, ek_handle, ak_handle, computed_ak_name, sizeof(computed_ak_name), decrypted_secret)) {
        free(ak_pub_tpm2b);
        tpm_flush_context(h_tbs_context, ak_handle);
        if (ek_is_transient) tpm_flush_context(h_tbs_context, ek_handle);
        return FALSE;
    }

    BYTE client_nonce[32];
    if (BCryptGenRandom(NULL, client_nonce, sizeof(client_nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        SecureZeroMemory(decrypted_secret, sizeof(decrypted_secret));
        free(ak_pub_tpm2b);
        tpm_flush_context(h_tbs_context, ak_handle);
        if (ek_is_transient) tpm_flush_context(h_tbs_context, ek_handle);
        return FALSE;
    }

    BYTE nonce_binding_input[64];
    memcpy(nonce_binding_input, client_nonce, 32);
    memcpy(nonce_binding_input + 32, decrypted_secret, 32);
    SecureZeroMemory(decrypted_secret, sizeof(decrypted_secret));

    BYTE bound_quote_nonce[32];
    calculate_sha256(nonce_binding_input, sizeof(nonce_binding_input), bound_quote_nonce);
    SecureZeroMemory(nonce_binding_input, sizeof(nonce_binding_input));

    BYTE attest_bytes[1024];
    UINT16 attest_size = 0;
    BYTE sig_bytes[512];
    UINT16 sig_size = 0;

    if (!tpm_quote(h_tbs_context, ak_handle, bound_quote_nonce, sizeof(bound_quote_nonce), attest_bytes, &attest_size, sig_bytes, &sig_size)) {
        free(ak_pub_tpm2b);
        tpm_flush_context(h_tbs_context, ak_handle);
        if (ek_is_transient) tpm_flush_context(h_tbs_context, ek_handle);
        return FALSE;
    }
    tpm_flush_context(h_tbs_context, ak_handle);

    if (!verify_quote_signature(attest_bytes, attest_size, sig_bytes, sig_size, ak_pub_tpm2b, ak_pub_tpm2b_size)) {
        free(ak_pub_tpm2b);
        if (ek_is_transient) tpm_flush_context(h_tbs_context, ek_handle);
        return FALSE;
    }
    free(ak_pub_tpm2b);

    BYTE signed_pcr_digest[32];
    UINT16 signed_pcr_digest_size = 0;
    if (!parse_and_verify_attest_structure(attest_bytes, attest_size, bound_quote_nonce, sizeof(bound_quote_nonce), expected_ak_qn, sizeof(expected_ak_qn), signed_pcr_digest, &signed_pcr_digest_size)) {
        if (ek_is_transient) tpm_flush_context(h_tbs_context, ek_handle);
        return FALSE;
    }

    if (signed_pcr_digest_size == 32) {
        *out_quote_verified = (memcmp(signed_pcr_digest, expected_pcr_digest, 32) == 0);
    }

    if (ek_is_transient) {
        tpm_flush_context(h_tbs_context, ek_handle);
    }
    return TRUE;
}