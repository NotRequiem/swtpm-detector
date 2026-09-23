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

BOOL tpm_pcr_extend(TBS_HCONTEXT hContext, UINT32 pcrIndex, const BYTE* digest32) {
    if (!hContext || !digest32) return FALSE;
    BYTE cmd[128];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_PCR_Extend);
    write_32(&b, pcrIndex);

    write_32(&b, 9);
    write_32(&b, TPM_RS_PW);
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);

    write_32(&b, 1);
    write_16(&b, TPM_ALG_SHA256);
    write_buf(&b, digest32, 32);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[256];
    UINT32 respSize = sizeof(resp);
    if (!send_tpm_command(hContext, cmd, b.write_pos, resp, &respSize)) return FALSE;
    if (respSize < 10) return FALSE;

    buf_parser p;
    init_parser(&p, resp, respSize);
    read_16(&p); read_32(&p);
    return (read_32(&p) == 0);
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

static BOOL hmac_sha256(const BYTE* key, DWORD keyLen, const BYTE* data, DWORD dataLen, BYTE outMac[32]) {
    if (!key || keyLen == 0 || !data || dataLen == 0 || !outMac) return FALSE;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbObj = 0, cbData = sizeof(DWORD);
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != STATUS_SUCCESS) return FALSE;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbObj, cbData, &cbData, 0);
    if (status != STATUS_SUCCESS || cbObj == 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    BYTE* obj = (BYTE*)malloc(cbObj);
    if (!obj) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    status = BCryptCreateHash(hAlg, &hHash, obj, cbObj, (PUCHAR)key, keyLen, 0);
    if (status == STATUS_SUCCESS) {
        status = BCryptHashData(hHash, (PUCHAR)data, dataLen, 0);
        if (status == STATUS_SUCCESS) {
            status = BCryptFinishHash(hHash, outMac, 32, 0);
        }
        BCryptDestroyHash(hHash);
    }
    free(obj);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return (status == STATUS_SUCCESS);
}

static BOOL aes_128_ecb_encrypt_block(const BYTE key[16], const BYTE in[16], BYTE out[16]) {
    if (!key || !in || !out) return FALSE;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbObj = 0, cbData = sizeof(DWORD);
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) return FALSE;
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbObj, cbData, &cbData, 0);
    if (status != STATUS_SUCCESS || cbObj == 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    BYTE* obj = (BYTE*)malloc(cbObj);
    if (!obj) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, obj, cbObj, (PUCHAR)key, 16, 0);
    if (status == STATUS_SUCCESS) {
        DWORD res = 0;
        status = BCryptEncrypt(hKey, (PUCHAR)in, 16, NULL, NULL, 0, out, 16, &res, 0);
        BCryptDestroyKey(hKey);
    }
    free(obj);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return (status == STATUS_SUCCESS);
}

static BOOL local_software_make_credential(
    PCCERT_CONTEXT ekCert,
    const BYTE* challenge,
    UINT16 challengeSize,
    const BYTE* akName,
    UINT16 akNameSize,
    BYTE* outBlob,
    UINT16* outBlobSize,
    BYTE* outSecret,
    UINT16* outSecretSize)
{
    if (!ekCert || !ekCert->pCertInfo || !challenge || challengeSize == 0 || challengeSize > 32 ||
        !akName || akNameSize == 0 || akNameSize > 64 ||
        !outBlob || !outBlobSize || !outSecret || !outSecretSize) {
        return FALSE;
    }
    *outBlobSize = 0;
    *outSecretSize = 0;

    BCRYPT_KEY_HANDLE hEkKey = NULL;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &ekCert->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &hEkKey)) {
        return FALSE;
    }

    BYTE seed[32];
    if (BCryptGenRandom(NULL, seed, sizeof(seed), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        return FALSE;
    }

    BCRYPT_OAEP_PADDING_INFO oaep = { 0 };
    oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    oaep.pbLabel = (PUCHAR)"IDENTITY";
    oaep.cbLabel = 9;

    DWORD encSecretLen = 0;
    NTSTATUS status = BCryptEncrypt(hEkKey, seed, sizeof(seed), &oaep, NULL, 0, outSecret, 1024, &encSecretLen, BCRYPT_PAD_OAEP);
    BCryptDestroyKey(hEkKey);
    if (status != STATUS_SUCCESS || encSecretLen == 0 || encSecretLen > 1024) {
        SecureZeroMemory(seed, sizeof(seed));
        return FALSE;
    }
    *outSecretSize = (UINT16)encSecretLen;

    BYTE hmacInput[18];
    patch_32(hmacInput, 0, 1);
    memcpy(hmacInput + 4, "INTEGRITY", 10);
    patch_32(hmacInput, 14, 256);
    BYTE hmacKey[32];
    if (!hmac_sha256(seed, sizeof(seed), hmacInput, sizeof(hmacInput), hmacKey)) {
        SecureZeroMemory(seed, sizeof(seed));
        return FALSE;
    }

    BYTE storageInput[128];
    patch_32(storageInput, 0, 1);
    memcpy(storageInput + 4, "STORAGE", 8);
    memcpy(storageInput + 12, akName, akNameSize);
    patch_32(storageInput, 12 + akNameSize, 128);
    BYTE symKeyFull[32];
    if (!hmac_sha256(seed, sizeof(seed), storageInput, 16 + akNameSize, symKeyFull)) {
        SecureZeroMemory(seed, sizeof(seed));
        SecureZeroMemory(hmacKey, sizeof(hmacKey));
        return FALSE;
    }

    BYTE symKey[16];
    memcpy(symKey, symKeyFull, 16);
    SecureZeroMemory(seed, sizeof(seed));
    SecureZeroMemory(symKeyFull, sizeof(symKeyFull));

    BYTE pt[64] = { 0 };
    pt[0] = (challengeSize >> 8) & 0xFF;
    pt[1] = challengeSize & 0xFF;
    memcpy(pt + 2, challenge, challengeSize);
    UINT32 ptLen = 2 + challengeSize;

    BYTE ct[64] = { 0 };
    BYTE iv[16] = { 0 };
    BYTE pad[16] = { 0 };
    UINT32 pos = 0;
    while (pos < ptLen) {
        if (!aes_128_ecb_encrypt_block(symKey, iv, pad)) {
            SecureZeroMemory(symKey, sizeof(symKey));
            SecureZeroMemory(hmacKey, sizeof(hmacKey));
            return FALSE;
        }
        UINT32 chunk = ptLen - pos;
        if (chunk > 16) chunk = 16;
        for (UINT32 k = 0; k < chunk; k++) {
            ct[pos + k] = pt[pos + k] ^ pad[k];
            iv[k] = ct[pos + k];
        }
        pos += chunk;
    }
    SecureZeroMemory(symKey, sizeof(symKey));

    BYTE hmacTarget[128];
    memcpy(hmacTarget, ct, ptLen);
    memcpy(hmacTarget + ptLen, akName, akNameSize);
    BYTE outerHmac[32];
    if (!hmac_sha256(hmacKey, sizeof(hmacKey), hmacTarget, ptLen + akNameSize, outerHmac)) {
        SecureZeroMemory(hmacKey, sizeof(hmacKey));
        return FALSE;
    }
    SecureZeroMemory(hmacKey, sizeof(hmacKey));

    outBlob[0] = 0x00;
    outBlob[1] = 0x20;
    memcpy(outBlob + 2, outerHmac, 32);
    memcpy(outBlob + 34, ct, ptLen);
    *outBlobSize = (UINT16)(34 + ptLen);
    return TRUE;
}

static BOOL validate_and_compute_ak_names(
    const BYTE* akPubTpm2b,
    DWORD akPubTpm2bSize,
    const BYTE* reportedAkName,
    UINT16 reportedAkNameSize,
    BYTE outAkName[34],
    BYTE outExpectedQn[34])
{
    if (!akPubTpm2b || akPubTpm2bSize < 14 || !reportedAkName || !outAkName || !outExpectedQn) return FALSE;

    buf_parser p;
    init_parser(&p, akPubTpm2b, akPubTpm2bSize);
    UINT16 pubSize = read_16(&p);
    if (pubSize == 0 || p.size - p.read_pos < pubSize) return FALSE;
    UINT32 maxEnd = p.read_pos + pubSize;

    UINT16 type = read_16(&p);
    UINT16 nameAlg = read_16(&p);
    if (type != TPM_ALG_RSA || nameAlg != TPM_ALG_SHA256) return FALSE;

    UINT32 attrs = read_32(&p);
    if ((attrs & 0x00000002) == 0) return FALSE;
    if ((attrs & 0x00000010) == 0) return FALSE;
    if ((attrs & 0x00000020) == 0) return FALSE;
    if ((attrs & 0x00000040) == 0) return FALSE;
    if ((attrs & 0x00000080) != 0) return FALSE;
    if ((attrs & 0x00010000) == 0) return FALSE;
    if ((attrs & 0x00020000) != 0) return FALSE;
    if ((attrs & 0x00040000) == 0) return FALSE;

    UINT16 authPolicySize = read_16(&p);
    if (p.size - p.read_pos < authPolicySize || p.read_pos + authPolicySize > maxEnd) return FALSE;
    p.read_pos += authPolicySize;

    if (p.read_pos + 12 > maxEnd) return FALSE;
    if (read_16(&p) != TPM_ALG_NULL) return FALSE;
    if (read_16(&p) != TPM_ALG_RSASSA) return FALSE;
    if (read_16(&p) != TPM_ALG_SHA256) return FALSE;
    if (read_16(&p) != 2048) return FALSE;
    UINT32 exp = read_32(&p);
    if (exp != 0 && exp != 65537) return FALSE;

    if (p.read_pos + 2 > maxEnd) return FALSE;
    UINT16 modSize = read_16(&p);
    if (modSize != 256 || p.read_pos + modSize > maxEnd) return FALSE;

    outAkName[0] = 0x00;
    outAkName[1] = 0x0B;
    calculate_sha256(akPubTpm2b + 2, pubSize, outAkName + 2);

    if (reportedAkNameSize != 34 || memcmp(reportedAkName, outAkName, 34) != 0) {
        return FALSE;
    }

    BYTE qnSeedConcat[38] = { 0 };
    qnSeedConcat[0] = 0x40;
    qnSeedConcat[1] = 0x00;
    qnSeedConcat[2] = 0x00;
    qnSeedConcat[3] = 0x0B;
    memcpy(qnSeedConcat + 4, outAkName, 34);

    outExpectedQn[0] = 0x00;
    outExpectedQn[1] = 0x0B;
    calculate_sha256(qnSeedConcat, sizeof(qnSeedConcat), outExpectedQn + 2);
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
                    nvram_success = TRUE;
                }
                free(ek_pub_tpm2b);
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

static BOOL tpm_quote(TBS_HCONTEXT hContext, UINT32 akHandle, const BYTE* nonce, UINT16 nonceSize, BYTE* outAttest, UINT16* outAttestSize, BYTE* outSig, UINT16* outSigSize) {
    if (!hContext || akHandle == 0 || !nonce || nonceSize == 0) return FALSE;
    if (outAttestSize) *outAttestSize = 0;
    if (outSigSize) *outSigSize = 0;

    BYTE cmd[1024];
    buf_builder b;
    init_builder(&b, cmd, sizeof(cmd));

    write_16(&b, TPM_ST_SESSIONS);
    write_32(&b, 0);
    write_32(&b, TPM_CC_Quote);
    write_32(&b, akHandle);

    write_32(&b, 9);
    write_32(&b, TPM_RS_PW);
    write_16(&b, 0); write_8(&b, 0); write_16(&b, 0);

    write_2b(&b, nonce, nonceSize);
    write_16(&b, TPM_ALG_NULL);

    // TPML_PCR_SELECTION
    // count = 1 selection
    // alg = TPM_ALG_SHA256
    // sizeofSelect = 3 bytes
    // byte 0: 0xFE (PCRs 1, 2, 3, 4, 5, 6, 7 - PCR 0 strictly excluded)
    // byte 1: 0x78 (PCRs 11, 12, 13, 14: bit 3=11, bit 4=12, bit 5=13, bit 6=14)
    // byte 2: 0x01 (PCR 16: bit 0=16)
    write_32(&b, 1);
    write_16(&b, TPM_ALG_SHA256);
    write_8(&b, 3);
    write_8(&b, 0xFE);
    write_8(&b, 0x78);
    write_8(&b, 0x01);

    patch_32(cmd, 2, b.write_pos);

    BYTE resp[4096];
    UINT32 respSize = sizeof(resp);
    if (!send_tpm_command(hContext, cmd, b.write_pos, resp, &respSize)) return FALSE;
    if (respSize < 10) return FALSE;

    buf_parser p;
    init_parser(&p, resp, respSize);
    UINT16 tag = read_16(&p);
    read_32(&p);
    if (read_32(&p) != 0) return FALSE;
    if (tag == TPM_ST_SESSIONS) read_32(&p);

    UINT16 attestSize = read_16(&p);
    if (attestSize == 0 || attestSize > 1024 || p.size - p.read_pos < attestSize) return FALSE;
    if (outAttest && outAttestSize) {
        memcpy(outAttest, p.buf + p.read_pos, attestSize);
        *outAttestSize = attestSize;
    }
    p.read_pos += attestSize;

    if (p.size - p.read_pos < 6) return FALSE;
    if (read_16(&p) != TPM_ALG_RSASSA || read_16(&p) != TPM_ALG_SHA256) return FALSE;

    UINT16 sigSize = read_16(&p);
    if (sigSize == 0 || sigSize > 512 || p.size - p.read_pos < sigSize) return FALSE;
    if (outSig && outSigSize) {
        memcpy(outSig, p.buf + p.read_pos, sigSize);
        *outSigSize = sigSize;
    }
    return TRUE;
}

static BOOL verify_quote_signature(const BYTE* attestBytes, UINT16 attestSize, const BYTE* sigBytes, UINT16 sigSize, const BYTE* akPubTpm2b, DWORD akPubTpm2bSize) {
    if (!attestBytes || attestSize == 0 || !sigBytes || sigSize == 0 || !akPubTpm2b || akPubTpm2bSize == 0) return FALSE;

    DWORD bcryptBlobSize = 0;
    BYTE* bcryptBlob = tpm_public_to_bcrypt_blob(akPubTpm2b, akPubTpm2bSize, &bcryptBlobSize);
    if (!bcryptBlob) return FALSE;

    BCRYPT_ALG_HANDLE hRsaAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE attestHash[32];

    if (!calculate_sha256(attestBytes, attestSize, attestHash)) {
        free(bcryptBlob);
        return FALSE;
    }

    if (BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0) != STATUS_SUCCESS) {
        free(bcryptBlob);
        return FALSE;
    }

    if (BCryptImportKeyPair(hRsaAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hKey, bcryptBlob, bcryptBlobSize, 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
        free(bcryptBlob);
        return FALSE;
    }

    BCRYPT_PKCS1_PADDING_INFO padInfo = { 0 };
    padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    NTSTATUS status = BCryptVerifySignature(hKey, &padInfo, attestHash, sizeof(attestHash), (PUCHAR)sigBytes, sigSize, BCRYPT_PAD_PKCS1);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hRsaAlg, 0);
    free(bcryptBlob);
    return (status == STATUS_SUCCESS);
}

static BOOL parse_and_verify_attest_structure(
    const BYTE* attestBytes, UINT16 attestSize,
    const BYTE* expectedNonce, UINT16 expectedNonceSize,
    const BYTE* expectedQn, UINT16 expectedQnSize,
    BYTE* outPcrDigest, UINT16* outPcrDigestSize)
{
    if (!attestBytes || attestSize < 37 || !expectedNonce || expectedNonceSize == 0) return FALSE;
    if (outPcrDigestSize) *outPcrDigestSize = 0;

    buf_parser p;
    init_parser(&p, attestBytes, attestSize);

    if (read_32(&p) != 0xFF544347) return FALSE; // TPM_GENERATED_VALUE
    if (read_16(&p) != 0x8018) return FALSE;     // TPM_ST_ATTEST_QUOTE

    UINT16 qualifiedSignerSize = read_16(&p);
    if (p.size - p.read_pos < qualifiedSignerSize) return FALSE;
    if (expectedQn && expectedQnSize > 0) {
        if (qualifiedSignerSize != expectedQnSize || memcmp(p.buf + p.read_pos, expectedQn, qualifiedSignerSize) != 0) {
            printf("[!] Quote verification failed: Qualified Signer mismatch.\n");
            return FALSE;
        }
    }
    p.read_pos += qualifiedSignerSize;

    UINT16 extraDataSize = read_16(&p);
    if (p.size - p.read_pos < extraDataSize) return FALSE;
    if (extraDataSize != expectedNonceSize || memcmp(p.buf + p.read_pos, expectedNonce, extraDataSize) != 0) {
        printf("[!] Quote verification failed: Nonce mismatch.\n");
        return FALSE;
    }
    p.read_pos += extraDataSize;

    if (p.size - p.read_pos < 25) return FALSE;
    UINT64 tpmClock = read_64(&p);
    read_32(&p); // resetCount
    read_32(&p); // restartCount
    BYTE safe = read_8(&p);

    if (tpmClock == 0 || safe != 1) {
        printf("[!] Quote rejected: TPM hardware clock is non-functional (zero).\n");
        return FALSE;
    }

    read_64(&p); // fwVersionObfuscated

    if (p.size - p.read_pos < 12) return FALSE;
    if (read_32(&p) != 1) return FALSE;
    if (read_16(&p) != TPM_ALG_SHA256) return FALSE;
    if (read_8(&p) != 3) return FALSE;
    if (read_8(&p) != 0xFE) return FALSE; // PCRs 1..7 (bit 0 = 0)
    if (read_8(&p) != 0x78) return FALSE; // PCRs 11..14
    if (read_8(&p) != 0x01) return FALSE; // PCR 16

    UINT16 digestSize = read_16(&p);
    if (digestSize != 32 || p.size - p.read_pos < digestSize) return FALSE;

    if (outPcrDigest && outPcrDigestSize) {
        memcpy(outPcrDigest, p.buf + p.read_pos, digestSize);
        *outPcrDigestSize = digestSize;
    }
    return TRUE;
}

BOOL tpm_generate_quote_and_verify(TBS_HCONTEXT hTbsContext, PCCERT_CONTEXT ekCert, const BYTE* expectedPcrDigest, BOOL* outQuoteVerified) {
    if (!hTbsContext || !ekCert || !expectedPcrDigest || !outQuoteVerified) return FALSE;
    *outQuoteVerified = FALSE;

    UINT32 handles[64] = { 0 };
    UINT32 handle_count = 0;
    UINT32 preinstalled_ek_handle = 0;

    if (tpm_enumerate_persistent_handles(hTbsContext, handles, &handle_count)) {
        for (UINT32 i = 0; i < handle_count; i++) {
            if (handles[i] >= 0x81010000 && handles[i] <= 0x810100FF) {
                BYTE* ek_pub_tpm2b = NULL;
                DWORD ek_pub_tpm2b_size = 0;
                if (tpm_read_public_area(hTbsContext, handles[i], &ek_pub_tpm2b, &ek_pub_tpm2b_size)) {
                    DWORD bcrypt_blob_size = 0;
                    BYTE* bcrypt_blob = tpm_public_to_bcrypt_blob(ek_pub_tpm2b, ek_pub_tpm2b_size, &bcrypt_blob_size);
                    if (bcrypt_blob) {
                        if (ekpub_matches_cert(ekCert, bcrypt_blob, bcrypt_blob_size)) {
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

    if (preinstalled_ek_handle == 0) return FALSE;

    UINT32 akHandle = 0;
    if (!tpm_create_primary_ak(hTbsContext, &akHandle)) return FALSE;

    BYTE* akPubTpm2b = NULL;
    DWORD akPubTpm2bSize = 0;
    if (!tpm_read_public_area(hTbsContext, akHandle, &akPubTpm2b, &akPubTpm2bSize)) {
        tpm_flush_context(hTbsContext, akHandle);
        return FALSE;
    }

    BYTE reportedAkName[128];
    UINT16 reportedAkNameSize = 0;
    BYTE reportedAkQn[128];
    UINT16 reportedAkQnSize = 0;
    if (!tpm_read_public(hTbsContext, akHandle, reportedAkName, &reportedAkNameSize, reportedAkQn, &reportedAkQnSize)) {
        free(akPubTpm2b);
        tpm_flush_context(hTbsContext, akHandle);
        return FALSE;
    }

    BYTE computedAkName[34];
    BYTE expectedAkQn[34];
    if (!validate_and_compute_ak_names(akPubTpm2b, akPubTpm2bSize, reportedAkName, reportedAkNameSize, computedAkName, expectedAkQn)) {
        free(akPubTpm2b);
        tpm_flush_context(hTbsContext, akHandle);
        return FALSE;
    }

    BYTE decryptedSecret[32];
    if (!execute_possession_challenge(hTbsContext, ekCert, preinstalled_ek_handle, akHandle, computedAkName, sizeof(computedAkName), decryptedSecret)) {
        free(akPubTpm2b);
        tpm_flush_context(hTbsContext, akHandle);
        return FALSE;
    }

    BYTE clientNonce[32];
    if (BCryptGenRandom(NULL, clientNonce, sizeof(clientNonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        return FALSE;
    }

    BYTE nonceBindingInput[64];
    memcpy(nonceBindingInput, clientNonce, 32);
    memcpy(nonceBindingInput + 32, decryptedSecret, 32);
    SecureZeroMemory(decryptedSecret, sizeof(decryptedSecret));

    BYTE boundQuoteNonce[32];
    calculate_sha256(nonceBindingInput, sizeof(nonceBindingInput), boundQuoteNonce);
    SecureZeroMemory(nonceBindingInput, sizeof(nonceBindingInput));

    BYTE attestBytes[1024];
    UINT16 attestSize = 0;
    BYTE sigBytes[512];
    UINT16 sigSize = 0;

    if (!tpm_quote(hTbsContext, akHandle, boundQuoteNonce, sizeof(boundQuoteNonce), attestBytes, &attestSize, sigBytes, &sigSize)) {
        free(akPubTpm2b);
        tpm_flush_context(hTbsContext, akHandle);
        return FALSE;
    }
    tpm_flush_context(hTbsContext, akHandle);

    if (!verify_quote_signature(attestBytes, attestSize, sigBytes, sigSize, akPubTpm2b, akPubTpm2bSize)) {
        free(akPubTpm2b);
        return FALSE;
    }
    free(akPubTpm2b);

    BYTE signedPcrDigest[32];
    UINT16 signedPcrDigestSize = 0;
    if (!parse_and_verify_attest_structure(attestBytes, attestSize, boundQuoteNonce, sizeof(boundQuoteNonce), expectedAkQn, sizeof(expectedAkQn), signedPcrDigest, &signedPcrDigestSize)) {
        return FALSE;
    }

    if (signedPcrDigestSize == 32) {
        BYTE emptyPCRsZero[12 * 32] = { 0 };
        BYTE emptyPCRsFF[12 * 32];
        memset(emptyPCRsFF, 0xFF, sizeof(emptyPCRsFF));

        BYTE unextendedZeroDigest[32] = { 0 };
        BYTE unextendedFFDigest[32] = { 0 };
        calculate_sha256(emptyPCRsZero, sizeof(emptyPCRsZero), unextendedZeroDigest);
        calculate_sha256(emptyPCRsFF, sizeof(emptyPCRsFF), unextendedFFDigest);

        if (memcmp(signedPcrDigest, unextendedZeroDigest, 32) == 0 ||
            memcmp(signedPcrDigest, unextendedFFDigest, 32) == 0) {
            printf("[!] Idle/unextended PCR bank detected in Quote.\n");
            *outQuoteVerified = FALSE;
            return TRUE;
        }

        *outQuoteVerified = (memcmp(signedPcrDigest, expectedPcrDigest, 32) == 0);
    }
    return TRUE;
}