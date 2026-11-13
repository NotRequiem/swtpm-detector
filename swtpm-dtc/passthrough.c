#include "tpm.h"

static inline BOOL match_et(uint32_t actual, uint32_t expected_standard) {
    return (actual == expected_standard);
}

static BOOL match_unicode_name(const uint8_t* ptr, size_t num_chars, const wchar_t* expected, size_t expected_len) {
    if (num_chars < expected_len) return FALSE;
    for (size_t i = 0; i < expected_len; ++i) {
        wchar_t ch = (wchar_t)(ptr[i * 2] | (ptr[i * 2 + 1] << 8));
        if (ch != expected[i]) return FALSE;
    }
    return TRUE;
}

static BOOL check_pcr7_variable_event(
    const uint8_t* payload,
    uint32_t event_size,
    BOOL* out_is_secure_boot,
    BOOL* out_is_enabled,
    BOOL* out_is_shim_mok)
{
    if (out_is_secure_boot) *out_is_secure_boot = FALSE;
    if (out_is_enabled) *out_is_enabled = FALSE;
    if (out_is_shim_mok) *out_is_shim_mok = FALSE;
    if (!payload || event_size < 32) return FALSE;

    static const uint8_t efi_global_variable_guid[16] = {
        0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11,
        0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C
    };
    static const uint8_t shim_lock_guid[16] = {
        0x50, 0xAC, 0x5D, 0x60, 0x84, 0x37, 0x52, 0x46,
        0xB2, 0xA7, 0x71, 0x7E, 0x91, 0xD3, 0xDA, 0x77
    };

    if (memcmp(payload, shim_lock_guid, 16) == 0) {
        if (out_is_shim_mok) *out_is_shim_mok = TRUE;
        return TRUE;
    }

    if (memcmp(payload, efi_global_variable_guid, 16) != 0) {
        return TRUE;
    }

    uint64_t name_len = 0, data_len = 0;
    memcpy(&name_len, payload + 16, 8);
    memcpy(&data_len, payload + 24, 8);

    if (name_len != 10 && name_len != 11) return TRUE;

    size_t name_bytes = (size_t)name_len * sizeof(WCHAR);
    if (32 + name_bytes > event_size || 32 + name_bytes + data_len != event_size) return FALSE;

    if (match_unicode_name(payload + 32, (size_t)name_len, L"SecureBoot", 10)) {
        if (name_len == 11) {
            wchar_t term = (wchar_t)(payload[32 + 20] | (payload[32 + 21] << 8));
            if (term != 0) return TRUE;
        }
        if (out_is_secure_boot) *out_is_secure_boot = TRUE;
        if (data_len >= 1) {
            const uint8_t* var_data = payload + 32 + name_bytes;
            if (out_is_enabled) *out_is_enabled = (var_data[0] == 0x01);
        }
    }

    return TRUE;
}

static BOOL parse_pcr7_dbx(const uint8_t* payload, uint32_t event_size, BOOL* out_dbx_valid) {
    if (out_dbx_valid) *out_dbx_valid = FALSE;
    if (!payload || event_size < 32) return FALSE;

    static const uint8_t efi_image_security_database_guid[16] = {
        0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45,
        0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F
    };

    if (memcmp(payload, efi_image_security_database_guid, 16) != 0) {
        return TRUE;
    }

    uint64_t name_len = 0, data_len = 0;
    memcpy(&name_len, payload + 16, 8);
    memcpy(&data_len, payload + 24, 8);

    if (name_len < 3 || name_len > 4) return TRUE;

    size_t name_bytes = (size_t)name_len * sizeof(WCHAR);
    if (32 + name_bytes > event_size || 32 + name_bytes + data_len != event_size) return FALSE;

    if (!match_unicode_name(payload + 32, (size_t)name_len, L"dbx", 3)) {
        return TRUE;
    }

    if (data_len < 28) return FALSE;

    const uint8_t* var_data = payload + 32 + name_bytes;
    size_t offset = 0;
    uint32_t valid_entries = 0;

    static const uint8_t efi_cert_sha256_guid[16] = {
        0x26, 0x16, 0xC4, 0xC1, 0x4C, 0x50, 0x92, 0x40,
        0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28
    };
    static const uint8_t efi_cert_x509_guid[16] = {
        0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A,
        0x87, 0xB5, 0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72
    };

    while (offset + 28 <= data_len) {
        uint32_t list_size = 0, header_size = 0, sig_size = 0;
        memcpy(&list_size, var_data + offset + 16, 4);
        memcpy(&header_size, var_data + offset + 20, 4);
        memcpy(&sig_size, var_data + offset + 24, 4);

        if (list_size < 28 + header_size || offset + list_size > data_len) {
            return FALSE;
        }
        if (sig_size == 0) {
            return FALSE;
        }

        const uint8_t* sig_type = var_data + offset;
        if (memcmp(sig_type, efi_cert_sha256_guid, 16) == 0 ||
            memcmp(sig_type, efi_cert_x509_guid, 16) == 0) {
            uint32_t payload_bytes = list_size - (28 + header_size);
            valid_entries += (payload_bytes / sig_size);
        }

        offset += list_size;
    }

    if (offset != data_len) return FALSE;

    if (valid_entries > 0 && out_dbx_valid) {
        *out_dbx_valid = TRUE;
    }

    return TRUE;
}

static pcr7_authority_type classify_pcr7_authority(
    const uint8_t* payload,
    uint32_t event_size,
    BOOL* out_is_windows_uefi_ca_2023)
{
    if (out_is_windows_uefi_ca_2023) *out_is_windows_uefi_ca_2023 = FALSE;
    if (!payload || event_size < 32) return AUTHORITY_UNKNOWN;

    static const uint8_t efi_image_security_database_guid[16] = {
        0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45,
        0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F
    };
    static const uint8_t efi_global_variable_guid[16] = {
        0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11,
        0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C
    };

    if (memcmp(payload, efi_image_security_database_guid, 16) != 0 &&
        memcmp(payload, efi_global_variable_guid, 16) != 0) {
        return AUTHORITY_UNKNOWN;
    }

    uint64_t name_len = 0, data_len = 0;
    memcpy(&name_len, payload + 16, 8);
    memcpy(&data_len, payload + 24, 8);

    if (name_len < 2 || name_len > 4) return AUTHORITY_UNKNOWN;

    size_t name_bytes = (size_t)name_len * sizeof(WCHAR);
    if (32 + name_bytes > event_size || 32 + name_bytes + data_len != event_size) return AUTHORITY_UNKNOWN;

    const uint8_t* name_ptr = payload + 32;
    if (!match_unicode_name(name_ptr, (size_t)name_len, L"db", 2) &&
        !match_unicode_name(name_ptr, (size_t)name_len, L"dbx", 3)) {
        return AUTHORITY_UNKNOWN;
    }

    if (data_len <= 16) return AUTHORITY_UNKNOWN;

    size_t cert_offset = 32 + name_bytes + 16;
    DWORD cert_size = (DWORD)(data_len - 16);

    PCCERT_CONTEXT p_cert = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        payload + cert_offset,
        cert_size
    );

    if (!p_cert) {
        return AUTHORITY_OPTION_ROM_OR_OEM;
    }

    BYTE leaf_sha1[20] = { 0 };
    DWORD cb_leaf_sha1 = sizeof(leaf_sha1);

    if (CertGetCertificateContextProperty(p_cert, CERT_SHA1_HASH_PROP_ID, leaf_sha1, &cb_leaf_sha1) && cb_leaf_sha1 == 20) {
        static const BYTE win_uefi_ca_2023_sha1[20] = {
            0x45, 0xA0, 0xFA, 0x32, 0x60, 0x47, 0x73, 0xC8, 0x24, 0x33,
            0xC3, 0xB7, 0xD5, 0x9E, 0x74, 0x66, 0xB3, 0xAC, 0x0C, 0x67
        };
        static const BYTE win_pca_2011_sha1[20] = {
            0x58, 0x0A, 0x6F, 0x4C, 0xC4, 0xE4, 0xB6, 0x69, 0xB9, 0xEB,
            0xDC, 0x1B, 0x2B, 0x3E, 0x08, 0x7B, 0x80, 0xD0, 0x67, 0x8D
        };
        static const BYTE uefi_ca_2011_sha1[20] = {
            0x46, 0xDE, 0xF6, 0x3B, 0x5C, 0xE6, 0x1C, 0xF8, 0xBA, 0x0D,
            0xE2, 0xE6, 0x63, 0x9C, 0x10, 0x19, 0xD0, 0xED, 0x14, 0xF3
        };
        static const BYTE uefi_ca_2023_sha1[20] = {
            0xB5, 0xEE, 0xB4, 0xA6, 0x70, 0x60, 0x48, 0x07, 0x3F, 0x0E,
            0xD2, 0x96, 0xE7, 0xF5, 0x80, 0xA7, 0x90, 0xB5, 0x9E, 0xAA
        };
        static const BYTE oprom_ca_2023_sha1[20] = {
            0x3F, 0xB3, 0x9E, 0x2B, 0x8B, 0xD1, 0x83, 0xBF, 0x9E, 0x45,
            0x94, 0xE7, 0x21, 0x83, 0xCA, 0x60, 0xAF, 0xCD, 0x42, 0x77
        };

        if (memcmp(leaf_sha1, win_uefi_ca_2023_sha1, 20) == 0) {
            if (out_is_windows_uefi_ca_2023) *out_is_windows_uefi_ca_2023 = TRUE;
            CertFreeCertificateContext(p_cert);
            return AUTHORITY_WINDOWS_PRODUCTION_PCA;
        }
        if (memcmp(leaf_sha1, win_pca_2011_sha1, 20) == 0) {
            CertFreeCertificateContext(p_cert);
            return AUTHORITY_WINDOWS_PRODUCTION_PCA;
        }
        if (memcmp(leaf_sha1, uefi_ca_2011_sha1, 20) == 0 ||
            memcmp(leaf_sha1, uefi_ca_2023_sha1, 20) == 0 ||
            memcmp(leaf_sha1, oprom_ca_2023_sha1, 20) == 0) {
            CertFreeCertificateContext(p_cert);
            return AUTHORITY_UEFI_CA;
        }
    }

    CERT_CHAIN_PARA chain_para = { sizeof(CERT_CHAIN_PARA) };
    PCCERT_CHAIN_CONTEXT p_chain = NULL;
    DWORD chain_flags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
    pcr7_authority_type result = AUTHORITY_OPTION_ROM_OR_OEM;

    if (CertGetCertificateChain(NULL, p_cert, NULL, NULL, &chain_para, chain_flags, NULL, &p_chain)) {
        if (p_chain && p_chain->cChain > 0 && p_chain->rgpChain[0]->cElement > 1) {
            DWORD err = p_chain->TrustStatus.dwErrorStatus;
            DWORD critical_errors = CERT_TRUST_IS_UNTRUSTED_ROOT |
                CERT_TRUST_IS_NOT_SIGNATURE_VALID |
                CERT_TRUST_IS_CYCLIC |
                CERT_TRUST_IS_NOT_TIME_VALID;

            if ((err & critical_errors) == 0) {
                PCERT_CHAIN_ELEMENT root_elem = p_chain->rgpChain[0]->rgpElement[p_chain->rgpChain[0]->cElement - 1];
                BYTE root_sha1[20] = { 0 };
                DWORD cb_root_sha1 = sizeof(root_sha1);
                if (CertGetCertificateContextProperty(root_elem->pCertContext, CERT_SHA1_HASH_PROP_ID, root_sha1, &cb_root_sha1) && cb_root_sha1 == 20) {
                    static const BYTE ms_root_2010_sha1[20] = {
                        0x3B, 0x1E, 0xFD, 0x3A, 0x66, 0xEA, 0x28, 0xB1, 0x66, 0x97,
                        0x39, 0x47, 0x03, 0xA7, 0x2C, 0xA3, 0x40, 0xA0, 0x5B, 0xD5
                    };
                    static const BYTE ms_root_auth_sha1[20] = {
                        0xA4, 0x34, 0x89, 0x15, 0x9A, 0x52, 0x0F, 0x0D, 0x93, 0xD0,
                        0x32, 0xCC, 0xAF, 0x37, 0xE7, 0xFE, 0x20, 0xA8, 0xB4, 0x19
                    };
                    static const BYTE ms_3p_root_sha1[20] = {
                        0xF4, 0x8D, 0x18, 0x28, 0x36, 0xAC, 0x1A, 0x60, 0x08, 0x33,
                        0x80, 0x47, 0xEA, 0x9E, 0xEE, 0x4B, 0x9A, 0x8B, 0x74, 0x90
                    };

                    if (memcmp(root_sha1, ms_root_2010_sha1, 20) == 0 ||
                        memcmp(root_sha1, ms_root_auth_sha1, 20) == 0) {
                        result = AUTHORITY_WINDOWS_PRODUCTION_PCA;
                    }
                    else if (memcmp(root_sha1, ms_3p_root_sha1, 20) == 0) {
                        result = AUTHORITY_UEFI_CA;
                    }
                }
            }
        }
        if (p_chain) CertFreeCertificateChain(p_chain);
    }

    CertFreeCertificateContext(p_cert);
    return result;
}

BOOL detect_tpm_passthrough(PCCERT_CONTEXT ek_cert) {
    if (!ek_cert) return FALSE;

    uint32_t pcr7_windows_auth_count = 0;
    uint32_t pcr7_pre_windows_non_ms_authority_count = 0;
    pcr7_authority_type pcr7_last_authority = AUTHORITY_UNKNOWN;
    BOOL pcr7_last_is_ca_2023 = FALSE;

    BOOL pcr7_separator_seen = FALSE;
    uint32_t pcr7_separator_count = 0;
    BOOL pcr7_invalid_sequence = FALSE;
    BOOL pcr7_authority_after_windows = FALSE;
    BOOL pcr7_secure_boot_enabled = FALSE;
    BOOL pcr7_secure_boot_disabled_seen = FALSE;
    BOOL pcr7_dbx_valid = FALSE;

    TBS_CONTEXT_PARAMS2 params = { 0 };
    TBS_HCONTEXT h_tbs_context = 0;
    UINT32 log_size = 0;
    BYTE* log_buffer = NULL;
    size_t offset = 0;

    uint8_t reconstructed_pcrs[24][32] = { 0 };
    const uint32_t selected_pcrs[] = { 7 };
    const uint32_t num_selected_pcrs = sizeof(selected_pcrs) / sizeof(selected_pcrs[0]);
    uint8_t concatenated_guest_pcrs[sizeof(selected_pcrs) / sizeof(selected_pcrs[0]) * 32] = { 0 };
    uint8_t expected_pcr_digest[32] = { 0 };

    AlgSizeMap alg_to_size = { 0 };
    alg_to_size.count = 0;

    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;

    if (Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &h_tbs_context) != TBS_SUCCESS) {
        printf("[-] Failed to establish TBS context.\n");
        return FALSE;
    }

    TBS_RESULT hr = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, NULL, &log_size);
    if ((hr != TBS_E_INSUFFICIENT_BUFFER && hr != TBS_SUCCESS) || log_size == 0 || log_size > 16 * 1024 * 1024) {
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    log_buffer = (BYTE*)malloc(log_size);
    if (!log_buffer) {
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    hr = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, log_buffer, &log_size);
    if (hr != TBS_SUCCESS || log_size == 0) {
        free(log_buffer);
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    alg_to_size.pairs[0].algId = 0x0004; alg_to_size.pairs[0].digestSize = 20;
    alg_to_size.pairs[1].algId = TPM_ALG_SHA256; alg_to_size.pairs[1].digestSize = 32;
    alg_to_size.pairs[2].algId = 0x000C; alg_to_size.pairs[2].digestSize = 48;
    alg_to_size.pairs[3].algId = 0x000D; alg_to_size.pairs[3].digestSize = 64;
    alg_to_size.count = 4;

    if (log_size >= sizeof(TCG_PCR_EVENT_HEADER)) {
        TCG_PCR_EVENT_HEADER first_header;
        memcpy(&first_header, log_buffer, sizeof(TCG_PCR_EVENT_HEADER));
        offset += sizeof(TCG_PCR_EVENT_HEADER);

        if (first_header.EventSize <= log_size - offset) {
            const uint8_t* first_event_data = log_buffer + offset;
            offset += first_header.EventSize;

            if (match_et(first_header.EventType, TCG_ET_NO_ACTION) && first_header.EventSize >= 28) {
                if (memcmp(first_event_data, "Spec ID Event03", 15) == 0) {
                    uint32_t num_algs = 0;
                    memcpy(&num_algs, first_event_data + 24, sizeof(num_algs));
                    uint32_t alg_offset = 28;
                    for (uint32_t j = 0; j < num_algs && alg_to_size.count < MAX_ALG_PAIRS; ++j) {
                        if (first_header.EventSize - alg_offset < 4) break;
                        uint16_t alg_id = 0, digest_size = 0;
                        memcpy(&alg_id, first_event_data + alg_offset, sizeof(alg_id));
                        memcpy(&digest_size, first_event_data + alg_offset + 2, sizeof(digest_size));
                        if (digest_size > 0 && digest_size <= 64) {
                            alg_to_size.pairs[alg_to_size.count].algId = alg_id;
                            alg_to_size.pairs[alg_to_size.count].digestSize = digest_size;
                            alg_to_size.count++;
                        }
                        alg_offset += 4;
                    }
                }
            }
        }
    }

    BOOL log_format_valid = TRUE;
    while (offset < log_size) {
        if (log_size - offset < 8) { log_format_valid = FALSE; break; }
        uint32_t pcr_index = 0, event_type = 0;
        memcpy(&pcr_index, log_buffer + offset, 4);
        memcpy(&event_type, log_buffer + offset + 4, 4);
        offset += 8;

        if (log_size - offset < 4) { log_format_valid = FALSE; break; }
        uint32_t digest_count = 0;
        memcpy(&digest_count, log_buffer + offset, 4);
        offset += 4;

        if (digest_count > 16) { log_format_valid = FALSE; break; }

        uint8_t current_sha256_digest[32];
        memset(current_sha256_digest, 0, sizeof(current_sha256_digest));
        BOOL has_sha256_digest = FALSE;

        for (uint32_t j = 0; j < digest_count; ++j) {
            if (log_size - offset < 2) { log_format_valid = FALSE; break; }
            uint16_t alg_id = 0;
            memcpy(&alg_id, log_buffer + offset, 2);
            offset += 2;

            uint16_t size = 0;
            for (uint32_t a = 0; a < alg_to_size.count; ++a) {
                if (alg_to_size.pairs[a].algId == alg_id) {
                    size = alg_to_size.pairs[a].digestSize;
                    break;
                }
            }
            if (size == 0 || size > log_size - offset) {
                log_format_valid = FALSE;
                break;
            }

            if (alg_id == TPM_ALG_SHA256 && size == 32) {
                memcpy(current_sha256_digest, log_buffer + offset, 32);
                has_sha256_digest = TRUE;
            }
            offset += size;
        }

        if (!log_format_valid) break;

        if (log_size - offset < 4) { log_format_valid = FALSE; break; }
        uint32_t event_size = 0;
        memcpy(&event_size, log_buffer + offset, 4);
        offset += 4;

        if (event_size > log_size - offset) { log_format_valid = FALSE; break; }
        const uint8_t* payload = log_buffer + offset;
        offset += event_size;

        if (pcr_index >= 24) continue;

        if (!has_sha256_digest) {
            log_format_valid = FALSE;
            break;
        }

        if (pcr_index == 7) {
            BOOL digest_matches = FALSE;

            if (match_et(event_type, TCG_ET_EFI_VARIABLE_DRIVER_CONFIG) || match_et(event_type, TCG_ET_SEPARATOR)) {
                uint8_t computed_payload_digest[32];
                if (calculate_sha256(payload, event_size, computed_payload_digest)) {
                    if (memcmp(computed_payload_digest, current_sha256_digest, 32) == 0) {
                        digest_matches = TRUE;
                    }
                }
            }
            else if (match_et(event_type, TCG_ET_EFI_VARIABLE_AUTHORITY)) {
                if (event_size >= 32) {
                    uint64_t name_len = 0, data_len = 0;
                    memcpy(&name_len, payload + 16, 8);
                    memcpy(&data_len, payload + 24, 8);
                    size_t name_bytes = (size_t)name_len * sizeof(WCHAR);

                    if (32 + name_bytes + data_len == event_size) {
                        const uint8_t* var_data = payload + 32 + name_bytes;
                        uint8_t computed_auth_digest[32];
                        if (calculate_sha256(var_data, (uint32_t)data_len, computed_auth_digest)) {
                            if (memcmp(computed_auth_digest, current_sha256_digest, 32) == 0) {
                                digest_matches = TRUE;
                            }
                        }
                    }
                }
                if (!digest_matches) {
                    uint8_t computed_fallback[32];
                    if (calculate_sha256(payload, event_size, computed_fallback)) {
                        if (memcmp(computed_fallback, current_sha256_digest, 32) == 0) {
                            digest_matches = TRUE;
                        }
                    }
                }
            }
            else {
                digest_matches = TRUE;
            }

            if (!digest_matches) {
                pcr7_invalid_sequence = TRUE;
            }

            if (match_et(event_type, TCG_ET_SEPARATOR)) {
                pcr7_separator_count++;
                pcr7_separator_seen = TRUE;
                if (pcr7_separator_count > 2) {
                    pcr7_invalid_sequence = TRUE;
                }
            }
            else if (match_et(event_type, TCG_ET_EFI_VARIABLE_DRIVER_CONFIG)) {
                BOOL is_sb = FALSE, is_enabled = FALSE, is_shim_mok = FALSE;
                if (!check_pcr7_variable_event(payload, event_size, &is_sb, &is_enabled, &is_shim_mok)) {
                    pcr7_invalid_sequence = TRUE;
                }
                if (is_shim_mok) {
                    pcr7_invalid_sequence = TRUE;
                }
                if (is_sb) {
                    if (is_enabled) {
                        pcr7_secure_boot_enabled = TRUE;
                    }
                    else {
                        pcr7_secure_boot_disabled_seen = TRUE;
                    }
                }
                BOOL dbx_status = FALSE;
                if (!parse_pcr7_dbx(payload, event_size, &dbx_status)) {
                    pcr7_invalid_sequence = TRUE;
                }
                if (dbx_status) {
                    pcr7_dbx_valid = TRUE;
                }
            }
            else if (match_et(event_type, TCG_ET_EFI_VARIABLE_AUTHORITY)) {
                BOOL is_ca_2023 = FALSE;
                pcr7_authority_type auth = classify_pcr7_authority(payload, event_size, &is_ca_2023);
                pcr7_last_authority = auth;
                pcr7_last_is_ca_2023 = is_ca_2023;

                if (auth == AUTHORITY_WINDOWS_PRODUCTION_PCA) {
                    pcr7_windows_auth_count++;
                }
                else {
                    if (pcr7_windows_auth_count == 0) {
                        pcr7_pre_windows_non_ms_authority_count++;
                    }
                    else {
                        pcr7_authority_after_windows = TRUE;
                    }
                }
            }
        }

        if (has_sha256_digest && !match_et(event_type, TCG_ET_NO_ACTION)) {
            uint8_t concat[64];
            memcpy(concat, reconstructed_pcrs[pcr_index], 32);
            memcpy(concat + 32, current_sha256_digest, 32);
            calculate_sha256(concat, 64, reconstructed_pcrs[pcr_index]);
        }
    }

    free(log_buffer);

    if (!log_format_valid || pcr7_invalid_sequence) {
        printf("[-] Attestation rejected: Malformed TCG Event Log or invalid PCR 7 sequence.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    if (!pcr7_secure_boot_enabled || pcr7_secure_boot_disabled_seen) {
        printf("[-] Attestation rejected: Secure Boot is disabled or modified in PCR 7.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    if (!pcr7_dbx_valid) {
        printf("[-] Attestation rejected: Missing or invalid DBX (revocation list) in PCR 7.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    if (pcr7_pre_windows_non_ms_authority_count > 1) {
        printf("[-] Attestation rejected: Multiple pre-boot authorities detected.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    if (pcr7_authority_after_windows) {
        printf("[-] Attestation rejected: Unauthorized authority observed after Windows Boot Manager.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    if (pcr7_windows_auth_count == 0) {
        printf("[-] Attestation rejected: Windows authority missing from PCR 7.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    if (pcr7_last_authority != AUTHORITY_WINDOWS_PRODUCTION_PCA) {
        printf("[-] Attestation rejected: Terminal authority in PCR 7 is not a genuine Windows authority.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    if (!pcr7_separator_seen || pcr7_separator_count < 1 || pcr7_separator_count > 2) {
        printf("[-] Attestation rejected: Invalid PCR 7 separator count or separator missing.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    if (!pcr7_last_is_ca_2023) {
        printf("[!] Warning: Terminal authority is legacy Windows Production PCA 2011. Updating to Windows UEFI CA 2023 is recommended.\n");
    }

    uint32_t offset_concat = 0;
    for (uint32_t k = 0; k < num_selected_pcrs; ++k) {
        uint32_t pcr_num = selected_pcrs[k];
        memcpy(concatenated_guest_pcrs + offset_concat, reconstructed_pcrs[pcr_num], 32);
        offset_concat += 32;
    }
    calculate_sha256(concatenated_guest_pcrs, sizeof(concatenated_guest_pcrs), expected_pcr_digest);

    BOOL quote_verified = FALSE;
    if (!tpm_generate_quote_and_verify(h_tbs_context, ek_cert, expected_pcr_digest, &quote_verified) || !quote_verified) {
        printf("[!] Signed TPM Quote does NOT match reconstructed PCR digest.\n");
        Tbsip_Context_Close(h_tbs_context);
        return FALSE;
    }

    Tbsip_Context_Close(h_tbs_context);
    return TRUE;
}