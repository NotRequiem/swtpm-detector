#include "tpm.h"

static BOOL is_cert_store_empty(HCERTSTORE hStore) {
    if (!hStore) return TRUE;
    PCCERT_CONTEXT first = CertEnumCertificatesInStore(hStore, NULL);
    if (!first) return TRUE;
    CertFreeCertificateContext(first);
    return FALSE;
}

static void add_downloaded_cert_or_bundle_to_store(HCERTSTORE hStore, const BYTE* data, DWORD size) {
    if (!hStore || !data || size == 0) return;

    PCCERT_CONTEXT direct = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, data, size);
    if (direct) {
        CertAddCertificateContextToStore(hStore, direct, CERT_STORE_ADD_USE_EXISTING, NULL);
        CertFreeCertificateContext(direct);
        return;
    }

    CRYPT_DATA_BLOB blob = { 0 };
    blob.pbData = (BYTE*)data;
    blob.cbData = size;

    DWORD dwMsgAndCertEncodingType = 0;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    HCERTSTORE hMsgStore = NULL;
    const void* pvContext = NULL;

    if (CryptQueryObject(
        CERT_QUERY_OBJECT_BLOB,
        &blob,
        CERT_QUERY_CONTENT_FLAG_CERT | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
        CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED | CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE,
        CERT_QUERY_FORMAT_FLAG_ALL,
        0,
        &dwMsgAndCertEncodingType,
        &dwContentType,
        &dwFormatType,
        &hMsgStore,
        NULL,
        &pvContext))
    {
        if (pvContext && dwContentType == CERT_QUERY_CONTENT_CERT) {
            CertAddCertificateContextToStore(hStore, (PCCERT_CONTEXT)pvContext, CERT_STORE_ADD_USE_EXISTING, NULL);
            CertFreeCertificateContext((PCCERT_CONTEXT)pvContext);
        }
        if (hMsgStore) {
            PCCERT_CONTEXT pEnum = NULL;
            while ((pEnum = CertEnumCertificatesInStore(hMsgStore, pEnum)) != NULL) {
                CertAddCertificateContextToStore(hStore, pEnum, CERT_STORE_ADD_USE_EXISTING, NULL);
            }
            CertCloseStore(hMsgStore, 0);
        }
    }
}

static PCCERT_CONTEXT find_cryptographic_issuer_in_store(HCERTSTORE hStore, PCCERT_CONTEXT leaf) {
    if (!hStore || !leaf || !leaf->pCertInfo) return NULL;

    PCCERT_CONTEXT fast = find_valid_issuer_in_store(hStore, leaf);
    if (fast) {
        if (cert_signature_validates_against_issuer(leaf, fast)) {
            return fast;
        }
        CertFreeCertificateContext(fast);
        fast = NULL;
    }

    PCCERT_CONTEXT candidate = NULL;
    while ((candidate = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &leaf->pCertInfo->Issuer,
        candidate)) != NULL)
    {
        if (cert_signature_validates_against_issuer(leaf, candidate)) {
            return candidate;
        }
    }

    return NULL;
}

static BOOL manual_ek_chain_walk(PCCERT_CONTEXT leaf,
    HCERTSTORE hCabRoots,
    HCERTSTORE hCandidateStore,
    DWORD depth,
    PCCERT_CONTEXT* outLeaf,
    FILE* out)
{
    char subject[1024] = { 0 };
    char issuerName[1024] = { 0 };

    if (!out) out = stdout;
    if (!leaf || !leaf->pCertInfo || !hCabRoots || !hCandidateStore || depth > 8) return FALSE;

    CertGetNameStringA(leaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, _countof(subject));
    CertGetNameStringA(leaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuerName, _countof(issuerName));
    fprintf(out, "%*sCertificate:\n", (int)(depth * 2), "");
    fprintf(out, "%*sSubject: %s\n", (int)(depth * 2), "", subject[0] ? subject : "(unknown)");
    fprintf(out, "%*sIssuer : %s\n", (int)(depth * 2), "", issuerName[0] ? issuerName : "(unknown)");

    if (CertVerifyTimeValidity(NULL, leaf->pCertInfo) != 0) {
        fprintf(out, "%*s[!] Certificate is expired or not yet valid.\n", (int)(depth * 2), "");
        return FALSE;
    }

    if (depth == 0 && cert_is_self_signed(leaf)) {
        fprintf(out, "%*s[!] Leaf EK certificate is self-signed. Rejecting chain.\n", (int)(depth * 2), "");
        return FALSE;
    }

    if (depth > 0 && cert_is_trusted_root(leaf, hCabRoots)) {
        return TRUE;
    }

    if (cert_is_self_signed(leaf)) {
        fprintf(out, "%*s[!] Self-signed root is NOT in the Microsoft trusted set. Rejecting chain.\n", (int)(depth * 2), "");
        return FALSE;
    }

    if (depth > 0) {
        if (!check_issuer_basic_constraints_and_key_usage(leaf)) {
            fprintf(out, "%*s[!] Basic Constraints validation failed (not a valid CA).\n", (int)(depth * 2), "");
            return FALSE;
        }
    }

    if (!check_cert_revocation(leaf)) {
        fprintf(out, "%*s[!] Certificate revocation verification failed (REVOKED or unavailable).\n", (int)(depth * 2), "");
        return FALSE;
    }

    PCCERT_CONTEXT issuer = find_cryptographic_issuer_in_store(hCandidateStore, leaf);

    if (!issuer) {
        WSTRINGLIST urls = { 0 };
        if (extract_aia_ca_issuers(leaf, &urls)) {
            for (size_t i = 0; i < urls.count; ++i) {
                if (!urls.items[i]) continue;

                BYTE* data = NULL;
                DWORD size = 0;
                if (download_url_to_memory(urls.items[i], &data, &size) && data && size > 0) {
                    add_downloaded_cert_or_bundle_to_store(hCandidateStore, data, size);
                }
                if (data) {
                    free(data);
                    data = NULL;
                }
            }
            free_wstringlist(&urls);
        }

        issuer = find_cryptographic_issuer_in_store(hCandidateStore, leaf);
    }

    if (!issuer) {
        fprintf(out, "%*s[!] No valid issuer certificate found in CAB or through AIA.\n", (int)(depth * 2), "");
        return FALSE;
    }

    if (!manual_ek_chain_walk(issuer, hCabRoots, hCandidateStore, depth + 1, outLeaf, out)) {
        CertFreeCertificateContext(issuer);
        return FALSE;
    }

    if (depth == 0 && outLeaf && !*outLeaf) {
        *outLeaf = CertDuplicateCertificateContext(leaf);
    }

    CertFreeCertificateContext(issuer);
    return TRUE;
}

static BOOL is_admin(void) {
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation = { 0 };
        DWORD dwSize = sizeof(elevation);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            elevated = (elevation.TokenIsElevated != 0);
        }
        CloseHandle(hToken);
    }
    return elevated;
}

static BOOL has_ek_eku(PCCERT_CONTEXT cert) {
    if (!cert || !cert->pCertInfo) return FALSE;

    PCERT_EXTENSION pExt = CertFindExtension(szOID_ENHANCED_KEY_USAGE,
        cert->pCertInfo->cExtension, cert->pCertInfo->rgExtension);
    if (!pExt || !pExt->Value.pbData || pExt->Value.cbData == 0) return FALSE;

    PCERT_ENHKEY_USAGE pUsage = NULL;
    DWORD cbUsage = 0;
    if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, szOID_ENHANCED_KEY_USAGE,
        pExt->Value.pbData, pExt->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, NULL, &pUsage, &cbUsage)) {

        if (!pUsage) return FALSE;

        BOOL found = FALSE;
        if (pUsage->rgpszUsageIdentifier) {
            for (DWORD i = 0; i < pUsage->cUsageIdentifier; i++) {
                if (pUsage->rgpszUsageIdentifier[i] &&
                    strcmp(pUsage->rgpszUsageIdentifier[i], "2.23.133.8.1") == 0) {
                    found = TRUE;
                    break;
                }
            }
        }
        LocalFree(pUsage);
        return found;
    }
    return FALSE;
}

static BOOL verify_ek_by_manual_chain(PCCERT_CONTEXT ekCert,
    const BYTE* ekPub,
    DWORD ekPubSize,
    HCERTSTORE hCabRoots,
    HCERTSTORE hCandidateStore,
    PCCERT_CONTEXT* outLeaf)
{
    if (outLeaf) *outLeaf = NULL;

    if (!ekCert || !ekPub || !ekPubSize || !hCabRoots || !hCandidateStore) return FALSE;

    if (!ekpub_matches_cert(ekCert, ekPub, ekPubSize)) {
        return FALSE;
    }

    if (!has_ek_eku(ekCert)) {
        printf("[!] Validation failed: Certificate lacks mandatory Endorsement Key EKU (2.23.133.8.1).\n");
        return FALSE;
    }

    return manual_ek_chain_walk(ekCert, hCabRoots, hCandidateStore, 0, outLeaf, stdout);
}

int wmain(void) {
    const wchar_t* trustedTpmUrl = L"https://go.microsoft.com/fwlink/?linkid=2097925";
    BYTE* cab = NULL;
    DWORD cabSize = 0;
    TPMINFO info = { 0 };
    HCERTSTORE hCabStore = NULL;
    HCERTSTORE hRoots = NULL;
    HCERTSTORE hEkStore = NULL;
    HCERTSTORE hCandidateStore = NULL;
    PCCERT_CONTEXT ekLeaf = NULL;
    BOOL ok = FALSE;

    if (!is_admin()) {
        printf("[-] Program must run as administrator.\n");
        system("pause");
        return 1;
    }

    if (!download_and_verify_trusted_tpm_cab(trustedTpmUrl, &cab, &cabSize)) {
        fprintf(stderr, "[!] Failed to download or verify Authenticode signature on TrustedTpm.cab.\n");
        goto cleanup;
    }

    if (!extract_cab_from_memory(cab, cabSize)) {
        fprintf(stderr, "[-] CAB extraction failed.\n");
        goto cleanup;
    }

    if (!get_tpm_info_via_ncrypt(&info)) {
        fprintf(stderr, "[-] Could not obtain TPM information via NCrypt provider.\n");
        goto cleanup;
    }

    if (!info.ekPub || info.ekPubSize == 0) {
        printf("[-] This TPM has no active EK.\n");
        goto cleanup;
    }

    if (!parse_certs_from_extracted_files(&hCabStore)) {
        fprintf(stderr, "[-] Could not build trust store from extracted CAB contents.\n");
        goto cleanup;
    }

    if (!build_cab_trust_stores(hCabStore, &hRoots, NULL, NULL, NULL)) {
        fprintf(stderr, "[-] Could not extract root store from CAB certs.\n");
        goto cleanup;
    }

    if (!get_ek_cert_store_from_nvram(&hEkStore) || !hEkStore || is_cert_store_empty(hEkStore)) {
        if (hEkStore) {
            CertCloseStore(hEkStore, 0);
            hEkStore = NULL;
        }
        printf("[-] Direct NV-RAM retrieval of EK certificates failed or empty. Falling back to PCP property...\n");
        NCRYPT_PROV_HANDLE hProv = 0;
        if (NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0) == ERROR_SUCCESS) {
            get_pcp_ek_cert_store(hProv, &hEkStore);
            NCryptFreeObject(hProv);
        }
    }

    if (!hEkStore || is_cert_store_empty(hEkStore)) {
        printf("[-] This TPM has no EK certificate provisioned.\n");
        goto cleanup;
    }

    if (!build_candidate_issuer_store(hCabStore, &hCandidateStore)) {
        fprintf(stderr, "[-] Could not build candidate issuer store.\n");
        goto cleanup;
    }

    {
        PCCERT_CONTEXT c = NULL;
        while ((c = CertEnumCertificatesInStore(hEkStore, c)) != NULL) {
            if (verify_ek_by_manual_chain(c, info.ekPub, info.ekPubSize, hRoots, hCandidateStore, &ekLeaf)) {
                ok = TRUE;
                CertFreeCertificateContext(c);
                c = NULL;
                break;
            }
        }
        if (c) {
            CertFreeCertificateContext(c);
            c = NULL;
        }
    }

    if (!ok) {
        printf("\n[-] Result: TPM is NOT trusted (EK failed Microsoft PKI validation).\n");
        goto cleanup;
    }

    if (!ekLeaf) {
        fprintf(stderr, "[-] Result: Verified EK leaf context is missing.\n");
        ok = FALSE;
        goto cleanup;
    }

    printf("\n[*] Running attestation checks...\n");
    if (!detect_tpm_passthrough(ekLeaf)) {
        printf("[-] Result: Virtualized, proxied, or spoofed TPM detected by attestation.\n");
        ok = FALSE;
    }
    else {
        printf("[+] Result: TPM is legit.\n");
    }

cleanup:
    if (ekLeaf) CertFreeCertificateContext(ekLeaf);
    if (hCandidateStore) CertCloseStore(hCandidateStore, 0);
    if (hEkStore) CertCloseStore(hEkStore, 0);
    if (hRoots) CertCloseStore(hRoots, 0);
    if (hCabStore) CertCloseStore(hCabStore, 0);
    if (info.ekPub) free(info.ekPub);
    free_filelist(&g_extracted);
    if (cab) free(cab);

    printf("Version: v4.1\n");
    system("pause");
    return ok ? 0 : 1;
}