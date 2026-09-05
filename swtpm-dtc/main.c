#include "tpm_verify.h"
#include "tpm_passthrough.h"

BOOL manual_ek_chain_walk(PCCERT_CONTEXT leaf,
    HCERTSTORE hCabRoots,
    HCERTSTORE hCandidateStore,
    DWORD depth,
    TRUST_PATH* outPath,
    PCCERT_CONTEXT* outLeaf,
    FILE* out)
{
    PCCERT_CONTEXT issuer = NULL;
    char subject[1024] = { 0 };
    char issuerName[1024] = { 0 };

    if (!leaf || !hCabRoots || !hCandidateStore || depth > 8) return FALSE;

    CertGetNameStringA(leaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, _countof(subject));
    CertGetNameStringA(leaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuerName, _countof(issuerName));
    fprintf(out, "%*sCertificate:\n", (int)(depth * 2), "");
    fprintf(out, "%*sSubject: %s\n", (int)(depth * 2), "", subject[0] ? subject : "(unknown)");
    fprintf(out, "%*sIssuer : %s\n", (int)(depth * 2), "", issuerName[0] ? issuerName : "(unknown)");

    if (CertVerifyTimeValidity(NULL, leaf->pCertInfo) != 0) {
        fprintf(out, "%*s[!] Certificate is expired or not yet valid.\n", (int)(depth * 2), "");
        return FALSE;
    }

    if (depth > 0) {
        if (!check_issuer_basic_constraints_and_key_usage(leaf)) {
            fprintf(out, "%*s[!] Basic Constraints validation failed (not a valid CA).\n", (int)(depth * 2), "");
            return FALSE;
        }
    }

    if (!check_cert_revocation(leaf)) {
        fprintf(out, "%*s[!] Certificate revocation verification failed (REVOKED).\n", (int)(depth * 2), "");
        return FALSE;
    }

    if (cert_is_self_signed(leaf)) {
        if (cert_is_trusted_root(leaf, hCabRoots)) {
            fprintf(out, "%*s[+] Self-signed root found in the verified Microsoft TrustedTpm CAB store.\n", (int)(depth * 2), "");
            if (outPath) *outPath = TRUST_PATH_TPM_CAB;
            return TRUE;
        }
        fprintf(out, "%*s[!] Self-signed root is NOT in the Microsoft trusted set. Rejecting chain.\n", (int)(depth * 2), "");
        return FALSE;
    }

    issuer = find_valid_issuer_in_store(hCandidateStore, leaf);
    if (!issuer) {
        WSTRINGLIST urls = { 0 };
        if (extract_aia_ca_issuers(leaf, &urls)) {
            for (size_t i = 0; i < urls.count; ++i) {
                if (!is_trusted_manufacturer_url(urls.items[i])) {
                    fprintf(out, "%*s[!] Skipping unpinned AIA domain: %ws\n", (int)(depth * 2), "", urls.items[i]);
                    continue;
                }

                BYTE* data = NULL;
                DWORD size = 0;
                if (download_url_to_memory(urls.items[i], &data, &size)) {
                    PCCERT_CONTEXT downloaded = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, data, size);
                    if (downloaded) {
                        CertAddCertificateContextToStore(hCandidateStore, downloaded, CERT_STORE_ADD_ALWAYS, NULL);
                        CertFreeCertificateContext(downloaded);
                    }
                    free(data);
                }
            }
            free_wstringlist(&urls);
            issuer = find_valid_issuer_in_store(hCandidateStore, leaf);
        }
    }

    if (!issuer) {
        fprintf(out, "%*s[!] No valid issuer certificate found in CAB or through AIA.\n", (int)(depth * 2), "");
        return FALSE;
    }

    if (!cert_signature_validates_against_issuer(leaf, issuer)) {
        fprintf(out, "%*s[!] Cryptographic signature validation against candidate issuer failed.\n", (int)(depth * 2), "");
        CertFreeCertificateContext(issuer);
        return FALSE;
    }

    if (!manual_ek_chain_walk(issuer, hCabRoots, hCandidateStore, depth + 1, outPath, outLeaf, out)) {
        CertFreeCertificateContext(issuer);
        return FALSE;
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
    if (!pExt) return FALSE;

    PCERT_ENHKEY_USAGE pUsage = NULL;
    DWORD cbUsage = 0;
    if (CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_ENHANCED_KEY_USAGE,
        pExt->Value.pbData, pExt->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, NULL, &pUsage, &cbUsage)) {

        BOOL found = FALSE;
        for (DWORD i = 0; i < pUsage->cUsageIdentifier; i++) {
            if (strcmp(pUsage->rgpszUsageIdentifier[i], "2.23.133.8.1") == 0) { // tcg-kp-EKCertificate
                found = TRUE;
                break;
            }
        }
        LocalFree(pUsage);
        return found;
    }
    return FALSE;
}

BOOL verify_ek_by_manual_chain(PCCERT_CONTEXT ekCert,
    const BYTE* ekPub,
    DWORD ekPubSize,
    HCERTSTORE hCabRoots,
    HCERTSTORE hCandidateStore,
    TRUST_PATH* outPath,
    PCCERT_CONTEXT* outLeaf)
{
    if (!ekCert || !ekPub || !ekPubSize || !hCabRoots || !hCandidateStore) return FALSE;

    if (!ekpub_matches_cert(ekCert, ekPub, ekPubSize)) {
        printf("  EK public key does not match this EK certificate.\n");
        return FALSE;
    }

    if (!has_ek_eku(ekCert)) {
        printf("[!] Validation failed: Certificate lacks mandatory Endorsement Key EKU (2.23.133.8.1).\n");
        return FALSE;
    }

    if (!manual_ek_chain_walk(ekCert, hCabRoots, hCandidateStore, 0, outPath, NULL, stdout)) {
        return FALSE;
    }

    if (outLeaf) *outLeaf = CertDuplicateCertificateContext(ekCert);
    return TRUE;
}

static void print_tpm_banner(const TPMINFO* info) {
    printf("TPM version: %s\n", info->isTpm2 ? "2.0" : "1.2");
    printf("TPM manufacturer ID: %lu (ASCII '%s')\n", (unsigned long)info->manufacturerId, info->manufacturerIdText);
    printf("TPM vendor string: %s\n", info->vendorString[0] ? info->vendorString : "(unknown)");
    printf("TPM firmware version: 0x%016llx\n", (unsigned long long)info->firmwareVersion);
    print_utf8_or_unknown("PCP platform type", info->providerType);
    print_utf8_or_unknown("PCP provider version", info->providerVersion);
    printf("EK present: %s\n", (info->ekPub && info->ekPubSize) ? "yes" : "no");
    printf("EK public key SHA-256: %s\n", info->ekPubSha256[0] ? info->ekPubSha256 : "(unknown)");
}

int wmain() {
    const wchar_t* trustedTpmUrl = L"https://go.microsoft.com/fwlink/?linkid=2097925";
    BYTE* cab = NULL;
    DWORD cabSize = 0;
    TPMINFO info = { 0 };
    HCERTSTORE hCabStore = NULL;
    HCERTSTORE hRoots = NULL;
    HCERTSTORE hIntermediates = NULL;
    HCERTSTORE hEkStore = NULL;
    HCERTSTORE hCandidateStore = NULL;
    PCCERT_CONTEXT ekLeaf = NULL;
    TRUST_PATH trustPath = TRUST_PATH_NONE;
    BOOL ok = FALSE;
    DWORD rootCount = 0, intermediateCount = 0;

    if (!is_admin()) {
        printf("[-] Program must run as administrator.\n");
        system("pause");
        return 0;
    }

    printf("Downloading and validating Microsoft TrustedTpm.cab...\n");
    if (!download_and_verify_trusted_tpm_cab(trustedTpmUrl, &cab, &cabSize)) {
        fprintf(stderr, "Failed to download or verify Authenticode signature on TrustedTpm.cab.\n");
        goto cleanup;
    }
    printf("[+] Authenticode verified: Microsoft TrustedTpm.cab package loaded (%lu bytes).\n", (unsigned long)cabSize);

    printf("Extracting TrustedTpm.cab in memory...\n");
    if (!extract_cab_from_memory(cab, cabSize)) {
        fprintf(stderr, "CAB extraction failed.\n");
        goto cleanup;
    }
    printf("Extracted %Iu candidate certificate files from CAB.\n", g_extracted.count);

    if (!get_tpm_info_via_ncrypt(&info)) {
        fprintf(stderr, "Could not obtain TPM information via NCrypt provider.\n");
        goto cleanup;
    }

    print_tpm_banner(&info);

    if (!info.ekPub || info.ekPubSize == 0) {
        printf("This TPM has no active EK.\n");
        goto cleanup;
    }

    printf("Building in-memory trust store from TrustedTpm.cab...\n");
    if (!parse_certs_from_extracted_files(&hCabStore)) {
        fprintf(stderr, "Could not build trust store from extracted CAB contents.\n");
        goto cleanup;
    }

    if (!build_cab_trust_stores(hCabStore, &hRoots, &hIntermediates, &rootCount, &intermediateCount)) {
        fprintf(stderr, "Could not split CAB certs into root/intermediate stores.\n");
        goto cleanup;
    }

    printf("Total Trusted Roots (CAB Strictly): %lu\n", (unsigned long)rootCount);
    printf("CAB Intermediates: %lu\n", (unsigned long)intermediateCount);

    printf("Loading EK certificate store directly from TPM NV memory...\n");
    if (!get_ek_cert_store_from_nvram(&hEkStore) || !hEkStore) {
        printf("[!] Direct NV-RAM retrieval of EK certificates failed. Falling back to PCP property...\n");
        NCRYPT_PROV_HANDLE hProv = 0;
        if (NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0) == ERROR_SUCCESS) {
            get_pcp_ek_cert_store(hProv, &hEkStore);
            NCryptFreeObject(hProv);
        }
    }

    if (!hEkStore) {
        printf("[!] This TPM has no EK certificate provisioned.\n");
        goto cleanup;
    }

    printf("Building candidate issuer store...\n");
    if (!build_candidate_issuer_store(hCabStore, &hCandidateStore)) {
        fprintf(stderr, "Could not build candidate issuer store.\n");
        goto cleanup;
    }

    printf("Matching EK certificate and verifying chain against Microsoft TrustedTpm roots...\n");
    {
        PCCERT_CONTEXT c = NULL;
        while ((c = CertEnumCertificatesInStore(hEkStore, c)) != NULL) {
            char subject[1024] = { 0 };
            char issuer[1024] = { 0 };
            CertGetNameStringA(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, _countof(subject));
            CertGetNameStringA(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuer, _countof(issuer));
            printf("EK candidate in NVRAM:\n");
            printf("  Subject: %s\n", subject[0] ? subject : "(unknown)");
            printf("  Issuer : %s\n", issuer[0] ? issuer : "(unknown)");

            if (!ekpub_matches_cert(c, info.ekPub, info.ekPubSize)) {
                printf("  EK public key does not match this certificate (expected for dual RSA/ECC).\n");
                continue;
            }

            printf("  [+] EK public key matches certificate.\n");

            if (verify_ek_by_manual_chain(c, info.ekPub, info.ekPubSize, hRoots, hCandidateStore, &trustPath, &ekLeaf)) {
                ok = TRUE;
                CertFreeCertificateContext(c);
                break;
            }
        }
    }

    if (!ok) {
        printf("\n[-] Result: TPM is NOT trusted (EK failed Microsoft PKI validation).\n");
        goto cleanup;
    }

    printf("\n[+] Result: EK certificate successfully verified against Microsoft TrustedTpm CAB.\n");

    printf("\n[*] Executing hardware quote and passthrough attestation...\n");
    if (!detect_tpm_passthrough(ekLeaf)) {
        printf("\n[-] Result: Virtualized or spoofed TPM detected by attestation!\n");
        ok = FALSE;
    }
    else {
        printf("\n[+] Result: This machine has access to a verified physical hardware TPM.\n");
    }

cleanup:
    if (ekLeaf) CertFreeCertificateContext(ekLeaf);
    if (hCandidateStore) CertCloseStore(hCandidateStore, 0);
    if (hEkStore) CertCloseStore(hEkStore, 0);
    if (hIntermediates) CertCloseStore(hIntermediates, 0);
    if (hRoots) CertCloseStore(hRoots, 0);
    if (hCabStore) CertCloseStore(hCabStore, 0);
    free(info.ekPub);
    free_filelist(&g_extracted);
    free(cab);

    printf("[*] Running version: v3.0\n");
    system("pause");
    return ok ? 0 : 1;
}