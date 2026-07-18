#include "tpm_verify.h"
#include "tpm_passthrough.h"

BOOL manual_ek_chain_walk(PCCERT_CONTEXT leaf,
    HCERTSTORE hCabRoots,
    HCERTSTORE hCandidateStore,
    DWORD depth,
    TRUST_PATH* outPath,
    PCCERT_CONTEXT* outLeaf,
    FILE* out) {
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
            fprintf(out, "%*s[!] Basic Constraints/Key Usage validation failed (not a valid CA).\n", (int)(depth * 2), "");
            return FALSE;
        }
    }

    if (!check_cert_revocation(leaf)) {
        fprintf(out, "%*s[!] Certificate revocation status verification failed (Certificate is REVOKED).\n", (int)(depth * 2), "");
        return FALSE;
    }

    if (cert_is_self_signed(leaf)) {
        if (cert_is_trusted_root(leaf, hCabRoots)) {
            fprintf(out, "%*sSelf-signed root found in the trusted root store.\n", (int)(depth * 2), "");
            if (outPath) *outPath = TRUST_PATH_TPM_CAB;
            return TRUE;
        }
        fprintf(out, "%*sSelf-signed certificate was not present in the trusted root set.\n", (int)(depth * 2), "");
        return FALSE;
    }

    issuer = find_valid_issuer_in_store(hCandidateStore, leaf);
    if (!issuer) {
        WSTRINGLIST urls = { 0 };
        if (extract_aia_ca_issuers(leaf, &urls)) {
            for (size_t i = 0; i < urls.count; ++i) {
                BYTE* data = NULL;
                DWORD size = 0;
                PCCERT_CONTEXT downloaded = NULL;
                if (!download_url_to_memory(urls.items[i], &data, &size)) {
                    continue;
                }
                downloaded = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, data, size);
                if (downloaded) {
                    if (CertAddCertificateContextToStore(hCandidateStore, downloaded, CERT_STORE_ADD_ALWAYS, NULL)) {
                        fprintf(out, "%*sLoaded AIA issuer candidate into memory.\n", (int)(depth * 2), "");

                        if (cert_is_self_signed(downloaded)) {
                            if (is_trusted_manufacturer_url(urls.items[i])) {
                                if (CertAddCertificateContextToStore(hCabRoots, downloaded, CERT_STORE_ADD_ALWAYS, NULL)) {
                                    fprintf(out, "%*s[+] Dynamic trust verified: Added downloaded manufacturer root to trusted store.\n", (int)(depth * 2) + 2, "");
                                    printf("[!] Trusted root store should be strictly closed and pinned offline for 100% bypass remediation. Downloading AIA links externally could be unsafe");
                                }
                            }
                            else {
                                fprintf(out, "%*s[!] Untrusted Root Source: Self-signed certificate downloaded from unpinned domain (%ws).\n", (int)(depth * 2) + 2, "", urls.items[i]);
                            }
                        }
                    }
                    CertFreeCertificateContext(downloaded);
                }
                free(data);
            }
            issuer = find_valid_issuer_in_store(hCandidateStore, leaf);
        }
        free_wstringlist(&urls);
    }

    if (!issuer) {
        CRYPT_DATA_BLOB aki = { 0 };
        if (get_cert_authority_key_identifier(leaf, &aki)) {
            fprintf(out, "%*sNo issuer certificate could be found in memory.\n", (int)(depth * 2), "");
            fprintf(out, "%*sAuthority Key Identifier present; issuer cert is missing.\n", (int)(depth * 2), "");
            free(aki.pbData);
        }
        else {
            fprintf(out, "%*sNo issuer certificate could be found.\n", (int)(depth * 2), "");
        }
        return FALSE;
    }

    if (!cert_signature_validates_against_issuer(leaf, issuer)) {
        fprintf(out, "%*sIssuer certificate did not validate the signature.\n", (int)(depth * 2), "");
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

static bool is_admin() {
    bool is_admin = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation = { 0 };
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            if (elevation.TokenIsElevated)
                is_admin = true;
        }
        CloseHandle(hToken);
    }
    return is_admin;
}

BOOL verify_ek_by_manual_chain(PCCERT_CONTEXT ekCert,
    const BYTE* ekPub,
    DWORD ekPubSize,
    HCERTSTORE hCabRoots,
    HCERTSTORE hCandidateStore,
    TRUST_PATH* outPath,
    PCCERT_CONTEXT* outLeaf) {
    if (!ekCert || !ekPub || !ekPubSize) return FALSE;

    if (!ekpub_matches_cert(ekCert, ekPub, ekPubSize)) {
        printf("  EK public key does not match the EK certificate public key.\n");
        return FALSE;
    }

    printf("  EK public key matches the EK certificate public key.\n");

    if (!manual_ek_chain_walk(ekCert, hCabRoots, hCandidateStore, 0, outPath, NULL, stdout)) {
        return FALSE;
    }

    if (!is_admin()) {
        printf("[!] Admin permissions required to perform the EK challenge. If this check doesn't run, the TPM can be spoofed by just dumping a valid public EK.\n");
        return FALSE;
    }

    if (perform_local_tpm_pop_challenge(ekCert)) {
        printf("TPM is physical. Proved to possess the private EK.\n");
    }
    else {
        printf("The TPM is spoofed with a valid certificate and EK. This is a software TPM.\n");
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

static void print_cert_count(HCERTSTORE store, const char* label) {
    DWORD count = 0;
    PCCERT_CONTEXT c = NULL;
    if (!store) {
        printf("%s: 0\n", label);
        return;
    }
    while ((c = CertEnumCertificatesInStore(store, c)) != NULL) count++;
    printf("%s: %lu\n", label, (unsigned long)count);
}

int wmain(int argc, wchar_t* argv[]) {
    const wchar_t* trustedTpmUrl = L"https://go.microsoft.com/fwlink/?linkid=2097925";
    const wchar_t* localCabPath = NULL;
    BYTE* cab = NULL;
    DWORD cabSize = 0;
    TPMINFO info = { 0 };
    HCERTSTORE hCabStore = NULL;
    HCERTSTORE hRoots = NULL;
    HCERTSTORE hIntermediates = NULL;
    HCERTSTORE hEkStore = NULL;
    PCCERT_CONTEXT ekLeaf = NULL;
    PCCERT_CONTEXT ekMatched = NULL;
    TRUST_PATH trustPath = TRUST_PATH_NONE;
    BOOL ok = FALSE;
    DWORD rootCount = 0, intermediateCount = 0;
    HCERTSTORE hCandidateStore = NULL;

    for (int i = 1; i < argc; ++i) {
        if ((_wcsicmp(argv[i], L"--cab") == 0 || _wcsicmp(argv[i], L"-c") == 0 || _wcsicmp(argv[i], L"-C") == 0) && (i + 1 < argc)) {
            localCabPath = argv[++i];
        }
        else if (_wcsicmp(argv[i], L"--help") == 0 || _wcsicmp(argv[i], L"-h") == 0) {
            wprintf(L"Usage: tpm-verify.exe [options]\n\n");
            wprintf(L"Options:\n");
            wprintf(L"  -c, --cab <path>   Use local TrustedTpm.cab file instead of downloading.\n");
            wprintf(L"  -h, --help         Show help information.\n");
            return 0;
        }
    }

    if (localCabPath) {
        wprintf(L"Loading local Cabinet package from: %s...\n", localCabPath);
        if (!read_file_to_memory(localCabPath, &cab, &cabSize)) {
            fwprintf(stderr, L"Failed to read local file: %s\n", localCabPath);
            goto cleanup;
        }
    }
    else {
        printf("Downloading TrustedTpm.cab from Microsoft...\n");
        if (!download_url_to_memory(trustedTpmUrl, &cab, &cabSize)) {
            fprintf(stderr, "Could not download TrustedTpm.cab, use tpm-verify.exe -c <path> to put your own file.\n");
            fprintf(stderr, "You can download one at https://download.microsoft.com/download/D/6/5/D65270B2-EAFD-43FD-B9BA-F65CA00B153E/TrustedTpm.cab\n");
            goto cleanup;
        }
    }
    printf("Loaded %lu bytes of Cabinet payload.\n", (unsigned long)cabSize);

    printf("Extracting TrustedTpm.cab in memory...\n");
    if (!extract_cab_from_memory(cab, cabSize)) {
        fprintf(stderr, "CAB extraction failed\n");
        goto cleanup;
    }
    printf("Extracted %Iu candidate certificate files\n", g_extracted.count);

    if (!get_tpm_info_via_ncrypt(&info)) {
        fprintf(stderr, "Could not obtain TPM information via NCrypt provider\n");
        goto cleanup;
    }

    print_tpm_banner(&info);

    if (!info.ekPub || info.ekPubSize == 0) {
        printf("This TPM has no EK\n");
        goto cleanup;
    }

    printf("Building in-memory trust store from TrustedTpm.cab...\n");
    if (!parse_certs_from_extracted_files(&hCabStore)) {
        fprintf(stderr, "Could not build trust store from extracted CAB contents\n");
        goto cleanup;
    }

    if (!build_cab_trust_stores(hCabStore, &hRoots, &hIntermediates, &rootCount, &intermediateCount)) {
        fprintf(stderr, "Could not split CAB certs into root/intermediate stores\n");
        goto cleanup;
    }

    printf("Total Trusted Roots (CAB Strictly): %lu\n", (unsigned long)rootCount);
    printf("CAB intermediates: %lu\n", (unsigned long)intermediateCount);

    printf("Loading EK certificate store directly from TPM NV memory...\n");
    if (!get_ek_cert_store_from_nvram(&hEkStore) || !hEkStore) {
        printf("[!] Direct NV-RAM retrieval of EK certificates failed. Falling back to PCP property...\n");

        NCRYPT_PROV_HANDLE hProv = 0;
        SECURITY_STATUS s = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
        if (s != ERROR_SUCCESS) {
            print_ntstatus("NCryptOpenStorageProvider", s);
            printf("This TPM has no EK certificate.\n");
            goto cleanup;
        }

        if (!get_pcp_ek_cert_store(hProv, &hEkStore) || !hEkStore) {
            NCryptFreeObject(hProv);
            printf("This TPM has no EK certificate.\n");
            goto cleanup;
        }
        NCryptFreeObject(hProv);
    }

    print_cert_count(hEkStore, "EK cert count from TPM");

    printf("Building candidate issuer store...\n");
    if (!build_candidate_issuer_store(hCabStore, NULL, NULL, &hCandidateStore)) {
        fprintf(stderr, "Could not build candidate issuer store\n");
        goto cleanup;
    }

    printf("Matching EK certificate and verifying chain...\n");
    {
        PCCERT_CONTEXT c = NULL;
        while ((c = CertEnumCertificatesInStore(hEkStore, c)) != NULL) {
            char subject[1024] = { 0 };
            char issuer[1024] = { 0 };
            CertGetNameStringA(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, _countof(subject));
            CertGetNameStringA(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuer, _countof(issuer));
            printf("EK certificate candidate:\n");
            printf("  Subject: %s\n", subject[0] ? subject : "(unknown)");
            printf("  Issuer : %s\n", issuer[0] ? issuer : "(unknown)");

            if (!ekpub_matches_cert(c, info.ekPub, info.ekPubSize)) {
                printf("  EK public key does not match this certificate.\n");
                continue;
            }

            printf("  EK public key matches this certificate.\n");
            ekMatched = CertDuplicateCertificateContext(c);

            if (verify_ek_by_manual_chain(c, info.ekPub, info.ekPubSize, hRoots, hCandidateStore, &trustPath, &ekLeaf)) {
                ok = TRUE;
                CertFreeCertificateContext(c);
                break;
            }
        }
    }

    if (!ok) {
        printf("\n\nResult: TPM is not trustable.\n");
        goto cleanup;
    }

    printf("Matched EK certificate from TPM:\n");
    {
        char subject[1024] = { 0 };
        char issuer[1024] = { 0 };
        CertGetNameStringA(ekLeaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, _countof(subject));
        CertGetNameStringA(ekLeaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuer, _countof(issuer));
        printf("  Subject: %s\n", subject[0] ? subject : "(unknown)");
        printf("  Issuer : %s\n", issuer[0] ? issuer : "(unknown)");
    }

    if (trustPath == TRUST_PATH_TPM_CAB) {
        printf("\n\nResult: TPM is legit. The EK chains to a vendor certificate in the Microsoft TrustedTpm package.\n");
    }
    else {
        printf("\n\nResult: TPM is legit.\n");
    }

    printf("\n[*] Starting passthrough checks...\n");
    if (!detect_tpm_passthrough()) {
        printf("\n\nResult: Passed-through virtualized hardware detected.\n");
        ok = FALSE;
    }
    else {
        printf("\n\nResult: Real hardware TPM verified.\n");
    }

cleanup:
    if (ekLeaf) CertFreeCertificateContext(ekLeaf);
    if (ekMatched) CertFreeCertificateContext(ekMatched);
    if (hCandidateStore) CertCloseStore(hCandidateStore, 0);
    if (hEkStore) CertCloseStore(hEkStore, 0);
    if (hIntermediates) CertCloseStore(hIntermediates, 0);
    if (hRoots) CertCloseStore(hRoots, 0);
    if (hCabStore) CertCloseStore(hCabStore, 0);
    free(info.ekPub);
    free_filelist(&g_extracted);
    free(cab);

    system("pause");
    return ok ? 0 : 1;
}