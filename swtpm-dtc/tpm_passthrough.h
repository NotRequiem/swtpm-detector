#ifndef TPM_PASSTHROUGH_H
#define TPM_PASSTHROUGH_H

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdbool.h>
#include <tbs.h>

BOOL detect_tpm_passthrough(PCCERT_CONTEXT ekCert);
BOOL tpm_generate_quote_and_verify(TBS_HCONTEXT hTbsContext, PCCERT_CONTEXT ekCert, const BYTE* expectedPcrDigest, BOOL* outQuoteVerified);

#endif