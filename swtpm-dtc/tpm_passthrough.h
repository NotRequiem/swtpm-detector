#ifndef TPM_PASSTHROUGH_H
#define TPM_PASSTHROUGH_H

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdbool.h>

	BOOL detect_tpm_passthrough(void);
	BOOL tpm_generate_quote_and_verify(TBS_HCONTEXT hTbsContext, const BYTE* expectedPcrDigest, BOOL* outQuoteVerified);

#endif