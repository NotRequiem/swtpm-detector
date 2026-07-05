#ifndef TPM_PASSTHROUGH_H
#define TPM_PASSTHROUGH_H

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdbool.h>

	BOOL detect_tpm_passthrough(void);

#endif