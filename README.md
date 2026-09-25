# Spoofed TPM Detector

> **`swtpm detection`**
- A software TPM will **never** possess a manufacturer-provisioned **private** EK whose corresponding certificate chains to a genuine certification authority.
- Dumping a private EK is impossible without a vulnerability. Software can verify if you're in possession of the correct private EK by asking your TPM to decipher a random blob with the public EK.
- Can't be bypassed.

> **`passthrough detection`**
- Checks if PCRs 1-7 mathematically reconstructed from TCG logs and actual hardware PCRs mismatch.
- PCR 0 is excluded. Firmware can place PCR0-related information into the event log without extending it.
- The detection can be bypassed if the firmware is patched so that the TPM never measures the host's boot chain.

> **`hypervisor proxying`**
- A hypervisor that is proxying commands to a physical TPM can be detected by asking the TPM to sign a quote, because a hardware TPM will only sign a quote containing its own internal host PCR values.
- Because the signature is calculated over the raw attestation data block (which contains the PCR selection and the PCR digest), any host-side modification of the PCR selection mask or the signed digest would cause the signature verification to fail when evaluated with the AK public key.

> **`using a secondary TPM`**
- An attacker could attach a discrete physical TPM like a cheap usb-based TPM, and the hypervisor could proxy the guest's TPM commands to this idle secondary TPM.
- The Quote check succeeds because the idle physical TPM signs its empty PCRs, which match the guest's simulated empty TCG log. 
- The bypass is detected by ensuring that the PCRs selected for the quote are not default-initialized.

---

## Build

### 1. Compiling with MSVC
*If using Visual Studio, just open the solution file and click on Build. If not, run:*
```cmd
cl.exe /O2 /MD main.c downloader.c cab_extractor.c crypto_helper.c tpm_info.c tpm_passthrough.c /Fe:tpm-verify.exe
```

### 2. Compiling with GCC / MinGW-w64
*Run the following command in your terminal or MSYS2 environment:*
```bash
gcc -O3 -municode main.c downloader.c cab_extractor.c crypto_helper.c tpm_info.c tpm_passthrough.c -o tpm-verify.exe -lwinhttp -lcrypt32 -lcabinet -ladvapi32 -lncrypt -ltbs -lbcrypt
```

---

## Disclaimers
Bypassing this program by directly tamper (hook/modify memory, etc) with it is not a valid bypass, because a detector could leverage the same methods used here and verify your TPM using remote attestation.

TPMs without EKs exist, and there are legitimate purposes for regenerating them. Extra policy is needed. Developers using this idea may decide to block TPMs without EK or modified EKs, other people may decide to just flag/log it as a suspicious signal for future manual verification, others may decide to do extra checks in those cases, and others may decide to allow TPMs in those cases.