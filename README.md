# Spoofed TPM Detector

> **`swtpm detection`**

- A non-physical TPM will **never** possess a manufacturer-provisioned **private** EK whose corresponding certificate chains to a genuine certification authority.
- Dumping a private EK is impossible without a vulnerability. Software can verify if you're in possession of the correct private EK by asking your TPM to decipher a random blob with the public EK.
- Can't be bypassed when the detection is implemented properly.

> **`passthrough detection`**
- Checks if PCRs 1-7 mathematically reconstructed from TCG logs and actual hardware PCRs mismatch.
- PCR0 is excluded. Firmware can place PCR0-related information into the event log without extending it.
- The detection can be bypassed if the firmware is patched so that the TPM never measures the host's boot chain, or if the attacker (who is in control of such chain) reconstructs the VM's TCG logs accordingly.

> **`flashing/resetting detection`**
- Changing the EPS to derive a new EK makes the manufacturer-backed credential chain broken unless the issuer re-enrolls and issues a fresh EK credential for that new EK.
- A change of EPS makes it **impossible** to recreate any EKs derived from the previous seed.
- A trust chain can be maintained by cross certification **only between the Platform and Endorsement hierarchies** when seeds change.

In summary, a probe that asks *"Is this the same TPM instance that the OEM originally certified?"* will always fail after HWID spoofing on your TPM.

---

## Build

### 1. Compiling with MSVC
```cmd
cl.exe /O2 /MD main.c downloader.c cab_extractor.c crypto_helper.c tpm_info.c tpm_passthrough.c /Fe:tpm-verify.exe
```
*If using Visual Studio, just open the solution file and click on Build.*

### 2. Compiling with GCC / MinGW-w64
```bash
gcc -O3 main.c downloader.c cab_extractor.c crypto_helper.c tpm_info.c tpm_passthrough.c -o tpm-verify.exe -lwinhttp -lcrypt32 -lcabinet -ladvapi32 -lncrypt -ltbs -lbcrypt
```

---

## Usage

### Online Mode (Default)
By default, the program downloads Microsoft's official trust database directly from their servers:

```cmd
tpm-verify.exe
```

### Offline Mode
To run offline, put your own certificate cabinet file or the official [TrustedTpm.cab](https://go.microsoft.com/fwlink/?linkid=2097925) file manually and pass it to the validator:

```cmd
tpm-verify.exe --cab "C:\Path\To\TrustedTpm.cab"
```

## Disclaimers
This program is still in beta.

This program is not designed to be tamper-resistant against memory modification or API call interception; it even allows you to put your own certificate database for testing purposes. Therefore, it is useless to try to bypass the program this way. The software is useful to check the integrity and trust of your own TPM.

TPMs without EKs exist, and there are legitimate purposes for regenerating them. Extra policy is needed. Developers using this idea may decide to block TPMs without EK or modified EKs, other people may decide to just flag/log it as a suspicious signal for future manual verification, others may decide to do extra checks in those cases, and others may decide to allow TPMs in those cases.