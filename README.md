# Spoofed TPM Detector

> **`swtpm/vtpm detection`**
- A pure software TPM will **never** possess a manufacturer-provisioned **private** EK whose corresponding certificate chains to a genuine certification authority.
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

> **`hypervisor proxying`**
- A hypervisor that is proxying commands to a physical TPM can be detected by asking the TPM to sign a quote, because a hardware TPM will only sign a quote containing its own internal host PCR values.
- Because the signature is calculated over the raw attestation data block (which contains the PCR selection and the PCR digest), any host-side modification of the PCR selection mask or the signed digest would cause the signature verification to fail when evaluated with the AK public key.

> **`attaching a secondary TPM`**
- An attacker could attach a discrete physical TPM like a cheap usb-based TPM, and the hypervisor could proxy the guest's TPM commands to this idle secondary TPM.
- The attacker configures the virtual machine's TCG Event Log to be empty or to represent a clean, unextended state.
- The Quote check succeeds because the idle physical TPM signs its empty PCRs, which match the guest's simulated empty TCG log. This way, the attacker doesn't have to deal with complex TCG reconstruction because it doesn't need to perfectly emulate a real host TCG log into the guest.
- However, because the secondary TPM is not the primary boot TPM of the host, it does not measure the host's boot process. Its PCRs 1–7 remain in their unextended initialization state. Therefore, the bypass is detected by ensuring that the PCRs selected for the quote are not default-initialized. Additionally, PCR 4 (EV_EFI_BOOT_SERVICES_APPLICATION) must match the Windows' bootloader hash.
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
This program is not designed to be tamper-resistant against memory modification or API call interception; it even allows you to put your own certificate database for testing purposes. Bypassing this program by directly hooking it is not a valid bypass, because a detector could leverage the same methods used here and verify your TPM using remote attestation.

TPMs without EKs exist, and there are legitimate purposes for regenerating them. Extra policy is needed. Developers using this idea may decide to block TPMs without EK or modified EKs, other people may decide to just flag/log it as a suspicious signal for future manual verification, others may decide to do extra checks in those cases, and others may decide to allow TPMs in those cases.

The program probes that the guest has access to a trusted TPM-backed identity path.

Attestation cannot be treated as a one-time gate. To prevent TOCTOU attacks, implement randomized periodic re-attestation loops.
