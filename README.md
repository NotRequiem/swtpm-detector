# Software TPM Detector

user-mode integrity tool designed to detect whether a TPM 2.0 interface is virtual/emulated. It also has the ability to detect TPM passthrough, EK spoofing and PCR spoofing.

A software TPM will never have a EKPub chaining to a real OEM CA. So in essence, this program does an attestation check, to make sure the EK is legit/valid for whatever TPM brand.
The code proves that:
- the TPM exposes an EK public key (some TPMs don't, this case is handled explictly)
- that EK matches the OEM-issued EK certificate
- the certificate chains to the OEM CA
- the certificate has not been replaced with a self-signed one
- the EK public key matches the certificate exactly

You can generate a new EK, but not directly by flashing/clearing the TPM, you do so by changing the EPS, since the EK is derived from there. On Intel, tpm2_changeeps is an authorized command. However, changing the EPS, which changes the EK, makes the certificate chain invalid, so this verifier theorically detects EK changes.

However, this verifier does not probe whether the TPM currently answering commands owns the EK private key. 

Someone can dump a legitimate public EK certificate and public key from a physical mobo. They can then configure a VM, a software-emulated TPM, or a custom KSP registry configuration to return this stolen certificate. Since the certificate itself is legitimate, the static chain walk will verify successfully.

To solve this bypass, I thought in the following:

`1.` Parse the public EK key from the validated EK certificate (not from the local OS registry or Windows APIs).

`2.` Generate a 16-byte random symmetric challenge locally.

`3.` Simulate the TPM2_MakeCredential wrapping protocol from scratch, which is very hard. We must encrypt an ephemeral seed to the validated EKPub using RSA-OAEP, derive symmetric keys via KDFa via SHA-256, encrypt our local challenge with AES-128-CFB, and sign it with HMAC-SHA256. 

`4.` Pass the wrapped credential blob to the local PCP on our transient AIK handle using the NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY property.

The local physical TPM must decrypt the seed using its non-exportable EK private key, run KDFa to derive the keys, decrypt the challenge, and return it. If the returned challenge matches our original local challenge, the local TPM has proven that it possesses the private key corresponding to the verified EK certificate (mathematically speaking).

The math in the code (tpm_info.c) is already correct according to the TCG specifications, but the Windows PCP path never exposed TPM2_ActivateCredential properly (only PCP_TPM12_IDACTIVATION_PROPERTY under my tests), so I'm just leaving this (currently disabled by default) method in code rather than just not shipping it

## Features
- Support for Intel ODCA, by resolving hardware-embedded EICAs directly from NVRAM via the PCP and Registry caches. This is because now (I think starting from Intel Core 11th Gen) the CPU's on-die secure enclave generates PTT EKs locally and the parent certificates (PTT, Kernel, and ROM EICAs) do not have standard online AIA paths.
- Doesn't use the standard local Windows Root Store for TPM validation, so rogue self-signed CA certificates installed locally won't affect the decision.
- Fileless verification, all crypto and download operations are done in-memory without ever touching disk.
- Supports both offline and online certificate validation.
- Experimental support for fTPMs.

---

## Build

### 1. Compiling with MSVC
```cmd
cl.exe /O2 /MD main.c downloader.c cab_extractor.c crypto_helper.c tpm_info.c tpm_passthrough.c /Fe:tpm-verify.exe
```
*If using Visual Studio, just open the solution file and click on Build.*

### 2. Compiling with GCC / MinGW-w64
To compile using GCC on Windows, pass the explicit linking parameters to the compiler:
```bash
gcc -O3 main.c downloader.c cab_extractor.c crypto_helper.c tpm_info.c tpm_passthrough.c -o tpm-verify.exe -lwinhttp -lcrypt32 -lcabinet -ladvapi32 -lncrypt -ltbs -lbcrypt
```

---

## Usage

### Online Mode (Default)
By default, the program downloads Microsoft's official trust database directly from Microsoft's servers:

```cmd
tpm-verify.exe
```

### Offline Mode
To run offline, put your own certificate cabinet file or the official [TrustedTpm.cab](https://go.microsoft.com/fwlink/?linkid=2097925) file manually and pass it to the validator:

```cmd
tpm-verify.exe --cab "C:\Path\To\TrustedTpm.cab"
```

## Disclaimer
This code is not heavily tested like other serious projects and it's currently in beta. False positives, false negatives, or even vulnerabilities in the C code may be present.