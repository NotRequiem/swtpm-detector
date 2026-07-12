# Spoofed TPM Detector

> **`swtpm detection`**

- Checks if the TPM is in possession of a **private** EK chained to a real certification authority. 
- Can't be bypassed if the detection is implemented properly.
- Dumping a private EK is not possible. Software can verify if you're in possession of a private EK by asking the TPM to decipher a random blob with the public EK.

> **`passthrough detection`**
- Checks if PCRs 1-7 mathematically reconstructed from TCG logs and actual hardware PCRs mismatch.
- PCR0 is excluded. Firmware can place PCR0-related information into the event log without extending it.
- Quoting the TPM is useless in this context.

Due to the aforementioned detections, the program indirectly detects any attempt to spoof PCRs or EKs.

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
This project is still in beta. Compatibility for all kind of TPMs must be finished.