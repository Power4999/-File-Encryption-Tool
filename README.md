# AES-128-CBC File Cryptor

A lightweight C-based utility for secure file encryption and decryption using the **Advanced Encryption Standard (AES)** in **Cipher Block Chaining (CBC)** mode. This project utilizes the **OpenSSL EVP** (High-Level Cryptographic Functions) library to ensure robust and industry-standard cryptographic processing.

---

## 🚀 Features

- **Symmetric Encryption:** Uses AES-128 bit keys for fast and secure data protection
- **Safety Staging:** Implements a temporary file staging mechanism (`.tmp`) to prevent data loss or corruption during the encryption/decryption process
- **Memory Managed:** Dynamically handles file buffers with a built-in safety cap of **50MB** to prevent system memory exhaustion
- **Automated Padding:** Handles non-block-aligned files automatically using **PKCS#7 padding** via the OpenSSL EVP interface
- **In-Place Operation:** Replaces the original file with the encrypted/decrypted version upon successful completion

---

## 🏗️ Technical Architecture

The utility operates by reading the target file into a memory buffer, performing the cryptographic transformation, and committing the changes only upon successful verification.

### Cryptographic Specifications

| Parameter | Value |
|:---|:---|
| **Algorithm** | AES-128 |
| **Mode** | CBC (Cipher Block Chaining) |
| **Library** | OpenSSL (libcrypto) |
| **Key Size** | 16 Bytes (128 bits) |
| **Block Size** | 16 Bytes |
| **Padding Scheme** | PKCS#7 |

---

## 📋 Prerequisites

Before compiling this project, ensure you have the following installed:

- **GCC** or compatible C compiler
- **OpenSSL development libraries**
  - **Debian/Ubuntu:** `sudo apt-get install libssl-dev`
  - **Red Hat/CentOS:** `sudo yum install openssl-devel`
  - **macOS:** `brew install openssl`

---

## 🛠️ Compilation

To compile the project, use the following command:

```bash
gcc main.c -o cryptor -lcrypto
```

This will create an executable named `cryptor` in your current directory.

### Compilation Flags (Optional)

For additional optimizations or warnings:

```bash
gcc main.c -o cryptor -lcrypto -O2 -Wall -Wextra
```

---

## 📖 Usage

The program follows a simple command structure:

```bash
./cryptor <operation> <filename>
```

### 1. Encryption

To encrypt a plaintext file:

```bash
./cryptor encrypt secret.txt
```

**What happens:**
- The original `secret.txt` is read into memory
- AES-128-CBC encryption is applied
- A temporary file `secret.txt.enc.tmp` is created during the process
- Upon successful encryption, the original file is replaced with the encrypted version

### 2. Decryption

To restore an encrypted file to its original state:

```bash
./cryptor decrypt secret.txt
```

**What happens:**
- The encrypted `secret.txt` is read into memory
- AES-128-CBC decryption is applied
- A temporary file `secret.txt.dec.tmp` is created during the process
- Upon successful decryption, the encrypted file is replaced with the plaintext version

---


## 🔒 File Size Limitations

- **Maximum file size:** 50MB
- Files larger than 50MB will be rejected to prevent memory exhaustion
- This limit can be adjusted in the source code if needed

---



## ⚡ Quick Reference

| Command | Description |
|:---|:---|
| `./cryptor encrypt <file>` | Encrypt a plaintext file |
| `./cryptor decrypt <file>` | Decrypt an encrypted file |
