# 🔐 Crypto Utils Usage Examples

> **Complete Guide for Using crypto_utils.cpp in C++ Authentication Systems**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](https://isocpp.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
[![Security](https://img.shields.io/badge/Security-Hardened-red.svg)](https://en.wikipedia.org/wiki/Security)

## 📖 Overview

This repository provides comprehensive examples and usage patterns for integrating `crypto_utils.cpp` into C++ authentication systems. Perfect for developers building secure license validation, anti-reverse engineering protection, and encrypted communication systems.

### Basic Integration

```cpp
#include "crypto_utils.h"

int main() {
    // Initialize crypto utilities
    CRYPTO_UTILS::StringObfuscator::initializeRandom();
    CRYPTO_UTILS::StaticRSA::initializeRSA();
    
    // Anti-reverse engineering setup
    CRYPTO_UTILS::AntiReverse::antiDump();
    
    // Your authentication code here...
    
    return 0;
}
```

### License Validation Example

```cpp
std::string validateLicense(const std::string& licenseKey) {
    // Security checks
    if (CRYPTO_UTILS::AntiReverse::isDebuggerPresent()) {
        return "ERROR|Debugger detected";
    }
    
    // Generate secure session
    auto keyIv = CRYPTO_UTILS::DynamicAES::generateKeyAndIV();
    std::string sessionKey = CRYPTO_UTILS::SecureNetwork::generateSessionKey();
    
    // Encrypt license data
    std::string encryptedLicense = CRYPTO_UTILS::DynamicAES::encrypt(
        licenseKey, keyIv.first, keyIv.second
    );
    
    return "SUCCESS = License validated";
}
```

## 📦 Installation

### Prerequisites

- Windows 10/11
- Visual Studio 2019 or later
- C++17 support
- Windows CryptoAPI

### Setup

1. **Include in your project**
   ```cpp
   #include "crypto_utils.h"
   #include "crypto_utils.cpp"
   ```

2. **Link required libraries**
   ```cpp
   #pragma comment(lib, "crypt32.lib")
   #pragma comment(lib, "advapi32.lib")
   ```

## 🔧 Usage Examples

### 1. Anti-Reverse Engineering

```cpp
// Debugger detection
if (CRYPTO_UTILS::AntiReverse::isDebuggerPresent()) {
    exit(1);
}

// Anti-dump protection
CRYPTO_UTILS::AntiReverse::antiDump();

// Integrity check
CRYPTO_UTILS::AntiReverse::checkIntegrity();
```


## 🛡️ Security Features

| Feature | Description | Use Case |
|---------|-------------|----------|
| **Debugger Detection** | Detects debugging tools and analysis software | Anti-reverse engineering |
| **Memory Protection** | Prevents memory dumping and patching | Code protection |
| **String Obfuscation** | Hides sensitive strings in binary | API key protection |
| **Dynamic Encryption** | Runtime key generation and encryption | Secure communication |
| **Time-based Security** | Prevents replay attacks | Request validation |
| **Integrity Checks** | Verifies code and data integrity | Tamper detection |

## 📚 API Reference

### AntiReverse Class
- `isDebuggerPresent()` - Detect debugger presence
- `antiDump()` - Prevent memory dumping
- `checkIntegrity()` - Verify file integrity
- `obfuscateString()` - Obfuscate sensitive strings
- `randomDelay()` - Add random delays

### DynamicAES Class
- `generateKeyAndIV()` - Generate encryption keys
- `encrypt()` - Encrypt data with AES
- `decrypt()` - Decrypt AES encrypted data
- `vectorToHex()` - Convert binary to hex
- `hexToVector()` - Convert hex to binary

### HMAC Class
- `generateHMAC()` - Create HMAC signature
- `verifyHMAC()` - Verify HMAC signature
- `generateRandomSalt()` - Generate random salt

### JWT Class
- `createJWT()` - Create JSON Web Token
- `verifyJWT()` - Verify JWT token
- `extractPayload()` - Extract JWT payload
- `base64Encode()` - Base64 encoding
- `base64Decode()` - Base64 decoding

### MemoryProtection Class
- `protectMemoryRegion()` - Protect memory pages
- `clearSensitiveData()` - Securely clear data
- `detectMemoryPatching()` - Detect memory modifications

## 🔍 Complete Examples

See the [CRYPTO_UTILS_USAGE_EXAMPLES.md](CRYPTO_UTILS_USAGE_EXAMPLES.md) file for comprehensive examples covering:

- ✅ All 12 major function categories
- ✅ Real-world integration scenarios
- ✅ Error handling patterns
- ✅ Security best practices
- ✅ Complete working examples

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Notice

This library is designed for educational and legitimate security purposes. Please use responsibly and in compliance with applicable laws and regulations.

## 🆘 Support

- 📧 **Email**: support@authguards.com
- 💬 **Discord**: [Join our server](https://discord.gg/authguards)
- 📖 **Documentation**: [Full API docs](https://authguards.com/docs)
- 🐛 **Issues**: [GitHub Issues](https://github.com/authguards.com/crypto-utils-examples/issues)

---

**Made with ❤️ for the C++ security community**
