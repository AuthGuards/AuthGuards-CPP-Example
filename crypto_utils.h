#pragma once
#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>
#include <algorithm>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
namespace CRYPTO_UTILS {
    class AntiReverse {
    public:
        static bool isDebuggerPresent();
        static bool isVirtualMachine();
        static void antiDump();
        static void checkIntegrity();
        static std::string obfuscateString(const std::string& input);
        static void randomDelay();
    };
    class DynamicAES {
    private:
        static std::vector<BYTE> generateRandomKey(size_t keySize);
        static std::vector<BYTE> generateIV();
        static std::vector<BYTE> hexToVector(const std::string& hex);

    public:
        static std::string encrypt(const std::string& plaintext, const std::vector<BYTE>& key, const std::vector<BYTE>& iv);
        static std::string decrypt(const std::string& ciphertext, const std::vector<BYTE>& key, const std::vector<BYTE>& iv);
        static std::string decryptBase64(const std::string& base64Data, const std::vector<BYTE>& key);
        static std::pair<std::vector<BYTE>, std::vector<BYTE>> generateKeyAndIV();
        static std::string vectorToHex(const std::vector<BYTE>& data);
    };
    class StaticRSA {
    private:
        static HCRYPTPROV hProv;
        static HCRYPTKEY hKey;

    public:
        static bool initializeRSA();
        static std::string encryptWithPublicKey(const std::string& data, const std::string& publicKey);
        static std::string decryptWithPrivateKey(const std::string& encryptedData, const std::string& privateKey);
        static void cleanup();
    };
    class HMAC {
    public:
        static std::string generateHMAC(const std::string& data, const std::string& key);
        static bool verifyHMAC(const std::string& data, const std::string& key, const std::string& expectedHMAC);
        static std::string generateRandomSalt(size_t length = 32);
    };
    class JWT {
    private:
        struct Header {
            std::string alg = "HS256";
            std::string typ = "JWT";
        };

        struct Payload {
            std::string hwid;
            std::string projectId;
            std::string version;
            long long exp;
            long long iat;
            std::string nonce;
        };

        static std::string base64Encode(const std::string& input);
        static std::string base64Decode(const std::string& input);
        static std::string createSignature(const std::string& header, const std::string& payload, const std::string& secret);

    public:
        static std::string createJWT(const std::string& hwid, const std::string& projectId,
            const std::string& version, const std::string& secret);
        static bool verifyJWT(const std::string& token, const std::string& secret);
        static std::string extractPayload(const std::string& token);
    };
    class StringObfuscator {
    private:
        static std::mt19937 rng;
        static std::uniform_int_distribution<int> dist;

    public:
        static std::string obfuscate(const std::string& input);
        static std::string deobfuscate(const std::string& obfuscated);
        static void initializeRandom();
    };
    class SecureNetwork {
    public:
        static std::string encryptRequest(const std::string& data, const std::string& sessionKey);
        static std::string decryptResponse(const std::string& encryptedData, const std::string& sessionKey);
        static std::string generateSessionKey();
    };
    class TimeSecurity {
    public:
        static long long getCurrentTimestamp();
        static bool isTimestampValid(long long timestamp, int toleranceSeconds = 300);
        static std::string generateTimeBasedToken(const std::string& data);
        static bool verifyTimeBasedToken(const std::string& token, const std::string& expectedData);
    };
    class MemoryProtection {
    public:
        static void protectMemoryRegion(void* address, size_t size);
        static void clearSensitiveData(void* data, size_t size);
        static bool detectMemoryPatching();
    };

}

#endif
