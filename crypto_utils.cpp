#include "crypto_utils.h"
#include <iostream>
#include <fstream>
#include <map>
#include <tlhelp32.h>
#include <winternl.h>
#include <cmath>

namespace CRYPTO_UTILS {
    HCRYPTPROV StaticRSA::hProv = 0;
    HCRYPTKEY StaticRSA::hKey = 0;
    std::mt19937 StringObfuscator::rng;
    std::uniform_int_distribution<int> StringObfuscator::dist(1, 255);
    bool AntiReverse::isDebuggerPresent() {
        if (::IsDebuggerPresent()) return true;
        PEB* peb = (PEB*)__readgsqword(0x60);
        if (peb && peb->BeingDebugged) return true;
        PVOID heap = GetProcessHeap();
        DWORD flags = *(PDWORD)((PBYTE)heap + 0x40);
        DWORD forceFlags = *(PDWORD)((PBYTE)heap + 0x44);
        if ((flags & ~HEAP_GROWABLE) || (forceFlags != 0)) return true;
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        Sleep(10);
        QueryPerformanceCounter(&end);
        double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000;
        if (elapsed > 50.0) return true; // Likely being debugged
        return false;
    }

    bool AntiReverse::isVirtualMachine() {
        std::vector<std::string> vmProcesses = {
            "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "VGAuthService.exe",
            "vmacthlp.exe", "vboxservice.exe", "vboxtray.exe", "xenservice.exe"
        };

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                // Convert WCHAR to std::string can use string
                std::wstring wProcessName = pe32.szExeFile;
                std::string processName(wProcessName.begin(), wProcessName.end());       
                for (const auto& vmProc : vmProcesses) {
                    if (processName == vmProc) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\SCSI", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256];
            DWORD bufferSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, "Identifier", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                std::string identifier = buffer;
                if (identifier.find("VBOX") != std::string::npos ||
                    identifier.find("VMWARE") != std::string::npos ||
                    identifier.find("QEMU") != std::string::npos) {
                    RegCloseKey(hKey);
                    return true;
                }
            }
            RegCloseKey(hKey);
        }

        return false;
    }

    void AntiReverse::antiDump() {
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID addr = GetModuleHandle(NULL);
        while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READ)) {
                DWORD oldProtect;
                VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE, &oldProtect);
            }
            addr = (LPBYTE)addr + mbi.RegionSize;
        }
    }

    void AntiReverse::checkIntegrity() {
        HANDLE hFile = CreateFileA(
            GetCommandLineA(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            std::vector<BYTE> buffer(fileSize);
            DWORD bytesRead;
            ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL);
            CloseHandle(hFile);
            DWORD checksum = 0;
            for (BYTE b : buffer) {
                checksum += b;
            }
            if (checksum == 0) {
                ExitProcess(1);
            }
        }
    }

    std::string AntiReverse::obfuscateString(const std::string& input) {
        std::string result = input;
        for (size_t i = 0; i < result.length(); ++i) {
            result[i] ^= (0xAA + (i % 16));
        }
        return result;
    }

    void AntiReverse::randomDelay() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(10, 100);
        Sleep(dis(gen));
    }

    std::vector<BYTE> DynamicAES::generateRandomKey(size_t keySize) {
        std::vector<BYTE> key(keySize);
        HCRYPTPROV hProv;
        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hProv, keySize, key.data());
            CryptReleaseContext(hProv, 0);
        }

        return key;
    }

    std::vector<BYTE> DynamicAES::generateIV() {
        return generateRandomKey(16);
    }

    std::string DynamicAES::vectorToHex(const std::vector<BYTE>& data) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (BYTE b : data) {
            ss << std::setw(2) << static_cast<int>(b);
        }
        return ss.str();
    }

    std::vector<BYTE> DynamicAES::hexToVector(const std::string& hex) {
        std::vector<BYTE> result;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            BYTE byte = static_cast<BYTE>(strtol(byteString.c_str(), NULL, 16));
            result.push_back(byte);
        }
        return result;
    }

    std::string DynamicAES::encrypt(const std::string& plaintext, const std::vector<BYTE>& key, const std::vector<BYTE>& iv) {
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        HCRYPTHASH hHash = 0;

        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return "";
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return "";
        }

        if (!CryptHashData(hHash, key.data(), key.size(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }

        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        std::vector<BYTE> buffer(plaintext.begin(), plaintext.end());
        DWORD bufferLen = buffer.size();
        DWORD finalLen = bufferLen;
        if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &finalLen, 0)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        buffer.resize(finalLen);
        bufferLen = plaintext.size();
        if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &bufferLen, finalLen)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        buffer.resize(bufferLen);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return vectorToHex(buffer);
    }

    std::string DynamicAES::decrypt(const std::string& ciphertext, const std::vector<BYTE>& key, const std::vector<BYTE>& iv) {
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        HCRYPTHASH hHash = 0;
        std::vector<BYTE> encryptedData = hexToVector(ciphertext);
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return "";
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return "";
        }
        if (!CryptHashData(hHash, key.data(), key.size(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        DWORD dataLen = encryptedData.size();
        if (!CryptDecrypt(hKey, 0, TRUE, 0, encryptedData.data(), &dataLen)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return std::string(encryptedData.begin(), encryptedData.begin() + dataLen);
    }

    std::pair<std::vector<BYTE>, std::vector<BYTE>> DynamicAES::generateKeyAndIV() {
        return std::make_pair(generateRandomKey(32), generateIV());
    }
    bool StaticRSA::initializeRSA() {
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return false;
        }
        if (!CryptGenKey(hProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hKey)) {
            CryptReleaseContext(hProv, 0);
            return false;
        }

        return true;
    }

    std::string StaticRSA::encryptWithPublicKey(const std::string& data, const std::string& publicKey) {
        HCRYPTPROV hProv;
        HCRYPTKEY hKey;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return "";
        }

        if (!CryptGenKey(hProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hKey)) {
            CryptReleaseContext(hProv, 0);
            return "";
        }

        std::vector<BYTE> buffer(data.begin(), data.end());
        DWORD bufferLen = buffer.size();

        if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufferLen, 0)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return "";
        }

        buffer.resize(bufferLen);
        bufferLen = data.size();

        if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &bufferLen, buffer.size())) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return "";
        }

        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);

        return DynamicAES::vectorToHex(buffer);
    }

    std::string StaticRSA::decryptWithPrivateKey(const std::string& encryptedData, const std::string& privateKey) {
        return encryptedData;
    }

    void StaticRSA::cleanup() {
        if (hKey) CryptDestroyKey(hKey);
        if (hProv) CryptReleaseContext(hProv, 0);
    }

    std::string HMAC::generateHMAC(const std::string& data, const std::string& key) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HCRYPTKEY hKey = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return "";
        }
        if (!CryptCreateHash(hProv, CALG_HMAC, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return "";
        }
        HMAC_INFO hmacInfo;
        hmacInfo.HashAlgid = CALG_SHA_256;
        hmacInfo.pbInnerString = NULL;
        hmacInfo.cbInnerString = 0;
        hmacInfo.pbOuterString = NULL;
        hmacInfo.cbOuterString = 0;
        if (!CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        if (!CryptHashData(hHash, (BYTE*)key.c_str(), key.length(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        if (!CryptHashData(hHash, (BYTE*)data.c_str(), data.length(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        BYTE hashValue[32];
        DWORD hashLen = sizeof(hashValue);
        if (!CryptGetHashParam(hHash, HP_HASHVAL, hashValue, &hashLen, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        std::vector<BYTE> hashVector(hashValue, hashValue + hashLen);
        return DynamicAES::vectorToHex(hashVector);
    }

    bool HMAC::verifyHMAC(const std::string& data, const std::string& key, const std::string& expectedHMAC) {
        std::string calculatedHMAC = generateHMAC(data, key);
        return calculatedHMAC == expectedHMAC;
    }

    std::string HMAC::generateRandomSalt(size_t length) {
        std::vector<BYTE> salt(length);
        HCRYPTPROV hProv;

        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hProv, length, salt.data());
            CryptReleaseContext(hProv, 0);
        }

        return DynamicAES::vectorToHex(salt);
    }
    std::string JWT::base64Encode(const std::string& input) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        int val = 0, valb = -6;
        for (unsigned char c : input) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (result.size() % 4) result.push_back('=');
        return result;
    }

    std::string JWT::base64Decode(const std::string& input) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        std::vector<int> T(128, -1);
        for (int i = 0; i < 64; i++) T[chars[i]] = i;
        int val = 0, valb = -8;
        for (unsigned char c : input) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                result.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return result;
    }

    std::string JWT::createSignature(const std::string& header, const std::string& payload, const std::string& secret) {
        std::string data = header + "." + payload;
        return HMAC::generateHMAC(data, secret);
    }

    std::string JWT::createJWT(const std::string& hwid, const std::string& projectId,
        const std::string& version, const std::string& secret) {
        std::string header = R"({"alg":"HS256","typ":"JWT"})";
        auto now = std::chrono::system_clock::now().time_since_epoch().count();
        std::string nonce = HMAC::generateRandomSalt(16);
        std::ostringstream payloadStream;
        payloadStream << R"({"hwid":")" << hwid << R"(",)"
            << R"("projectId":")" << projectId << R"(",)"
            << R"("version":")" << version << R"(",)"
            << R"("exp":)" << (now + 3600000000000LL) << ","
            << R"("iat":)" << now << ","
            << R"("nonce":")" << nonce << R"("})";

        std::string payload = payloadStream.str();
        std::string encodedHeader = base64Encode(header);
        std::string encodedPayload = base64Encode(payload);
        std::string signature = createSignature(encodedHeader, encodedPayload, secret);
        std::string encodedSignature = base64Encode(signature);
        return encodedHeader + "." + encodedPayload + "." + encodedSignature;
    }

    bool JWT::verifyJWT(const std::string& token, const std::string& secret) {
        size_t firstDot = token.find('.');
        size_t secondDot = token.find('.', firstDot + 1);

        if (firstDot == std::string::npos || secondDot == std::string::npos) {
            return false;
        }
        std::string header = token.substr(0, firstDot);
        std::string payload = token.substr(firstDot + 1, secondDot - firstDot - 1);
        std::string signature = token.substr(secondDot + 1);
        std::string expectedSignature = createSignature(header, payload, secret);
        std::string encodedExpectedSignature = base64Encode(expectedSignature);

        if (signature != encodedExpectedSignature) {
            return false;
        }
        std::string decodedPayload = base64Decode(payload);
        size_t expPos = decodedPayload.find("\"exp\":");
        if (expPos != std::string::npos) {
            expPos += 6;
            size_t expEnd = decodedPayload.find(',', expPos);
            if (expEnd == std::string::npos) expEnd = decodedPayload.find('}', expPos);
            std::string expStr = decodedPayload.substr(expPos, expEnd - expPos);
            long long exp = std::stoll(expStr);
            long long now = std::chrono::system_clock::now().time_since_epoch().count();
            if (now > exp) return false;
        }
        return true;
    }

    std::string JWT::extractPayload(const std::string& token) {
        size_t firstDot = token.find('.');
        size_t secondDot = token.find('.', firstDot + 1);
        if (firstDot == std::string::npos || secondDot == std::string::npos) {
            return "";
        }
        std::string payload = token.substr(firstDot + 1, secondDot - firstDot - 1);
        return base64Decode(payload);
    }
    void StringObfuscator::initializeRandom() {
        std::random_device rd;
        rng.seed(rd());
    }

    std::string StringObfuscator::obfuscate(const std::string& input) {
        std::string result = input;
        for (size_t i = 0; i < result.length(); ++i) {
            result[i] ^= (dist(rng) + i) & 0xFF;
        }
        return result;
    }

    std::string StringObfuscator::deobfuscate(const std::string& obfuscated) {
        return obfuscated;
    }

    std::string SecureNetwork::encryptRequest(const std::string& data, const std::string& sessionKey) {
        auto keyIv = DynamicAES::generateKeyAndIV();
        return DynamicAES::encrypt(data, keyIv.first, keyIv.second);
    }

    std::string SecureNetwork::decryptResponse(const std::string& encryptedData, const std::string& sessionKey) {
        auto keyIv = DynamicAES::generateKeyAndIV();
        return DynamicAES::decrypt(encryptedData, keyIv.first, keyIv.second);
    }

    std::string SecureNetwork::generateSessionKey() {
        return HMAC::generateRandomSalt(32);
    }

    long long TimeSecurity::getCurrentTimestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    bool TimeSecurity::isTimestampValid(long long timestamp, int toleranceSeconds) {
        long long current = getCurrentTimestamp();
        return std::abs(current - timestamp) <= toleranceSeconds;
    }

    std::string TimeSecurity::generateTimeBasedToken(const std::string& data) {
        long long timestamp = getCurrentTimestamp();
        std::string tokenData = data + "|" + std::to_string(timestamp);
        return HMAC::generateHMAC(tokenData, "time_secret_key");
    }

    bool TimeSecurity::verifyTimeBasedToken(const std::string& token, const std::string& expectedData) {
        long long timestamp = getCurrentTimestamp();
        std::string tokenData = expectedData + "|" + std::to_string(timestamp);
        std::string expectedToken = HMAC::generateHMAC(tokenData, "time_secret_key");
        return token == expectedToken && isTimestampValid(timestamp);
    }
    void MemoryProtection::protectMemoryRegion(void* address, size_t size) {
        DWORD oldProtect;
        VirtualProtect(address, size, PAGE_READONLY, &oldProtect);
    }

    void MemoryProtection::clearSensitiveData(void* data, size_t size) {
        SecureZeroMemory(data, size);
    }

    bool MemoryProtection::detectMemoryPatching() {
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID addr = GetModuleHandle(NULL);
        while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && mbi.Protect & PAGE_EXECUTE_WRITECOPY) {
                return true;
            }
            addr = (LPBYTE)addr + mbi.RegionSize;
        }

        return false;
    }


}
