#include "akc.h"
#ifndef AUTH_H
#define AUTH_H
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include "crypto_utils.h"
typedef unsigned char BYTE;
#define AG(str) std::string(str)

namespace AUTH {
    extern const std::string PROJECT_NAME;
    extern const std::string PROJECT_ID;
    extern const std::string VERSION;
    extern const std::string CUSTOM_ID;
    extern const std::string PRIVATE_KEY;
    extern const std::string PUBLIC_KEY;
    extern const std::string API_URL;
    extern const std::string SECRET_CON;
    class SystemInfo {
    public:
        static std::string getCPUInfo();
        static std::string getRAMInfo();
        static std::string getUptime();
        static std::string getDiskInfo();
        static std::string getArchitecture();
        static std::string getOSInfo();
        static std::string getMotherboardID();
        static std::string getMACAddress();
        static std::string getGPUName();
        static std::string getAppPath();
        static std::string getPCName();
        static std::string getUUID();
        static std::string getHWID();
        static std::string getSMBIOSUUID();
        static std::string getClientIPAddress();
        static std::string getCPUId();
        static std::string getGPUId();
        static std::string getMotherboardId();
        static std::string getRAMSerialNumbers();
        static std::string getSMBIOSInfo();
        static std::string getComprehensiveFingerprint();
        static std::string getHashedFingerprint();
        static std::string getLocalIP();
    };
    class Logger {
    public:
        static void log(const std::string& message, const std::string& projectID = AUTH::PROJECT_ID);
    };
    class NovACorE {
    public:
        static std::string ARE(const std::string& value);
    };
    class Api {
    public:
        struct SystemData {
            std::string cpuInfo;
            std::string motherboardID;
            std::string gpuName;
            std::string macAddress;
            std::string ramInfo;
            std::string diskInfo;
            std::string uptime;
            std::string architecture;
            std::string appPath;
            std::string pcName;
            std::string uuid;
            std::string osInfo;
            std::string productID;
            std::string hwid;
            std::string comprehensiveFingerprint;
        };        
        static SystemData systemData;
        static std::string project_id;
        static std::atomic<bool> isRunning;
        static std::thread validationThread;
        static std::string lastLicenseKey;
        static std::string sessionKey;
        static std::string dynamicSalt;
        static std::vector<BYTE> aesKey;
        static std::vector<BYTE> aesIV;
        static std::string init();
        static std::string getProductID();
        static void ban();
        static std::string validateLicense(const std::string& licenseKey, bool silent = false);
        static void displayRemainingTime(const std::string& response);
        static void startPeriodicValidation(const std::string& licenseKey);
        static void stopPeriodicValidation();
        static std::string registerAccount(const std::string& username, const std::string& password, const std::string& licenseKey);
        static std::string validateAccount(const std::string& username, const std::string& password);
        static std::string resetaccount(const std::string& username, const std::string& oldPassword, const std::string& newPassword);
        static std::string changeusername(const std::string& currentUsername, const std::string& password, const std::string& newUsername);
        static bool checkblack();
        static bool validateJWTPermission(const std::string& requiredPermission = "");
        static std::string getJWTPayload();
        static bool hasPermission(const std::string& permission);
        static bool isJWTTokenValid();
        static bool validateJWTWithServer(const std::string& jwtToken);
        static std::string decryptJWTToken(const std::string& encryptedToken);
        static std::string getInitialJWTToken();
        static std::string lastLevel;
        static std::string getLastLevel();
        static bool downloadAndInstallUpdate(const std::string& updateUrl);
        static std::vector<unsigned char> download(const std::string& fileId);
        static void backgroundchecker(const std::string& licenseKey);
        static void check(const std::string& licenseKey);
        struct UserData {
            std::string username;
            std::string license;
            std::string ip;
            std::string hwid;
            std::string createdate;
            std::string lastlogin;
            std::string subscriptions;
            std::string expiry;
            std::string customerpanellink;
            std::string usercount;
        };
        static UserData userData;
        static const UserData& getUserData();
    };

}

#endif
