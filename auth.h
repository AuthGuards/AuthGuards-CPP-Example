#include "akc.h"
#ifndef AUTH_H
#define AUTH_H
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include "crypto_utils.h"
#include "client_text.h"
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
    const std::string& responseSigningPublicKey();
    void setResponseSigningPublicKey(const std::string& publicKey);
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
}

namespace AuthGuards {
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
        static std::string clientSessionToken;
        static std::string initToken;
        static std::string dynamicSalt;
        static std::vector<BYTE> aesKey;
        static std::vector<BYTE> aesIV;
        static void setinittoken(const std::string& token);
        static const std::string& getinittoken();
        static std::string init();
        static bool refreshSessionToken();
        static bool checkclientsession();
        static bool logoutclientsession();
        static std::string fetchglobalvar(const std::string& name);
        static std::string fetchuservar(const std::string& varkey);
        static bool setuservar(const std::string& varkey, const std::string& value);
        static std::string invokewebhook(const std::string& webhookname, const std::string& body = "");
        static std::string fetchchatmessages(const std::string& channel = "main");
        static bool sendchatmessage(const std::string& message, const std::string& channel = "main", const std::string& displayname = "");
        static std::string lastpanelactionerror();
        static void configurefromenvironment();
        static std::string getProductID();
        static void ban(const std::string& reason = "");
        static std::string validatelicense(const std::string& licensekey, bool silent = false);
        static std::string loginwithweb();
        static void displayremainingtime(const std::string& response);
        static void startperiodicvalidation(const std::string& licensekey);
        static void stopperiodicvalidation();
        static std::string registeraccount(const std::string& username, const std::string& password, const std::string& licensekey);
        static std::string validateaccount(const std::string& username, const std::string& password, const std::string& totptoken = "");
        static std::string resetaccount(const std::string& username, const std::string& oldpassword, const std::string& newpassword);
        static std::string changeusername(const std::string& currentusername, const std::string& password, const std::string& newusername);
        static std::string applyupgradekey(const std::string& username, const std::string& password, const std::string& upgradekey);
        static bool checkblack();
        static bool validateJWTPermission(const std::string& requiredPermission = "");
        static std::string getJWTPayload();
        static bool hasPermission(const std::string& permission);
        static bool isJWTTokenValid();
        static bool validateJWTWithServer(const std::string& jwtToken);
        static std::string decryptJWTToken(const std::string& encryptedToken);
        static std::string getInitialJWTToken();
        static std::string lastLevel;
        static std::string getlastlevel();
        static bool downloadandinstallupdate(const std::string& updateurl);
        static std::vector<unsigned char> download(const std::string& fileId);
        static std::string msg(const std::string& fieldId);
        static std::string rebrand(const std::string& fieldId);
        static bool applyrebrand();
        static void rebrandprint(const std::string& text, const std::string& colorfieldid);
        static void rebrandprintfields(const std::string& textfieldid, const std::string& colorfieldid);
        static void backgroundchecker(const std::string& licensekey);
        static void check(const std::string& licensekey);
        static void setdevverbose(bool enabled);
        static bool isdevverbose();
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
        static const UserData& getuserdata();
    };
}

#endif
