#include <iostream>
#include <string>
#include <windows.h>
#include "auth.h"
#include <sstream>


namespace AUTH {
    const std::string PROJECT_NAME = AG(AuthGuards("YOUR_PROJECT_NAME | https://authguards.com/application").decrypt());
    const std::string PROJECT_ID = AG(AuthGuards("YOUR_PROJECT_ID | https://authguards.com/application").decrypt());
    const std::string VERSION = AG(AuthGuards("YOUR_PROJECT_VERSION | https://authguards.com/application").decrypt());
    const std::string CUSTOM_ID = AG(AuthGuards("YOUR_CUSTOM_ID AKA SELLER ID | https://authguards.com/account").decrypt());
    const std::string PRIVATE_KEY = AG(AuthGuards("YOUR_PRIVATE_KEY | https://authguards.com/account#apikeys").decrypt());
    const std::string PUBLIC_KEY = AG(AuthGuards("YOUR_PUBLIC_KEY | https://authguards.com/account#apikeys").decrypt());
    const std::string SECRET_CON = AG(AuthGuards("YOUR_SECRET_CON | https://authguards.com/account#apikeys").decrypt());
    const std::string API_URL = AG(AuthGuards("http://api.authguards.com/api/").decrypt()); /*DO NOT CHANGE UNLESS SELF-HOSTING OR HAVE THE SOURCE CODE*/
}




int main() {
    CRYPTO_UTILS::AntiReverse::randomDelay();
    CRYPTO_UTILS::StringObfuscator::initializeRandom();
    CRYPTO_UTILS::StaticRSA::initializeRSA();
    CRYPTO_UTILS::AntiReverse::antiDump();
    if (CRYPTO_UTILS::MemoryProtection::detectMemoryPatching()) { std::cout << "Memory patching detected! Exiting..." << std::endl; 
    Sleep(2000);
        return 1;
    }



    /*MAIN PROGRAM*/
    std::string consoleTitle = AG(AuthGuards("AG - Built at: ").decrypt()) + std::string(__DATE__) + " " + std::string(__TIME__);
    SetConsoleTitleA(consoleTitle.c_str());
    AUTH::Api::init();
    std::string licenseKey;
    std::cout << AG(AuthGuards("Enter license key: ").decrypt());
    std::getline(std::cin, licenseKey);

    std::cout << AG(AuthGuards("\n").decrypt());

    std::string response = AUTH::Api::validateLicense(licenseKey);
    AUTH::Api::displayRemainingTime(response);

    std::cout << AG(AuthGuards("Press Enter to exit...").decrypt());
    std::cin.get();
    CRYPTO_UTILS::StaticRSA::cleanup();
    /*END MAIN PROGRAM*/

    return 0;
} 