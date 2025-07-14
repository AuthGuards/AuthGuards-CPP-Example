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

    std::cout << AG(AuthGuards("Your license level: ").decrypt()) << AUTH::Api::getLastLevel() << std::endl;

    /*std::string level = AUTH::Api::getLastLevel();
    int userLevel = std::stoi(level);
    std::cout << "Your License Level: " << userLevel << std::endl;
    
    int choice;
    do {
        if (userLevel == 1) {
            std::cout << "\n[LEVEL 1 - BASIC MENU]" << std::endl;
            std::cout << "0. Exit" << std::endl;
        } else if (userLevel == 2) {
            std::cout << "\n[LEVEL 2 - ADVANCED MENU]" << std::endl;
            std::cout << "0. Exit" << std::endl;
        } else if (userLevel == 3) {
            std::cout << "\n[LEVEL 3 - PREMIUM MENU]" << std::endl;
            std::cout << "0. Exit" << std::endl;
        } else if (userLevel == 4) {
            std::cout << "\n[LEVEL 4 - VIP MENU]" << std::endl;
            std::cout << "0. Exit" << std::endl;
        } else {
            std::cout << "\n[UNKNOWN LEVEL MENU]" << std::endl;
            std::cout << "0. Exit" << std::endl;
        }
        
        std::cout << "\nEnter your choice: ";
        std::cin >> choice;
        
        if (choice == 0) {
            std::cout << "\nThank you for using AuthGuards!\n";
            break;
        } else if (choice >= 1 && choice <= 3) {
            if (choice == userLevel) {
                std::cout << "\nAccess granted to option " << choice << "!\n";
                std::cout << "Feature is now available for use.\n";
            } else {
                std::cout << "\nAccess denied! Your level (" << userLevel << ") does not match this feature.\n";
                std::cout << "You can only access feature level " << userLevel << ".\n";
            }
        } else {
            std::cout << "\nInvalid choice. Please enter a valid option.\n";
        }
    } while (true);*/

    std::cout << AG(AuthGuards("Press Enter to exit...").decrypt());
    std::cin.get();
    CRYPTO_UTILS::StaticRSA::cleanup();
    /*END MAIN PROGRAM*/

    return 0;
} 
