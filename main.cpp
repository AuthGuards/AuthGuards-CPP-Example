#include <iostream>
#include <string>
#include <windows.h>
#include <vector>
#include <fstream>
#include "auth.h"
#include <sstream>

namespace AUTH {
    // -------------------------------- (CHANGE TO YOUR OWN INFORMATION) --------------------------------
    // project_name can be found here: https://authguards.com/application#application
    const std::string PROJECT_NAME = AG(AuthGuards("").decrypt());
    // project_id can be found here: https://authguards.com/application#application
    const std::string PROJECT_ID = AG(AuthGuards("").decrypt());      
    // version can be found here https://authguards.com/application#application
    const std::string VERSION = AG(AuthGuards("").decrypt());    
    // custom_id can be found here: https://authguards.com/application#application
    const std::string CUSTOM_ID = AG(AuthGuards("").decrypt());   
    // private_key can be found here: https://authguards.com/account -> API TAB -> PRIVATE KEY
    const std::string PRIVATE_KEY = AG(AuthGuards("").decrypt());    
    // public_key can be found here: https://authguards.com/account -> API TAB -> PUBLIC KEY    
    const std::string PUBLIC_KEY = AG(AuthGuards("").decrypt());          
    // secret_con can be found here: https://authguards.com/account -> API TAB -> SECRET CONNECTION STRING
    const std::string SECRET_CON = AG(AuthGuards("").decrypt());    
    // DO NOT CHANGE THIS (UNLESS YOUR SELF HOSTING!)
    const std::string API_URL = AG(AuthGuards("http://api.authguards.com/api/").decrypt());
}

int main() {
    // You can remove this if you dont want authguards crytography to be applied to your program.
    CRYPTO_UTILS::AntiReverse::randomDelay();
    CRYPTO_UTILS::StringObfuscator::initializeRandom();
    CRYPTO_UTILS::StaticRSA::initializeRSA();
    CRYPTO_UTILS::AntiReverse::antiDump();
    if (CRYPTO_UTILS::MemoryProtection::detectMemoryPatching()) { std::cout << "Memory patching detected! Exiting..." << std::endl; 
    Sleep(2000);
        return 1;
    }
    // END OF CRYPTO UTILS

    // This will be the start of your program starting the title and other builds
    // This will initialize the authguards api and start the session.
    AUTH::Api::init();

    // Example: send a custom log message to your Discord webhook (https://authguards.com/application)
    // AUTH::Logger::log("User started the program"); or AUTH::Logger::log(AG(AuthGuards("User started the program").decrypt()));

    // Example: ban the user from the program
    // After a license fails validation, or wherever you decide to ban the user
    // AUTH::Api::ban(); or AUTH::Api::ban();

    // This will set the console title to the current date and time.
    std::string consoleTitle = AG(AuthGuards("AG - Built at: ").decrypt()) + std::string(__DATE__) + " " + std::string(__TIME__);
    SetConsoleTitleA(consoleTitle.c_str());

    // This will prompt the user to enter a license key.
    std::string licenseKey; 
    std::cout << AG(AuthGuards("Enter license key: ").decrypt());
    std::getline(std::cin, licenseKey);
    std::cout << AG(AuthGuards("\n").decrypt());

    // This will validate the license key.
    std::string response = AUTH::Api::validateLicense(licenseKey);
    // This will display the remaining time of the license.
    AUTH::Api::displayRemainingTime(response);
    // This will display the user's license level.

    // This will display the user's license level for subscriptions. (https://authguards.com/subscriptions) 
    std::cout << AG(AuthGuards("Your license level: ").decrypt()) << AUTH::Api::getLastLevel() << std::endl;

    // This will check if the license has been blacklisted/banned.
    if (AUTH::Api::checkblack()) {
        std::cout << "\nYour license was banned, please contact support. Exiting...\n";
        Sleep(2000);
        return 1;
    }

    // This will display the user's data, example: userdata.username will be the license key.
    const auto& userdata = AUTH::Api::getUserData();
    std::cout << "\nUser Data:" << std::endl;
    std::cout << "Username: " << userdata.username << std::endl;
    std::cout << "IP: " << userdata.ip << std::endl;
    std::cout << "HWID: " << userdata.hwid << std::endl;
    std::cout << "Expiry: " << userdata.expiry << std::endl;
    std::cout << "Created: " << userdata.createdate << std::endl;
    std::cout << "Last Login: " << userdata.lastlogin << std::endl;
    std::cout << "Subscriptions: " << userdata.subscriptions << std::endl;
    std::cout << "Customer Panel: " << userdata.customerpanellink << std::endl;
    std::cout << "Number of Users: " << userdata.usercount << std::endl;

    // Example: download a protected file via the AuthGuards proxy (direct-link kept on your dashboard) >> https://authguards.com/files
    /*
    auto fileBytes = AUTH::Api::download("YOUR_FILE_ID");
    if (fileBytes.empty()) {
        std::cout << "Download failed." << std::endl;
    } else {
        std::ofstream outFile("file.exe", std::ios::binary);
        outFile.write(reinterpret_cast<const char*>(fileBytes.data()), fileBytes.size());
        outFile.close();
    }
    */

    // This is an example of how to use the license level subscriptions and display the menu based on the license level.
    // -----------------------------------------------------------------------------------------------------------------
    // .. Simply remove the /* and */ to use the example below.

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
    CRYPTO_UTILS::StaticRSA::cleanup(); // you can remove this if you dont want authguards crytography to be applied to your program.
    return 0;
} 
