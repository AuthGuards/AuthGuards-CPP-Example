#include <iostream>
#include <string>
#include <windows.h>
#include <vector>
#include <fstream>
#include "auth.h"
#include <sstream>

std::string licenseKey; // call this if globle and not using a menu based program.

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
    // DO NOT CHANGE THIS UNLESS YOUR SELF HOSTING.
    const std::string API_URL = AG(AuthGuards("http://api.authguards.com/api-1.0/").decrypt());
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

    std::cout << " Please select an authentication method:\n";
    std::cout << "-----------------------------------------\n";
    std::cout << "  [1] License key only\n";
    std::cout << "  [2] Register account (username/password + license key)\n";
    std::cout << "  [3] Login with username/password\n";
    std::cout << "  [4] Reset account password\n";
    std::cout << "  [5] Change account username\n";
    std::cout << "-----------------------------------------\n";
    std::cout << " Enter your choice: ";
    // this is just for the selection of the menu, you can remove this if you dont want to use it.
    std::string methodInput;
    std::getline(std::cin, methodInput);
    int method = 1;
    try {
        if (!methodInput.empty()) {
            method = std::stoi(methodInput);
        }
    }
    catch (...) {
        method = 1;
    }
    // end of the selection of the menu, you can remove this if you dont want to use it.
    // this is the main menu options, you can remove this if you dont want to use it, you can copy and paste the options you want to use.
    switch (method) {
    case 1: {
        std::string licenseKey;
        std::cout << AG(AuthGuards("Enter license key: ").decrypt());
        std::getline(std::cin, licenseKey);
        std::cout << AG(AuthGuards("\n").decrypt());
        AUTH::Api::validateLicense(licenseKey);
        break;
    }
    case 2: {
        std::string username;
        std::string password;
        std::string licenseKey;

        std::cout << "\nEnter username: ";
        std::getline(std::cin, username);
        std::cout << "Enter password: ";
        std::getline(std::cin, password);
        std::cout << "Enter license key: ";
        std::getline(std::cin, licenseKey);
        std::cout << "\n";
        AUTH::Api::registerAccount(username, password, licenseKey);
        break;
    }
    case 3: {
        std::string username;
        std::string password;
        std::cout << "\nEnter username: ";
        std::getline(std::cin, username);
        std::cout << "Enter password: ";
        std::getline(std::cin, password);
        std::cout << "\n";
        AUTH::Api::validateAccount(username, password);
        break;
    }
    case 4: {
        std::string username;
        std::string oldPassword;
        std::string newPassword;
        std::cout << "\nEnter username: ";
        std::getline(std::cin, username);
        std::cout << "Enter current password: ";
        std::getline(std::cin, oldPassword);
        std::cout << "Enter new password: ";
        std::getline(std::cin, newPassword);
        std::cout << "\n";
        AUTH::Api::resetaccount(username, oldPassword, newPassword);
        break;
    }
    case 5: {
        std::string currentUsername;
        std::string password;
        std::string newUsername;
        std::cout << "\nEnter current username: ";
        std::getline(std::cin, currentUsername);
        std::cout << "Enter current password: ";
        std::getline(std::cin, password);
        std::cout << "Enter new username: ";
        std::getline(std::cin, newUsername);
        std::cout << "\n";
        AUTH::Api::changeusername(currentUsername, password, newUsername);
        break;
    }
    default: {
        std::cout << "Not an option. Please select 1 to enter a license key. Exiting..." << std::endl;
        Sleep(2000);
        return 1;
    }
    }


    // This will display the user's license level for subscriptions. (https://authguards.com/subscriptions) 
    std::cout << AG(AuthGuards("Your license level: ").decrypt()) << AUTH::Api::getLastLevel() << std::endl;

    // This will check if the license has been blacklisted/banned.
    if (AUTH::Api::checkblack()) {
        std::cout << "\nYour license was banned, please contact support. Exiting...\n";
        Sleep(2000);
        return 1;
    }

    // This will log a message to the Discord webhook.
    AUTH::Logger::log(AG(AuthGuards("This will be sent to your discord webhook.").decrypt()));
    
    // This will display the user's data, example: userdata.username will be the license key.
    const auto& userdata = AUTH::Api::getUserData();
    
    // This will check if the license is valid in the background.
    AUTH::Api::backgroundchecker(userdata.license); // you can use userdata.license or licenseKey if you want to use the license key directly, if you use userdata.license you have to call the getUserData function first.

    // This will check if the license is valid.
    AUTH::Api::check(userdata.license); // you can use userdata.license or licenseKey if you want to use the license key directly, if you use userdata.license you have to call the getUserData function first.

    // This will display the user's data.
    std::cout << "\n" << AG(AuthGuards("User Data:").decrypt()) << std::endl;
    std::cout << AG(AuthGuards("Username: ").decrypt()) << userdata.username << std::endl;
    std::cout << AG(AuthGuards("License: ").decrypt()) << userdata.license << std::endl;
    std::cout << AG(AuthGuards("IP: ").decrypt()) << userdata.ip << std::endl;
    std::cout << AG(AuthGuards("HWID: ").decrypt()) << userdata.hwid << std::endl;
    std::cout << AG(AuthGuards("Expiry: ").decrypt()) << userdata.expiry << std::endl;
    std::cout << AG(AuthGuards("Created: ").decrypt()) << userdata.createdate << std::endl;
    std::cout << AG(AuthGuards("Last Login: ").decrypt()) << userdata.lastlogin << std::endl;
    std::cout << AG(AuthGuards("Subscriptions: ").decrypt()) << userdata.subscriptions << std::endl;
    std::cout << AG(AuthGuards("Customer Panel: ").decrypt()) << userdata.customerpanellink << std::endl;
    std::cout << AG(AuthGuards("Number of Users: ").decrypt()) << userdata.usercount << std::endl;

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
