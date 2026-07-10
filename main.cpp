#include <iostream>
#include <string>
#include <windows.h>
#include <vector>
#include <fstream>
#include "auth.h"
#include <sstream>

std::string licensekey;

namespace AUTH {
    const std::string PROJECT_NAME = AG(AuthGuards("").decrypt());
    const std::string PROJECT_ID = AG(AuthGuards("").decrypt());
    const std::string VERSION = AG(AuthGuards("").decrypt());
    const std::string CUSTOM_ID = AG(AuthGuards("").decrypt());
    const std::string PRIVATE_KEY = AG(AuthGuards("").decrypt());
    const std::string PUBLIC_KEY = AG(AuthGuards("").decrypt());
    const std::string SECRET_CON = AG(AuthGuards("").decrypt());
    const std::string API_URL = AG(AuthGuards("https://api.authguards.net/api-1.0/").decrypt());
}

static void printchathistory(const std::string& raw) {
    if (raw.empty()) {
        return;
    }
    std::istringstream stream(raw);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        const size_t sep = line.find('|');
        if (sep == std::string::npos) {
            std::cout << line << std::endl;
            continue;
        }
        std::cout << line.substr(0, sep) << AG(AuthGuards(": ").decrypt()) << line.substr(sep + 1) << std::endl;
    }
}

static void runchatmenu(const std::string& displayname) {
    auto& t = AUTH::AuthGuards::text();
    std::string chatchannel = AG(AuthGuards("main").decrypt());

    while (true) {
        std::cout << t.chatmenutitle;
        std::cout << t.chatmenuchannellabel << chatchannel << std::endl;
        std::cout << t.chatmenuoptionhistory;
        std::cout << t.chatmenuoptionsend;
        std::cout << t.chatmenuchangechannel;
        std::cout << t.chatmenuoptionexit;
        std::cout << t.chatmenuchoiceprompt;

        std::string choiceinput;
        std::getline(std::cin, choiceinput);
        int choice = -1;
        try {
            if (!choiceinput.empty()) {
                choice = std::stoi(choiceinput);
            }
        } catch (...) {
            choice = -1;
        }

        switch (choice) {
        case 1: {
            std::string history = AuthGuards::Api::fetchchatmessages(chatchannel);
            std::cout << t.chatmenuhistorytitle;
            if (history.empty()) {
                std::cout << t.chatmenunomessages;
                if (AuthGuards::Api::isdevverbose()) {
                    const std::string err = AuthGuards::Api::lastpanelactionerror();
                    if (!err.empty()) {
                        std::cout << err << std::endl;
                    }
                }
            } else {
                printchathistory(history);
            }
            break;
        }
        case 2: {
            std::cout << t.chatmenusendprompt;
            std::string message;
            std::getline(std::cin, message);
            if (message.empty()) {
                std::cout << t.chatmenuinvalid;
                break;
            }
            const std::string sender = displayname.empty()
                ? AuthGuards::Api::getuserdata().license.substr(0, std::min<size_t>(8, AuthGuards::Api::getuserdata().license.size()))
                : displayname;
            if (AuthGuards::Api::sendchatmessage(message, chatchannel, sender)) {
                std::cout << t.chatmenusendok;
            } else {
                std::cout << t.chatmenusendfail;
                if (AuthGuards::Api::isdevverbose()) {
                    const std::string err = AuthGuards::Api::lastpanelactionerror();
                    if (!err.empty()) {
                        std::cout << err << std::endl;
                    }
                }
            }
            break;
        }
        case 3: {
            std::cout << t.chatmenuchannelprompt;
            std::string newchannel;
            std::getline(std::cin, newchannel);
            if (!newchannel.empty()) {
                chatchannel = newchannel;
            }
            break;
        }
        case 0:
            return;
        default:
            std::cout << t.chatmenuinvalid;
            break;
        }
    }
}

int main() {
    AuthGuards::Api::configurefromenvironment();

    // You can remove this if you dont want authguards crytography to be applied to your program.
    CRYPTO_UTILS::AntiReverse::randomdelay();
    CRYPTO_UTILS::StringObfuscator::initializerandom();
    CRYPTO_UTILS::StaticRSA::initializersa();
    CRYPTO_UTILS::AntiReverse::antidump();
    if (CRYPTO_UTILS::MemoryProtection::detectmemorypatching()) { std::cout << AG(AuthGuards("Memory patching detected! Exiting...").decrypt()) << std::endl;
    Sleep(2000);
        return 1;
    }
    // END OF CRYPTO UTILS

    // This will be the start of your program starting the title and other builds
    // This will initialize the authguards api and start the session.
    std::string initresult = AuthGuards::Api::init();
    const std::string okStatus = AG(AuthGuards("OK").decrypt());
    const std::string versionUpdateStatus = AG(AuthGuards("VERSION_UPDATE").decrypt());
    if (initresult != okStatus) {
        if (initresult != versionUpdateStatus) {
            std::cout << AG(AuthGuards("Init failed: ").decrypt()) << initresult << std::endl;
            Sleep(2000);
        }
        return 1;
    }
    AuthGuards::Api::applyrebrand();
    std::string rebrandmsg1 = AuthGuards::Api::rebrand(AG(AuthGuards("b94fa01656e143a984728de9daeae8fd3").decrypt()));
    std::cout << rebrandmsg1 << std::endl << std::flush;
    AUTH::Logger::log(AG(AuthGuards("User started the program").decrypt()));

    // Example: ban the user from the program
    // After a license fails validation, or wherever you decide to ban the user
    // AuthGuards::Api::ban(AG(AuthGuards("try your luck again").decrypt())); or AuthGuards::Api::ban();

    // This will set the console title to the current date and time.
    std::string consoletitle = AG(AuthGuards("AG - Built at: ").decrypt()) + std::string(__DATE__) + " " + std::string(__TIME__);
    SetConsoleTitleA(consoletitle.c_str());

    std::cout << AG(AuthGuards(" Please select an authentication method:\n").decrypt());
    std::cout << AG(AuthGuards("-----------------------------------------\n").decrypt());
    std::cout << AG(AuthGuards("  [1] License key only\n").decrypt());
    std::cout << AG(AuthGuards("  [2] Register account (username/password + license key)\n").decrypt());
    std::cout << AG(AuthGuards("  [3] Login with username/password\n").decrypt());
    std::cout << AG(AuthGuards("  [4] Reset account password\n").decrypt());
    std::cout << AG(AuthGuards("  [5] Change account username\n").decrypt());
    std::cout << AG(AuthGuards("  [6] Add time (stack/upgrade key)\n").decrypt());
    std::cout << AG(AuthGuards("  [7] Login with web (browser)\n").decrypt());
    std::cout << AG(AuthGuards("-----------------------------------------\n").decrypt());
    std::cout << AG(AuthGuards(" Enter your choice: ").decrypt());
    // this is just for the selection of the menu, you can remove this if you dont want to use it.
    std::string methodinput;
    std::getline(std::cin, methodinput);
    int method = 1;
    try {
        if (!methodinput.empty()) {
            method = std::stoi(methodinput);
        }
    }
    catch (...) {
        method = 1;
    }
    // end of the selection of the menu, you can remove this if you dont want to use it.
    // this is the main menu options, you can remove this if you dont want to use it, you can copy and paste the options you want to use.
    switch (method) {
    case 1: {
        std::string licensekey;
        std::cout << AG(AuthGuards("Enter license key: ").decrypt());
        std::getline(std::cin, licensekey);
        std::cout << AG(AuthGuards("\n").decrypt());
        AuthGuards::Api::validatelicense(licensekey);
        break;
    }
    case 2: {
        std::string username;
        std::string password;
        std::string licensekey;

        std::cout << AG(AuthGuards("\nEnter username: ").decrypt());
        std::getline(std::cin, username);
        std::cout << AG(AuthGuards("Enter password: ").decrypt());
        std::getline(std::cin, password);
        std::cout << AG(AuthGuards("Enter license key: ").decrypt());
        std::getline(std::cin, licensekey);
        std::cout << AG(AuthGuards("\n").decrypt());
        AuthGuards::Api::registeraccount(username, password, licensekey);
        break;
    }
    case 3: {
        std::string username;
        std::string password;
        std::cout << AG(AuthGuards("\nEnter username: ").decrypt());
        std::getline(std::cin, username);
        std::cout << AG(AuthGuards("Enter password: ").decrypt());
        std::getline(std::cin, password);
        std::cout << AG(AuthGuards("\n").decrypt());
        AuthGuards::Api::validateaccount(username, password);
        break;
    }
    case 4: {
        std::string username;
        std::string oldpassword;
        std::string newpassword;
        std::cout << AG(AuthGuards("\nEnter username: ").decrypt());
        std::getline(std::cin, username);
        std::cout << AG(AuthGuards("Enter current password: ").decrypt());
        std::getline(std::cin, oldpassword);
        std::cout << AG(AuthGuards("Enter new password: ").decrypt());
        std::getline(std::cin, newpassword);
        std::cout << AG(AuthGuards("\n").decrypt());
        AuthGuards::Api::resetaccount(username, oldpassword, newpassword);
        break;
    }
    case 5: {
        std::string currentusername;
        std::string password;
        std::string newusername;
        std::cout << AG(AuthGuards("\nEnter current username: ").decrypt());
        std::getline(std::cin, currentusername);
        std::cout << AG(AuthGuards("Enter current password: ").decrypt());
        std::getline(std::cin, password);
        std::cout << AG(AuthGuards("Enter new username: ").decrypt());
        std::getline(std::cin, newusername);
        std::cout << AG(AuthGuards("\n").decrypt());
        AuthGuards::Api::changeusername(currentusername, password, newusername);
        break;
    }
    case 6: {
        std::string username;
        std::string password;
        std::string upgradekey;
        std::cout << AG(AuthGuards("\nEnter username: ").decrypt());
        std::getline(std::cin, username);
        std::cout << AG(AuthGuards("Enter password: ").decrypt());
        std::getline(std::cin, password);
        std::cout << AG(AuthGuards("Enter upgrade key (to add time to your account): ").decrypt());
        std::getline(std::cin, upgradekey);
        std::cout << AG(AuthGuards("\n").decrypt());
        AuthGuards::Api::applyupgradekey(username, password, upgradekey);
        break;
    }
    case 7: {
        std::cout << AG(AuthGuards("\nOpening browser for secure sign-in...\n").decrypt());
        AuthGuards::Api::loginwithweb();
        break;
    }
    default: {
        std::cout << AG(AuthGuards("Not an option. Please select 1-7. Exiting...").decrypt()) << std::endl;
        Sleep(2000);
        return 1;
    }
    }

    // This will display the user's license level for subscriptions. (https://authguards.com/subscriptions) 
    std::cout << AG(AuthGuards("Your license level: ").decrypt()) << AuthGuards::Api::getlastlevel() << std::endl;

    // This will check if the license has been blacklisted/banned.
    if (AuthGuards::Api::checkblack()) {
        std::cout << AG(AuthGuards("\nYour license was banned, please contact support. Exiting...\n").decrypt());
        Sleep(2000);
        return 1;
    }

    // This will log a message to the Discord webhook.
    const auto& userdata = AuthGuards::Api::getuserdata();
    AUTH::Logger::log(std::string(AG(AuthGuards("User logged in: ").decrypt())) + userdata.username);
    
    // This will display the user's data, example: userdata.username will be the license key.
    // AuthGuards::Api::backgroundchecker(userdata.license);

    // This will check if the license is valid.
    AuthGuards::Api::check(userdata.license); // you can use userdata.license or licensekey if you want to use the license key directly, if you use userdata.license you have to call the getuserdata function first.

    // This will display the user's data.
    std::cout << AG(AuthGuards("\n").decrypt()) << AG(AuthGuards("User Data:").decrypt()) << std::endl;
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

    // Keep client session alive for panel API calls (Functions - session policy).
    AuthGuards::Api::startperiodicvalidation(userdata.license);

    runchatmenu(userdata.username);

    // Panel APIs (use in your app):
    // AuthGuards::Api::fetchglobalvar("your_var_name");
    // AuthGuards::Api::fetchuservar("your_key");
    // AuthGuards::Api::setuservar("your_key", "value");
    // AuthGuards::Api::invokewebhook("your_webhook", "body=optional");
    // AuthGuards::Api::fetchchatmessages("main");
    // AuthGuards::Api::sendchatmessage("message", "main", userdata.username);

    // Example: download a protected file via the AuthGuards proxy (direct-link kept on your dashboard) >> https://authguards.com/files
    /*
    auto filebytes = AuthGuards::Api::download(AG(AuthGuards("YOUR_FILE_ID").decrypt()));
    if (filebytes.empty()) {
        std::cout << AG(AuthGuards("Download failed.").decrypt()) << std::endl;
    } else {
        std::ofstream outfile(AG(AuthGuards("file.exe").decrypt()), std::ios::binary);
        outfile.write(reinterpret_cast<const char*>(filebytes.data()), filebytes.size());
        outfile.close();
    }
    */
    
    // Custom messages - https://authguards.com/application/messages
    //std::string custommsg = AuthGuards::Api::msg(AG(AuthGuards("YOUR_FIELD_ID").decrypt()));
    //std::cout << custommsg << std::endl << std::flush;

    // Live rebrand - https://authguards.com/rebrander (sub-account license keys; master template + sub overrides)
    //AuthGuards::Api::applyrebrand();

    // Text field only (plain console):
    //std::string rebrandmsg = AuthGuards::Api::rebrand(AG(AuthGuards("SET_YOUR_TEXT_FIELD_ID").decrypt()));
    //std::cout << rebrandmsg << std::endl << std::flush;
    // Color field only (your hardcoded message, server color):
    //AuthGuards::Api::rebrandprint(AG(AuthGuards("Connected!\n").decrypt()), AG(AuthGuards("SET_YOUR_COLOR_FIELD_ID").decrypt()));
    // Text + color (both live rebrand field IDs):
    //AuthGuards::Api::rebrandprintfields(AG(AuthGuards("SET_YOUR_TEXT_FIELD_ID").decrypt()), AG(AuthGuards("SET_YOUR_COLOR_FIELD_ID").decrypt()));

    // This is an example of how to use the license level subscriptions and display the menu based on the license level.
    // -----------------------------------------------------------------------------------------------------------------
    // .. Simply remove the /* and */ to use the example below.

    /*std::string level = AuthGuards::Api::getlastlevel();
    int userlevel = std::stoi(level);
    std::cout << AG(AuthGuards("Your License Level: ").decrypt()) << userlevel << std::endl;
    
    int choice;
    do {
        if (userlevel == 1) {
            std::cout << AG(AuthGuards("\n[LEVEL 1 - BASIC MENU]").decrypt()) << std::endl;
            std::cout << AG(AuthGuards("0. Exit").decrypt()) << std::endl;
        } else if (userlevel == 2) {
            std::cout << AG(AuthGuards("\n[LEVEL 2 - ADVANCED MENU]").decrypt()) << std::endl;
            std::cout << AG(AuthGuards("0. Exit").decrypt()) << std::endl;
        } else if (userlevel == 3) {
            std::cout << AG(AuthGuards("\n[LEVEL 3 - PREMIUM MENU]").decrypt()) << std::endl;
            std::cout << AG(AuthGuards("0. Exit").decrypt()) << std::endl;
        } else if (userlevel == 4) {
            std::cout << AG(AuthGuards("\n[LEVEL 4 - VIP MENU]").decrypt()) << std::endl;
            std::cout << AG(AuthGuards("0. Exit").decrypt()) << std::endl;
        } else {
            std::cout << AG(AuthGuards("\n[UNKNOWN LEVEL MENU]").decrypt()) << std::endl;
            std::cout << AG(AuthGuards("0. Exit").decrypt()) << std::endl;
        }
        
        std::cout << AG(AuthGuards("\nEnter your choice: ").decrypt());
        std::cin >> choice;
        
        if (choice == 0) {
            std::cout << AG(AuthGuards("\nThank you for using AuthGuards!\n").decrypt());
            break;
        } else if (choice >= 1 && choice <= 3) {
            if (choice == userlevel) {
                std::cout << AG(AuthGuards("\nAccess granted to option ").decrypt()) << choice << AG(AuthGuards("!\n").decrypt());
                std::cout << AG(AuthGuards("Feature is now available for use.\n").decrypt());
            } else {
                std::cout << AG(AuthGuards("\nAccess denied! Your level (").decrypt()) << userlevel << AG(AuthGuards(") does not match this feature.\n").decrypt());
                std::cout << AG(AuthGuards("You can only access feature level ").decrypt()) << userlevel << AG(AuthGuards(".\n").decrypt());
            }
        } else {
            std::cout << AG(AuthGuards("\nInvalid choice. Please enter a valid option.\n").decrypt());
        }
    } while (true);*/

    std::cout << AG(AUTH::AuthGuards::text().pressenterexit) << std::endl;
    std::cin.get();
    CRYPTO_UTILS::StaticRSA::cleanup(); // you can remove this if you dont want authguards crytography to be applied to your program.
    return 0;
} 
