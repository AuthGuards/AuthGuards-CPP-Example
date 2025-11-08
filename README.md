# AuthGuards C++ Example

> **Lightweight sample that shows how to call the AuthGuards API from a native Windows console program.**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](https://isocpp.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
[![Security](https://img.shields.io/badge/Security-Hardened-red.svg)](https://en.wikipedia.org/wiki/Security)

## 1. Prep Your API Info
Edit the constants inside `main.cpp` (namespace `AUTH`). Replace the placeholders with the values from your AuthGuards dashboard:

- `PROJECT_NAME`, `PROJECT_ID`, `VERSION`
- `CUSTOM_ID`, `PRIVATE_KEY`, `PUBLIC_KEY`, `SECRET_CON`

You can keep `API_URL` as-is unless you self-host the API.

## 2. Build & Run
1. Open the solution (`AuthGuards.sln`) in Visual Studio 2019+.
2. Build the `AuthGuards` project (Debug or Release, x64 recommended).
3. Run the executable. The sample now asks which auth path to use (plain license, register credentials, login with credentials, reset password, or change username) and then:
   - Initializes crypto protections (can be commented out if not wanted).
   - Calls `AUTH::Api::init()`.
   - Runs the selected flow and prints license/user data.

## 3. Optional Blocks in `main.cpp`
Several features are ready to toggle on by simply uncommenting code:

| Feature | How to enable | What it does |
| --- | --- | --- |
| **Download protected file** | Un-comment the `AUTH::Api::download("YOUR_FILE_ID")` block | Streams a file through the AuthGuards proxy and saves it locally |
| **License level menu** | Un-comment the long menu example at the bottom | Shows how to gate features by subscription level |
| **Logger & ban helpers** | Un-comment the `AUTH::Logger::log` and `AUTH::Api::ban` lines | Sends a custom log message or bans a user |
| **Crypto utils** | Comment out the `CRYPTO_UTILS::...` calls at the top if not needed | Controls anti-debug/anti-dump helpers |

Each section is already clearly marked in `main.cpp` with comments so you can turn features on/off without searching through other files.

### Project Constants (`namespace AUTH`)
```cpp
namespace AUTH {
    const std::string PROJECT_NAME = "YOUR_PROJECT_NAME";
    const std::string PROJECT_ID   = "YOUR_PROJECT_ID";
    const std::string VERSION      = "1.0.0";
    const std::string CUSTOM_ID    = "YOUR_CUSTOM_ID";
    const std::string PRIVATE_KEY  = "YOUR_PRIVATE_KEY";
    const std::string PUBLIC_KEY   = "YOUR_PUBLIC_KEY";
    const std::string SECRET_CON   = "YOUR_SECRET_CONNECTION";
    const std::string API_URL      = "http://api.authguards.com/api/";
}
```

### Basic Startup Skeleton
```cpp
#include <iostream>
#include "auth.h"

int main() {
    CRYPTO_UTILS::AntiReverse::randomDelay();
    CRYPTO_UTILS::StaticRSA::initializeRSA();
    
    AUTH::Api::init();
    
    // add flows from the sections below
    
    CRYPTO_UTILS::StaticRSA::cleanup();
    return 0;
}
```

### License Key login
```cpp
std::string licenseKey;
std::cout << "Enter license key: ";
std::getline(std::cin, licenseKey);

const std::string response = AUTH::Api::validateLicense(licenseKey);
AUTH::Api::displayRemainingTime(response);

const auto& user = AUTH::Api::getUserData();
std::cout << "Username: " << user.username << '\n';
```

### Register with Credentials
```cpp
// --- Register Account ---
std::string regUsername, regPassword, regLicenseKey;
std::cout << "Enter username: ";
std::getline(std::cin, regUsername);
std::cout << "Enter password: ";
std::getline(std::cin, regPassword);
std::cout << "Enter license key: ";
std::getline(std::cin, regLicenseKey);

const std::string regResponse = AUTH::Api::registerAccount(regUsername, regPassword, regLicenseKey);
std::cout << regResponse << std::endl;
const auto& regUser = AUTH::Api::getUserData();
std::cout << "Registered as: " << regUser.username << '\n';
```

### Login with Credentials
```cpp
// --- Login with Credentials ---
std::string loginUsername, loginPassword;
std::cout << "Enter username: ";
std::getline(std::cin, loginUsername);
std::cout << "Enter password: ";
std::getline(std::cin, loginPassword);

const std::string loginResponse = AUTH::Api::validateAccount(loginUsername, loginPassword);
std::cout << loginResponse << std::endl;
const auto& loginUser = AUTH::Api::getUserData();
std::cout << "Logged in as: " << loginUser.username << '\n';
```

### Reset Account Password
```cpp
AUTH::Api::resetaccount(username, oldPassword, newPassword);
const auto& user = AUTH::Api::getUserData();
std::cout << "Password updated for " << user.username << '\n';
```

### Change Account Username
```cpp
std::string currentUsername, password, newUsername;
std::cout << "Enter current username: ";
std::getline(std::cin, currentUsername);
std::cout << "Enter current password: ";
std::getline(std::cin, password);
std::cout << "Enter new username: ";
std::getline(std::cin, newUsername);
AUTH::Api::changeusername(currentUsername, password, newUsername);
const auto& user = AUTH::Api::getUserData();
std::cout << "Username changed successfully! New username: " << user.username << '\n';
```

### Logger (Send a Discord webhook)
```cpp
1: AUTH::Logger::log("User started the program");
2: AUTH::Logger::log();

```

### Ban Helpers
   ```cpp
1: AUTH::Api::ban();
2: AUTH::Api::ban("User has been banned");
   ```

### Download Protected File
   ```cpp
auto bytes = AUTH::Api::download("YOUR_FILE_ID");
if (bytes.empty()) {
    std::cout << "Download failed.\n";
} else {
    std::ofstream out("file.exe", std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}
```

### License Level Menu Skeleton (Subscription)
```cpp
std::string level = AUTH::Api::getLastLevel();
int userLevel = std::stoi(level);

int choice = -1;
while (choice != 0) {
    std::cout << "\n[LEVEL " << userLevel << "] Options" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << "Enter choice: ";
    std::cin >> choice;

    if (choice == 0) {
        std::cout << "Goodbye!\n";
    } else if (choice == userLevel) {
        std::cout << "Access granted to option " << choice << "!\n";
    } else {
        std::cout << "Access denied.\n";
    }
}
```

## 4. What’s Included
- `auth.cpp` / `auth.h`: AuthGuards API wrapper
- `crypto_utils.cpp` / `crypto_utils.h`: optional security helpers used by the sample
- `main.cpp`: minimal console app demonstrating the flow

That’s it—swap in your keys, build, and decide which optional blocks you want to ship. Happy testing!
