# AuthGuards C++ Client

Production template for Windows apps using the AuthGuards API. The SDK ships as a **closed-source static library** - you write your app; we protect the auth logic inside `AuthGuards.lib`.

## Requirements

- Windows 10 or later
- Visual Studio 2019+ (v145 toolset, **x64 Release** recommended)
- An AuthGuards seller account and project credentials from [authguards.net](https://authguards.net)

## 1. Download the library

Download the latest prebuilt library:

**http://api.authguards.net/AuthGuards.lib**

Save it in **this folder** (same directory as `main.cpp`):

```
ClientBase/
  main.cpp
  client_text.cpp
  auth.h
  client_text.h
  crypto_utils.h
  akc.h
  AuthGuards.lib    <-- download and place here
```

Do not put the `.lib` under `x64/Release/` or other build subfolders.

## 2. What is in this repo

| Included | Purpose |
|----------|---------|
| `main.cpp` | Your app entry + `namespace AUTH` credentials |
| `client_text.cpp` | Your branded console text |
| `auth.h`, `client_text.h`, `crypto_utils.h`, `akc.h` | **Headers only** - needed to compile against the `.lib` |
| `AuthGuards.lib` | **You download this** - compiled SDK (not stored on GitHub) |

You do **not** get SDK source code. Headers declare the API; the `.lib` contains the implementation.

## 3. Configure your project

Edit the `namespace AUTH` block at the top of `main.cpp`:

- `PROJECT_NAME`, `PROJECT_ID`, `VERSION`
- `CUSTOM_ID`, `PRIVATE_KEY`, `PUBLIC_KEY`, `SECRET_CON`
- `API_URL` (default: `https://api.authguards.net/api-1.0/`)

Edit `client_text.cpp` for your branded console messages.

## 4. Build

1. Open `ClientBase.sln` in Visual Studio.
2. Set configuration to **Release | x64**.
3. Build **ClientBase**.
4. Output: `ClientBase.exe` in this same folder.

## 5. Enable panel features

In your AuthGuards dashboard, open **Application - Functions** and enable the API endpoints you use.

After login, call `startperiodicvalidation(license)` before using panel APIs. The template includes an interactive **chat menu** after login.

## Docs

- API reference: [authguards.net/developers/docs](https://authguards.net/developers/docs)

## Support

Open a ticket from your seller dashboard if you need help.

## Notes

- Re-download `AuthGuards.lib` when we announce SDK updates.
- Never commit real API keys to a public repository.
