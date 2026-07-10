#include "auth.h"

namespace {
struct clienttextbootstrap {
    clienttextbootstrap() {
        auto& t = AUTH::AuthGuards::text();

        // Init / flow
        t.pressentercontinue = AG(AuthGuards("[!] Press Enter to continue...").decrypt());
        t.pressenterexit = AG(AuthGuards("Press Enter to exit...").decrypt());

        // License input
        t.nolicensekey = AG(AuthGuards("No license key has been entered!").decrypt());

        // Network help
        t.checkinternet = AG(AuthGuards("Please check your internet connection and try again.").decrypt());
        t.checkfirewall = AG(AuthGuards("Please check your firewall/antivirus and try again.").decrypt());

        // Session
        t.invalidsession = AG(AuthGuards("Invalid license key or session. Please check your key and try again.").decrypt());

        // Auto-update flow
        t.updateauto = AG(AuthGuards("Attempting to download and install update automatically...").decrypt());
        t.updateexit = AG(AuthGuards("The application will now exit to complete the update process.").decrypt());
        t.updatefail = AG(AuthGuards("Automatic update failed. Please try again later.").decrypt());
        t.updatecontact = AG(AuthGuards("Please contact support for the correct version.").decrypt());
        t.downloadingupdate = AG(AuthGuards("Downloading update...").decrypt());
        t.downloadcomplete = AG(AuthGuards("Download completed. Launching update...").decrypt());

        // Web login (case 7 / loginwithweb)
        t.webloginopen = AG(AuthGuards("Complete sign-in in your browser. Opening approval page...\n").decrypt());
        t.webloginnolicense = AG(AuthGuards("Device login failed: missing license from server.").decrypt());
        t.webloginapproved = AG(AuthGuards("Browser approved. Completing sign-in...\n").decrypt());
        t.weblogintimeout = AG(AuthGuards("Device login timed out waiting for browser approval.").decrypt());

        // Expiry display (displayremainingtime / after successful verify)
        t.licenseexpired = AG(AuthGuards("License has expired!").decrypt());
        t.expirytitle = AG(AuthGuards("License Expiry Information:").decrypt());
        t.expirydivider = AG(AuthGuards("------------------------").decrypt());
        t.expirydatelabel = AG(AuthGuards("Expiry Date: ").decrypt());
        t.expiryremaininglabel = AG(AuthGuards("Time Remaining: ").decrypt());
        t.expirydays = AG(AuthGuards(" days, ").decrypt());
        t.expiryhours = AG(AuthGuards(" hours, ").decrypt());
        t.expiryminutes = AG(AuthGuards(" minutes, ").decrypt());
        t.expiryseconds = AG(AuthGuards(" seconds").decrypt());

        // Chat menu (after login - fetchchatmessages / sendchatmessage)
        t.chatmenutitle = AG(AuthGuards("\n--- Chat ---\n").decrypt());
        t.chatmenuchannellabel = AG(AuthGuards("Channel: ").decrypt());
        t.chatmenuoptionhistory = AG(AuthGuards("  [1] View chat history\n").decrypt());
        t.chatmenuoptionsend = AG(AuthGuards("  [2] Send message\n").decrypt());
        t.chatmenuchangechannel = AG(AuthGuards("  [3] Change channel\n").decrypt());
        t.chatmenuoptionexit = AG(AuthGuards("  [0] Exit chat\n").decrypt());
        t.chatmenuchoiceprompt = AG(AuthGuards("Enter choice: ").decrypt());
        t.chatmenuchannelprompt = AG(AuthGuards("Enter channel name: ").decrypt());
        t.chatmenusendprompt = AG(AuthGuards("Enter message: ").decrypt());
        t.chatmenuhistorytitle = AG(AuthGuards("\nChat history:\n").decrypt());
        t.chatmenunomessages = AG(AuthGuards("(no messages yet)\n").decrypt());
        t.chatmenusendok = AG(AuthGuards("Message sent.\n").decrypt());
        t.chatmenusendfail = AG(AuthGuards("Failed to send message.\n").decrypt());
        t.chatmenuinvalid = AG(AuthGuards("Invalid choice.\n").decrypt());
    }
} g_clienttextbootstrap;

}
