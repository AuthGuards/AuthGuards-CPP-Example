#ifndef AUTH_CLIENT_TEXT_H
#define AUTH_CLIENT_TEXT_H
#include <string>
namespace AUTH {
namespace AuthGuards {
    struct Strings {
        std::string pressentercontinue;
        std::string pressenterexit;
        std::string nolicensekey;
        std::string checkinternet;
        std::string checkfirewall;
        std::string invalidsession;
        std::string updateauto;
        std::string updateexit;
        std::string updatefail;
        std::string updatecontact;
        std::string webloginopen;
        std::string webloginnolicense;
        std::string webloginapproved;
        std::string weblogintimeout;
        std::string licenseexpired;
        std::string expirytitle;
        std::string expirydivider;
        std::string expirydatelabel;
        std::string expiryremaininglabel;
        std::string expirydays;
        std::string expiryhours;
        std::string expiryminutes;
        std::string expiryseconds;
        std::string downloadingupdate;
        std::string downloadcomplete;
        std::string chatmenutitle;
        std::string chatmenuchannellabel;
        std::string chatmenuoptionhistory;
        std::string chatmenuoptionsend;
        std::string chatmenuchangechannel;
        std::string chatmenuoptionexit;
        std::string chatmenuchoiceprompt;
        std::string chatmenuchannelprompt;
        std::string chatmenusendprompt;
        std::string chatmenuhistorytitle;
        std::string chatmenunomessages;
        std::string chatmenusendok;
        std::string chatmenusendfail;
        std::string chatmenuinvalid;
    };

    inline Strings& text() {
        static Strings instance;
        return instance;
    }
}
}

#endif
