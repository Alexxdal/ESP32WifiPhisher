#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "vendors.h"


static const char *vendor_string[] = 
{
    "Generic",
    "Vodafone",
    "Fastweb",
    "TP-Link",
    "TIM",
    "D-Link",
    "Skywifi",
    "Wind",
    "Linkem",
    "Huawei",
    "Netgear",
    "Tiscali",
    "FritzBox",
    "Netis"
};


static void to_lowercase(char *input, char *output) {
    for (int i = 0; i < strlen(input); i++) {
        output[i] = tolower(input[i]);
    }
    output[strlen(input)] = '\0';
}


vendors_t getVendor(char *ssid)
{
    if( ssid == NULL )
    {
        return GENERIC;
    }

    char ssid_lower[34] = { 0 };
    char temp_lower[34] = { 0 };
    to_lowercase((char *)ssid, (char *)&ssid_lower);
    for(uint8_t i = 0; i < sizeof(vendor_string)/sizeof(vendor_string[0]); i++ )
    {
        to_lowercase((char *)vendor_string[i], (char *)&temp_lower);
        if( strstr((char *)&ssid_lower, (char *)&temp_lower) != NULL )
        {
            return (vendors_t)i;
        }
    }
    return GENERIC;
}


const char * vendorToString(vendors_t vendor)
{
    return vendor_string[vendor];
}