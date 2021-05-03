#!/usr/bin/env python3
# -*- coding: utf-8 -*-



# Global imports
import logging

#  modules import
from warn.util.util import *

# Logguer
log = logging.getLogger('log')

def detect_content_provider_access(x):
    """
        @param x : a Analysis instance
        
        @rtype : a list of formatted strings
    """
    formatted_str = []
    
    string_listing = [  ("content://sms",                                   "This application accesses the SMS list"),
                        ("content://mms-sms",                               "This application accesses the SMS/MMS list"),
                        ("content://mms",                                   "This application accesses the MMS list"),
                        ("content://com.google.contacts",                   "This application accesses the contacts list"),
                        ("content://com.android.contacts",                  "This application accesses the contacts list"),
                        ("content://contacts",                              "This application accesses the contacts list"),
                        ("content://downloads",                             "This application accesses the downloads folder"),
                        ("content://com.android.calendar",                  "This application accesses the calendar"),
                        ("content://calendar",                              "This application accesses the calendar"),
                        ("content://call_log",                              "This application accesses the call log"),
                        ("content://com.android.fmradio",                   "This application accesses the FM radio"),
                        ("content://com.android.browser",                   "This application accesses the native browser data"),
                        ("content://com.android.providers.voicemail",       "This application accesses the voicemail"),
                        ("content://sync",                                  "This application accesses the synchronisation history"),
                        ("content://com.android.bluetooth.opp/",            "This application accesses the Bluetooth"),
                        ("content://com.android.email.provider",            "This application accessed the mail application data"),
                        ("content://com.android.email.attachmentprovider",  "This application accessed the mail application data"),
                        ("content://com.android.browser",                   "This application accesses the native browser data")
    ]
    
    return structural_analysis_search_string_bulk(string_listing, x)


def detect_clipboard_manager_calls(x):
    """
        @param x : a Analysis instance
        
        @rtype : a list of formatted strings
    """
    method_listing = [
            ("getPrimaryClip",              "This application accesses data stored in the clipboard"),
            ("getText",                     "This application accesses data stored in the clipboard"),
            ("hasPrimaryClip",              "This application accesses data stored in the clipboard"),
            ("hasText",                     "This application accesses data stored in the clipboard"),
    ]
    
    class_name = "Landroid/content/ClipboardManager"
    
    return structural_analysis_search_method_bulk(class_name, method_listing, x)

def gather_PIM_data_leakage(x):
    """
        @param x : a Analysis instance
    
        @rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
    """
    result = []
    
    result.extend( detect_content_provider_access(x) )
    result.extend( detect_clipboard_manager_calls(x) )
        
    return result
