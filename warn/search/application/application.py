#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# Global imports
import re
import logging

# Play-scraper import
try :
    import play_scraper
except ImportError :
    sys.exit("[!] The play-scraper module is not installed, please install it and try again")

# Constants 
ERROR_APP_DESC_NOT_FOUND = 'N/A'

# Logguer
log = logging.getLogger('log')

def grab_application_name(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the application common name
    """
    return apk.get_app_name()

def grab_application_package_name(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the package name
    """
    return apk.get_package()

def grab_application_name_description_icon(package_name, online_lookup) :
    """
        @param package_name : package name
    
        @rtype : (description, icon) string tuple
    """
    if not(online_lookup):
        return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND     
    
    try :
        
        app_details = play_scraper.details(package_name)
        
        if app_details:
            name = app_details['title'] if 'title' in app_details else ERROR_APP_DESC_NOT_FOUND
            desc = app_details['description'] if 'description' in app_details else ERROR_APP_DESC_NOT_FOUND
            icon_link = app_details['icon'] if 'icon' in app_details else ERROR_APP_DESC_NOT_FOUND
            
            return desc, "Icon link: %s" % icon_link
        
        else:
            log.warning("'%s' application's description and icon could not be found in the page" % str(package_name))
            return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND
    
    except ValueError:
        log.warning("'%s' application name does not exist on Google Play" % str(package_name))
        return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND

def grab_androidversion_code(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the android version code
    """
    return apk.get_androidversion_code()

def grab_androidversion_name(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the android version name
    """
    return apk.get_androidversion_name()
