#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Global imports
import sys
import logging


from warn.search.search import *
# Logguer
log = logging.getLogger('log')

# Consolidate all data
def perform_analysis(apk_file, a, d, x, online_lookup) :
    """
        @param apk_file         : apk file path
        @param a                : a APK instance
        @param d                : a DalvikVMFormat instance
        @param x                : a Analysis instance
        @param online_lookup    : boolean value, enable/disable online lookup
    
        @rtype : a list of dictionaries of strings lists [ { "application_information": [ ("application_name", ["com.test"]), ("application_version", ["1.0"]) ] }, { ... }]
    """
    # application general information 
    app_package_name = grab_application_package_name(a)
    app_desc, app_icon = grab_application_name_description_icon(app_package_name, online_lookup)
    app_description = [app_icon, app_desc]
    
    
    # data gathering
    data = []
    data.append(
                { 'application_information' :
                    [
                        ( 'application_name',                       [grab_application_name(a)] ),
                        ( 'application_version',                    [grab_androidversion_name(a)] ),
                        ( 'package_name',                           [app_package_name] ),
                        ( 'description',                             app_description )
                    ]
                }
    )
    
    data.append(
                { 'analysis_results' :
                    [
                        ( 'telephony_identifiers_leakage',           gather_telephony_identifiers_leakage(x) ),
                        ( 'device_settings_harvesting',              gather_device_settings_harvesting(x) ),
                        ( 'location_lookup',                         gather_location_lookup(x) ),
                        ( 'connection_interfaces_exfiltration',      gather_connection_interfaces_exfiltration(x) ),
                        ( 'telephony_services_abuse',                gather_telephony_services_abuse(a,x) ),
                        ( 'audio_video_eavesdropping',               gather_audio_video_eavesdropping(x) ),
                        ( 'suspicious_connection_establishment',     gather_suspicious_connection_establishment(x) ),
                        ( 'PIM_data_leakage',                        gather_PIM_data_leakage(x) ),
                        ( 'code_execution',                          gather_code_execution(x) ),
                        ( 'Malign or Bengin',                        gather_classifed(apk_file) )
                    ],
                }
    )
    
    data.append(
                { 'apk_file' :
                    [
                        ( 'file_name',                              [grab_filename(a)] ),
                        ( 'fingerprint',                             grab_apk_file_hashes(apk_file) ),
                        ( 'file_list',                               grab_file_list(a) ),
                        ( 'certificate_information',                 grab_certificate_information(a) )
                    ]
                }
    )   
    
    data.append(
                { 'androidmanifest.xml' :
                    [
                        ( 'main_activity',                          [grab_main_activity(a)] ),
                        ( 'sdk_versions',                            grab_sdk_versions(a) ),
                        ( 'activities',                              grab_activities(a) ),
                        ( 'services',                                grab_services(a) ),
                        ( 'receivers',                               grab_receivers(a) ),
                        ( 'providers',                               grab_providers(a) ),
                        ( 'permissions',                             grab_permissions(a) ),
                        ( 'features',                                grab_features(a) ),
                        ( 'libraries',                               grab_libraries(a) )
                    ]
                }
    )

    data.append(
                { 'apis_used' :
                    [
                        ( 'classes_list',                            grab_classes_list(d, x) ),
                        ( 'internal_classes_list',                   grab_internal_classes_list(d, x) ),
                        ( 'classes_hierarchy',                       grab_classes_hierarchy(d, x) ),
                        ( 'intents_sent',                            grab_intents_sent(x) )
                    ]
                }
    )   
    
    return data
