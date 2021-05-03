#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# Global imports
import sys
import logging
import os
import time
import textwrap
import json
import codecs

# Jinja2 module import
try :
    from jinja2 import Environment, PackageLoader, FileSystemLoader, Template
except ImportError :
    sys.exit("[!] The Jinja2 module is not installed, please install it and try again")

# Logguer
log = logging.getLogger('log')



# Constants
REPORT_TXT = 'txt'
REPORT_JSON = 'json'

# Data tab cleaner
def clean_list(list_to_clean,purge_list) :
    """
        @param list_to_clean : a list to be cleaned up
        @param purge_list : the list of elements to remove in the list
    
        @rtype : a cleaned list
    """
    if list_to_clean and purge_list :
        for i in reversed(purge_list) :
            del list_to_clean[i]

# Dump
def flush_simple_string(string, file) :
    """
        @param string : a unique string
        @param file : output file descriptor
    """
    file.write("%s\n" % string)

def dump_analysis_results(data, file_descriptor) :
    """
        @param data : analysis results list
        @param file_descriptor : dump output, file or sys.stdout
    
        @rtype : void - it only prints out the list
    """
    # Watch out for encoding error while priting
    flush_simple_string("===== Checkchecker Report =====", file_descriptor)
    if data:
        for item in data:
            for category, element_tuple in item.items():
                
                if isinstance(category, str):
                    flush_simple_string("[+] %s" % category.replace('_',' ').title(), file_descriptor)
                
                for name,content in element_tuple :
                    if content and isinstance(name, str):
                        flush_simple_string("\t[.] %s" % name.replace('_',' ').title().ljust(40), file_descriptor)
                        
                        for element in content:
                            if isinstance(element,str) or isinstance(element,unicode):
                                prefix = "\t\t - "
                                wrapper = textwrap.TextWrapper(initial_indent=prefix, width=200, subsequent_indent="\t\t   ")
                                flush_simple_string(wrapper.fill(element), file_descriptor)
                        
                        flush_simple_string("", file_descriptor)
                flush_simple_string("", file_descriptor)


def filter_analysis_results(data, verbosity) :
    
    # Analysis data levels (must match with the analysis module)
    data_level  = {
                    # Application
                     'application_name'                     : 1 ,
                     'application_version'                  : 1 ,
                     'package_name'                         : 1 ,
                     'description'                          : 1 ,
                    
                    
                    # Malicious Behaviours Detection
                    # -- Telephony identifiers leakage              
                     'telephony_identifiers_leakage'        : 1 ,
                    
                    # -- Device settings harvesting             
                     'device_settings_harvesting'           : 1 ,
                    
                    # -- Physical location lookup
                     'location_lookup'                      : 1 ,

                    # -- Connection interfaces information exfiltration
                     'connection_interfaces_exfiltration'   : 1 ,

                    # -- Telephony services abuse
                     'telephony_services_abuse'             : 1 ,
                    
                    # -- Audio/Video eavesdropping
                     'audio_video_eavesdropping'            : 1 ,
                    
                    # -- Suspicious connection establishment
                     'suspicious_connection_establishment'  : 1 ,

                    # -- PIM dataleakage
                     'PIM_data_leakage'                     : 1 ,
                    
                    # -- Native code execution
                     'code_execution'                       : 1 ,

                     'Malign or Bengin'                     :1,
                    
                    # APK 
                     'file_name'                            : 1 ,
                     'fingerprint'                          : 1 ,
                     'file_list'                            : 1 ,
                     'certificate_information'              : 1,
                    
                    
                    # Manifest
                     'main_activity'                        : 1 ,
                     'sdk_versions'                         : 1 ,
                     'activities'                           : 1 ,
                     'services'                             : 1 ,
                     'receivers'                            : 1 ,
                     'providers'                            : 1 ,
                     'permissions'                          : 1 ,
                     'features'                             : 1 ,
                     'libraries'                            : 1 ,
                    
                    
                    # APIs
                     'classes_list'                         : 1,
                     'internal_classes_list'                : 1 ,
                     'external_classes_list'                : 1 ,
                     'classes_hierarchy'                    : 1 ,
                     'intents_sent'                         : 1 
    }

    if data :
        purge_category = []
        
        for category_index, item in enumerate(data) :
            for category, element_tuple in item.items() :
                purge_tuple = []
                
                for tuple_index, tuple in enumerate(element_tuple) :
                    name, content = tuple
                    
                    # if the defined level for an item is above the user's chosen verbosity, remove it
                    if (name in data_level) and (int(data_level[name]) > int(verbosity)) :
                        purge_tuple.append(tuple_index)
                    
                    elif not(name in data_level) :
                        log.error("'%s' item has no defined level of verbosity", name)
                
                clean_list(element_tuple,purge_tuple)

            # if there's no item for a category, remove the entire category
            if not(element_tuple) :
                purge_category.append(category_index)
        
        clean_list(data,purge_category)
        
    return data

def generate_report_txt(data, report, output_file) :
    """
        @param data : analysis result list
        @param verbosity : desired verbosity
        @param report : report type
        @param output_file : output file name
    """
    output, extension = os.path.splitext(output_file)
    output_file = output_file + ".txt" if ".txt" not in extension.lower() else output_file
    
    with open(output_file, 'w') as f_out:
        dump_analysis_results(data, f_out)
    f_out.close()
    
    print("[+] Analysis successfully completed and TXT file report available '%s'" % output_file)

def generate_report_json(data, report, output_file) :
    """
        @param data : analysis result list
        @param verbosity : desired verbosity
        @param report : report type
        @param output_file : output file name
    """
    output, extension = os.path.splitext(output_file)
    output_file = output_file + ".json" if ".json" not in extension.lower() else output_file
    
    with open(output_file, 'w') as f_out:
        json.dump(data, f_out)
    f_out.close()
    
    print("[+] Analysis successfully completed and JSON file report available '%s'" % output_file)
    return output_file


def generate_report(package_name, data, verbosity, report, output) :
    """
        @param data : analysis result list
        @param verbosity : desired verbosity
        @param report : report type
    """
    if (sys.version_info < (3, 0)):
        os_getcwd = os.getcwdu
    
    else:
        os_getcwd = os.getcwd
    
    output_file = os.path.join(os_getcwd(), package_name + "_%s" % str(int(time.time()))) if not(output) else output
    
    filter_analysis_results(data,1)
    
    if report == REPORT_TXT:
        outa =generate_report_txt(data, report, output_file)
        return outa

    
    if report == REPORT_JSON:
        outa =generate_report_json(data, report, output_file)
        return outa