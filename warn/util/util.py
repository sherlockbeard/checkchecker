#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# Global imports
import re
import logging

# Logger
log = logging.getLogger('log')

def convert_dex_to_canonical(dex_name) :
    """
        @param dex_name : a dex name, for instance "Lcom/name/test"
    
        @rtype : a dotted string, for instance "com.name.test"
    """
    final_name = ''
    if re.match('^\[?L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', dex_name) :
        global_part = dex_name[1:-1].split('/')
        final_part = global_part[:-1]
        last_part = global_part[-1].split('$')[0]
        final_part.append(str(last_part))
        final_name = '.'.join(str(i) for i in final_part)
    else :
        log.debug("[!] Conversion to canonical dotted name failed : \"" + dex_name + "\" is not a valid library dex name")
    return final_name

def convert_canonical_to_dex(canonical_name) :
    return 'L' + canonical_name.replace('.', '/') + ';'

# Log extra information
def log_result_path_information(detectors) :
    """
        @param detectors : a result from the detector's result list
    
        @rtype : void - it only logs extra information about the analysis result
    """
    for res in detectors :
        xrefs_from = res.get_xref_from()
        for xref_analysis, xref_encodedmethod in xrefs_from:
            xref_encodedmethod_class, xref_encodedmethod_function, _ = xref_encodedmethod.get_triple()
            log.info("'%s' called by function '%s' of class '%s'" % (res.get_value(), xref_encodedmethod_function, xref_encodedmethod_class))


# XML parsing
def get_parent_child_grandchild(tree):
    """
        @param tree : xml root Element
    
        @rtype : parent, child and grandchild Element
    """
    for parent in tree.iter() :
        for child in parent :
            for grandchild in child :
                yield parent, child, grandchild

# Single structural analysis
def structural_analysis_search_method(class_name, method_name, x):
    return x.find_methods(classname=class_name, methodname=method_name)

def structural_analysis_search_string(pattern, x):
    result = list(x.find_strings(pattern))
    log_result_path_information(result)
    return result

def structural_analysis_search_field(pattern, x):
    return list(x.find_fields(fieldname=pattern))

# Bulk structural analysis
def structural_analysis_search_method_bulk(class_name, method_listing, x):
    """
        @param list : a list of tuple (class function name, class function description)
    
        @rtype : a list of strings related to the findings
    """
    formatted_str = []
    
    for method_name, description in method_listing:
        if list(structural_analysis_search_method(class_name, method_name, x)):
            if description not in formatted_str:
                formatted_str.append(description)
    
    return sorted(formatted_str)

def structural_analysis_search_string_bulk(string_listing, x):
    formatted_str = []
    for string_name, description in string_listing:
        if structural_analysis_search_string(string_name, x):
            if description not in formatted_str:
                formatted_str.append(description)
            
    return sorted(formatted_str)
    
# OR Bitwise option recovery
def recover_bitwise_flag_settings(flag, constants_dict) :
    """
        @param flag : an integer value to be matched with bitwise OR options set
        @param constants_dict : a dictionary containing each options' integer value
    
        @rtype : a string summing up settings
    """
    recover = ''
    options = []
    
    try:
        flag_int = int(flag)
    except:
        return recover
    
    for option_value in constants_dict :
        if (int(flag) & option_value) == option_value :
            options.append(constants_dict[option_value])
            
    recover = ', '.join(i for i in options)
    
    return recover

# Check if extracted values are ALL register numbers, following the pattern 'v[0-9]+', as they obviously are register numbers and thus useless
def isnt_all_regs_values(string_list) :
    """
        @param list : a list of strings, extracted from the data flow analysis
    
        @rtype : a boolean, True if there's at least 1 non-register number value, Else False
    """
    result = False
    p_reg = re.compile('^v[0-9]+$')
    
    for i in string_list :
        if not(p_reg.match(i)):
            result = True
    
    return result
