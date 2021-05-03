#!/usr/bin/env python3
# -*- coding: utf-8 -*-



# Global imports
import logging

#  modules import
from warn.core.core import *
from warn.util.util import *

# Logguer
log = logging.getLogger('log')

def detect_Location_lookup(x) :
    """
        @param x : a Analysis instance
        
        @rtype : a list of formatted strings
    """
    formatted_str = []
    
    structural_analysis_results = structural_analysis_search_method("Landroid/location/LocationManager","getProviders", x)
    
    for registers in data_flow_analysis(structural_analysis_results, x):
        local_formatted_str = "This application reads location information from all available providers (WiFi, GPS etc.)" 
        
        # we want only one occurence
        if not(local_formatted_str in formatted_str) :
            formatted_str.append(local_formatted_str)
        
    return sorted(formatted_str)

def gather_location_lookup(x) :
    """
        @param x : a Analysis instance
    
        @rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
    """
    result = []
    
    result.extend( detect_Location_lookup(x) )
    
    return result
