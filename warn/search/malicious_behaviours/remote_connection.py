#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# Global imports
import logging

#  modules import
from warn.core.core import *
from warn.util.util import *

# Logguer
log = logging.getLogger('log')

def detect_Socket_use(x) :
    """
        @param x : a Analysis instance
        
        @rtype : a list of formatted strings
    """
    formatted_str = []
    
    structural_analysis_results = structural_analysis_search_method("Ljava/net/Socket", "<init>", x)
    
    for registers in data_flow_analysis(structural_analysis_results, x):
        if len(registers) >= 2 :
            remote_address  = get_register_value(1, registers) # 1 is the index of the PARAMETER called in the method
            remote_port     = get_register_value(2, registers)
            
            local_formatted_str = "This application opens a Socket and connects it to the remote address '%s' on the '%s' port " % (remote_address, remote_port)
            if not(local_formatted_str in formatted_str) :
                formatted_str.append(local_formatted_str)       
    
    return sorted(formatted_str)

def gather_suspicious_connection_establishment(x) : 
    """
        @param x : a Analysis instance
    
        @rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
    """
    result = []
    
    result.extend( detect_Socket_use(x) ) 
        
    return result
