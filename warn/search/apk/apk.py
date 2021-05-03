#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# Global imports
import os
import hashlib
import logging

# Logguer
log = logging.getLogger('log')

# APK and Manifest related functions #
def grab_apk_file_hashes(apk_file) :
    """
        @param apk_file : apk file path (not an apk instance)
    
        @rtype : a list of several hexified hashes
    """
    results = []
        
    block_size=2**20
    
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    with open(apk_file,'rb') as f:
        while True:
            data = f.read(block_size)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
    
    f.close()
    
    results.append("MD5: %s" % md5.hexdigest())
    results.append("SHA-1: %s" % sha1.hexdigest())
    results.append("SHA-256: %s" % sha256.hexdigest())
    
    return results

def grab_filename(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the APK's filename
    """
    # Grab only the name.apk, not the full path provided
    return os.path.basename(apk.get_filename())