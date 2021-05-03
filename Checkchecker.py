#!/usr/bin/env python3
# -*- coding: utf-8 -*-



from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

# Global imports
import sys
import os
import re
import logging
import argparse
import io

#  modules import
from warn.search.search import grab_application_package_name
from warn.analysis.analysis import perform_analysis
from warn.report.report import dump_analysis_results
from warn.report.report import generate_report
from train_and_test import *
from imports import *
import json
from json2html import *



# Androguard import
try :
    from androguard.misc import AnalyzeAPK
except ImportError :
    sys.exit("[!] The androguard module is not installed, please install it and try again")

# Logger definition
log = logging.getLogger('log')
log.setLevel(logging.ERROR)
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
log.addHandler(handler)



# Options definition
parser = argparse.ArgumentParser()

applicationname ='none'

# Options definition
parser.add_argument('-i', '--input', help='APK file to analyze', required=True, type=str)
parser.add_argument('-o', '--output', help='Output report file (default "./<apk_package_name>_<timestamp>.<report_type>")', type=str)
parser.add_argument('-v', '--verbose', help='Verbosity level (ESSENTIAL 1, ADVANCED 2, EXPERT 3) (default 1)', type=int, choices=[1,2,3], default=1)
parser.add_argument('-r', '--report', help='Report type (default "html")', choices=['txt', 'html', 'json'], type=str, default='json')
parser.add_argument('-d', '--display-report', help='Display analysis results to stdout', action='store_true', default=False)
parser.add_argument('-L', '--log-level', help='Log level (default "ERROR")', type=str, choices=['debug','info','warn','error','critical','DEBUG', 'INFO','WARN','ERROR','CRITICAL'], default="ERROR")
parser.add_argument('-w', '--with-playstore-lookup', help='Enable online lookups on Google Play', action='store_true', default=False)

def chceckname(o):
    global applicationname
    applicationname=o.input

def main():
    global parser
    options = parser.parse_args()
    log.debug("[+] options: %s'" % options)
    
    # Log_Level
    try :
        log.setLevel(options.log_level.upper())
    except :
        parser.error("Please specify a valid log level")

    # Input
    print("[+] Loading the APK file...")
    chceckname(options)
    a, d, x = AnalyzeAPK(options.input)
    print(options.input)
    package_name = grab_application_package_name(a)
    
    # Analysis
    data = perform_analysis(options.input, a, d, x, options.with_playstore_lookup)


    
    # Synthesis
    if options.display_report:
        # Brace yourself, a massive dump is coming
        dump_analysis_results(data,sys.stdout) 
    
    outa = generate_report(package_name, data, options.verbose, options.report, options.output)
    f = open(outa,'r')
    data_processed = json.loads(f.read())
    #print(data)
    build_dir = "LEFT_TO_RIGHT"
    table_attr = {"style" : "width:100%", "class" : "table table-striped"}
    html = json2html.convert(data_processed,table_attributes=table_attr)
    #formatted_table = json2html.convert(json = data_processed)
    
    with open("YOURFILE.html", "w") as ht:
        ht.write(html)
    #your_file= open("YOURFILE.HTML","w")
    #your_file.write(formatted_table)
    #your_file.close()


  
# returns JSON object as 
# a dictionary




if __name__ == "__main__":
    main()