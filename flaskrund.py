
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


parser = argparse.ArgumentParser()

applicationname ='none'

# Options definition
parser.add_argument('-o', '--output', help='Output report file (default "./<apk_package_name>_<timestamp>.<report_type>")', type=str)
parser.add_argument('-v', '--verbose', help='Verbosity level (ESSENTIAL 1, ADVANCED 2, EXPERT 3) (default 1)', type=int, choices=[1,2,3], default=1)
parser.add_argument('-r', '--report', help='Report type (default "html")', choices=['txt', 'html', 'json'], type=str, default='json')


def main(apk):
    
    global parser
    options = parser.parse_args()
    log.debug("[+] options: %s'" % options)
    # Input
    print("[+] Loading the APK file...")
    a, d, x = AnalyzeAPK(apk)
    package_name = grab_application_package_name(a)
    print(package_name)
    # Analysis
    data = perform_analysis(apk, a, d, x, False)


    
    # Synthesis
    if False:
        # Brace yourself, a massive dump is coming
        dump_analysis_results(data,sys.stdout) 
    
    print("sdvbsssssss")
    outa = generate_report(package_name, data, options.verbose, options.report, options.output)
    f = open(outa,'r')
    data_processed = json.loads(f.read())
    #print(data)
    build_dir = "LEFT_TO_RIGHT"
    table_attr = {"style" : "width:100%", "class" : "table table-striped"}
    html = json2html.convert(data_processed,table_attributes=table_attr)
    #formatted_table = json2html.convert(json = data_processed)
    
    with open("templates/YOURFILE.html", "w") as ht:
        ht.write(html)
    #your_file= open("YOURFILE.HTML","w")
    #your_file.write(formatted_table)
    #your_file.close()


  
# returns JSON object as 
# a dictionary



if __name__ == "__main__":
    main(apk)