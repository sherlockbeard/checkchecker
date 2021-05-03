#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 29 15:46:29 2021

@author: reap
"""

from json2html import *
import json

f = open('com.tcd.appstore_1619691213.json','r')
data_processed = json.loads(f.read())
#print(data)
build_dir = "LEFT_TO_RIGHT"
table_attr = {"style" : "width:100%", "class" : "table table-striped"}
html = json2html.convert(data_processed,table_attributes=table_attr,encode=('utf-8'))
#formatted_table = json2html.convert(json = data_processed)
    
with open("YOURFILE.html", "wb") as ht:
    ht.write(html)