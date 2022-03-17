#!/usr/bin/env python3
import argparse
from openpyxl import load_workbook
import io
import os
import requests
from collections import OrderedDict
import subprocess

parser = argparse.ArgumentParser(description='Run with no option to generate files to /tmp or point to the mscp directory')
parser.add_argument("-r", "--repo", default="/tmp/", help="Directory mscp is cloned to", type=str)
results = parser.parse_args()

if results.repo != "/tmp/":
    if results.repo[-1] != "/":
        path = results.repo + "/build"
    else:
        path = results.repo + "/build"
else:
    path = results.repo


url = 'https://raw.githubusercontent.com/securecontrolsframework/securecontrolsframework/main/SCF_current.xlsx'
r = requests.get(url, allow_redirects=True)

open(path + '/SCF_current.xlsx', 'wb').write(r.content)

workbook = load_workbook(filename=path + "/SCF_current.xlsx")
sheet = workbook.active


frameworklist = [""]
for cell in sheet[1]:    
    if cell.fill.start_color.index == 5 or cell.fill.start_color.index == 9 or cell.fill.start_color.index == 4 or cell.fill.start_color.index == 3:
        if "Risk" not in str(cell.value) and "800-53" not in str(cell.value) and "800-171" not in str(cell.value) and "CIS" not in str(cell.value) and "SP-CMM" not in str(cell.value):
            # print()
            frameworklist.append(str(cell.value).replace('\n'," "))

frameworklist.sort()
for framework in frameworklist[1:]:
    print("{}. {}".format(frameworklist.index(framework),framework))
        
print()
print()
framework_number = input("Enter Number for Framework for Mapping: ")
framework = frameworklist[int(framework_number)]


mapping = {}
keys = []
values = []

print("Generating mapping for {}".format(framework))
row_array = []
nist_column = int()
for column_cell in sheet.iter_cols(1, sheet.max_column):  # iterate column cell

    if str(column_cell[0].value).replace("\n"," ") == framework:    # check for your column
        keys.append(framework)
        for data in column_cell[1:]:    # iterate your column
            if data.value == None:
                continue
            else:
                keys.append("\"" + str(data.value).replace("\n",", ") + "\"")
                row_array.append(data.row)
        break
    

for column_cell in sheet.iter_cols(1, sheet.max_column):
    if str(column_cell[0].value).replace("\n"," ") == "NIST 800-53 rev5":
        values.append("800-53r5")
        for data in column_cell[1:]:
            if data.row in row_array:
                if data.value == None:
                    values.append("N/A")
                else:
                    values.append("\"" + str(data.value).replace("\n",", ") + "\"")


fullcsv = str()
missingcontrols = str()

counter = 0
for key in keys:
    fullcsv = fullcsv + key + "," + values[counter] + "\n"
    if values[counter] == "N/A":
        missingcontrols = missingcontrols + key + "\n"
    counter += 1

framework_filename = framework.replace(" ","_")
path_to_framework_mapping = path + "/" + framework_filename + "-mapping.csv"
missing_controls = path + "/" + framework_filename + "-missingcontrols.txt"
with open(path_to_framework_mapping,'w') as rite:
        rite.write(fullcsv)
rite.close()

with open(missing_controls,'w') as rite:
        rite.write(missingcontrols)
rite.close()

print("{} and {} written to {}".format(framework_filename + "-mapping.csv", framework_filename + "-missingcontrols.txt", path))

if results.repo != "/tmp/":
    
    script_path = path[:-6]
    print(script_path)
    full_path_mapping = os.path.abspath(path_to_framework_mapping)
    subprocess.call(script_path + "/scripts/generate_mapping.py " + full_path_mapping , shell=True)
