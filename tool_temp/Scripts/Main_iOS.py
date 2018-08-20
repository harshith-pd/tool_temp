import Constants

from HelperFunctions import *
from ClassTestComponents import TestComponents
from Info_Plist_Tests import *
from OTool_Tests import *

logging_directory = Constants.LOGS_FOLDER

### Setup logging
logging.basicConfig(filename="{}/{}".format(logging_directory, "log.txt"),
                              format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%m/%d/%Y %I:%M:%S %p',
                              level=logging.DEBUG)

INFO_PLIST_PATH = f"{Constants.OUTPUT_FOLDER}/Info.plist"
APP_EXECUTABLE_PATH = f"{Constants.OUTPUT_FOLDER}/{Constants.APP_NAME}"

config_xml_dict = parse_xml_to_dict("{}/{}".format(Constants.CONFIG_FOLDER, 'Config_iOS.xml'))

for test_name in config_xml_dict.keys():
    test_dict = config_xml_dict[test_name]
    execution_result = {}
    logging.info(f"Execution Test - {test_dict['title']}\n")
    if test_dict['verification_type'] == "plist":
        execution_result = globals()[test_dict['test_function']](INFO_PLIST_PATH)
    elif test_dict['verification_type'] == "executable":
        execution_result = globals()[test_dict['test_function']](APP_EXECUTABLE_PATH)
    else:
        print ("something went wrong")
        exit()
    logging.info(f"{execution_result[Constants.STATUS]}\n")
    test_dict['test_result'] = execution_result[Constants.STATUS]
    logging.info(f"{execution_result[Constants.EXECUTION_OUTPUT]}\n")
    test_dict['test_findings'] = execution_result[Constants.EXECUTION_OUTPUT]

print (config_xml_dict)
f = open('report.html','w')
message = "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css'><div class='container'>"
message += "<table class='table table-bordered'>"
message += "<tr>"
count = 0
for key,values in config_xml_dict.items():
    if count > 1:
        break
    for k in values.keys():
        message += "<td>" + k + "</td>"
        count += 1
print(message)

message += "</tr>"
for key,values in config_xml_dict.items():
    message = message + "<tr>"
    for k,v in values.items():
        try:
            message += "<td>" + values[k] + "</td>"
            # message += "<td>" + values['description'] + "</td>"
            # message += "<td>" + values['test_result'] + "</td>"
            # message += "<td>" + values['test_findings'] + "</td>"
            # message += "<td>" + values['remediation'] + "</td>"
        except TypeError:
            message += "<td></td>"
    message = message + "</tr>"
message = message + "</div></table>"
f.write(message)
f.close()


