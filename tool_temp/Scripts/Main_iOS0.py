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
# test_dict = {"check_for_app_transport_security":"plist",
#                 "check_for_declared_URL_schemes":"plist",
#                 "cryptid_check":"executable",
#                 "stack_smash_protection_check":"executable",
#                 "pie_flag_check":"executable",
#                 "objc_release_flag_check":"executable",
#                 "third_party_frameworks_check":"executable",
#                 }

for test_name in config_xml_dict.keys():
    test_dict = config_xml_dict[test_name]
    execution_result = {}
    print (test_dict)
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
    test_dict['test_findings'] = execution_result[Constants.STATUS]

print (config_xml_dict)