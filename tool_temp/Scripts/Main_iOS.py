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

test_dict = {"check_for_app_transport_security":"plist",
                "check_for_declared_URL_schemes":"plist",
                "cryptid_check":"executable",
                "stack_smash_protection_check":"executable",
                "pie_flag_check":"executable",
                "objc_release_flag_check":"executable",
                "third_party_frameworks_check":"executable",
                }

for test_name in test_dict.keys():
    logging.info(f"Execution Test - stack_smash_protection_check\n")
    if test_dict[test_name] is "plist":
        execution_result = globals()[ test_name ](INFO_PLIST_PATH)
    elif test_dict[test_name] is "executable":
        execution_result = globals()[ test_name ](APP_EXECUTABLE_PATH)
    logging.info(f"{execution_result[Constants.STATUS]}\n")
    logging.info(f"{execution_result[Constants.EXECUTION_OUTPUT]}\n")
