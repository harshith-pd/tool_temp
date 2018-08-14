import Constants

from HelperFunctions import *
from ClassTestComponents import TestComponents
from AppUnzipTests import *

logging_directory = Constants.LOGS_FOLDER

### Setup logging
logging.basicConfig(filename="{}/{}".format(logging_directory, "log.txt"),
                              format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%m/%d/%Y %I:%M:%S %p',
                              level=logging.DEBUG)

### parse the config file
xml_dict = parse_xml_to_dict("{}/{}".format(Constants.CONFIG_FOLDER, 'sample_config.xml'))

test_result = {}
for test_component in xml_dict.keys():
    if TestComponents.APP_UNZIP.value in test_component:
        test_result = execute_tests(xml_dict[TestComponents.APP_UNZIP.value]['Test'])
    elif TestComponents.SOURCE_CODE_ANALYSIS.value in test_component:
        pass
    elif TestComponents.ROOTED_DEVICE_TESTS.value in test_component:
        pass
    elif TestComponents.DEX_TO_JAR.value in test_component:
        pass
    else:
        logging.error("Test not yet implemented")
