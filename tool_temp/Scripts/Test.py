from HelperFunctions import *
import Constants
import plistlib as plist_to_dictionary_lib
import os


def check_for_declared_URL_schemes( plist_file_path=None ):
    execution_output="\n"
    if os.path.exists(plist_file_path):
        with open(plist_file_path, "rb") as plist_file:
            plist_dict = plist_to_dictionary_lib.load(plist_file)
            if "CFBundleURLTypes" in plist_dict:
                bundle_url_types_array = plist_dict["CFBundleURLTypes"]
                for bundle_url_type in bundle_url_types_array:
                    if "CFBundleTypeRole" in bundle_url_type:
                        execution_output=f"{execution_output}Bundle type role is set as :{bundle_url_type['CFBundleTypeRole']}, for URL schemes:\n"
                    for url_scheme in bundle_url_type["CFBundleURLSchemes"]:
                        execution_output=f"{execution_output}-{url_scheme}\n"
                    execution_output= f"{execution_output}Please ensure that the URL schemes are validated in the canOpenURL app-delegate method\n"
            else:
                execution_output = f"{execution_output}No entries for URL schemes were found in this application"
    else:
        execution_output = f"{execution_output}Unable to find the Info.plist file"

    return execution_output

################### sample call
#PATH = "/Users/harshith/Desktop/python/pythonFiles/tempdir/Payload/WhatsApp.app/Info.plist"
#result = check_for_declared_URL_schemes(PATH)
#logging.info (result)
