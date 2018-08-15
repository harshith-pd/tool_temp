from HelperFunctions import *
import Constants
import os


def check_for_declared_URL_schemes( plist_file_path=None ):
    execution_output="\n"
    if convert_plist_into_a_dictionary(plist_file_path)["Successful"]:
        plist_dict = convert_plist_into_a_dictionary(plist_file_path)["plist_dict"]
        if Constants.BUNDLE_URL_TYPES_KEY in plist_dict:
            bundle_url_types_array = plist_dict[Constants.BUNDLE_URL_TYPES_KEY]
            for bundle_url_type in bundle_url_types_array:
                if Constants.BUNDLE_TYPE_ROLE_KEY in bundle_url_type:
                    execution_output=f"{execution_output}Bundle type role is set as :{bundle_url_type[Constants.BUNDLE_TYPE_ROLE_KEY]}, for URL schemes:\n"
                for url_scheme in bundle_url_type[Constants.URL_SCHEME_NAMES_KEY]:
                    execution_output=f"{execution_output}-{url_scheme}\n"
                execution_output= f"{execution_output}Please ensure that the URL schemes are validated in the canOpenURL app-delegate method\n"
        else:
            execution_output = f"{execution_output}No entries for URL schemes were found in this application"
    else:
        logging.info(f"{execution_output}Unable to find the Info.plist file")

    return execution_output

################### sample call
#PATH = "/Users/harshith/Desktop/python/pythonFiles/tempdir/Payload/WhatsApp.app/Info.plist"
#result = check_for_declared_URL_schemes(PATH)
#print (result)

def check_for_app_transport_security( plist_file_path=None ):
    execution_output="\n"
    if convert_plist_into_a_dictionary(plist_file_path)["Successful"]:
        plist_dict = convert_plist_into_a_dictionary(plist_file_path)["plist_dict"]
        if Constants.APP_TRANSPORT_SECURITY_KEY in plist_dict:
            app_transport_security_dict = plist_dict[Constants.APP_TRANSPORT_SECURITY_KEY]
            for security_subkey in app_transport_security_dict.keys():
                if app_transport_security_dict[security_subkey] != Constants.APP_TRANSPORT_SECURITY_EXPECTED_VALUES[security_subkey]:
                    execution_output=f"{execution_output}{security_subkey} is set to {app_transport_security_dict[security_subkey]}.\nExpected value is {Constants.APP_TRANSPORT_SECURITY_EXPECTED_VALUES[security_subkey]}"
                if security_subkey == Constants.EXCEPTION_DOMAINS_KEY:
                    exception_domains = plist_dict[security_subkey]
                    for exception_domain in  exception_domains.keys():
                        exception_domain_subkeys_dict = exception_domains[exception_domain]
                        for exception_domain_subkey in exception_domain_subkeys_dict.keys():
                            if exception_domain_subkeys_dict[exception_domain_subkey] != Constants.EXCEPTION_DOMAINS_EXPECTED_VALUES[exception_domain_subkey]:
                                execution_output=f"{execution_output}{exception_domain_subkey} is set to {exception_domain_subkeys_dict[exception_domain_subkey]}.\nExpected value is {Constants.EXCEPTION_DOMAINS_EXPECTED_VALUES[exception_domain_subkey]}"
    else:
        logging.info(f"{execution_output}Unable to find the Info.plist file")

    return execution_output


################### sample call
#PATH = "/Users/harshith/Desktop/python/pythonFiles/tempdir/Payload/WhatsApp.app/Info.plist"
#result = check_for_app_transport_security(PATH)
#print (result)
