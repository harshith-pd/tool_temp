ENCRYPTED = "encrypted"
NOT_A_ZIP = "not a zip file"
CORRUPT = "corrupt"
SUCCESS = "SUCCESS"

#APKTOOL folder names
ASSETS_FOLDER = "assets"
RES_FOLDER = "res"
ANDROID_MANIFEST = "AndroidManifest"
SMALI_FOLDER = "smali"
LIB_FOLDER = "lib"
PERMISSIONS_ANDROID_MANIFEST = "permissions"
ORIGINAL_FOLDER = "original"

#Verification items for the signing info
DEBUG_SIGNATURE = "CN=Android Debug"

#Verification items for manifest xml
ANDROID_DEBUGGABLE_KEY = "android_debuggable"
ANDROID_ALLOW_BACKUP_KEY = "android_allow_backup"
ANDROID_FULL_BACKUP_CONTENT_KEY = "android_full_backup"
ANDROID_EXPORTED_KEY = "android_exported"
ANDROID_PROTECTION_LEVEL_KEY = "android_protection_level"
ANDROID_PROTECTION_VALUE_SIGNATURE = "signature"

#Verification items for re/xml
ALLOW_INTENT_HTTP = "http://*/*"
ALLOW_INTENT_HTTPS = "https://*/*"
ALLOW_INTENT_NAVIGATION = "http://*/*"
ACCESS_ORIGIN = "*"

ACCESS_ORIGIN_KEY = 'access_origin'
ALLOW_INTENT_KEY = 'allow_intent'
ALLOW_INTENT_NAVIGATION_KEY = 'allow_navigation'

#Application components from manifest file
SERVICE = "service"
ACTIVITY = "activity"
PROVIDER = "provider"
RECEIVER = "receiver"

#Info plist Constants
#url schemes
BUNDLE_URL_TYPES_KEY = "CFBundleURLTypes"
BUNDLE_TYPE_ROLE_KEY = "CFBundleTypeRole"
URL_SCHEME_NAMES_KEY = "CFBundleURLSchemes"
APP_TRANSPORT_SECURITY_KEY = "NSAppTransportSecurity"
EXCEPTION_DOMAINS_KEY = "NSExceptionDomains"
#ATS
APP_TRANSPORT_SECURITY_EXPECTED_VALUES = {"NSAllowsArbitraryLoads":False,
                                        "NSAllowsArbitraryLoadsForMedia":False,
                                        "NSAllowsArbitraryLoadsInWebContent":False,
                                        "NSAllowsLocalNetworking":False,
                                        "NSIncludesSubdomains":False,
                                        "NSExceptionAllowsInsecureHTTPLoads":False,
                                        "NSExceptionMinimumTLSVersion":"TLSv1.2 or above",
                                        "NSExceptionRequiresForwardSecrecy":True,
                                        "NSRequiresCertificateTransparency":False,
                                        "NSExceptionDomains":""}
#Execution constants
#values
PASS = "PASS"
FAIL = "FAIL"
#Security Threat levelname
SEVERE = "Severe"
MEDIUM = "Medium"
LOW = "Low"

STATUS = "test_result"
EXECUTION_OUTPUT = "test_findings"

 
 
 
########################################## 
APP_NAME = "Altoro-App"

INPUT_FOLDER = "/Users/harshith/PycharmProjects/android_restructuring/tool_temp/test_run/Altoro-App/09_05_2018_00_15_20/input"

OUTPUT_FOLDER = "/Users/harshith/PycharmProjects/android_restructuring/tool_temp/test_run/Altoro-App/09_05_2018_00_15_20/output"

LOGS_FOLDER = "/Users/harshith/PycharmProjects/android_restructuring/tool_temp/test_run/Altoro-App/09_05_2018_00_15_20/logs"

REPORT_FOLDER = "/Users/harshith/PycharmProjects/android_restructuring/tool_temp/test_run/Altoro-App/09_05_2018_00_15_20/report"

CONFIG_FOLDER = "/Users/harshith/PycharmProjects/android_restructuring/tool_temp/test_run/Altoro-App/09_05_2018_00_15_20/config"

TEST_RUN_FOLDER = "/Users/harshith/PycharmProjects/android_restructuring/tool_temp/test_run"

CONFIG_ROOT_FOLDER = "/Users/harshith/PycharmProjects/android_restructuring/tool_temp/config"

SCRIPTS_FOLDER = "/Users/harshith/PycharmProjects/android_restructuring/tool_temp/Scripts"

TOOLS_FOLDER = "/Users/harshith/PycharmProjects/android_restructuring/tool_temp/Tools"

TMP_FOLDER = "/Users/harshith/PycharmProjects/android_restructuring/tool_temp/.tmp"
