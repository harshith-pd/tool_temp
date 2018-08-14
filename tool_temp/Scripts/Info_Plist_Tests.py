
import Constants



def app_transport_security_tests:
    pass

def url_schemes_test:
    plist_file_path = f"{Constants.OUTPUT_FOLDER}/Info.plist"
    with open(plist_file_path, r) as info_plist:
        plist_dict = p.load(file)
        url_schemes = plist_dict['CFBundleURLTypes'][0]['CFBundleURLSchemes']
        logging.info("*********************************** URL Schemes**********************************")
        if len(url_schemes) == 0:
            logging.info("There are no URL Schemes in this app")
        else:
            logging.info("These are the URL Schemes built with app")
