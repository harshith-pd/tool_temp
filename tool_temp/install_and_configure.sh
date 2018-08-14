#!/bin/sh

####################################################################################################

# input :
# output :

# download scripts
# check for the type of the input file iOS/Android
# check for the tools installed, install & configure if not
# get app name
# create the test_run folder in the following pattern
## test_run
### app_name_<platform>
#### test_run_<date_time>
##### i/p
##### o/p
###### apktool (if android)
###### d2j (if android)
##### logs
##### report
##### app_details.txt - containing app_name, version, bundle id etc
# place the input to the input folder
# unzip based on the platform into apktool & d2j folder if android, else just unzip if iOS
# write the locations into the constants file
####################################################################################################

### Specify the folder structure & variables
## constants
     error_string="command not found"
#     usage="$(basename "$0") -input_app_file=<input file location> -input_source_code=<input source code>"
     usage="$(basename "$0") -input_app_file=<input file location>"

     WORKSPACE="$HOME/Desktop/tool_temp"
     TMP_FOLDER_LOCATION="${WORKSPACE}/.tmp"
     SCRIPTS_FOLDER="${WORKSPACE}/Scripts"
     TOOLS_FOLDER="${WORKSPACE}/Tools"
     TEST_RUN_FOLDER="${WORKSPACE}/test_run"
     CONSTANTS_FILE_LOCATION="Scripts/Constants.py"

     APK_TOOL_COMMAND="java -jar ${WORKSPACE}/Tools/apktool.jar"
     ENJARIFY_TOOL_COMMAND="${WORKSPACE}/Tools/enjarify-master/enjarify.sh"
     JDCORE_JAR="java -jar ${WORKSPACE}/Tools/jd-core.jar"

     app_file_path=""
     app_source_code_path=""
     app_type=""

## folder structures
    ios_folder_structure=( "INPUT_FOLDER:input" "OUTPUT_FOLDER:output" "LOGS_FOLDER:logs" "REPORT_FOLDER:report" "CONFIG_FOLDER:config" )
    android_folder_structure=( "INPUT_FOLDER:input" "APKTOOL_OUTPUT_FOLDER:output/apktool" "ENJARIFY_OUTPUT_FOLDER:output/enjarify" "LOGS_FOLDER:logs" "REPORT_FOLDER:report" "CONFIG_FOLDER:config" )
    generic_folder_structure=( "TEST_RUN_FOLDER:test_run" "CONFIG_ROOT_FOLDER:config" "SCRIPTS_FOLDER:Scripts" "TOOLS_FOLDER:Tools" "TMP_FOLDER:.tmp" )

#####################################################################################
# function desc : called during an uncrossable exception
# arguments : error string
# return value : none
#####################################################################################
handle_error () {
    echo "$1"
    echo "Aborting..."
    exit 1
}

#####################################################################################
# function desc : clean up the .tmp folder
# arguments : -
# return value : -
#####################################################################################
clean_up_temp () {
    rm -rf "$TMP_FOLDER_LOCATION"/*
}

#####################################################################################
# function desc : get the type of the app given as input for evaluation
# arguments : input application file
# return value : none
#####################################################################################
get_app_type_and_create_folders () {
    app_file=$1
    app_file_extension=${app_file##*.}
    if [[ "$app_file_extension" == "ipa" ]]
    then
        app_type="iOS"
        create_ios_app_instance_folder $app_file
    elif [[ "$app_file_extension" == "apk" ]]
    then
        app_type="Android"
        create_android_app_instance_folder $app_file
    else
        echo "Invalid app file, please input proper file type"
    fi
}

#####################################################################################
# function desc : get the ios app name
# arguments : input application file
# return value : application name
#####################################################################################
get_ios_app_name () {
    app_file=$1
    unzip $app_file -d $TMP_FOLDER_LOCATION 2>/dev/null 1>/dev/null || handle_error "App unzip failed"

    info_plist="${TMP_FOLDER_LOCATION}/Payload/*/Info.plist"
    app_name=$( defaults read $info_plist CFBundleExecutable )
    if [[ "$app_name" = *"does not exist"* ]]
    then
        echo "App name could not be determined"
    fi
    app_name=$(echo $app_name | sed "s/ //g")

    echo "$app_name"
}

#####################################################################################
# function desc : get the android app name
# arguments : input application file
# return value : application name
#####################################################################################
get_android_app_name () {
    app_file=$1
    aapt dump badging $app_file | grep 'application-label:' | sed "s/.*label:'\(.*\)'/\1/" || handle_error "Error in dumping app info"
}

write_generic_folder_structure () {
  for folder_name in "${generic_folder_structure[@]}"
  do
      KEY="${folder_name%%:*}"
      VALUE="${folder_name#*:}"

      echo "$KEY = \"${WORKSPACE}/$VALUE\"\n" >> $TMP_FOLDER_LOCATION/tmp.txt
  done
}

#####################################################################################
# function desc : create folder structure for the ios apps evaluation
# arguments : input application file
# return value : application name
#####################################################################################
create_ios_app_instance_folder () {
    app_file=$1
    app_name=$( get_ios_app_name $app_file )
    date_time=$( date +"%m_%d_%Y_%H_%M_%S" )

    for folder_name in "${ios_folder_structure[@]}"
    do
        KEY="${folder_name%%:*}"
        VALUE="${folder_name#*:}"

        mkdir -p "${TEST_RUN_FOLDER}/$app_name/$date_time/$VALUE" 2>/dev/null 1>/dev/null
        echo "$KEY = \"${TEST_RUN_FOLDER}/$app_name/$date_time/$VALUE\"\n" >> $TMP_FOLDER_LOCATION/tmp.txt
    done

    cp -rf ${TMP_FOLDER_LOCATION}/Payload/$app_name.app/* "${TEST_RUN_FOLDER}/$app_name/$date_time/output/"
    cp -f $app_file "${TEST_RUN_FOLDER}/$app_name/$date_time/input/"
    cp -f ${WORKSPACE}/config/Config_$app_type.xml "${TEST_RUN_FOLDER}/$app_name/$date_time/config/"
}

#####################################################################################
# function desc : create folder structure for the android apps evaluation
# arguments : input application file
# return value : application name
#####################################################################################
create_android_app_instance_folder () {
    app_file=$1
    app_name=$( get_android_app_name $app_file )
    date_time=$( date +"%m_%d_%Y_%H_%M_%S" )

    for folder_name in "${android_folder_structure[@]}"
    do
        KEY="${folder_name%%:*}"
        VALUE="${folder_name#*:}"

        mkdir -p "${TEST_RUN_FOLDER}/$app_name/$date_time/$VALUE" 2>/dev/null 1>/dev/null
        echo "$KEY = \"${TEST_RUN_FOLDER}/$app_name/$date_time/$VALUE\"\n" >> $TMP_FOLDER_LOCATION/tmp.txt
    done

    cp -f $app_file "${TEST_RUN_FOLDER}/$app_name/$date_time/input/" 2>/dev/null 1>/dev/null
    cp -f ${WORKSPACE}/config/Config_$app_type.xml "${TEST_RUN_FOLDER}/$app_name/$date_time/config/"
    $APK_TOOL_COMMAND d -f -o ${TEST_RUN_FOLDER}/$app_name/$date_time/output/apktool $app_file 2>/dev/null 1>/dev/null || handle_error "Error running apktool jar on the apk file"
    $ENJARIFY_TOOL_COMMAND $app_file -o ${TEST_RUN_FOLDER}/$app_name/$date_time/output/enjarify/$app_name.jar 2>/dev/null 1>/dev/null || handle_error "Error decompiling the apk file"
    $JDCORE_JAR ${TEST_RUN_FOLDER}/$app_name/$date_time/output/enjarify/$app_name.jar ${TEST_RUN_FOLDER}/$app_name/$date_time/output/enjarify/ 2>/dev/null 1>/dev/null || handle_error "Error decompiling app jar "
}

#####################################################################################
# function desc : write the folder structure to the constants file
# arguments : -
# return value : -
#####################################################################################
create_constants_file () {
    split_delimiter="##########################################"
    constants_file_contents=$(cat $SCRIPTS_FOLDER/Constants.py)
    constants_file_base_contents="${constants_file_contents%%$split_delimiter*}"
    echo "$constants_file_base_contents \n$split_delimiter \n$(cat $TMP_FOLDER_LOCATION/tmp.txt)" > $TMP_FOLDER_LOCATION/tmp_constants.txt
    mv -f $TMP_FOLDER_LOCATION/tmp_constants.txt $SCRIPTS_FOLDER/Constants.py
}

run_security_scripts_on_application () {
    current_directory=$(pwd)
    cd ${WORKSPACE}/Scripts
    python3 Main_$app_type.py || handle_error "Failure to run the Main script for security tests"
    cd $current_directory
}
################################## Consume options
while [ $# -gt 0 ]
do
  case "$1" in
    -input_app_file=*)
      app_file_path="${1#*=}"
        if [ ! -f "$app_file_path" ]
        then
            handle_error "Please provide a valid application file path"
        fi
        echo "Found input file $app_file..."
    ;;
    *)
      echo "***************************\n"
      echo "* Error: Invalid argument.*\n"
      echo "***************************\n"
      exit 1
  esac
  shift
done

clean_up_temp
get_app_type_and_create_folders $app_file_path
write_generic_folder_structure
create_constants_file
run_security_scripts_on_application $app_type
