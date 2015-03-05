import requests, time, re
import logging, os, platform, sys
import urllib
from phishfeed import *
import xml.dom.minidom, xml.sax.saxutils

#ENVIRONMENTAL INFORMATION
__author__ = "george@georgestarcher.com (George Starcher)"
_MI_APP_NAME = 'TA-openphish'
_SPLUNK_HOME = os.getenv("SPLUNK_HOME")
if _SPLUNK_HOME == None:
    _SPLUNK_HOME = os.getenv("SPLUNKHOME")
if _SPLUNK_HOME == None:
    _SPLUNK_HOME = "/opt/splunk"

_OPERATING_SYSTEM = platform.system()
_APP_HOME = _SPLUNK_HOME + "/etc/apps/TA-openphish"
_LIB_PATH = _APP_HOME + "bin/lib"
_PID = os.getpid()
_IS_WINDOWS = False

if _OPERATING_SYSTEM.lower() == "windows":
    _IS_WINDOWS = True
    _LIB_PATH.replace("/","\\")
    _APP_HOME.replace("/","\\")

#SYSTEM EXIT CODES
_SYS_EXIT_FAILED_FEED = 9 
_SYS_EXIT_GPARENT_PID_ONE = 8
_SYS_EXIT_FAILED_VALIDATION = 7

#Setup logging
logging.root
logging.root.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.root.addHandler(handler)

#Define scheme for the modular input
SCHEME = """<scheme>
    <title>Openphish</title>
    <description>Collect the openphish extended feed.</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>simple</streaming_mode>
    <endpoint>
        <args>
            <arg name="username">
                <title>Openphish Username</title>
                <description>The Openphish feed Username</description>
            </arg>
            <arg name="password">
                <title>Password</title>
                <description>Your Openphish feed password</description>
            </arg>
            <arg name="feedtype">
                <title>Feed Type</title>
                <description>Your Openphish Feed Type</description>
            </arg>
            <arg name="mimedefang">
                <title>MIMEdefang</title>
                <description>Enable replacing http with hxxp?</description>
                <data_type>boolean</data_type>
                <validation>is_bool(mimedefang)</validation>
            </arg>
            <arg name="asn">
                <title>Autonomous System Number</title>
                <description>Specific ASN to Index</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="brand">
                <title>Brand</title>
                <description>Specific Brand to Index</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
        </args>
    </endpoint>
</scheme>
"""

def print_error(s):
    """ print any errors that occur """
    doPrint("<error><message>%s</message></error>" % escape(s))
    logging.error(s)

def get_validation_data():
    val_data = {}
    # read everything from stdin
    val_str = sys.stdin.read()
    # parse the validation XML
    doc = xml.dom.minidom.parseString(val_str)
    root = doc.documentElement
    logging.debug("XML: found items")
    item_node = root.getElementsByTagName("item")[0]
    if item_node:
        logging.debug("XML: found item")
        name = item_node.getAttribute("name")
        val_data["stanza"] = name
        params_node = item_node.getElementsByTagName("param")
        for param in params_node:
            name = param.getAttribute("name")
            logging.debug("Found param %s" % name)
            if name and param.firstChild and \
               param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                val_data[name] = param.firstChild.data
    return val_data

def validate_arguments():
    val_data = get_validation_data()
    try:
        if val_data["feedtype"].lower() not in ["complete", "extended"]:
            raise Exception, "Feedtype must be complete or extended" 

        try: isinstance(val_data["username"],str)
        except: raise Exception, "Username must be a string"
        try: isinstance(val_data["password"],str)
        except: raise Exception, "Password must be a string"
        try: isinstance(val_data["mimedefang"],bool)
        except: raise Exception, "Mimedefang must be a boolean"

    except Exception, e:
        print_error("Invalid configuration specified: %s" % str(e))
        sys.exit(_SYS_EXIT_FAILED_VALIDATION)

def validate_conf(config, key):
    """ Validate that required key is in the config as parsed from stdin """
    if key not in config:
        raise Exception, "Invalid configuration received from Splunk: key '%s' is missing." % key

def validate_feed_login(username,password,feedtype):

    if feedtype.lower() == "complete":
        _FEED_URL = "https://openphish.com/prvt-intell/"
    else:
        _FEED_URL = "https://openphish.com/prvt-ex/"

    page = requests.head(_FEED_URL,auth=(username, password))
    if page.status_code == 401:
        return False
    else:
        return True 
    
def save_checkpoint(checkpoint_file, timestamp):
    logging.info("Checkpointing file=%s, timestamp=%s", checkpoint_file, timestamp)
    f = open(checkpoint_file, "w")
    f.write(timestamp)
    f.close()
    return True

def load_checkpoint(checkpoint_file):
    timestamp = ""
    try:
        f = open(checkpoint_file,"r").close()
    except Exception, e:
        f = open(checkpoint_file,"w").close()

    f = open(checkpoint_file,"r")
    timestamp = f.read()
    f.close()
    return timestamp

#read XML configuration passed from splunkd
def get_config():
    """ Read XML Configuration data passed from splunkd on stdin """
    config = {}
    try:
        # read everything from stdin
        config_str = sys.stdin.read()

        # parse the config XML
        doc = xml.dom.minidom.parseString(config_str)
        root = doc.documentElement
        conf_node = root.getElementsByTagName("configuration")[0]
        if conf_node:
            logging.debug("XML: found configuration")
            stanza = conf_node.getElementsByTagName("stanza")[0]
            if stanza:
                stanza_name = stanza.getAttribute("name")
                if stanza_name:
                    logging.debug("XML: found stanza " + stanza_name)
                    config["name"] = stanza_name

                    params = stanza.getElementsByTagName("param")
                    for param in params:
                        param_name = param.getAttribute("name")
                        logging.debug("XML: found param '%s'" % param_name)
                        if param_name and param.firstChild and \
                           param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                            data = param.firstChild.data
                            config[param_name] = data
                            logging.debug("XML: '%s' -> '%s'" % (param_name, data))

            checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]
            if checkpnt_node and checkpnt_node.firstChild and \
                checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE:
                    config["checkpoint_dir"] = checkpnt_node.firstChild.data

        if not config:
            raise Exception, "Invalid configuration received from Splunk."

        # just some validation: make sure these keys are present (required)
        validate_conf(config, "username")
        validate_conf(config, "password")
        validate_conf(config, "feedtype")
        validate_conf(config, "mimedefang")
        validate_conf(config, "checkpoint_dir")

        if not validate_feed_login(config["username"], config["password"], config["feedtype"]):
            raise Exception,"Invalid openphish.com credential or feed type."
            logging.error("Invalid openphish.com credential of feed type.")

    except Exception, e:
        raise Exception, "Error getting Splunk configuration via STDIN: %s" % str(e)

    return config

def doPrint(s):
    """ A wrapper Function to output data by same method (print vs sys.stdout.write)"""
    sys.stdout.write(s)

def doScheme():
    """ Prints the Scheme """
    doPrint(SCHEME)

def getSource(config):
    return "phishfeed:" + config

def run():

    config = get_config()
    username = config["username"]
    password = config["password"]
    _FEED_TYPE = config["feedtype"]
    mimedefang = config["mimedefang"]
    filterASN = ""
    filterBrand = ""
   
    checkpointFile = os.path.join(config["checkpoint_dir"], config["name"].split("://")[1])
 
    if "asn" in config:
        if len(config["asn"])>0:
            filterASN = config["asn"]
    if "brand" in config:
        if len(config["brand"])>0:
            filterBrand = config["brand"]

    try:
        oldCheckpointTime = ""
        oldCheckpointTime = load_checkpoint(checkpointFile)

        currentFeedData = eventFeed(_FEED_TYPE, username, password, mimedefang)

        if filterASN:
            currentFeedData.filterASN(filterASN, oldCheckpointTime)
        if filterBrand:
            currentFeedData.filterBrand(filterBrand, oldCheckpointTime)
        
        if filterASN or filterBrand:
            currentFeedData.outputFilter()
        else:
            currentFeedData.outputAll(oldCheckpointTime)

        checkpointSuccess = save_checkpoint(checkpointFile, currentFeedData.checkpointTime)
        if not checkpointSuccess:
            raise Exception, "Failed to save checkpoint"
    except Exception, e:
        logging.debug("script="+_MI_APP_NAME+" %s" % str(e))
        exit(_SYS_EXIT_FAILED_FEED)

if __name__ == "__main__":

    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            doScheme()
        elif sys.argv[1] == "--validate-arguments":
            validate_arguments()
        elif sys.argv[1] == "--test":
            doPrint('No tests for the scheme present')
    else:
        run()

exit(0)
