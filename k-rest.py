#####################################################################################
#
# 	Name: k-rest.py
# 	Author: Rick R
# 	Purpose:  Python-based REST Key Transfer
#   Usage: py k-rest.py -srcHost <hostname or IP> -srcUser <username> -srcPass <password> 
#                   -dstHost <hostname or IP> -dstUser <username> -dstPass <password> 
#                   
#####################################################################################

import argparse
import binascii
import codecs
import hashlib
import json
import requests
from urllib3.exceptions import InsecureRequestWarning

# ---------------- Functions-----------------------------------------------------
# -------------------------------------------------------------------------------
def makeHexStr(t_val):

    tmpStr = str(t_val)
    t_hexStr = hex(int("0x" + tmpStr[2:-1], 0))

    return t_hexStr


# ---------------- End of Functions ----------------------------------------------

# ---------------- CONSTANTS -----------------------------------------------------
DEFAULT_SRC_PORT = ["9443"]
DEFAULT_DST_PORT = ["443"]

STATUS_CODE_OK  =   200

# ---------------- Major Declarations --------------------------------------------
srcObjectsList = []

# ----- Input Parsing ------------------------------------------------------------

# Parse command.  Note that if the arguments are not complete, a usage message will be printed
# automatically
parser = argparse.ArgumentParser(prog="k-rest.py", description="REST Client Data Exchange")

# Source Information
parser.add_argument("-srcHost", nargs=1, action="store", dest="srcHost", required=True)
parser.add_argument(
    "-srcPort", nargs=1, action="store", dest="srcPort", default=DEFAULT_SRC_PORT
)
parser.add_argument("-srcUser", nargs=1, action="store", dest="srcUser", required=True)
parser.add_argument("-srcPass", nargs=1, action="store", dest="srcPass", required=True)

# Destination Information
parser.add_argument("-dstHost", nargs=1, action="store", dest="dstHost", required=True)
parser.add_argument(
    "-dstPort", nargs=1, action="store", dest="dstPort", default=DEFAULT_DST_PORT
)
parser.add_argument("-dstUser", nargs=1, action="store", dest="dstUser", required=True)
parser.add_argument("-dstPass", nargs=1, action="store", dest="dstPass", required=True)


# Args are returned as a LIST.  Separate them into individual strings
args = parser.parse_args()

t_srcHost = str(" ".join(args.srcHost))
t_srcPort = str(" ".join(args.srcPort))
t_srcUser = str(" ".join(args.srcUser))
t_srcPass = str(" ".join(args.srcPass))

t_dstHost = str(" ".join(args.dstHost))
t_dstPort = str(" ".join(args.dstPort))
t_dstUser = str(" ".join(args.dstUser))
t_dstPass = str(" ".join(args.dstPass))

print("\n ---- INPUT STATS: ----")
print("Source: ", t_srcHost, t_srcPort, t_srcUser)
print("  Dest: ", t_dstHost, t_dstPort, t_dstUser)

# ---- Parsing Complete ----------------------------------------------------------

# -----------------------------------------------------------------------------
# REST Assembly for SOURCE LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the src host in return for a AUTHORIZATION STRING (token)
# that is used for authentication of other commands
# -----------------------------------------------------------------------------

t_srcRESTPreamble       = "/SKLM/rest/v1/"
t_srcRESTLogin          = t_srcRESTPreamble + "ckms/login"
t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTLogin)
t_srcHeaders            = {"Content-Type":"application/json", "Accept":"application/json"}
t_srcBody               = {"userid":t_srcUser, "password":t_srcPass}

# Suppress SSL Verification Warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Note that GKLM does not required Basic Auth to retrieve information.  
# Instead, the body of the call contains the userID and password.
r = requests.post(t_srcHostRESTCmd, data=json.dumps(t_srcBody), headers=t_srcHeaders, verify=False)

if(r.status_code != STATUS_CODE_OK):
    print("Status Code:", r.status_code)

# Extract the UserAuthId from the value of the key-value pair of the JSON reponse.
t_srcUserAuthID = r.json()['UserAuthId']
t_srcAuthorizationStr   = "SKLMAuth UserAuthId="+t_srcUserAuthID 

# -----------------------------------------------------------------------------
# REST Assembly for reading List of Source Cryptographic Objects 
#
# The objective of this section is to querry a list of cryptographic
# objects current stored or managed by the src host.
# -----------------------------------------------------------------------------

t_srcRESTListObjects        = t_srcRESTPreamble + "objects"
t_srcHostRESTCmd            = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects)
t_srcHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_srcAuthorizationStr}

# Note that REST Command does not require a body object in this GET REST Command
r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
if(r.status_code != STATUS_CODE_OK):
    print("Status Code:", r.status_code)

srcObjectList       = r.json()['managedObject']
srcObjectListCnt    = len(srcObjectList)

print("\nNumber of Src Objects: ", srcObjectListCnt)

# -----------------------------------------------------------------------------
# REST Assembly for reading specific Object Data 
#
# Using the LISTOBJECTs API above, the src host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------

t_srcRESTListObjects        = t_srcRESTPreamble + "objects"

for obj in range(srcObjectListCnt):
    srcObjID = srcObjectList[obj]['uuid']
    t_srcHostRESTCmd = "https://%s:%s%s/%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects, srcObjID)
    t_srcHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_srcAuthorizationStr}

    # Note that REST Command does not require a body object in this GET REST Command
    r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        print("Status Code:", r.status_code)

    srcObjectData       = r.json()['managedObject']
    srcObjectDataCnt    = len(srcObjectData)

    print("\nObject UUID:", srcObjectData['uuid'])
    print("Number of Src Object Data Elements: ", srcObjectDataCnt)
#    print("Object Result:", srcObjectData.keys())
#    print("Object Result:", srcObjectData.values())

print("\nTotal Objects: ", srcObjectListCnt)
print("\n --- COMPLETE --- ")