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
DEFAULT_SRC_PORT    = ["9443"]
DEFAULT_DST_PORT    = ["443"]

STATUS_CODE_OK      = 200
HTTPS_PORT_VALUE    = 443

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
t_srcUserAuthID         = r.json()['UserAuthId']
t_srcAuthorizationStr   = "SKLMAuth UserAuthId="+t_srcUserAuthID 

# -----------------------------------------------------------------------------
# REST Assembly for reading List of Source Cryptographic Objects 
#
# The objective of this section is to querry a list of cryptographic
# objects current stored or managed by the src host.
# -----------------------------------------------------------------------------

t_srcRESTListObjects    = t_srcRESTPreamble + "objects"
t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects)
t_srcHeaders            = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_srcAuthorizationStr}

# Note that this REST Command does not require a body object in this GET REST Command
r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
if(r.status_code != STATUS_CODE_OK):
    print("Status Code:", r.status_code)

srcObjectList           = r.json()['managedObject']
srcObjectListCnt        = len(srcObjectList)

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
    print("Object Result:", srcObjectData)

print("\nTotal Src Objects: ", srcObjectListCnt)
print("\n\n --- SOURCE REST COMPLETE --- \n\n")

# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION HOST LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the dst host in return for a BEARER TOKEN that is 
# used for authentication of other commands.
# -----------------------------------------------------------------------------

t_dstRESTPreamble       = "/api/v1/"

t_dstRESTTokens         = t_dstRESTPreamble + "auth/tokens/"
t_dstHostRESTCmd        = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTTokens)    

t_dstHeaders            = {"Content-Type":"application/json"}
t_dstBody               = {"name":t_dstUser, "password":t_dstPass}

# DEBUG
# print("\n d_dstHostRESTCmd: ", t_dstHostRESTCmd)

# Suppress SSL Verification Warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Note that CM does not required Basic Auth to retrieve information.  
# Instead, the body of the call contains the username and password.
r = requests.post(t_dstHostRESTCmd, data=json.dumps(t_dstBody), headers=t_dstHeaders, verify=False)

if(r.status_code != STATUS_CODE_OK):
    print("Status Code:", r.status_code)
    print("All of response: ", r.reason)
    exit()

# Extract the Bearer Token from the value of the key-value pair of the JSON reponse which is identified by the 'jwt' key.
t_dstUserBearerToken            = r.json()['jwt']
t_dstUserBearerTokenDuration    = r.json()['duration']
t_dstAuthorizationStr           = "Bearer "+t_dstUserBearerToken

# print("\n Dst Authorization Duration: ", t_dstUserBearerTokenDuration)
# print("\n Dst Authorization String: ", t_dstAuthorizationStr)

# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION OBJECT READING KEYS
# 
# The objective of this section is to use the Dst Authorization / Bearer Token
# to query the dst hosts REST interface about keys.
# -----------------------------------------------------------------------------
t_dstRESTKeyList        = t_dstRESTPreamble + "vault/keys2"
t_dstHostRESTCmd        = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList)   
t_dstHeaders            = {"Content-Type":"application/json", "Accept":"application/json", "Authorization": t_dstAuthorizationStr}

# Note that this REST Command does not require a body object in this GET REST Command
r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)

if(r.status_code != STATUS_CODE_OK):
    print("Status Code:", r.status_code)
    print("All of response: ", r.reason)
    exit()
    
dstObjectList           = r.json()['resources']
dstObjectListCnt        = len(dstObjectList)

print("\nCount of Dst Objects: ", dstObjectListCnt)
print("\n         Dst Objects: ", dstObjectList[0].keys())

# -----------------------------------------------------------------------------
# REST Assembly for READING specific Object Data from DESTINATION HOST
#
# Using the VAULT/KEYS2 API above, the dst host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------

t_dstRESTKeyList        = t_dstRESTPreamble + "vault/keys2"

for obj in range(dstObjectListCnt):
    dstObjID = dstObjectList[obj]['id']
    t_dstHostRESTCmd = "https://%s:%s%s/%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList, dstObjID)
    t_dstHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_dstAuthorizationStr}

    # Note that REST Command does not require a body object in this GET REST Command
    r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        print("Status Code:", r.status_code)
        print("     Reason:", r.reason)
        print("Obj ID:", dstObjID)
        print("CMD: ",t_dstHostRESTCmd)
        continue

    dstObjectData       = r.json()
    dstObjectDataCnt    = len(dstObjectData)

    print("\nObject UUID:", dstObjectData['id'])
    print("Exportable?:", dstObjectData['unexportable'])
    print("Number of Dst Object Data Elements: ", dstObjectDataCnt)
#    print("Object Result:", dstObjectData.keys())
#    print("Object Result:", dstObjectData.values())
    print("Object Result:", dstObjectData)

print("\nTotal Dst Objects: ", dstObjectListCnt)

# -----------------------------------------------------------------------------
# REST Assembly for EXPORTING specific Object Data from DESTINATION HOST
#
# Using the VAULT/KEYS2 API above, the dst host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------

t_dstRESTKeyList        = t_dstRESTPreamble + "vault/keys2"
t_dstRESTKeyExportFlag  = "export"

for obj in range(dstObjectListCnt):
    dstObjID = dstObjectList[obj]['id']
    if dstObjectList[obj]['unexportable']==True:
        tmpStr ="\nUNEXPORTABLE! ObjID: %s" %dstObjID
        print(tmpStr)
        continue
        
    t_dstHostRESTCmd = "https://%s:%s%s/%s/%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList, dstObjID, t_dstRESTKeyExportFlag)
    t_dstHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_dstAuthorizationStr}

    # Note that REST Command does not require a body object in this GET REST Command
    r = requests.post(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        print("Status Code:", r.status_code)
        print("     Reason:", r.reason)
        print("Obj ID:", dstObjID)
        print("CMD: ",t_dstHostRESTCmd)
        continue

    dstObjectData       = r.json()
    dstObjectDataCnt    = len(dstObjectData)

    print("\nObject UUID:", dstObjectData['id'])
    print("Number of Dst Object Data Elements: ", dstObjectDataCnt)
#    print("Object Result:", dstObjectData.keys())
#    print("Object Result:", dstObjectData.values())
    print("Object Result:", dstObjectData)

print("\nTotal Dst Objects: ", dstObjectListCnt)

print("\n ---- COMPLETE ---- ")