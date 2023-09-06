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

# ---------------- CONSTANTS -----------------------------------------------------
DEFAULT_SRC_PORT    = ["9443"]
DEFAULT_DST_PORT    = ["443"]

STATUS_CODE_OK      = 200
HTTPS_PORT_VALUE    = 443

SRC_REST_PREAMBLE   = "/SKLM/rest/v1/"
DST_REST_PREAMBLE   = "/api/v1/"

# ---------------- Major Declarations --------------------------------------------
srcObjList = []

# ---------------- Functions-----------------------------------------------------
# -------------------------------------------------------------------------------
# makeHexString
# -------------------------------------------------------------------------------
def makeHexStr(t_val):

    tmpStr = str(t_val)
    t_hexStr = hex(int("0x" + tmpStr[2:-1], 0))

    return t_hexStr

# -----------------------------------------------------------------------------
# REST Assembly for SOURCE LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the src host in return for a AUTHORIZATION STRING (token)
# that is used for authentication of other commands
# -----------------------------------------------------------------------------
def createSrcAuthStr(t_srcHost, t_srcPort, t_srcUser, t_srcPass):

    t_srcRESTLogin          = SRC_REST_PREAMBLE + "ckms/login"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTLogin)

    t_srcHeaders            = {"Content-Type":"application/json", "Accept":"application/json"}
    t_srcBody               = {"userid":t_srcUser, "password":t_srcPass}

    # print("\nCMD: ", t_srcHostRESTCmd)
    
    # Suppress SSL Verification Warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    # Note that GKLM does not required Basic Auth to retrieve information.  
    # Instead, the body of the call contains the userID and password.
    r = requests.post(t_srcHostRESTCmd, data=json.dumps(t_srcBody), headers=t_srcHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        print("Status Code:", r.status_code)

    # Extract the UserAuthId from the value of the key-value pair of the JSON reponse.
    t_srcUserAuthID         = r.json()['UserAuthId']
    t_srcAuthStr   = "SKLMAuth UserAuthId="+t_srcUserAuthID 

    return t_srcAuthStr

# -----------------------------------------------------------------------------
# REST Assembly for reading List of Source Cryptographic Objects 
#
# The objective of this section is to querry a list of cryptographic
# objects current stored or managed by the src host.
# -----------------------------------------------------------------------------
def getSrcObjList(t_srcHost, t_srcPort, t_srcAuthStr):

    t_srcRESTListObjects    = SRC_REST_PREAMBLE + "objects"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects)

    t_srcHeaders            = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_srcAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        print("Status Code:", r.status_code)

    t_srcObjList           = r.json()['managedObject']
    t_srcObjListCnt        = len(t_srcObjList)

    return t_srcObjList, t_srcObjListCnt

# -----------------------------------------------------------------------------
# REST Assembly for reading specific Object Data 
#
# Using the LISTOBJECTs API above, the src host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------
def getSourceObjData(t_srcHost, t_srcPort, t_srcAuthStr)
    t_srcRESTListObjects        = SRC_REST_PREAMBLE + "objects"

    for obj in range(srcObjListCnt):
        srcObjID = srcObjList[obj]['uuid']
        t_srcHostRESTCmd = "https://%s:%s%s/%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects, srcObjID)
        t_srcHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_srcAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            print("Status Code:", r.status_code)

        t_srcObjData       = r.json()['managedObject']
        t_srcObjDataCnt    = len(t_srcObjData)

        print("\nObject UUID:", t_srcObjData['uuid'])
    #    print("Number of Src Object Data Elements: ", t_srcObjDataCnt)
    #    print("Object Result:", t_srcObjData.keys())
    #    print("Object Result:", t_srcObjData.values())
        
        return t_srcObjData, t_srcObjDataCnt

# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION HOST LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the dst host in return for a BEARER TOKEN that is 
# used for authentication of other commands.
# -----------------------------------------------------------------------------
def createDstAuthStr(t_dstHost, t_dstPort, t_dstPass)

    t_dstRESTTokens         = DST_REST_PREAMBLE + "auth/tokens/"
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
    t_dstAuthStr           = "Bearer "+t_dstUserBearerToken

    return t_dstAuthStr

# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION OBJECT READING KEYS
# 
# The objective of this section is to use the Dst Authorization / Bearer Token
# to query the dst hosts REST interface about keys.
# -----------------------------------------------------------------------------
def getDstObjList(t_dstHost, t_dstPort, t_dstAuthStr)

    t_dstRESTKeyList        = DST_REST_PREAMBLE + "vault/keys2"
    t_dstHostRESTCmd        = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList)   

    t_dstHeaders            = {"Content-Type":"application/json", "Accept":"application/json", "Authorization": t_dstAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        print("Status Code:", r.status_code)
        print("All of response: ", r.reason)
        exit()

    t_dstObjList           = r.json()['resources']
    t_dstObjListCnt        = len(t_dstObjList)

    # print("\nCount of Dst Objects: ", t_dstObjListCnt)
    # print("\n         Dst Objects: ", t_dstObjList[0].keys())
    return t_dstObjList, t_dstObjListCnt
    
# -----------------------------------------------------------------------------
# REST Assembly for READING specific Object Data from DESTINATION HOST
#
# Using the VAULT/KEYS2 API above, the dst host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------
def getDstObjData(t_dstHost, t_dstPort, t_dstObjList, t_dstAuthStr)

    t_dstRESTKeyList        = DST_REST_PREAMBLE + "vault/keys2"
    
    t_dstObjListCnt = len(t_distObjList)
    
    for obj in range(t_dstObjListCnt):
        t_dstObjID = t_dstObjList[obj]['id']
        t_dstHostRESTCmd = "https://%s:%s%s/%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList, t_dstObjID)
        t_dstHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_dstAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            print("Status Code:", r.status_code)
            print("     Reason:", r.reason)
            print("Obj ID:", dstObjID)
            print("CMD: ",t_dstHostRESTCmd)
            continue

        t_dstObjData       = r.json()
        t_dstObjDataCnt    = len(t_dstObjData)

        # print("\nObject UUID:", t_dstObjData['id'])
        # print("Exportable?:", t_dstObjData['unexportable'])
        # print("Number of Dst Object Data Elements: ", t_dstObjDataCnt)
        # print("Object Result:", t_dstObjData.keys())
        # print("Object Result:", t_dstObjData.values())
        # print("Object Result:", dstObjData)
        # print("\nTotal Dst Objects: ", dstObjListCnt)
        
    return t_dstObjData, t_dstObjDataCnt

# -----------------------------------------------------------------------------
# REST Assembly for EXPORTING specific Object Data from DESTINATION HOST
#
# Using the VAULT/KEYS2 API above, the dst host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------
def exportDstObjData(t_dstHost, t_dstPort, t_dstObjList, t_dstAuthStr)

    t_dstRESTKeyList        = DST_REST_PREAMBLE + "vault/keys2"
    t_dstRESTKeyExportFlag  = "export"

    for obj in range(dstObjListCnt):
        dstObjID = dstObjList[obj]['id']

        # If the object is not exportable, then an error code will be returned.  So, check for exportability prior to
        # attempting to export the key material from the DESTINATION.
        if dstObjList[obj]['unexportable']==True:
            tmpStr ="\nUNEXPORTABLE! ObjID: %s" %dstObjID
            print(tmpStr)
            continue

        t_dstHostRESTCmd = "https://%s:%s%s/%s/%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList, dstObjID, t_dstRESTKeyExportFlag)
        t_dstHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_dstAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.post(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            print("Status Code:", r.status_code)
            print("     Reason:", r.reason)
            print("Obj ID:", dstObjID)
            print("CMD: ",t_dstHostRESTCmd)
            continue

        t_dstObjData       = r.json()
        t_dstObjDataCnt    = len(dstObjData)

        # print("\nObject UUID:", t_dstObjData['id'])
        # print("Number of Dst Object Data Elements: ", t_dstObjDataCnt)
        # print("Object Result:", t_dstObjData.keys())
        # print("Object Result:", t_dstObjData.values())
        # print("Object Result:", t_dstObjData)

    # print("\nTotal Dst Objects: ", t_dstObjListCnt)
    
    return t_dstObjData, t_dstObjDataCnt

#
# ---------------- End of Functions ----------------------------------------------
#

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

srcHost = str(" ".join(args.srcHost))
srcPort = str(" ".join(args.srcPort))
srcUser = str(" ".join(args.srcUser))
srcPass = str(" ".join(args.srcPass))

t_dstHost = str(" ".join(args.dstHost))
t_dstPort = str(" ".join(args.dstPort))
t_dstUser = str(" ".join(args.dstUser))
t_dstPass = str(" ".join(args.dstPass))

print("\n ---- INPUT STATS: ----")
print("Source: ", srcHost, srcPort, srcUser)
print("  Dest: ", t_dstHost, t_dstPort, t_dstUser)

# ---- Parsing Complete ----------------------------------------------------------

# --------------------------------------------------------------------------------
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# --------------------------------------------------------------------------------
srcAuthStr = createSrcAuthStr(srcHost, srcPort, srcUser, srcPass)
print("\n SAS:", srcAuthStr)

srcObjList, srcObjListCnt = getSrcObjList(t_srcHost, t_srcPort, t_srcAuthStr)
print("\nNumber of Src Objects: ", srcObjListCnt)


print("\nTotal Src Objects: ", srcObjListCnt)
print("\n\n --- SOURCE REST COMPLETE --- \n\n")
exit()


# Next STEPS:  Map Object Dictionary keys between Source an Destination and they copy over.

print("\n ---- COMPLETE ---- ")