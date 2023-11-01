# key-rest-cmds
#
# definition file of assorted REST Commands for communicating
# with the source and destination servers
#
######################################################################
import  requests
from    urllib3.exceptions import InsecureRequestWarning
import  json
from    kerrors import *
from    krestenums import ObjectType, GKLMAttributeType
from    krestenums import CMAttributeType

import  enum
import  re

# ---------------- CONSTANTS -----------------------------------------------------
STATUS_CODE_OK      = 200
STATUS_CODE_CREATED = 201

HTTPS_PORT_VALUE    = 443

SRC_REST_PREAMBLE   = "/SKLM/rest/v1/"
DST_REST_PREAMBLE   = "/api/v1/"

APP_JSON            = "application/json"


def makeHexStr(t_val):
# -------------------------------------------------------------------------------
# makeHexString
# -------------------------------------------------------------------------------
    tmpStr = str(t_val)
    t_hexStr = hex(int("0x" + tmpStr[2:-1], 0))

    return t_hexStr

def createSrcAuthStr(t_srcHost, t_srcPort, t_srcUser, t_srcPass):
# -----------------------------------------------------------------------------
# REST Assembly for Src LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the src host in return for a AUTHORIZATION STRING (token)
# that is used for authentication of other commands
# -----------------------------------------------------------------------------
    t_srcRESTLogin          = SRC_REST_PREAMBLE + "ckms/login"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTLogin)

    t_srcHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON}
    t_srcBody               = {"userid":t_srcUser, "password":t_srcPass}

    # Suppress SSL Verification Warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    # Note that GKLM does not required Basic Auth to retrieve information.  
    # Instead, the body of the call contains the userID and password.
    r = requests.post(t_srcHostRESTCmd, data=json.dumps(t_srcBody), headers=t_srcHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        kPrintError("createSrcAuthStr", r)
        exit()

    # Extract the UserAuthId from the value of the key-value pair of the JSON reponse.
    t_srcUserAuthID         = r.json()['UserAuthId']
    t_srcAuthStr            = "SKLMAuth UserAuthId="+t_srcUserAuthID 

    return t_srcAuthStr

def getSrcObjList(t_srcHost, t_srcPort, t_srcAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for reading List of Src Cryptographic Objects 
#
# The objective of this section is to querry a list of cryptographic
# objects current stored or managed by the src host.

# Returns a list of cryptographic objects
# -----------------------------------------------------------------------------
    t_srcRESTListObjects    = SRC_REST_PREAMBLE + "objects?clientName=KMIP_SCRIPT"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects)

    t_srcHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        kPrintError("getSrcObjList", r)
        exit()

    t_srcObjList           = r.json()['managedObject']

    return t_srcObjList

def getSrcObjData(t_srcHost, t_srcPort, t_srcObjList, t_srcAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for reading specific Object Data 
#
# Using the getSrcObjList API above, the src host delivers all BUT the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------
    t_srcRESTListObjects        = SRC_REST_PREAMBLE + "objects"
    t_ListLen = len(t_srcObjList)

    t_srcObjData    = [] # created list to be returned later

    for obj in range(t_ListLen):
        t_srcObjID          = t_srcObjList[obj][GKLMAttributeType.UUID.value]
        t_srcHostRESTCmd    = "https://%s:%s%s/%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects, t_srcObjID)
        t_srcHeaders        = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            kPrintError("getSrcObj", r)
            exit()

        t_data   = r.json()['managedObject']
        t_srcObjData.append(t_data)     # Add data to list

        # print("Src Object ", obj, " UUID:", t_srcObjData[obj][GKLMAttributeType.UUID.value])
        
    return t_srcObjData

def getSrcKeyList(t_srcHost, t_srcPort, t_srcAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for reading specific Key List 
#
# Using the keys API, the src host delivers all material EXCEPT for the actual
# key block of keys.  Once we have this information (especially the UUID), we can
# retrieve the key block material
#
# Returns a list of keys, but no key material
# -----------------------------------------------------------------------------
    t_srcRESTListKeys       = SRC_REST_PREAMBLE + "keys"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTListKeys)

    t_srcHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        kPrintError("getSrcKeyList", r)
        exit()

    t_srcKeyList           = r.json()

    return t_srcKeyList

def getSrcKeyDataList(t_srcHost, t_srcPort, t_srcKeyList, t_srcAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for reading specific Key Data 
#
# Using the getSrcKeyList API above, this routin queries the src and returns
# the KEYBLOCK for each key.
#
# NOTE that this call exports the key into an encrypted file on GKLM....
#
# * INCOMPLETE *
# -----------------------------------------------------------------------------
    t_srcRESTGetKeys        = SRC_REST_PREAMBLE + "keys/export"
    t_ListLen               = len(t_srcKeyList)

    t_srcKeyDataList        = [] # created list to be returned later

    for obj in range(t_ListLen):
        t_srcKeyAlias       = t_srcKeyList[obj][GKLMAttributeType.ALIAS.value]
        t_srcHostRESTCmd    = "https://%s:%s%s/%s" %(t_srcHost, t_srcPort, t_srcRESTGetKeys, t_srcKeyAlias)
        
        t_srcHeaders        = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.post(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            kPrintError("getSrcKeyDataList", r)
            exit()

        t_data          = r.json()
        t_srcKeyData.append(t_data)     # Add data to list

        # print("Src Key ", obj, " Alias:", t_srcKeyData[obj][GKLMAttributeType.ALIAS.value])
        
    return t_srcKeyDataList

def getSrcKeyObjDataList(t_srcHost, t_srcPort, t_srcKeyList, t_srcAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for reading specific Key Data via OBJECT
#
# Using the getSrcKeyList API above, the src host delivers all BUT the actual
# key block of a key.  This section returns and collects the key block for 
# each key by collecting them from the OBJECT REST API.
# -----------------------------------------------------------------------------
    
    t_srcRESTKeyObjects = SRC_REST_PREAMBLE + "objects"
    t_ListLen           = len(t_srcKeyList)

    t_srcKeyObjDataList = [] # created list to be returned later
    t_cnt               = 0  # keep track of the number of exportable key objects

    for obj in range(t_ListLen):
        
        # Separate string conversions before sending.  Python gets confused if they are all converted as part of the string assembly of tmpStr
        
#        t_alias = str(t_srcKeyList[obj][GKLMAttributeType.ALIAS.value])
#        t_uuid  = str(t_srcKeyList[obj][GKLMAttributeType.UUID.value])
#        t_ksn   = str(t_srcKeyList[obj][GKLMAttributeType.KEY_STORE_NAME.value])
#        t_ksu   = str(t_srcKeyList[obj][GKLMAttributeType.KEY_STORE_UUID.value])
        t_owner = str(t_srcKeyList[obj][GKLMAttributeType.OWNER.value])
#        t_usage = str(t_srcKeyList[obj][GKLMAttributeType.USAGE.value])
        t_kt    = str(t_srcKeyList[obj][GKLMAttributeType.KEY_TYPE.value])
#        
#        tmpStr =    "\nSrc Key List Info: %s Alias: %s UUID: %s"    \
#                    "\n  Key Store Name: %s Key Store UUID: %s"  \
#                    "\n  Owner: %s\n  Usage: %s Key Type: %s" \
#                    %(obj, t_alias, t_uuid, t_ksn, t_ksu, t_owner, t_usage, t_kt)

#        print(tmpStr)

        t_srcObjID      = t_srcKeyList[obj][GKLMAttributeType.UUID.value]
        t_srcObjAlias   = t_srcKeyList[obj][GKLMAttributeType.ALIAS.value]
        
        t_srcHostRESTCmd = "https://%s:%s%s/%s" %(t_srcHost, t_srcPort, t_srcRESTKeyObjects, t_srcObjID)
        t_srcHeaders = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}
        
        # Note that REST Command does not require a body object in this GET REST Command
        # Also, only process SYMMETRIC_KEYS
            
        if (t_kt == ObjectType.SYMMETRIC_KEY.name and len(t_owner) > 1):
        # if (t_kt == ObjectType.SYMMETRIC_KEY.name):
            r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
            if(r.status_code != STATUS_CODE_OK):
                kPrintError("getSrcKeyObjDataList", r)
                continue

            else:
                t_data   = r.json()['managedObject']
                t_srcKeyObjDataList.append(t_data)     # Add data to list

                # print("\n   --> OBJECT ADDED - List Size: ", len(t_srcKeyObjDataList))
                t_cnt += 1  # increment object count
                
#        else:
#            print("     *** SKIPPED - Wrong Key Type or No Owner")
        
    return t_srcKeyObjDataList

def printSrcKeyList(t_srcKeyList):
# -----------------------------------------------------------------------------
# Display the contents of a srcKeyList
# -----------------------------------------------------------------------------
    
    t_success           = True
    t_ListLen           = len(t_srcKeyList)

    for obj in range(t_ListLen):
        
        # Separate string conversions before sending.  
        # Python gets confused if they are all converted as part of the string assembly of tmpStr
        
        t_alias = str(t_srcKeyList[obj][GKLMAttributeType.ALIAS.value])
        t_uuid  = str(t_srcKeyList[obj][GKLMAttributeType.UUID.value])
        t_ksn   = str(t_srcKeyList[obj][GKLMAttributeType.KEY_STORE_NAME.value])
        t_ksu   = str(t_srcKeyList[obj][GKLMAttributeType.KEY_STORE_UUID.value])
        t_owner = str(t_srcKeyList[obj][GKLMAttributeType.OWNER.value])
        t_usage = str(t_srcKeyList[obj][GKLMAttributeType.USAGE.value])
        t_kt    = str(t_srcKeyList[obj][GKLMAttributeType.KEY_TYPE.value])
        
        tmpStr =    "\nSrc Key List Info: %s Alias: %s UUID: %s"    \
                    "\n  Key Store Name: %s Key Store UUID: %s"  \
                    "\n  Owner: %s\n  Usage: %s Key Type: %s" \
                    %(obj, t_alias, t_uuid, t_ksn, t_ksu, t_owner, t_usage, t_kt)

        print(tmpStr)
    return t_success

def convertGKLMHashToString(t_GKLMHash):
# -----------------------------------------------------------------------------
# GKLM stores the has a string that looks like:
#  [[INDEX 0] [HASH SHA256] [VALUE xcc,x43,xd9,x72,xd8,x0f,x57,xb7,x5a,x01,xf4,x42,x16,x42,x0a,x90,x63,xf3,xf0,xd7,x46,x6a,x58,x56,x18,x4d,x04,xad,xac,xf0,x9d,x10] [DIGESTED_KEY_FORMAT RAW]]
#
# But this is onweildly.  This routine trims out all of the brackets, commas, x's
# and leading and  trailing block information.
#
# This routine uses a couple of temporary string variables to trim down the string
# -----------------------------------------------------------------------------

    t_Header    = "[VALUE "     # string that preceeds the hash value
    t_sizeH     = len(t_Header)
    t_Trailer   = " [DIGESTED"  # first few characters of string at end of hash value
    t_chars     = "[^0-9a-f]"          # only characters that need to be kept
    
    t_startPos  = t_GKLMHash.find(t_Header)
    t_endPos    = t_GKLMHash.find(t_Trailer)
    
    tmpStr1  = t_GKLMHash[t_startPos+t_sizeH:t_endPos]
    tmpStr2 = re.sub(t_chars, "", tmpStr1)
        
    return tmpStr2


def printSrcKeyObjDataList(t_srcKeyObjDataList):
# -----------------------------------------------------------------------------
# Display the contents of a srcKeyObjDataList
# -----------------------------------------------------------------------------
    
    t_success           = True
    t_ListLen           = len(t_srcKeyObjDataList)
        
    for obj in range(t_ListLen):
        
        # Separate string conversions before sending.  
        # Python gets confused if they are all converted as part of the string assembly of tmpStr.  tmpStr.strip("[]")
        
        t_alias = str(t_srcKeyObjDataList[obj][GKLMAttributeType.ALIAS.value])
        t_uuid  = str(t_srcKeyObjDataList[obj][GKLMAttributeType.UUID.value])
        t_kt     = str(t_srcKeyObjDataList[obj][GKLMAttributeType.KEY_TYPE.value])
        t_hv     = str(t_srcKeyObjDataList[obj][GKLMAttributeType.DIGEST.value])
        
        tmpStr =    "\nSrc Key Obj Data List Info: %s Alias: %s" \
                    "\n  UUID: %s"    \
                    "\n  Key Type: %s " \
                    "\n  Hash: %s" \
                    %(obj, t_alias.strip("[]"), t_uuid, t_kt, convertGKLMHashToString(t_hv))

        print(tmpStr)
        

        
    return t_success

def createDstAuthStr(t_dstHost, t_dstPort, t_dstUser, t_dstPass):
# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION HOST LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the dst host in return for a BEARER TOKEN that is 
# used for authentication of other commands.
# -----------------------------------------------------------------------------

    t_dstRESTTokens         = DST_REST_PREAMBLE + "auth/tokens/"
    t_dstHostRESTCmd        = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTTokens)    

    t_dstHeaders            = {"Content-Type":APP_JSON}
    t_dstBody               = {"name":t_dstUser, "password":t_dstPass}

    # Suppress SSL Verification Warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    # Note that CM does not required Basic Auth to retrieve information.  
    # Instead, the body of the call contains the username and password.
    r = requests.post(t_dstHostRESTCmd, data=json.dumps(t_dstBody), headers=t_dstHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        kPrintError("createDstAuthStr", r)
        exit()

    # Extract the Bearer Token from the value of the key-value pair of the JSON reponse which is identified by the 'jwt' key.
    t_dstUserBearerToken            = r.json()['jwt']
    t_dstAuthStr                    = "Bearer "+t_dstUserBearerToken

    return t_dstAuthStr

def getDstObjList(t_dstHost, t_dstPort, t_dstAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION OBJECT READING KEYS
# 
# The objective of this section is to use the Dst Authorization / Bearer Token
# to query the dst hosts REST interface about keys.
# -----------------------------------------------------------------------------

    t_dstRESTKeyList        = DST_REST_PREAMBLE + "vault/keys2"
    t_dstHostRESTCmd        = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList)   

    t_dstHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization": t_dstAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        kPrintError("getDstObjList", r)
        exit()

    t_dstObjList           = r.json()['resources']

    # print("\n         Dst Objects: ", t_dstObjList[0].keys())
    return t_dstObjList
    
def getDstObjData(t_dstHost, t_dstPort, t_dstObjList, t_dstAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for READING specific Object Data from DESTINATION HOST
#
# Using the VAULT/KEYS2 API above, the dst host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------

    t_dstRESTKeyList        = DST_REST_PREAMBLE + "vault/keys2"
    t_ListLen               = len(t_dstObjList)

    t_dstObjData            = [] # created list to be returned later
        
    for obj in range(t_ListLen):
        t_dstObjID = t_dstObjList[obj][CMAttributeType.ID.value]
        t_dstHostRESTCmd = "https://%s:%s%s/%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList, t_dstObjID)
        t_dstHeaders = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            print("  Obj ID:", dstObjID)
            kPrintError("getDstObjData", r)
            continue

        t_data      = r.json()
        t_dstObjData.append(t_data)     # Add data to list
        
        # print("Dst Object ", obj, " ID:", t_dstObjData[obj][CMAttributeType.NAME.value])

    return t_dstObjData

def exportDstObjData(t_dstHost, t_dstPort, t_dstObjList, t_dstAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for EXPORTING specific Object Data from DESTINATION HOST
#
# Using the VAULT/KEYS2 API above, the dst host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------

    t_dstRESTKeyList        = DST_REST_PREAMBLE + "vault/keys2"
    t_dstRESTKeyExportFlag  = "export"
    
    t_dstObjData            = [] # created list to be returned later
    t_ObjCnt                = 0  # Initialize counter
    t_ListLen               = len(t_dstObjList)
    
    for obj in range(t_ListLen):
        dstObjID    = t_dstObjList[obj][CMAttributeType.ID.value]
        dstObjName  = t_dstObjList[obj][CMAttributeType.NAME.value]

        # If the object is not exportable, then an error code will be returned.  So, check for exportability prior to
        # attempting to export the key material from the DESTINATION.
        if t_dstObjList[obj][CMAttributeType.UNEXPORTABLE.value]==True:
            tmpStr ="Dst Obj: %s Name: %s *UNEXPORTABLE*" %(obj, dstObjName)
            # print(tmpStr)
            continue

        t_dstHostRESTCmd = "https://%s:%s%s/%s/%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList, dstObjID, t_dstRESTKeyExportFlag)
        t_dstHeaders = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.post(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            print("  Obj ID:", dstObjID)
            kPrintError("exportDstObjData", r)
            continue

        t_data      = r.json()        
        t_dstObjData.append(t_data)  #Add data to te list
        
        # tmpStr ="Dst Obj: %s Name: %s " %(obj, dstObjName)
        # print(tmpStr)
        
        t_ObjCnt += 1

    return t_dstObjData

def importDstDataObject(t_dstHost, t_dstPort, t_dstUser, t_dstAuthStr, t_xKeyObj):
# -----------------------------------------------------------------------------
# REST Assembly for IMPORTING specific Object Data into DESTINATION HOST
#
# Using the VAULT/KEYS2 API, this code writes adds individual keys to the desitation.
# This routine needs to be called for EACH key that needs to be written.
#
# Note that an ERROR will occur if a key of the same name already exists in the 
# destination.
# -----------------------------------------------------------------------------
    t_success = True
    
    t_dstRESTKeyCreate        = DST_REST_PREAMBLE + "vault/keys2"

    t_dstHostRESTCmd = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTKeyCreate)
    t_dstHeaders = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

    # Note that REST Command does not require a body object in this GET REST Command
    r = requests.post(t_dstHostRESTCmd, data=json.dumps(t_xKeyObj), headers=t_dstHeaders, verify=False)

    if(r.status_code == STATUS_CODE_CREATED):
        t_Response      = r.json()        
        # print("  ->Object Created: ", t_Response[CMAttributeType.NAME.value])
    else:
        kPrintError("importDstDataObject", r)        
        t_success = False
        
    return t_success

def printDstObjList(t_dstObjList):
# -----------------------------------------------------------------------------
# Display the contents of a dstKeyObjList
# -----------------------------------------------------------------------------
    
    t_success           = True
    t_ListLen           = len(t_dstObjList)

    # print("\nDst List Keys: \n", json.dumps(t_dstObjList, indent=4))
    # print("end")
    # exit()
    
    for obj in range(t_ListLen):
        
        # Separate string conversions before sending.  Python gets confused if they are all converted as part of the string assembly of tmpStr
        
        t_name  = str(t_dstObjList[obj][CMAttributeType.NAME.value])
        t_uuid  = str(t_dstObjList[obj][CMAttributeType.UUID.value])
        t_ot    = str(t_dstObjList[obj][CMAttributeType.OBJECT_TYPE.value])
        t_size  = str(t_dstObjList[obj][CMAttributeType.SIZE.value])
        t_fp    = str(t_dstObjList[obj][CMAttributeType.SHA256_FINGERPRINT.value])
        
        tmpStr =    "\nDst Obj: %s Name: %s" \
                    "\n  UUID: %s" \
                    "\n  Key Type: %s Size: %s" \
                    "\n  Hash: %s" \
                    %(obj, t_name, t_uuid, t_ot, t_size, t_fp)

        print(tmpStr)
    return t_success

def printDstObjData(t_dstObjData):
# -----------------------------------------------------------------------------
# Display the contents of a dstObjData
# -----------------------------------------------------------------------------
    
    t_success           = True
    t_ListLen           = len(t_dstObjData)

    for obj in range(t_ListLen):
        
        # Separate string conversions before sending.  Python gets confused if they are all converted as part of the string assembly of tmpStr
        
        t_name  = str(t_dstObjData[obj][CMAttributeType.NAME.value])
        t_uuid  = str(t_dstObjData[obj][CMAttributeType.UUID.value])
        t_ot    = str(t_dstObjData[obj][CMAttributeType.OBJECT_TYPE.value])
        t_size  = str(t_dstObjData[obj][CMAttributeType.SIZE.value])
        t_fp    = str(t_dstObjData[obj][CMAttributeType.SHA256_FINGERPRINT.value])
        
        tmpStr =    "\nDst Obj: %s Name: %s" \
                    "\n  UUID: %s" \
                    "\n  Key Type: %s Size: %s" \
                    "\n  Hash: %s" \
                    %(obj, t_name, t_uuid, t_ot, t_size, t_fp)

        print(tmpStr)
    return t_success