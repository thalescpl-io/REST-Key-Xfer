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

# ---------------- CONSTANTS -----------------------------------------------------
STATUS_CODE_OK      = 200
HTTPS_PORT_VALUE    = 443

SRC_REST_PREAMBLE   = "/SKLM/rest/v1/"
DST_REST_PREAMBLE   = "/api/v1/"


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

    t_srcHeaders            = {"Content-Type":"application/json", "Accept":"application/json"}
    t_srcBody               = {"userid":t_srcUser, "password":t_srcPass}

    # print("\nCMD: ", t_srcHostRESTCmd)
    
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

    t_srcHeaders            = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_srcAuthStr}

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
        t_srcHeaders        = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_srcAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            kPrintError("getSrcObj", r)
            exit()

        t_data   = r.json()['managedObject']
        t_srcObjData.append(t_data)     # Add data to list

        print("Src Object ", obj, " UUID:", t_srcObjData[obj][GKLMAttributeType.UUID.value])
        
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

    t_srcHeaders            = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_srcAuthStr}

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
        
        t_srcHeaders        = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_srcAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.post(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            kPrintError("getSrcKeyDataList", r)
            exit()

        t_data          = r.json()
        t_srcKeyData.append(t_data)     # Add data to list

        print("Src Key ", obj, " Alias:", t_srcKeyData[obj][GKLMAttributeType.ALIAS.value])
        
    return t_srcKeyDataList

# -----------------------------------------------------------------------------
# REST Assembly for reading specific Key Data via OBJECT
#
# Using the getSrcKeyList API above, the src host delivers all BUT the actual
# key block of a key.  This section returns and collects the key block for 
# each key by collecting them from the OBJECT REST API.
# -----------------------------------------------------------------------------
def getSrcKeyObjDataList(t_srcHost, t_srcPort, t_srcKeyList, t_srcAuthStr):
    
    t_srcRESTKeyObjects = SRC_REST_PREAMBLE + "objects"
    t_ListLen           = len(t_srcKeyList)

    t_srcKeyObjDataList = [] # created list to be returned later
    t_cnt               = 0  # keep track of the number of exportable key objects

    for obj in range(t_ListLen):
        
        # Separate string conversions before sending.  Python gets confused if they are all converted as part of the string assembly of tmpStr
        
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

        t_srcObjID      = t_srcKeyList[obj][GKLMAttributeType.UUID.value]
        t_srcObjAlias   = t_srcKeyList[obj][GKLMAttributeType.ALIAS.value]
        
        t_srcHostRESTCmd = "https://%s:%s%s/%s" %(t_srcHost, t_srcPort, t_srcRESTKeyObjects, t_srcObjID)
        t_srcHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_srcAuthStr}
        
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

                # print("Src Key ObjData", obj, " Alias: ", t_srcKeyObjData[obj][GKLMAttributeType.ALIAS.value], " UUID: ", t_srcKeyObjData[obj][GKLMAttributeType.UUID.value])
                tmpstr =    "\n   Src Key ObjData: %s Alias: %s"     \
                            "\n   Key Block: %s"                     \
                            "\n   --> OBJECT ADDED - List Size: %s"  \
                            %(t_cnt, t_srcKeyObjDataList[t_cnt][GKLMAttributeType.UUID.value], t_srcKeyObjDataList[t_cnt][GKLMAttributeType.KEY_BLOCK.value], len(t_srcKeyObjDataList))
                            
                print(tmpstr)

                t_cnt += 1
                
        else:
            print("     *** SKIPPED - Wrong Key Type or No Owner")
        
    return t_srcKeyObjDataList
# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION HOST LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the dst host in return for a BEARER TOKEN that is 
# used for authentication of other commands.
# -----------------------------------------------------------------------------
def createDstAuthStr(t_dstHost, t_dstPort, t_dstUser, t_dstPass):

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
        kPrintError("createDstAuthStr", r)
        exit()

    # Extract the Bearer Token from the value of the key-value pair of the JSON reponse which is identified by the 'jwt' key.
    t_dstUserBearerToken            = r.json()['jwt']
    t_dstAuthStr                    = "Bearer "+t_dstUserBearerToken

    return t_dstAuthStr

# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION OBJECT READING KEYS
# 
# The objective of this section is to use the Dst Authorization / Bearer Token
# to query the dst hosts REST interface about keys.
# -----------------------------------------------------------------------------
def getDstObjList(t_dstHost, t_dstPort, t_dstAuthStr):

    t_dstRESTKeyList        = DST_REST_PREAMBLE + "vault/keys2"
    t_dstHostRESTCmd        = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList)   

    t_dstHeaders            = {"Content-Type":"application/json", "Accept":"application/json", "Authorization": t_dstAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        kPrintError("getDstObjList", r)
        exit()

    t_dstObjList           = r.json()['resources']

    # print("\n         Dst Objects: ", t_dstObjList[0].keys())
    return t_dstObjList
    
# -----------------------------------------------------------------------------
# REST Assembly for READING specific Object Data from DESTINATION HOST
#
# Using the VAULT/KEYS2 API above, the dst host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------
def getDstObjData(t_dstHost, t_dstPort, t_dstObjList, t_dstAuthStr):

    t_dstRESTKeyList        = DST_REST_PREAMBLE + "vault/keys2"
    t_ListLen               = len(t_dstObjList)

    t_dstObjData            = [] # created list to be returned later
        
    for obj in range(t_ListLen):
        t_dstObjID = t_dstObjList[obj]['id']
        t_dstHostRESTCmd = "https://%s:%s%s/%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList, t_dstObjID)
        t_dstHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_dstAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            print("  Obj ID:", dstObjID)
            kPrintError("getDstObjData", r)
            continue

        t_data      = r.json()
        t_dstObjData.append(t_data)     # Add data to list
        
        print("Dst Object ", obj, " ID:", t_dstObjData[obj]['id'])

    return t_dstObjData

# -----------------------------------------------------------------------------
# REST Assembly for EXPORTING specific Object Data from DESTINATION HOST
#
# Using the VAULT/KEYS2 API above, the dst host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------
def exportDstObjData(t_dstHost, t_dstPort, t_dstObjList, t_dstAuthStr):

    t_dstRESTKeyList        = DST_REST_PREAMBLE + "vault/keys2"
    t_dstRESTKeyExportFlag  = "export"
    
    t_dstObjData            = [] # created list to be returned later
    
    t_ListLen               = len(t_dstObjList)
    
    for obj in range(t_ListLen):
        dstObjID = t_dstObjList[obj]['id']

        # If the object is not exportable, then an error code will be returned.  So, check for exportability prior to
        # attempting to export the key material from the DESTINATION.
        if t_dstObjList[obj]['unexportable']==True:
            tmpStr ="  UNEXPORTABLE! Dst Obj: %s ObjID: %s" %(obj, dstObjID)
            print(tmpStr)
            continue

        t_dstHostRESTCmd = "https://%s:%s%s/%s/%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList, dstObjID, t_dstRESTKeyExportFlag)
        t_dstHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_dstAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.post(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            print("  Obj ID:", dstObjID)
            kPrintError("exportDstObjData", r)
            continue

        t_data      = r.json()        
        t_dstObjData.append(t_data)  #Add data to te list

        print("Dst Object ", obj, " ID:", t_dstObjData[obj]['id'])
    
    return t_dstObjData


# -----------------------------------------------------------------------------
# REST Assembly for IMPORTING specific Object Data into DESTINATION HOST
#
# Using the VAULT/KEYS2 API, this code writes adds individual keys to the desitation.
# This routine needs to be called for EACH key that needs to be written.
# -----------------------------------------------------------------------------
def importDstDataObject(t_dstHost, t_dstPort, t_dstUser, t_dstAuthStr, t_srcObj):
    t_success = True
    
    t_dstRESTKeyCreate        = DST_REST_PREAMBLE + "vault/keys2"

    # define object
    # populate objet - src-dst mapping

    t_dstObj = {}   # create a dicionary to submit
    
    t_dstObj['name']        = "My First Key"
    t_dstObj['usageMask']   = 76    # Uses?
    t_dstObj['algorithm']   = "aes"
    t_dstObj['meta']        = {"ownerId": "local|e923406f-5a62-4d6e-972b-8f6866164a07"}
    t_dstObj['state']       = "Active"  # states?
    t_dstObj['material']    = 'cc1581e80414a258693bcb823ef76d378f7dfee8839bc6ed58fa6d303c908324'
    t_dstObj['format']      = 'raw'
    
#{
#  "name": "My Encryption Key",
#  "usageMask": 12,
#  "algorithm": "aes",
#  "meta": {
#    "ownerId": "local|1a45d..."
#  },
#  "state": "Pre-Active",
#  "deactivationDate": "2018-10-02T14:24:37.436073Z",
#  "protectStopDate": "2018-10-02T14:24:37.436073Z",
#  "aliases": [
#    {
#      "alias": "altname1",
#      "type": "string"
#    },
#    {
#      "alias": "altname2:keysecure:gemalto:com",
#      "type": "uri"
#    }
#  ]
#}
    
    t_dstHostRESTCmd = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTKeyCreate)
    t_dstHeaders = {"Content-Type":"application/json", "Accept":"application/json", "Authorization":t_dstAuthStr}

    # Note that REST Command does not require a body object in this GET REST Command
    r = requests.post(t_dstHostRESTCmd, data=json.dumps(t_dstObj), headers=t_dstHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        kPrintError("importDstDataObject", r)        
        success = False
    else:
    
        t_Response      = r.json()        
        
        print("Created Object: ", t_response)
    
    return t_success

