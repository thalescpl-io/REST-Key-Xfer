#####################################################################################
#
# 	Name: k-rest.py
# 	Author: Rick R
# 	Purpose:  Python-based REST Key Transfer
#   Usage: py k-rest.py -srcHost <hostname or IP> -srcUser <username> -srcPass <password> 
#                   -dstHost <hostname or IP> -dstUser <username> -dstPass <password> 
#                   
#####################################################################################

import  argparse
import  binascii
import  codecs
import  hashlib
#import  json
#import  requests
#from    urllib3.exceptions import InsecureRequestWarning
from    kerrors import *
from    krestcmds import *
from    krestenums import CryptographicUsageMask
from    krestenums import listOnlyOption
from    krestenums import CMUserAttribute

# ---------------- Constants ----------------------------------------------------
DEFAULT_SRC_PORT    = ["9443"]
DEFAULT_DST_PORT    = ["443"]

# ################################################################################

# ----- Input Parsing ------------------------------------------------------------

# Parse command.  Note that if the arguments are not complete, a usage message 
# will be printed automatically
parser = argparse.ArgumentParser(prog="k-rest.py", description="REST Client Data Exchange")

# Src Information
parser.add_argument("-srcHost", nargs=1, action="store", dest="srcHost", required=True)
parser.add_argument("-srcPort", nargs=1, action="store", dest="srcPort", default=DEFAULT_SRC_PORT)
parser.add_argument("-srcUser", nargs=1, action="store", dest="srcUser", required=True)
parser.add_argument("-srcPass", nargs=1, action="store", dest="srcPass", required=True)

# Destination Information
parser.add_argument("-dstHost", nargs=1, action="store", dest="dstHost", required=True)
parser.add_argument("-dstPort", nargs=1, action="store", dest="dstPort", default=DEFAULT_DST_PORT)
parser.add_argument("-dstUser", nargs=1, action="store", dest="dstUser", required=True)
parser.add_argument("-dstPass", nargs=1, action="store", dest="dstPass", required=True)

# List only Flag - just list key material and do not change anything
parser.add_argument("-listOnly", nargs=1, action="store", dest="listOnly", required=False, 
                    choices=[listOnlyOption.NEITHER.value,
                             listOnlyOption.SOURCE.value,
                             listOnlyOption.DESTINATION.value,
                             listOnlyOption.BOTH.value
                            ],
                    default=[listOnlyOption.NEITHER.value] )

# Added ability to specify a source UUID.  If populated, then the actions 
# specified (read or migrate) will only apply to the particular UUID
parser.add_argument("-srcuuid", nargs=1, action="store", dest="srcUuid", required=False)
srcUUID = ""   #set default to a zero length string

# Args are returned as a LIST.  Separate them into individual strings
args = parser.parse_args()

srcHost = str(" ".join(args.srcHost))
srcPort = str(" ".join(args.srcPort))
srcUser = str(" ".join(args.srcUser))
srcPass = str(" ".join(args.srcPass))

dstHost = str(" ".join(args.dstHost))
dstPort = str(" ".join(args.dstPort))
dstUser = str(" ".join(args.dstUser))
dstPass = str(" ".join(args.dstPass))

listOnly = str(" ".join(args.listOnly))

print("\n ---- INPUT STATS: ----")
print("  Src: ", srcHost, srcPort, srcUser)
print(" Dest: ", dstHost, dstPort, dstUser)
print(" ListOnly:", listOnly)

if args.srcUuid is not None:
    srcUUID = str(" ".join(args.srcUuid))
    print(" UUID:", srcUUID)

# ---- Parsing Complete ----------------------------------------------------------

# --------------------------------------------------------------------------------
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# --------------------------------------------------------------------------------

# Get Source and Destination Authorization Token/Strings
print("\n Accessing Source and Destination Hosts and collecting Authorization Strings...")

srcAuthStr      = createSrcAuthStr(srcHost, srcPort, srcUser, srcPass)
print("  * Source Access Confirmed *")
tmpStr = "    Username: %s\n" %(srcUser)
print(tmpStr)

dstAuthStr      = createDstAuthStr(dstHost, dstPort, dstUser, dstPass)
print("  * Destination Access Confirmed *")

# Get destination user meta data that will be used later for 
dstUsrSelfJSON  = getDstUserSelf(dstHost, dstPort, dstAuthStr)

CM_userName     = dstUsrSelfJSON[CMUserAttribute.NAME.value]
CM_userNickname = dstUsrSelfJSON[CMUserAttribute.NICKNAME.value]
CM_userID       = dstUsrSelfJSON[CMUserAttribute.USER_ID.value]

tmpStr = "    Username: %s\n    User: %s\n    UserID: %s\n" %(CM_userNickname, CM_userName, CM_userID)
print(tmpStr)

# Get a list of all users on the destination for later use and create a dictionary of user_id and nickname
dstUsrsAllData  = getDstUsersAll(dstHost, dstPort, dstAuthStr)
dstUsrsAllJSON  = dstUsrsAllData[CMAttributeType.RESOURCES.value]   # extract just the user data
dstUsrsAllDict  = {} # define user dictionary - to be used later

for t_idx in dstUsrsAllJSON:
    t_user_id   = t_idx[CMUserAttribute.USER_ID.value]
    t_nickname  = t_idx[CMUserAttribute.NICKNAME.value]
    dstUsrsAllDict[t_user_id] = t_nickname
    

# Get list of Source Keys
srcKeyList      = getSrcKeyList(srcHost, srcPort, srcAuthStr)
srcKeyListCnt   = len(srcKeyList)

# Get detailed information, including key material, for each key/object.
# The returned list is a COMPLETE package of key attributes and key material for
# each object.
#
# Note that we have now added the ability to specify a UUID.
srcKeyObjDataList   = getSrcKeyObjDataList(srcHost, srcPort, srcKeyList, srcAuthStr, srcUUID)
srcKeyObjCnt        = len(srcKeyObjDataList)

if listOnly != listOnlyOption.DESTINATION.value:
    print("\nNumber of Src List Keys: ", srcKeyListCnt)
    print("Number of exportable Src Key Objects: ", srcKeyObjCnt)
    printSrcKeyObjDataList(srcKeyObjDataList)

    print("\n --- SRC KEY OBJECT RETRIEVAL COMPLETE --- \n")

if listOnly == listOnlyOption.NEITHER.value:
# Create and upload all of the key objects to the destination unless a flag to LIST ONLY has been specified.  

    #  Map GKLM keys and values to CM
    xKeyObj     = {}
    xKeyObjList = []

    # -------------- MAPPING ------------------------------------------------------------------------ 
    # For each key object in the source, map it with the proper dictionary keys to a x-formed list of 
    # dictionaries for later upload to the destination
    # -----------------------------------------------------------------------------------------------
    for k in range(srcKeyObjCnt):
        # xKeyObj[CMAttributeType.UUID.value]         = srcKeyObjDataList[k][GKLMAttributeType.UUID.value]

        # GKLM stores the Key Usage Mask as a string.  CM stores it a the associated KMIP value.  As such,
        # The GKLM Key Usage Mask string must be replaced with the appropriate value before storing it in CM.
        srcUM       = srcKeyObjDataList[k][GKLMAttributeType.CRYPTOGRAPHIC_USAGE_MASK.value]
        srcUMClean  = "".join(srcUM.split())    #trim leading and trailing spaces from srcUM string
        for tmpUM in CryptographicUsageMask:        
            if srcUMClean == tmpUM.name:
                xKeyObj[CMAttributeType.USAGE_MASK.value]   = tmpUM.value

        # The GKLM Alias seems to match the patter of the CM Name key.  
        # However, GKLM includes brakcets ("[]") in the string
        # and they need to be removed before copying the true alias value to CM
        tmpStr = srcKeyObjDataList[k][GKLMAttributeType.ALIAS.value]
        xKeyObj[CMAttributeType.NAME.value]         = tmpStr.strip("[]")

        # xKeyObj[CMAttributeType.STATE.value]        = srcKeyObjDataList[k][GKLMAttributeType.KEY_STATE.value]
        xKeyObj[CMAttributeType.ALGORITHM.value]    = srcKeyObjDataList[k][GKLMAttributeType.KEY_ALGORITHM.value]
        xKeyObj[CMAttributeType.SIZE.value]         = int(srcKeyObjDataList[k][GKLMAttributeType.KEY_LENGTH.value])

        # In GKLM, the Object Type uses underscores intead of spaces ("SYMMETRIC_KEY" vs "Symmetric Key")
        # and, therefore, needs some adjusting before it can be sent to CM.
        tmpStr  = srcKeyObjDataList[k][GKLMAttributeType.KEY_TYPE.value]
        tmpStr2 = tmpStr.replace("_", " ")  # SYMMETRIC_KEY -> SYMMETRIC KEY
        xKeyObj[CMAttributeType.OBJECT_TYPE.value]  = tmpStr2.title()   # SYMMETRIC KEY -> Symmetric Key

        xKeyObj[CMAttributeType.MATERIAL.value]     = srcKeyObjDataList[k][GKLMAttributeType.KEY_BLOCK.value]['KEY_MATERIAL']
        xKeyObj[CMAttributeType.FORMAT.value]       = srcKeyObjDataList[k][GKLMAttributeType.KEY_BLOCK.value]['KEY_FORMAT'].lower()
        
        # Add a userID to the associated key object so it can be made owner of the key
        # when uploaded to CM
        xKeyObj[CMAttributeType.META.value]= {CMAttributeType.OWNER_ID.value: CM_userID}

        # After assembling the key object, append it to the list of other key objects
        xKeyObjList.append(xKeyObj.copy())
        # print("\n Key Obj: ", json.dumps(xKeyObj, skipkeys = True, allow_nan = True, indent = 3))

        
# Errors are thrown if the key already exists.
    print("\nImporting key material into destination...\n")
    for xKeyObj in xKeyObjList:
        print("\n xKeyObj: ",  xKeyObj[CMAttributeType.NAME.value])    
        success = importDstDataObject(dstHost, dstPort, dstUser, dstAuthStr, xKeyObj)
        print("\n importDstDataOjbect Success:", success)

if listOnly != listOnlyOption.SOURCE.value:
    # Read keys that are now in the destination unless the user asks for source-only information
    print("\nRetrieving list of objects from destination...")
    dstObjList      = getDstObjList(dstHost, dstPort, dstAuthStr)
    print("\nDst Object List Count: ", len(dstObjList))
    
    dstObjData      = exportDstObjData(dstHost, dstPort, dstObjList, dstAuthStr)
    dstExpObjCnt    = len(dstObjData)
    print("Dst Exportable Data Object Count: ", dstExpObjCnt)
    printDstObjDataAndOwner(dstObjData, dstUsrsAllDict)

    print("\n --- DST OBJECT RETRIEVAL COMPLETE --- \n")

#####################################################################################
#
