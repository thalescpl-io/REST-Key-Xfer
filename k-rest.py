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


# ---- Parsing Complete ----------------------------------------------------------

# --------------------------------------------------------------------------------
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# --------------------------------------------------------------------------------

# Get Source and Destination Authorization Token/Strings
srcAuthStr      = createSrcAuthStr(srcHost, srcPort, srcUser, srcPass)
dstAuthStr      = createDstAuthStr(dstHost, dstPort, dstUser, dstPass)

# Get list of keys
srcKeyList      = getSrcKeyList(srcHost, srcPort, srcAuthStr)
srcKeyListCnt   = len(srcKeyList)
# Get detailed information, including key material, for each key/object.
# The returned list is a COMPLETE package of key attributes and key material for
# each object.

srcKeyObjDataList   = getSrcKeyObjDataList(srcHost, srcPort, srcKeyList, srcAuthStr)
srcKeyObjCnt        = len(srcKeyObjDataList)

if listOnly != listOnlyOption.DESTINATION.value:
    print("\nNumber of Src List Keys: ", srcKeyListCnt)
    #printSrcKeyList(srcKeyList)
    print("Number of transferrable Src Key Objects: ", srcKeyObjCnt)
    printSrcKeyObjDataList(srcKeyObjDataList)

    print("\n --- SRC KEY OBJECT REST EXPORT COMPLETE --- \n")

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

        # The GKLM Alias seems to match the patter of the CM Name key.  However, GKLM includes brakcets ("[]") in the string
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
    print("\nRetrieving list of objects from destination")
    dstObjList      = getDstObjList(dstHost, dstPort, dstAuthStr)
    print("\nDst Object List Count: ", len(dstObjList))
    # printDstObjList(dstObjList)
    
    dstObjData      = exportDstObjData(dstHost, dstPort, dstObjList, dstAuthStr)
    dstExpObjCnt    = len(dstObjData)
    print("\nDst Exportable Data Object Count: ", dstExpObjCnt)
    printDstObjData(dstObjData)

    print("\n\n --- Dst REST COMPLETE --- \n")

#####################################################################################
#
