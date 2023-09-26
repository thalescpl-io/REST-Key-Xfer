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

# ---------------- Constants ----------------------------------------------------
DEFAULT_SRC_PORT    = ["9443"]
DEFAULT_DST_PORT    = ["443"]

# ---------------- Functions ----------------------------------------------------

# -------------------------------------------------------------------------------
# makeHexString
# -------------------------------------------------------------------------------
def makeHexStr(t_val):

    tmpStr = str(t_val)
    t_hexStr = hex(int("0x" + tmpStr[2:-1], 0))

    return t_hexStr

#
# ---------------- End of Functions ----------------------------------------------
# ################################################################################

# ----- Input Parsing ------------------------------------------------------------

# Parse command.  Note that if the arguments are not complete, a usage message 
# will be printed automatically
parser = argparse.ArgumentParser(prog="k-rest.py", description="REST Client Data Exchange")

# Src Information
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

dstHost = str(" ".join(args.dstHost))
dstPort = str(" ".join(args.dstPort))
dstUser = str(" ".join(args.dstUser))
dstPass = str(" ".join(args.dstPass))

print("\n ---- INPUT STATS: ----")
print(" Src: ", srcHost, srcPort, srcUser)
print("Dest: ", dstHost, dstPort, dstUser)

# ---- Parsing Complete ----------------------------------------------------------

# --------------------------------------------------------------------------------
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# --------------------------------------------------------------------------------

# Get Source Authorization Token/String
srcAuthStr      = createSrcAuthStr(srcHost, srcPort, srcUser, srcPass)
print("\nSAS:", srcAuthStr)

# Get list of keys
srcKeyList      = getSrcKeyList(srcHost, srcPort, srcAuthStr)
print("\nNumber of Src List Keys: ", len(srcKeyList))
# print("\nSrc List Keys: \n", json.dumps(srcKeyList, indent=4))

# Get detailed information, including key material, for each key/object.
# The returned list is a COMPLETE package of key attributes and key material for
# each object.

srcKeyObjDataList   = getSrcKeyObjDataList(srcHost, srcPort, srcKeyList, srcAuthStr)
srcKeyObjCnt        = len(srcKeyObjDataList)
print("\nLength of Src Key Objects: ",srcKeyObjCnt)
print("\nSrc Obj Data List: ", json.dumps(srcKeyObjDataList[1], skipkeys = True, allow_nan = True, indent = 3))


print("\n --- SRC KEY OBJECT REST EXPORT COMPLETE --- \n")

#  Map GKLM keys and values to CM
xKeyObj     = {}
xKeyObjList = []

# -------------- MAPPING ------------------------------------------------------------------------ 
# For each key object in the source, map it with the proper dictionary keys to a x-formed list of 
# dictionaries for later upload to the destination
# -----------------------------------------------------------------------------------------------

for k in range(srcKeyObjCnt):
    xKeyObj[CMAttributeType.UUID.value]         = srcKeyObjDataList[k][GKLMAttributeType.UUID.value]
    
    # GKLM stores the Key Usage Mask as a string.  CM stores it a the associated KMIP value.  As such,
    # The GKLM Key Usage Mask string must be replaced with the appropriate value before storing it in CM.
    srcUM       = srcKeyObjDataList[k][GKLMAttributeType.CRYPTOGRAPHIC_USAGE_MASK.value]
    srcUMClean  = "".join(srcUM.split())    #trim leading and trailing spaces from srcUM string
    for tmpUM in CryptographicUsageMask:        
        if srcUMClean == tmpUM.name:
            print(srcUMClean, tmpUM.name, tmpUM.value)
            xKeyObj[CMAttributeType.USAGE_MASK.value]   = tmpUM.value
    
    # the GKLM Alias seems to match the patter of the CM Name key.  However, GKLM includes brakcets ("[]") in the string
    # and they need to be removed before copying the true alias value to CM
    tmpStr = srcKeyObjDataList[k][GKLMAttributeType.ALIAS.value]
    xKeyObj[CMAttributeType.NAME.value]         = tmpStr.strip("[]")
    
    xKeyObj[CMAttributeType.STATE.value]        = srcKeyObjDataList[k][GKLMAttributeType.KEY_STATE.value]
    xKeyObj[CMAttributeType.ALGORITHM.value]    = srcKeyObjDataList[k][GKLMAttributeType.KEY_ALGORITHM.value]
    xKeyObj[CMAttributeType.SIZE.value]         = int(srcKeyObjDataList[k][GKLMAttributeType.KEY_LENGTH.value])
    xKeyObj[CMAttributeType.OBJECT_TYPE.value]  = srcKeyObjDataList[k][GKLMAttributeType.KEY_TYPE.value]
    xKeyObj[CMAttributeType.MATERIAL.value]     = srcKeyObjDataList[k][GKLMAttributeType.KEY_BLOCK.value]['KEY_MATERIAL']
    xKeyObj[CMAttributeType.FORMAT.value]       = srcKeyObjDataList[k][GKLMAttributeType.KEY_BLOCK.value]['KEY_FORMAT'].lower()
    
    xKeyObjList.append(xKeyObj)
    print("\n Key Obj: ", json.dumps(xKeyObj, skipkeys = True, allow_nan = True, indent = 3))


# Get Destination Authorization Token/String
dstAuthStr      = createDstAuthStr(dstHost, dstPort, dstUser, dstPass)
print("\nDAS: ", dstAuthStr)

for xKeyObj in xKeyObjList:
    success = importDstDataObject(dstHost, dstPort, dstUser, dstAuthStr, xKeyObj)
    print("\n xKeyObj: ",  xKeyObj[CMAttributeType.NAME.value])
    print("\n importDstDataOjbect Success:", success)

dstObjList      = getDstObjList(dstHost, dstPort, dstAuthStr)
print("\nNumber of Dst List Objects: ", len(dstObjList))

dstObjData      = exportDstObjData(dstHost, dstPort, dstObjList, dstAuthStr)
print("\nNumber of Dst Exportable Data Objects: ", len(dstObjData))
print("\nDst Data Object:", json.dumps(dstObjData[6], skipkeys = True, allow_nan = True, indent = 3))
print("\n Dst Data Object Type: ", type(dstObjData[6]))

print("\n\n --- Dst REST COMPLETE --- \n")

exit() # Temporarily Stop here.  Lets see if we can properly read before we write.


print("\n ---- COMPLETE ---- ")
#####################################################################################
#
