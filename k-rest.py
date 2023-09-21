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
import  krestenums
from    krestcmds import *


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

# Get Sourth Authorization Token/String
srcAuthStr      = createSrcAuthStr(srcHost, srcPort, srcUser, srcPass)
print("\nSAS:", srcAuthStr)

srcKeyList      = getSrcKeyList(srcHost, srcPort, srcAuthStr)
print("\nNumber of Src List Keys: ", len(srcKeyList))
# print("\nSrc List Keys: \n", json.dumps(srcKeyList, indent=4))

srcKeyObjDataList    = getSrcKeyObjDataList(srcHost, srcPort, srcKeyList, srcAuthStr)
print("\nNumber of Src Key Objects: ", len(srcKeyObjDataList))

print("\n\ --- SRC KEY OBJECT REST EXPORT COMPLETE --- \n")

exit() # Temporarily Stop here

dstAuthStr      = createDstAuthStr(dstHost, dstPort, dstUser, dstPass)
print("\nDAS: ", dstAuthStr)

dstObjList      = getDstObjList(dstHost, dstPort, dstAuthStr)
print("\nNumber of Dst List Objects: ", len(dstObjList))

dstObjData      = exportDstObjData(dstHost, dstPort, dstObjList, dstAuthStr)
print("\nNumber of Dst Exportable Data Objects: ", len(dstObjData))
print("\nDst Data Object 0:", dstObjData[0])

print("\n\n --- Dst REST COMPLETE --- \n")

success = importDstDataObject(dstHost, dstPort, dstUser, dstAuthStr, srcObjData[0])
print("\n importDstDataOjbect Success:", success)

# Next STEPS:  Map Object Dictionary keys between Src an Destination and they copy over.

print("\n ---- COMPLETE ---- ")
#####################################################################################
#
