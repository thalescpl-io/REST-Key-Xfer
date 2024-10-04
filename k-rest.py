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
from    krestenums import *
from    netappfilters import *

# ---------------- Constants ----------------------------------------------------
DEFAULT_SRC_PORT    = ["9443"]
DEFAULT_DST_PORT    = ["443"]

# ################################################################################

# ----- INPUT PARSING BEGIN ------------------------------------------------------

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

####################################################################################
# NOTE: The following OPTIONAL flags are commulative, meaning that only keys that satisfy ALL
# of the UUID and NetApp flags will be processed.
####################################################################################

# Added ability to specify a source UUID.  If populated, then the actions 
# specified (read or migrate) will only apply to the particular UUID
parser.add_argument("-srcuuid", nargs=1, action="store", dest="srcUuid", required=False)
srcUUID = ""   #set default to a zero length string

# Added ability to specify NetApp CUSTOME ATTRIBUTES.  If populated, then the actions 
# specified (read or migrate) will only apply to the those keys that satisfy the specified
# attribute requirements.
parser.add_argument("-netAppNodeID", nargs=1, action="store", dest="srcNANodeID", required=False)
srcNetAppNodeID = ""   #set default to a zero length string

parser.add_argument("-netAppClusterName", nargs=1, action="store", dest="srcNAClusterName", required=False)
srcNetAppClusterName = ""   #set default to a zero length string

parser.add_argument("-netAppVserverID", nargs=1, action="store", dest="srcNAVserverID", required=False)
srcNetAppVserverID = ""   #set default to a zero length string

parser.add_argument("-dstUserGroupName", nargs=1, action="store", dest="dstUserGroupName", required=False)
dstUserGroupName = ""   #set default to a zero length string

parser.add_argument("-srcClientName", nargs=1, action="store", dest="srcClientName", required=False)
srcClientName = ""   #set default to a zero length string

parser.add_argument("-listSrcClients", action="store_true", dest="listSrcClients", required=False)
listSrcClients = False   #set default to be false

# Args are returned as a LIST.  Separate them into individual strings
args = parser.parse_args()



# Display results from inputs
print("\n ---- SRC & DST PARAMETERS ----")

srcHost = str(" ".join(args.srcHost))
srcPort = str(" ".join(args.srcPort))
srcUser = str(" ".join(args.srcUser))
srcPass = str(" ".join(args.srcPass))
tmpStr = " SrcHost: %s\n SrcPort: %s\n SrcUser: %s\n" %(srcHost, srcPort, srcUser)
print(tmpStr)

dstHost = str(" ".join(args.dstHost))
dstPort = str(" ".join(args.dstPort))
dstUser = str(" ".join(args.dstUser))
dstPass = str(" ".join(args.dstPass))
tmpStr = " DstHost: %s\n DstPort: %s\n DstUser: %s\n" %(dstHost, dstPort, dstUser)
print(tmpStr)

# ------------- Group Management ------------------------------------
# If a Group is specified, then capture the group name and check to 
# see if it is present. The flag variable will be used later to create
# the group (and add the user to it), # if keys needs to be added 
# to the desitation.
# -------------------------------------------------------------------
t_flagGroupIsAbsent = False
if args.dstUserGroupName is not None:
    dstUserGroupName = str(" ".join(args.dstUserGroupName))
    print(" DstUserGroupName: %s" %(dstUserGroupName))
    
    # If Group is specified, download the existing groups from the destination
    # and see if the group is already present.
    dstAuthStr = createDstAuthStr(dstHost, dstPort, dstUser, dstPass)
    dstGrpList = getDstGroupsAll(dstHost, dstPort, dstAuthStr)
    # printJList("dstGrpList:", dstGrpList)
    
    # Presume the group is not present, unless it is found within
    # the list of download group names.
    t_flagGroupIsAbsent = True
    for t_Grp in dstGrpList[CMAttributeType.RESOURCES.value]:
        if dstUserGroupName == t_Grp[CMAttributeType.NAME.value]:
            print(" ", dstUserGroupName, "is present on the destination server.")
            t_flagGroupIsAbsent = False
    

# ---- List Only Filters ----------------------------------------------
# Collect the list only filter value and print it
# ---------------------------------------------------------------------
listOnly = str(" ".join(args.listOnly))
print("\n ListOnly:", listOnly)

# ---- List srcUUID ---------------------------------------------------
# Collect the UUID string and print it
# ---------------------------------------------------------------------
if args.srcUuid is not None:
    srcUUID = str(" ".join(args.srcUuid))
    print(" Source UUID (filter):", srcUUID)

# ---- NetAPP Customer Attributes---------------------------------------
# If custom attributes are specified in the command line, ensure they 
# are included in a dictionary that will be used to filter out the objects
# -----------------------------------------------------------------------
srcNetAppFilterDict = {}
if args.srcNANodeID is not None:
    srcNetAppNodeID = str(" ".join(args.srcNANodeID))
    print(" NetApp NodeID:", srcNetAppNodeID)
    srcNetAppFilterDict[NetAppAttribute.NODEID.value] = srcNetAppNodeID
    
if args.srcNAClusterName is not None:
    srcNetAppClusterName = str(" ".join(args.srcNAClusterName))
    print(" NetApp ClusterName:", srcNetAppClusterName)
    srcNetAppFilterDict[NetAppAttribute.CLUSTERNAME.value] = srcNetAppClusterName

if args.srcNAVserverID is not None:
    srcNetAppVserverID = str(" ".join(args.srcNAVserverID))
    print(" NetApp VServer ID:", srcNetAppVserverID)
    srcNetAppFilterDict[NetAppAttribute.VSERVERID.value] = srcNetAppVserverID
    
# DEBUG - this is a custom attribute that appears occastionally for non-NetApp objects
# srcNetAppFilterDict['y-RNGSimulation'] = 'Qg'

# ------------- Source Client ------------------------------------
# Set the client information if it is specified
# -------------------------------------------------------------------
if args.srcClientName is not None:
    srcClientName = str(" ".join(args.srcClientName))
    print(" Source Client Name:", srcClientName)

if args.listSrcClients:
    listSrcClients = True

# ---- PARSING COMPLETE ----------------------------------------------------------

# ################################################################################
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# ################################################################################

# Get Source and Destination Authorization Token/Strings
print("\n Accessing Source and Destination Hosts and collecting Authorization Strings...")

if listOnly != listOnlyOption.DESTINATION.value:
    srcAuthStr      = createSrcAuthStr(srcHost, srcPort, srcUser, srcPass)
    print("  * Source Access Confirmed *")
    tmpStr = "    Username: %s\n" %(srcUser)
    print(tmpStr)

# ------------- Source Client Information ---------------------------
# If a list of clients is requested, then provide it.
# -------------------------------------------------------------------
    clientList = getSrcClients(srcHost, srcPort, srcAuthStr)
    listLen = len(clientList)
    srcClientFound = False
    srcClientKeyCount = 0

    if listSrcClients:  # if user wants a list of available clients, provide it
        tmpStr = "    Available Source Clients (%s): " %(listLen)
        print(tmpStr)
        for client in range(listLen):
            t_clientName = clientList[client][GKLMAttributeType.CLIENT_NAME.value]
            t_symKeyCount = 0
            # Now check for the presents of any objects for the client
            if GKLMAttributeType.OBJECT_COUNT.value in clientList[client].keys():

                # Now since the client has objects, check for the presence of any SYMMETRIC KEYS.
                if GKLMAttributeType.SYMMETRIC_KEY.value in clientList[client][GKLMAttributeType.OBJECT_COUNT.value].keys():
                    t_symKeyCount = clientList[client][GKLMAttributeType.OBJECT_COUNT.value][GKLMAttributeType.SYMMETRIC_KEY.value]

            tmpStr = "      %s contains %s Exportable Symmetric Keys" %(t_clientName, t_symKeyCount)
            print(tmpStr)

            # Aftewards, if a client name is specified, then check to ensure it is present.
            if len(srcClientName) > 0: # if client name was specified, search for it
                if srcClientName == t_clientName:
                    srcClientFound = True
                    srcClientKeyCount = t_symKeyCount

    # Once list of clients has been parse, if the srcClientName was specified but it is not present (or has no keys),
    # then bail and make the user coorect and resubmit the command.
    if len(srcClientName) > 0: 
        if srcClientFound == False:
            tmpStr = "\n    ERROR: Client Name %s not found in list of available clients. Please try again." %(srcClientName)
            print(tmpStr)
            exit()
        elif srcClientKeyCount == 0:
            tmpStr = "\n    ERROR: Client Name %s was found in list of available clients, but does not contain any SYMMETRIC keys. Please try again." %(srcClientName)
            print(tmpStr)
            exit()
        else:
            tmpStr = "\n    Client Name %s was found in list of available clients and contains %s SYMMETRIC keys. " %(srcClientName, srcClientKeyCount)
            print(tmpStr)            

    # Let's go get some key information from the source
    # If the srcClientName has been specified, only search for those keys.  It is faster.
    # Get detailed information, including key material, for each key/object.
    # The returned list is a COMPLETE package of key attributes and key material for
    # each object.
    srcKeyObjDataList   = getSrcKeyObjDataListByClient(srcHost, srcPort, srcAuthStr, srcUUID, srcClientName)
    srcKeyListCnt       = len(srcKeyObjDataList)

    # If no srcClientName has been provided, the above ObjDataList will still be retrieved, but now lets get all of the 
    # objects stored on the host (just for the count)
    if len(srcClientName) == 0: 
        srcKeyList      = getSrcKeyList(srcHost, srcPort, srcAuthStr)
        srcKeyListCnt   = len(srcKeyList)

    # If the length of the NetApp filter (dictionary) is greater than zero, apply NetApp filter.
    if len(srcNetAppFilterDict) > 0:
        t_srcFilteredList = filterNetAppSrcKeyObjDataList(srcKeyObjDataList, srcNetAppFilterDict)
        srcKeyObjDataList = t_srcFilteredList   # replace key obj data list with filtered list

    srcKeyObjCnt        = len(srcKeyObjDataList)
        
    if listOnly != listOnlyOption.DESTINATION.value:
        print("\n Number of Src List Keys: ", srcKeyListCnt)
        print(" Number of filtered and exportable Src Key Objects: ", srcKeyObjCnt)
        printSrcKeyObjDataList(srcKeyObjDataList)

        print("\n --- SRC KEY OBJECT RETRIEVAL COMPLETE --- \n")

if listOnly != listOnlyOption.SOURCE.value:
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


        
        
if listOnly == listOnlyOption.NEITHER.value:
###########################################################################################################        
# Create and upload all of the key objects to the destination unless a flag to LIST ONLY has been specified. 
########################################################################################################### 

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

    # ----------------------------------------------------------------
    # Now that the keys have been read and mapped, send them to the
    # destiation.  
    #
    # The first step is to ensure that if the dstUserGroup name is
    # provided, that it exists on the destination server.  If it does
    # not exist, create it and add the dstUsr to the group.
    # ----------------------------------------------------------------

    if args.dstUserGroupName is not None:
        if t_flagGroupIsAbsent:
            createDstUsrGroup(dstHost, dstPort, dstAuthStr, dstUserGroupName)
            addDstUsrToGroup(dstHost, dstPort, dstAuthStr, CM_userNickname, CM_userID, dstUserGroupName)
            print(" * ", dstUserGroupName, "group configuration complete. * ")
    
    print("\nImporting key material into destination...")
    
    for xKeyObj in xKeyObjList:
        t_keyObjName = xKeyObj[CMAttributeType.NAME.value]
        print("\n xKeyObjName: ",  t_keyObjName)    
        success = importDstDataObject(dstHost, dstPort, dstUser, dstAuthStr, xKeyObj)
        print(" --> importDstDataOjbect Success:", success)
        
        # After the object has been successfully created, assign it to the Group, if one has been provided.
        
        if success:
            if args.dstUserGroupName is not None:
                xKeyObjFromDst = getDstKeyByName(dstHost, dstPort, dstAuthStr, t_keyObjName)
                
                addDataObjectToGroup(dstHost, dstPort, dstUserGroupName, dstAuthStr, xKeyObjFromDst)

        

if listOnly != listOnlyOption.SOURCE.value:
###########################################################################################################        
# Read keys that are now in the destination unless the user asks for source-only information 
########################################################################################################### 

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
