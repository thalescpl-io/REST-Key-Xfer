# NetApp Filters
#
# definition file of assorted REST Commands for communicating
# with the source and destination servers
#
######################################################################
import  requests
from    urllib3.exceptions import InsecureRequestWarning
import  json
from    kerrors import *
from    krestenums import *
from    krestcmds import *

import  enum
import  re

def getAttribValue(t_attribKey, t_attribStr):
# --------------------------------------------------------------------
# Get attribute value from attibute string
# 
# This is to make a simple answer out of a complex mess of data in the
# Custom Attributes String
# --------------------------------------------------------------------
    t_header    = "["+t_attribKey+" "
    t_lenH      = len(t_header)
    t_trailer   = "]"
    t_strValue  = ""
    
    t_startPos  = t_attribStr.find(t_header)
    if t_startPos > -1: # test for non-existance of attribKey
        t_endPos    = t_attribStr.find(t_trailer, t_startPos+t_lenH)
        t_strValue  = t_attribStr[t_startPos+t_lenH:t_endPos]
    else:
        t_strValue = ""

    return t_strValue

def createNameValueDict(t_str):
# --------------------------------------------------------------------
# Create a dictionary of ALL name-value pairs from a string that contains
# many bracketed pieces of information with '[NAME ' as the primary key
# to the name of the n-v pair and '[VALUE ' as the primary key to the
# value in the n-v pair.
# --------------------------------------------------------------------
    t_nvPairDict = {}   # Create return dictionary
    t_shrinkingStr = t_str
    t_nameKey   = "NAME"
    t_valueKey  = "VALUE"
    t_err       = False
    t_complete  = False
    
    while (t_complete==False):
        
        t_nameVal   = getAttribValue(t_nameKey, t_shrinkingStr)
        t_valueVal  = getAttribValue(t_valueKey, t_shrinkingStr)
            
        # If the name and value are present (non-zero), then enter
        # them into the dictionary and then shrink the string to 
        # search for more instances of 'NAME'
        if (len(t_nameVal)>0 and len(t_valueVal)>0):
            
            t_nvPairDict[t_nameVal] = t_valueVal
            t_newStrStart = t_shrinkingStr.find(t_valueKey)+len(t_valueVal)+1
            t_shorterStr = t_shrinkingStr[t_newStrStart:]
            
            t_shrinkingStr = t_shorterStr 
        else:
            t_complete = True

    return t_nvPairDict
        
    
def filterSrcNetAppObjDataList(t_srcObjDataList, t_netAppFilterDict):
# -----------------------------------------------------------------------------
# Filters ObjDataList by the NetApp filter definitions described by user.
#
# Using the netAppFilterDict Dictionary, filter the srcObjDataList such that 
# only those keys satisfy all of the defined filters are returned.
# -----------------------------------------------------------------------------
    
    t_ListLen           = len(t_srcObjDataList)
    t_filteredList      = [] # created list to be returned later
    
    # -------------------------------------------------------------------------
    # For each object in the Source Object Data List, you will need to check for
    # the presence of a 'Custom Attributes' field.  If that field exists, you will
    # need to check for each of the attribute fields included in the
    # t_netAppFilterDict dictionary.  For each of thoses fields, you will need
    # to check the corresponding value.  If ALL of the values in the for each 
    # of the dictionary keys exist (partially or entirely), then the 
    # corresponding object is included in the returned list (t_filteredList)
    # --------------------------------------------------------------------------
    
    for obj in range(t_ListLen):
        
        # Check for the presence of the 'Custom Attributes' field    
        if GKLMAttributeType.CUSTOM_ATTRIBUTES.value in t_srcObjDataList[obj]: 
            
            # Since the Custom Attributes field is present, proceed with retrieving the list of
            # custom attributes.
            t_CustAttribStr = t_srcObjDataList[obj][GKLMAttributeType.CUSTOM_ATTRIBUTES.value]
            
            # Note.  This is ugly.  The NetApp Custom Attributes are a single list of strings with brackets...
            # I.e. "Custom Attributes": "[[NAME x-NETAPP-KeyId] [[INDEX 0] [TYPE JAVA_STRING] 
            # [VALUE 00000000000000000200000000000500b6b927c7927b570e7121539c3b98ceec0000000000000000]]]
            # [[NAME x-NETAPP-NodeId] [[INDEX 0] [TYPE JAVA_STRING] [VALUE 8d901e7e-741f-11eb-9863-00a098e0f13b]]].
            #
            # The first step is to parse the Custom Attributes 'value' to its own dictionary of name-value pairs
            # based on the string of words NAME and VALUE, which may occur multiple times in the 
            # Custom Attributes value field.

            t_objNameValueDict = createNameValueDict(t_CustAttribStr)

            # Before checking for the presence of each of the dictionary attributes/keys, assume they are
            # present in the list until one is NOT discovered.
            addObjToFilteredList = True # default
                    
            for netAppAttrib in t_netAppFilterDict.keys():
                netAppAttribVal = t_netAppFilterDict.get(netAppAttrib)
                
                # Now check to see if the netAppAttribute is in the nameValueDictionary.
                # If the attribute is present, check for the presence of the search value in t_dictAttribValue.  
                # If both the attribute is present and the value contains the filtered characters, then add
                # object to filtered list.
                if netAppAttrib in t_objNameValueDict:
                    t_objDictAttribValue = t_objNameValueDict[netAppAttrib]
                    if netAppAttribVal in t_objDictAttribValue:
                        addObjToFilteredList = addObjToFilteredList & True 
                    else:
                        addObjToFilteredList = False    # exclude object from filtered list since value is not found
                else:
                    addObjToFilteredList = False        # exclude object from filtered list since name is not found
                    
            # If all NetApp Attributes are found in the Custom Attributes field of the object, then save the Obj
            if addObjToFilteredList == True:
                t_filteredList.append(t_srcObjDataList[obj])
                
    return t_filteredList


def filterDstNetAppObjDataList(t_dstObjDataList, t_netAppFilterDict):
# -----------------------------------------------------------------------------
# Filters ObjDataList by the NetApp filter definitions described by user.
#
# Using the netAppFilterDict Dictionary, filter the dstObjDataList such that 
# only those keys satisfy all of the defined filters are returned.
#
# Filtering the destination list is much easier that the source list because
# it is better organized.
# -----------------------------------------------------------------------------
    
    t_ListLen           = len(t_dstObjDataList)
    t_filteredList      = [] # create list to be returned later
    t_objectDict        = {} # create working dictionary

    # -------------------------------------------------------------------------
    # For each object in the Dst Object Data List, you will need to check for the
    # presence of a {"meta":{"kmip":{"custom":[]}] meta structure.  If that
    # structure exists, then each element in that list ([]), with have a three
    # dictionary with the following keys: type, index, and x-NETAPP-??? where the
    # x-NETAPP-??? will be a key name associated with each NetApp-specific parameter.
    # You need to check for each of the attribute fields included in the
    # t_netAppFilterDict dictionary.  For each of thoses fields, you will need
    # to check the corresponding value.  If ALL of the values in the for each 
    # of the dictionary keys exist (partially or entirely), then the 
    # corresponding object is included in the returned list (t_filteredList)
    # --------------------------------------------------------------------------
    
    for obj in range(t_ListLen):
        t_customAttribList  = []
        tmpdict = {}

        # Check for the presence of the meta key
        t_objectDict = t_dstObjDataList[obj]

        # Check for the presence of the a {"meta":{"kmip":{"custom":[]}] structure. If present, extract the custom list.
        if CMAttributeType.META.value in t_objectDict.keys(): 
            if t_objectDict[CMAttributeType.META.value]:
                if NetAppMetaAttribute.KMIP.value in t_objectDict[CMAttributeType.META.value].keys():
                    if NetAppMetaAttribute.CUSTOM.value in t_objectDict[CMAttributeType.META.value][NetAppMetaAttribute.KMIP.value].keys():
                        t_customAttribList = t_objectDict[CMAttributeType.META.value][NetAppMetaAttribute.KMIP.value][NetAppMetaAttribute.CUSTOM.value]

            # Before checking for the presence of each of the dictionary attributes/keys, assume they are
            # present in the list until one is NOT discovered.
            addObjToFilteredList = True # default
                    
            for netAppAttrib in t_netAppFilterDict.keys():
                netAppAttribVal = t_netAppFilterDict.get(netAppAttrib)

                # Now check to see if the netAppAttribute is in the list of custom attributes.
                # If the attribute is present, check for the presence of the value .  
                # If both the attribute is present and the value contains the filtered characters, then add
                # object to filtered list.                
                t_attribFound           = False     # reset for each attribute
                t_valueFound            = False
                addObjToFilteredList    = False

                for t_attrib in t_customAttribList:
                    if netAppAttrib in t_attrib.keys():
                        # print("netAppAttrib Found:", netAppAttrib)
                        t_attribFound = t_attribFound | True
                        if netAppAttribVal in t_attrib[netAppAttrib]:  #check to see if the value is there
                            t_valueFound = t_valueFound | True
                            # print("netAppAttribValue Found:", netAppAttribVal)
                
                # If the attribute and value were found in the object's custome attribute list, then allow that
                # object to be added to the filterned objects list.
                if t_attribFound and t_valueFound:
                    addObjToFilteredList = True

                # print("Obj netAppAttrib and netAppValue addOBJToFilterd:", obj, netAppAttrib, netAppAttribVal, addObjToFilteredList)
                # if addObjToFilteredList:
                #    print("t_customAttribList:", t_customAttribList)
                  
            # If ALL NetApp Attributes are found in the Custom Attributes field of the object, then save the Obj
            if addObjToFilteredList == True:
                t_filteredList.append(t_dstObjDataList[obj])

    # printJList("filterDstNetAppObjDataList: ", t_filteredList)

    return t_filteredList