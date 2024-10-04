ECHO OFF
REM
REM k-rest.py REST Client Data Transfer
REM
REM This is sample batch file for demonstration purposes only.
REM
REM Arguments:

REM srcHost:    IP Address or Hostname of Source G/SKLM server
REM srcPort:    Listen Port on Source Server (optional, default=9443)
REM srcUser:    Username on Source Server
REM srcPass:    Password for Username on Source Server

REM dstHost:    IP Address or Hostname of Destination CM Key Manager
REM dstPort:    Listen Port on Destination Server (optional, default=443)
REM dstUser:    Username on Desitnation Server
REM dstPass:    Password for Username on Destination Server

REM ListOnly:   (optional)
REM            NEITHER - Read and Copy Keys From Source to Destination
REM            SOURCE - Only Read and List Keys on Source Server.  No reads from or writes to Destination Server
REM            DESTINATION - Only Read and List Keys on Destination Server.  No reads from Source Server
REM            BOTH - Only Read and List Keys on Source and Destination Server.  No writes are made to Destination Server
            
REM srcuuid:    (optional)
REM            Limits reads or copies from the Source Server to only those keys whose UUIDs contain all or part of the SRCUUID string

REM srcClientName:    (optional)
REM            Limits reads or copies from the Source Server to only those keys that belong to a specific KMIP client.  Partial name allowed.

REM listSrcClients:    (optional)
REM            Lists clients that are available on the Source Server.

REM netAppNodeID:   (optional)
REM            NetApp Specific Feature.  Similar to srcuuid.  Limits reads or copies from the Source Server to only those keys contain a NetApp-specific KMIP attribute x-NETAPP-NodeId and contain all or part of the NODEID string.

REM netAppClusterName:  (optional)
REM            NetApp Specific Feature.  Similar to srcuuid.  Limits reads or copies from the Source Server to only those keys contain a NetApp-specific KMIP attribute x-NETAPP-ClusterName and contain all or part of the NODENAME string.
            
REM netAppVserverID:    (optional)
REM           NetApp Specific Feature.  Similar to srcuuid.  Limits reads or copies from the Source Server to only those keys contain a NetApp-specific KMIP attribute x-NETAPP-VserverId and contain all or part of the NODENAME string.            

REM dstUserGroupName:    (optional)
REM           Desitination Group Name.  When supplied, keys written to the destination are also accessible by memembers of this group.  If the group does not originally exist, it is created and the dstUser is automatically added to the group on the destination server.

REM Note that the paramters above are independent.  But when included, their filters are combined so that all criteria are applied when selecting the source keys. 



py k-rest.py -srcHost xklm-22.test256.io -srcUser sklmrick -srcPass Thales_4567 -dstHost cm-kirk.test256.io -dstUser rest_alice -dstPass Thales234! -listSrcClients -listOnly SOURCE