# REST-Key-Xfer
A utility for querrying REST APIs for cryptographic material

The file k-rest.py is the "main" file for this application.

*krest.bat and k-rest.sh have also been created to simplify execution of the application and include all of the paramters.*

__usage:__ k-rest.py [-h] -srcHost SRCHOST [-srcPort SRCPORT] -srcUser SRCUSER -srcPass SRCPASS -dstHost DSTHOST [-dstPort DSTPORT] -dstUser DSTUSER -dstPass DSTPASS [-listOnly {NEITHER,SOURCE,DESTINATION,BOTH}] [-srcuuid SRCUUID] [-netAppNodeID NODEID] [-netAppClusterName NODENAME] [-netAppVserverID VSID] [--dstUserGroupName GROUPNAME]

Arguments:
srcHost:    IP Address or Hostname of Source G/SKLM server
srcPort:    Listen Port on Source Server (optional, default=9443)
srcUser:    Username on Source Server
srcPass:    Password for Username on Source Server

dstHost:    IP Address or Hostname of Destination CM Key Manager
dstPort:    Listen Port on Destination Server (optional, default=443)
dstUser:    Username on Desitnation Server
dstPass:    Password for Username on Destination Server

ListOnly:   (optional)
            NEITHER - Read and Copy Keys From Source to Destination
            SOURCE - Only Read and List Keys on Source Server.  No reads from or writes to Destination Server
            DESTINATION - Only Read and List Keys on Destination Server.  No reads from Source Server
            BOTH - Only Read and List Keys on Source and Destination Server.  No writes are made to Destination Server
            
srcuuid:    (optional)
            Limits reads or copyies from the Source Server to only those keys whose UUIDs contain all or part of the SRCUUID string

netAppNodeID:   (optional)
            NetApp Specific Feature.  Similar to srcuuid.  Limits reads or copyies from the Source Server to only those keys contain a NetApp-specific KMIP attribute NODEID and contain all or part of the NODEID string.

netAppClusterName:  (optional)
            NetApp Specific Feature.  Similar to srcuuid.  Limits reads or copyies from the Source Server to only those keys contain a NetApp-specific KMIP attribute NODENAME and contain all or part of the NODENAME string.
            
netAppVserverID:    (optional)
            NetApp Specific Feature.  Similar to srcuuid.  Limits reads or copyies from the Source Server to only those keys contain a NetApp-specific KMIP attribute NODENAME and contain all or part of the NODENAME string.            
Note that srcuuid, netAppNodeID, netAppClusterName, and netAppVserverID are optional, independent flags.  But when included, their filters are combined so that all criteria are applied when selecting the source keys.

dstUserGroupName:
            Desitination Group Name.  When supplied, keys written to the destination are also accessible by memembers of this group.  If the group does not originally exist, it is created and the dstUser is automatically added to the group on the destination server.


Additional Notes:

a) No certificate validation is performed.  It is presumed that the customer natively trusts the source and destination server certificates

