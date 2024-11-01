# REST-Key-Xfer
A utility for querrying REST APIs for cryptographic material

The file k-rest.py is the "main" file for this application.

*krest.bat and k-rest.sh have also been created to simplify execution of the application and include all of the paramters.*

__usage:__ k-rest.py [-h] -srcHost SRCHOST [-srcPort SRCPORT] -srcUser SRCUSER -srcPass SRCPASS -dstHost DSTHOST [-dstPort DSTPORT] -dstUser DSTUSER -dstPass DSTPASS [-listOnly {NEITHER,SOURCE,DESTINATION,BOTH}] [-srcuuid SRCUUID] [--srcClientName SOURCECLIENTNAME] [--listSrcClients] [-resolveSrcClientOwnership] [-netAppNodeID NODEID] [-netAppClusterName NODENAME] [-netAppVserverID VSID] [--dstUserGroupName GROUPNAME] [--includeSecrets]

__Arguments:__

__srcHost:__    IP Address or Hostname of Source G/SKLM server
__srcPort:__    Listen Port on Source Server (optional, default=9443)
__srcUser:__    Username on Source Server
__srcPass:__    Password for Username on Source Server

__dstHost:__    IP Address or Hostname of Destination CM Key Manager
__dstPort:__    Listen Port on Destination Server (optional, default=443)
__dstUser:__    Username on Desitnation Server
__dstPass:__    Password for Username on Destination Server

__ListOnly:__   (optional)
            NEITHER - Read and Copy Keys and Secrets From Source to Destination
            SOURCE - Only Read and List Keys and Secrets on Source Server.  No reads from or writes to Destination Server
            DESTINATION - Only Read and List Objects on Destination Server.  No reads from Source Server
            BOTH - Only Read and List Keys, Secrets, or Objects on Source and Destination Server.  No writes are made to Destination Server
            
__srcuuid:__    (optional)
            Limits reads or copies from the Source Server to only those keys or secrets whose UUIDs contain all or part of the SRCUUID string

__srcClientName:__    (optional)
            Limits reads or copies from the Source Server to only those keys and secrets that belong to a specific KMIP client.  Partial Names NOT allowed.

__listSrcClients:__    (optional)
            Lists clients that are available on the Source Server.

__resolveSrcClientOwnership:__    (optional)
            In some instances, the source clients have no administrative ownership.  This command temporarly adds the SrcUser to the ownership of the client for the purposes of completing the actions of key copying and the returns the client ownership to its original configuration.  The srcUser must have the _klmClientUser_ role and be a member of the _klmSecurityOfficerGroup_ group in the source server to use this feature.

__netAppNodeID:__   (optional)
            NetApp Specific Feature.  Similar to srcuuid.  Limits reads or copies from the Source Server to only those keys contain a NetApp-specific KMIP attribute x-NETAPP-NodeId and contain all or part of the NODEID string.

__netAppClusterName:__  (optional)
            NetApp Specific Feature.  Similar to srcuuid.  Limits reads or copies from the Source Server to only those keys contain a NetApp-specific KMIP attribute x-NETAPP-ClusterName and contain all or part of the NODENAME string.
            
__netAppVserverID:__    (optional)
            NetApp Specific Feature.  Similar to srcuuid.  Limits reads or copies from the Source Server to only those keys contain a NetApp-specific KMIP attribute x-NETAPP-VserverId and contain all or part of the NODENAME string.            

__dstUserGroupName:__    (optional)
            Desitination Group Name.  When supplied, keys written to the destination are also accessible by memembers of this group.  If the group does not originally exist, it is created and the dstUser is automatically added to the group on the destination server.

__includeSecrets:__   (optional)
            Applies actions to Secrets in addition to Keys

__Note:__ The paramters above are independent.  When more than one flag is specified, their filters are combined so that all criteria are applied when selecting the source keys or secrets. 

__Additional Notes:__

a) No certificate validation is performed.  It is presumed that the customer natively trusts the source and destination server certificates

