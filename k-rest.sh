#!/bin/bash
#
# Script for executing k-rest.by on Linux
#
# This is sample script file for demonstration purposes only.
#
# Please see README file at https://github.com/thalescpl-io/REST-Key-Xfer for a detailed explaination of the parameters.
#
python3 k-rest.py \
-srcHost xklm.test256.io \
-srcUser SKLMAdmin -srcPass Thales_4567 \
-dstHost cm-kirk.test256.io \
-dstUser rest_alice -dstPass Thales234! \
-listOnly SOURCE \
-srcuuid KEY-c \
-netAppNodeID 8d \
-netAppClusterName AFF \
-netAppVserverID 42 \
-dstUserGroupName Group3 \
-listSrcClients \
-srcClientName Client1
# -includeSecrets
# -resolveSrcClientOwnership 
