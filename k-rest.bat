ECHO OFF
REM
REM k-rest.py REST Client Data Transfer
REM
REM This is sample batch file for demonstration purposes only.
REM
REM py k-rest.py -srcHost xklm.test256.io -srcUser SKLMAdmin -srcPass Thales_4567 -dstHost cm-kirk.test256.io -dstUser rest_alice -dstPass Thales234! -listOnly BOTH -srcuuid KEY-c -netAppNodeID 8d -netAppClusterName AFF -netAppVserverID 42

REM py k-rest.py -srcHost xklm.test256.io -srcUser SKLMAdmin -srcPass Thales_4567 -dstHost cm-kirk.test256.io -dstUser rest_alice -dstPass Thales234! -dstUserGroupName Group3

py k-rest.py -srcHost xklm.test256.io -srcUser SKLMAdmin -srcPass Thales_4567 -dstHost cm-kirk.test256.io -dstUser rest_alice -dstPass Thales234! -srcuuid KEY-c5c299d-59b885b5-0a82-488a-9c09 -dstUserGroupName Group3