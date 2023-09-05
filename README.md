# REST-Key-Xfer
A utility for querrying REST APIs for cryptographic material

The file k-rest.py is the "main" file for this application.

*krest.bat and k-rest.sh have also been created to simplify execution of the application and include all of the paramters.*

__usage:__ k-rest.py [-h] -srcHost SRCHOST [-srcPort SRCPORT] -srcUser SRCUSER -srcPass SRCPASS -dstHost DSTHOST [-dstPort DSTPORT] -dstUser DSTUSER -dstPass DSTPASS

Notes:

a) No certificate validation is performed.  It is presumed that the customer natively trusts the source and destination server certificates

