#####################################################################################
#
# 	Name: k-rest.py
# 	Author: Rick R
# 	Purpose:  Python-based REST Client Data Exchange
#
#   Usage: py k-rest.py -srcHost <hostname or IP> -srcUser <username> -srcPass <password> 
#                   -dstHost <hostname or IP> -dstUser <username> -dstPass <password> 
#                   
#####################################################################################

import argparse
import binascii
import codecs
import hashlib
import json
import requests
from urllib3.exceptions import InsecureRequestWarning

# ---------------- Functions-----------------------------------------------------
# -------------------------------------------------------------------------------
def makeHexStr(t_val):

    tmpStr = str(t_val)
    t_hexStr = hex(int("0x" + tmpStr[2:-1], 0))

    return t_hexStr


# ---------------- End of Functions ----------------------------------------------

DEFAULT_SRC_PORT = ["9443"]
DEFAULT_DST_PORT = ["443"]

# ----- Input Parsing ------------------------------------------------------------

# Parse command.  Note that if the arguments are not complete, a usage message will be printed
# automatically
parser = argparse.ArgumentParser(prog="k-rest.py", description="REST Client Data Exchange")

# Source Information
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

t_srcHost = str(" ".join(args.srcHost))
t_srcPort = str(" ".join(args.srcPort))
t_srcUser = str(" ".join(args.srcUser))
t_srcPass = str(" ".join(args.srcPass))

t_dstHost = str(" ".join(args.dstHost))
t_dstPort = str(" ".join(args.dstPort))
t_dstUser = str(" ".join(args.dstUser))
t_dstPass = str(" ".join(args.dstPass))

print("\n ---- INPUT STATS: ----")
print("Source: ", t_srcHost, t_srcPort, t_srcUser)
print("  Dest: ", t_dstHost, t_dstPort, t_dstUser)

# ---- Parsing Complete ----------------------------------------------------------

# --- Source REST Assembly -------------------------------------------------------

t_srcRESTPreamble = "/SKLM/rest/v1/ckms"
t_srcRESTLogin = t_srcRESTPreamble + "/login"
t_srcHostRESTLogin = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTLogin)
print("login string:", t_srcHostRESTLogin)

t_srcHeaders = {"Content-Type":"application/json", "Accept":"application/json"}
t_srcBody = {"userid":t_srcUser, "password":t_srcPass}

print("JSON dumps: ", json.dumps(t_srcBody))

# Suppress SSL Verification Warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

r = requests.post(t_srcHostRESTLogin, data=json.dumps(t_srcBody), headers=t_srcHeaders, verify=False)

# print("Result: ", dir(r))
print("Status Code:", r.status_code)
# print("Headers:", r.headers)
print("JSON:", r.text)


r.json()


print("\n --- COMPLETE --- ")


