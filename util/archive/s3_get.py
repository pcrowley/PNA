#!/usr/bin/python

# Get a file from Amazon S3

from datetime import datetime, date, time
import hashlib, hmac, base64
import httplib
import sys

BUCKETNAME = "mjschultz"
AWSHOST = "s3.amazonaws.com"
ACCESSKEY = "AKIAJVYJ4QJDBZ37T2QQ"
SECRETKEY = "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"

# str_to_sign ::= HTTP-verb\n
#                 Content-MD5\n
#                 Content-Type\n
#                 Date\n
#                 CanonicalAmzHeader\n
#                 CanonicalResource
def get_auth(action, md5, type, date, file) :
    str_to_sign = u""
    str_to_sign += action+"\n" # HTTP-verb
    str_to_sign += md5+"\n"    # Content-MD5
    str_to_sign += type+"\n"   # Content-Type
    str_to_sign += date+"\n"   # Date
    str_to_sign += "/"+BUCKETNAME+"/"+file
    sig = hmac.new(SECRETKEY, str_to_sign, hashlib.sha1)
    return "AWS "+ACCESSKEY+":"+base64.b64encode(sig.digest())

def main(file) :
    HOST = BUCKETNAME+"."+AWSHOST
#    s3_rest = httplib.HTTPSConnection(HOST)
    s3_rest = httplib.HTTPConnection(HOST)
    dt = datetime.utcnow()
    dt_str = dt.strftime('%a, %d %b %Y %H:%M:%S +0000')
    auth = get_auth("GET", "", "", dt_str, file)
    headers = { 'Date': dt_str, 'Authorization': auth }
    s3_rest.request("GET", "/"+file, "", headers)
    response = s3_rest.getresponse()
    print response.status,response.reason
    print response.read()
    s3_rest.close()
    if response.status != 200 :
        exit(1)

if len(sys.argv) > 1 :
	file = sys.argv[1]
	main(file)
