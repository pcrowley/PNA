#!/usr/bin/python

# Put a file on Amazon S3

from datetime import datetime, date, time
import hashlib, hmac, base64
import httplib
import sys
import os

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
def put_auth(action, md5, type, date, file) :
    str_to_sign = u""
    str_to_sign += action+"\n" # HTTP-verb
    str_to_sign += md5+"\n"    # Content-MD5
    str_to_sign += type+"\n"   # Content-Type
    str_to_sign += date+"\n"   # Date
    str_to_sign += "/"+BUCKETNAME+"/"+file
    sig = hmac.new(SECRETKEY, str_to_sign, hashlib.sha1)
    return "AWS "+ACCESSKEY+":"+base64.b64encode(sig.digest())

def main(hostid, localname) :
    HOST = BUCKETNAME+"."+AWSHOST
    size = os.path.getsize(localname)
    fd = open(localname, 'r')
    remotename = 'pna/'+hostid+'/'+os.path.basename(localname)
#    s3_rest = httplib.HTTPSConnection(HOST)
    s3_rest = httplib.HTTPConnection(HOST)
    dt = datetime.utcnow()
    dt_str = dt.strftime('%a, %d %b %Y %H:%M:%S +0000')
    auth = put_auth("PUT", "", "", dt_str, remotename)
    headers = { 'Date': dt_str,
                'Authorization': auth,
                'Content-Length': str(size), }
    s3_rest.request("PUT", "/"+remotename, fd.read(), headers)
    response = s3_rest.getresponse()
    s3_rest.close()
    fd.close()
    if response.status != 200 :
        exit(1)

if len(sys.argv) > 2 :
    hostid = sys.argv[1]
    localname = sys.argv[2]
    main(hostid, localname)
else :
	print 'usage: %s <hostid> <localfile>' % sys.argv[0]
