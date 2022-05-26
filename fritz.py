import re
import sys
import hashlib
import time
import urllib.request
import urllib.parse
import requests
import xml.etree.ElementTree as ET
from datetime import datetime

from config import url, username, password, headers, domain, out_path

LOGIN_SID_ROUTE = "/login_sid.lua?version=1"

class LoginState:
    def __init__(self, challenge: str, blocktime: int):
        self.challenge = challenge
        self.blocktime = blocktime

def get_sid(box_url: str, username: str, password: str) -> str:
    try:
        state = get_login_state(box_url)
    except Exception as ex:
        raise Exception("Failed to get challenge") from ex

    challenge_response = calculate_md5_response(state.challenge, password)
    if state.blocktime > 0:
        print(f"Waiting for {state.blocktime} seconds...")
        time.sleep(state.blocktime)
    try:
        sid = send_response(box_url, username, challenge_response)
    except Exception as ex:
        raise Exception("failed to login") from ex
    if (sid == "0000000000000000"):
        raise Exception("wrong username or password")
    return sid

def get_login_state(box_url: str) -> LoginState:
    url = box_url + LOGIN_SID_ROUTE
    http_response = urllib.request.urlopen(url)
    xml = ET.fromstring(http_response.read())
    challenge = xml.find("Challenge").text
    blocktime = int(xml.find("BlockTime").text)
    return LoginState(challenge, blocktime)

def calculate_md5_response(challenge: str, password: str) -> str:
    response = challenge + "-" + password
    response = response.encode("utf_16_le")
    md5_sum = hashlib.md5()
    md5_sum.update(response)
    response = challenge + "-" + md5_sum.hexdigest()
    return response

def send_response(box_url: str, username: str, challenge_response: str) -> str:
    post_data_dict = {"username": username, "response": challenge_response}
    post_data = urllib.parse.urlencode(post_data_dict).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    url = box_url + LOGIN_SID_ROUTE

    http_request = urllib.request.Request(url, post_data, headers)
    http_response = urllib.request.urlopen(http_request)

    xml = ET.fromstring(http_response.read())
    return xml.find("SID").text

def login():
    sid = get_sid(url, username, password)
    return sid


def upload_key_cert(sid, key, cert):
    sid = login()

    params = {
        'sid': sid,
    }

    certfile = {
        'BoxCertImportFile': ('BoxCert.pem', f'{key}{cert}', 'application/x-x509-ca-cert', ),
    }

    response = requests.post(f'{url}/cgi-bin/firmwarecfg', data=params, files=certfile)
    if response.status_code != 200:
        raise Exception(f'Failed to upload certificate.', response)

    for line in response.text.split('\n'):
        if re.search('SSL', line):
            return line
        elif error_message := re.match('.*<ErrorMsg>([^<]+)</ErrorMsg>.*', line, re.MULTILINE):
            raise Exception(error_message)

    raise Exception(f'Uploaded certificate, but the FRITZ!Box did not acknowledge it.', response, response.text)
