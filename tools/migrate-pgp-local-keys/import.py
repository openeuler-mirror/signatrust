# Script to migrate keys from GPG local store to signatrust server

import sys
import gnupg
from datetime import datetime, timezone
import requests


class KeyImport:
    def __init__(self, signatrust_url=None, token=None, name=None, email=None, private_key=None, public_key=None, passphrase=None):
        self.headers = {
            "Authorization": token,
            "Content-Type": "application/json"
        }
        self.signatrust_url = signatrust_url.strip("/")
        self.name = name
        self.email = email
        self.private_key = private_key
        self.public_key = public_key
        self.passphrase = passphrase

    def _check_name_exists(self, name):
        response = requests.head("{}/api/v1/keys/name_identical?name={}&visibility=public".format(self.signatrust_url, name), headers=self.headers, verify=False)
        if response.status_code == 200:
            print("key: {} does not exist".format(name))
            return True
        if response.status_code == 409:
            print("key: {} already exists".format(name))
            return False
        print("failed to check key name existence code {}: and response: {}".format(response.status_code, response.content))
        raise Exception("failed to determine key duplication")

    def _check_key_enabled(self, name):
        response = requests.get("{}/api/v1/keys/{}".format(self.signatrust_url, name), headers=self.headers, verify=False)
        if response.status_code == 200:
            key_status = response.json()
            return key_status["key_state"] == "enabled"
        print("failed to get key status code {}: and response: {}".format(response.status_code, response.content))
        raise Exception("failed to get key")

    def _enable_key(self, name):
        response = requests.post("{}/api/v1/keys/{}/actions/enable".format(self.signatrust_url, name), headers=self.headers, verify=False)
        if response.status_code == 200:
            print("key: {} has been successfully enabled".format(name))
            return
        print("failed to enable key {}: and response: {}".format(response.status_code, response.content))
        raise Exception("failed to enable key")

    def _create_key(self, attribute):
        response = requests.post("{}/api/v1/keys/import".format(self.signatrust_url), json=attribute, headers=self.headers, verify=False)
        if response.status_code == 201:
            print("key: {} has been successfully created".format(attribute["name"]))
            return response.json()["name"]
        raise Exception("failed to create key {} status {} and response {}".format(attribute["name"], response.status_code, response.content))

    def import_key(self):
        print("====================== processing key: {} ====================".format(self.name))
        private_key = open(self.private_key, "r").read()
        public_key = open(self.public_key, "r").read()
        key = {
                    "attributes": {
                        "digest_algorithm": "sha2_256",
                        "key_type": "rsa",
                        "passphrase": self.passphrase,
                        "key_length": "2048",
                        "expire_at": "2050-12-30 00:00:57+08:00",
                    },
                    'name': self.name,
                    'key_type': 'x509ee',
                    'visibility': 'public',
                    'email': self.email,
                    "description": "imported from EUR server",
                    'expire_at': "2050-12-30 00:00:57+08:00",
                    'public_key': public_key,
                    'private_key': private_key,
                    'certificate': "",
                }
        if len(self.name) > 256:
            print("key: {} is too long, skip import".format(self.name))
            return
        if self._check_name_exists(self.name):
            self._create_key(key)
            print("key: {} has been successfully created".format(self.name))
        else:
            print("key: {} skip creating".format(self.name))
        if not self._check_key_enabled("{}".format(self.name)):
            print("key: {} is not enabled".format(self.name))
            self._enable_key("{}:{}".format(self.email, self.name))



if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("please use file as following:  python import.py <signatrust-url> <token> <name> <email> <private-key> <public-key> <passphrase>")
    else:
        worker = KeyImport(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
        worker.import_key()
