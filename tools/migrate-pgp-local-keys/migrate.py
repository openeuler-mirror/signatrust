# Script to migrate keys from GPG local store to signatrust server

import sys
import gnupg
from datetime import datetime, timezone
import requests


class KeyMigration:
    def __init__(self, signatrust_url=None, token=None, gpg_home=None):
        self.headers = {
            "Authorization": token,
            "Content-Type": "application/json"
        }
        self.signatrust_url = signatrust_url.strip("/")
        self.gpg = gnupg.GPG(gnupghome=gpg_home)

    def _check_name_exists(self, name):
        response = requests.head("{}/api/v1/keys/name_identical?name={}".format(self.signatrust_url, name), headers=self.headers, verify=False)
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
            return
        raise Exception("failed to create key {} status {} and response {}".format(attribute["name"], response.status_code, response.content))

    def _collect_keys_from_pgp_local_store(self):
        results = []
        keys = self.gpg.list_keys(True)
        for k in keys:
            ids = k["uids"][0].split(" ")
            key = {
                "attributes": {
                    "digest_algorithm": "sha2_256",
                    "key_type": "rsa",
                    "key_length": k["length"],
                    "expire_at": "{}".format(datetime.fromtimestamp(int(k["expires"]), tz=timezone.utc)),
                },
                'name': ids[0],
                'key_type': 'pgp',
                'email': ids[2].strip('<').strip('>'),
                "description": "imported from EUR server",
                'create_at': "{}".format(datetime.fromtimestamp(int(k["date"]), tz=timezone.utc)),
                'expire_at': "{}".format(datetime.fromtimestamp(int(k["expires"]), tz=timezone.utc)),
                'public_key': self.gpg.export_keys(k["keyid"]),
                'private_key': self.gpg.export_keys(k["keyid"], secret=True, passphrase=""),
                'certificate': "",
            }
            results.append(key)
        return results

    def migrate(self):
        keys = self._collect_keys_from_pgp_local_store()
        for i, k in enumerate(keys):
            print("====================== processing {} key: {} ====================".format(i+1, k["name"]))
            # Remove this when supported.
            if len(k["name"]) > 210:
                print("key: {} is too long, skip creating".format(k["name"]))
                continue
            if self._check_name_exists(k["name"]):
                self._create_key(k)
                print("key: {} has been successfully created".format(k["name"]))
            else:
                print("key: {} skip creating".format(k["name"]))
            if not self._check_key_enabled(k["name"]):
                print("key: {} is not enabled".format(k["name"]))
                self._enable_key(k["name"])


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("please use file as following:  python migrate.py <signatrust-url> <token> <pgp-base-folder>")
    else:
        migration = KeyMigration(sys.argv[1], sys.argv[2], sys.argv[3])
        migration.migrate()
