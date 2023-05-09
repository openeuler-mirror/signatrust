# Integrate Signatrust with COPR
## Background
COPR use obs-sign project as their sign backend. obs-sign is a project that widely used in the package build system and
supports rpm and kernel module files, in order to replace obs-sign with Signatrust, we need to find out all the scenarios
that obs-sign used and make sure Signatrust can support them all.

## Scenarios
1. Generate user openPGP key pairs with `name_real` and `name_email`, the rest parameters of key type/key length/expire date is configure as default value.
Also, the uniqueness of the key is identified by `name_email`.
```python
def create_user_keys(username, projectname, opts):
    """
    Generate a new key-pair at sign host

    :param username:
    :param projectname:
    :param opts: backend config

    :return: None
    """
    data = {
        "name_real": "{}_{}".format(username, projectname),
        "name_email": create_gpg_email(username, projectname)
    }

    log = get_redis_logger(opts, "sign", "actions")
    keygen_url = "http://{}/gen_key".format(opts.keygen_host)
    query = dict(url=keygen_url, data=data, method="post")
    try:
        request = SafeRequest(log=log)
        response = request.send(**query)
    except Exception as e:
        raise CoprKeygenRequestError(
            msg="Failed to create key-pair for user: {},"
                " project:{} with error: {}"
            .format(username, projectname, e), request=query)

    if response.status_code >= 400:
        raise CoprKeygenRequestError(
            msg="Failed to create key-pair for user: {}, project:{}, status_code: {}, response: {}"
            .format(username, projectname, response.status_code, response.text),
            request=query, response=response)
```
2. Export the user's public key and save into local file
```python
def get_pubkey(username, projectname, log, outfile=None):
    """
    Retrieves public key for user/project from signer host.

    :param outfile: [optional] file to write obtained key
    :return: public keys

    :raises CoprSignError: failed to retrieve key, see error message
    :raises CoprSignNoKeyError: if there are no such user in keyring
    """
    usermail = create_gpg_email(username, projectname)
    cmd = [SIGN_BINARY, "-u", usermail, "-p"]

    returncode, stdout, stderr = call_sign_bin(cmd, log)
    if returncode != 0:
        if "unknown key:" in stderr:
            raise CoprSignNoKeyError(
                "There are no gpg keys for user {} in keyring".format(username),
                return_code=returncode,
                cmd=cmd, stdout=stdout, stderr=stderr)
        raise CoprSignError(
            msg="Failed to get user pubkey\n"
                "sign stdout: {}\n sign stderr: {}\n".format(stdout, stderr),
            return_code=returncode,
            cmd=cmd, stdout=stdout, stderr=stderr)

    if outfile:
        with open(outfile, "w") as handle:
            handle.write(stdout)

    return stdout
```
3. Sign the rpm packages with obs-sign client. currently, the package is signed in sequence and the digest method is determined by specific mock environment.
```python
def _sign_one(path, email, hashtype, log):
    cmd = [SIGN_BINARY, "-4", "-h", hashtype, "-u", email, "-r", path]
    returncode, stdout, stderr = call_sign_bin(cmd, log)
    if returncode != 0:
        raise CoprSignError(
            msg="Failed to sign {} by user {}".format(path, email),
            return_code=returncode,
            cmd=cmd, stdout=stdout, stderr=stderr)
    return stdout, stderr
```
4. Drop signature of rpm packages, COPR use rpm command util to drop signature.
```python
def unsign_rpms_in_dir(path, opts, log):
    """
    :param path: directory with rpms to be signed
    :param Munch opts: backend config
    :type log: logging.Logger
    :raises: :py:class:`backend.exceptions.CoprSignError` failed to sign at least one package
    """
    rpm_list = [
        os.path.join(path, filename)
        for filename in os.listdir(path)
        if filename.endswith(".rpm")
        ]

    if not rpm_list:
        return

    errors = []  # tuples (rpm_filepath, exception)
    for rpm in rpm_list:
        try:
            _unsign_one(rpm)
            log.info("unsigned rpm: {}".format(rpm))

        except CoprSignError as e:
            log.exception("failed to unsign rpm: {}".format(rpm))
            errors.append((rpm, e))

    if errors:
        raise CoprSignError("Rpm unsign failed, affected rpms: {}"
                            .format([err[0] for err in errors]))
```
5. Check server liveness.
```python
@app.route('/ping')
def ping():
    """
    Checks if server still alive

    :status 200: server alive
    """
    app.logger.debug("got ping")
    return Response("pong\n", content_type="text/plain;charset=UTF-8")
```
6. Delete user related key pairs. it's missing in COPR project currently, but also needs to be considered.

# Requirements for Signatrust

To support COPR signing scenarios, Signatrust need to support the following features:
1. Considering there would be hundreds of projects/key pairs in COPR, it's reasonable to support private key pairs which
can be managed by users(clients) themselves. in the meantime the public keys will be managed by admin group with much caution.
2. Add liveness/readiness endpoint for signatrust control server.
3. **Optional**: Support to delete rpm signature in client.
4. Support to specify different digest method in signing request.

# Possible changes for COPR

1. Delete copr-keygen and obs-sign components
2. Integrate copr-backend with signatrust for generate/sign/delete operations, including updating invoke API/Command as well as related configuration.
3. Support delete key pairs when deleting projects.
4. Add script to migrate existing key pairs from copr-keygen to signatrust.

# Architecture update
![architecture](./images/copr%20with%20signatrust.png)

