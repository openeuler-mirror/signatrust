# Process to migrate keys from EUR to Signatrust

## Requirements
1. Python, Pip and Gpg
2. python-gnupg and requests libraries

## Copy pgp data files from EUR to local
Get the kubeconfig and copy the whole directory by kubectl command
```shell
mkdir local-store
kubectl cp -c <container-name> <namespace>/<pod-name>:/var/lib/copr-keygen/gnupg ./local-store
```

## Using python docker image to run the script
we need to mount the pgp data folder as well as the python script folder
```shell
docker pull python:3.11
# mount local_store and migrate.py folder
docker run -it --entrypoint bash  -v <path-to-migrate.py-directory>:/app/working-dir -v  <path-to-local-store>:/app/data python:3.11
```

## Install requirements(in Docker)
```shell
cd /app/working-dir
pip install -r requirments.txt
``
```

## Migrate Keys(in Docker)
Generate the signatrust API token, user email and use it in the following command
```shell
python migrate.py https://signatrust.test.osinfra.cn/  <api-token> <email>  /app/data
====================== processing 1 key: mywaaagh_admin_copr ====================
key: mywaaagh_admin_copr already exists
key: mywaaagh_admin_copr skip creating
====================== processing 2 key: mywaaagh_admin_fish ====================
key: mywaaagh_admin_fish already exists
key: mywaaagh_admin_fish skip creating
exit
```
## Remove the local folder
```shell
rm -f <path-to-local-store>
```