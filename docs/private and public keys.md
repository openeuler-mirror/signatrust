# Problem description
When considering the integration of Signatrust with COPR, we found the COPR will create hundreds of key pairs for its user and projects.
Since these keys are only used for one specific project and can be a temporary keys, we would like to introduce the concept of private/public key pairs to support this.
1. **private key pairs**: the private key pairs are managed by one signatrust administrator, that is to say, the key owner is responsible for create/manage/delete those keys and no other administrator except the owner could see/use these keys.
2. **public key pairs**: the public key pairs can be created/used by any administrator, but in order to delete it, we require multiple confirms from different administrator.
# Proposed change
## Database change
The `data_key` table will have a new string column named `visibility`.
## Control API changes
1. Create key pairs: Add an attribute `visibility` which only accepts the value `public` or `private`. for any private keys, the key name will be prefixed with user's email for example: `tommylikehu@gmail.com:copr-user1-project1`
2. List Key pairs: Add an query parameter `visibility` to filter keys accordingly.
3. The private key can be deleted by user directly, while the case of the public key is more complex.
```shell
                     >Requst delete by one administrator                       two more administrator confirmed deletion
Key in Normal State <-------------------------------------> Pending Delete key<----------------------------------------->Deleted
                     <Cancel delete by the administrator  
```
## Data API changes
For the purpose of limiting access to private keys, there are two possible solutions.
1. Use the SAN attribute in client certificate, the email `SAN` of the client can be verified whether it matches to the key owner's when requesting a private key pairs. But this requires the support of openssl/tonic library.
2. Add attribute `token` to the grpc requests, and that the verification can be performed without any library changes.
Note: this verification will be performed only when key name is prefixed with email address.


