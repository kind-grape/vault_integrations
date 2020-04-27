# Using AWS Auth Guide for Gitlab Runner (or anything running on AWS EC2)

## Concept of the AWS Auth 
AWS auth method provides automated mechanism to retrive vault token for IAM principles and AWS EC2 instance.
IAM method - a special AWS request signed with AWS IAM credentials is used for auth. IAM credentials are automatically supplied to AWS instances in IAM instance profiles
EC2 method - AWS is treated as Trusted 3rd party and cryptographically signed dynamic metadata info that uniquely represent each EC2 instance is used for authentication. This metadata info is automatically supplied by AWS to all EC2 instances

## Example of using IAM method AWS auth 
Consider the following example with the environmental setup 
we have 1 vault server 
and another vault client running vault agent 

First, we should create an EC2 IAM role for the vault client to authenticate with 
This will make sure the IAM role will use AWS ec2 principle to authenticate
We call this vault-agent-gitlab-demo-vault-client-role
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VaultClient",
            "Effect": "Allow",
            "Action": "ec2:DescribeInstances",
            "Resource": "*"
        }
    ]
}
```
Then on the Vault server, make sure we have the following IAM role associated to the vault server
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ConsulAutoJoin",
            "Effect": "Allow",
            "Action": "ec2:DescribeInstances",
            "Resource": "*"
        },
        {
            "Sid": "VaultAWSAuthMethod",
            "Effect": "Allow",
            "Action": [
                "iam:GetUser",
                "iam:GetRole",
                "iam:GetInstanceProfile",
                "ec2:DescribeInstances"
            ],
            "Resource": "*"
        },
        {
            "Sid": "VaultKMSUnseal",
            "Effect": "Allow",
            "Action": [
                "kms:Encrypt",
                "kms:DescribeKey",
                "kms:Decrypt"
            ],
            "Resource": "*"
        }
    ]
}
```
Please note that the IAM role above not only includes the AWS auth, but also KMS auto unseal and consul server auto join. 

Once its completed set up on AWS IAM side, lets move onto the authentication part

## AWS auth configs [demo running on AWS]
On the server side, enable aws auth end point 
To demo this, lets create a kv secret engines and create a kv pair

```  
vault secrets enable -path="secret" kv
vault kv put secret/myapp/config ttl='30s' username='appuser' password='suP3rsec(et!'
```

Then write a policy for the vault client so that it can read into this secret engine 
```
echo "path \"secret/myapp/*\" {
    capabilities = [\"read\", \"list\"]
}" | vault policy write myapp -
```

Configure the vault aws auth role for the vault client 
the arn profile should be from the IAM user we created earlier 
```
vault write auth/aws/role/gitlab-role-iam auth_type=iam bound_iam_principal_arn="arn:aws:iam::794824571486:role/vault-agent-gitlab-demo-vault-client-role" policies=myapp ttl=24h
```

make sure the role is present at the list 
```
ubuntu@ip-10-0-101-80:~$ vault list auth/aws/role
Keys
----
dev-role-iam
gitlab-role-iam
```

Let's move onto the vault client running vault agent. First generate a vault-agent.hcl config
```
[ec2-user@ip-172-31-17-255 ~]$ cat vault-agent.hcl
exit_after_auth = true
pid_file = "./pidfile"

auto_auth {
   method "aws" {
       mount_path = "auth/aws"
       config = {
           type = "iam"
           role = "gitlab-role-iam"
       }
   }

   sink "file" {
       config = {
           path = "/home/ec2-user/vault-token-via-agent"
       }
   }
}

vault {
   address = "http://3.101.73.161:8200"
}
```
Note that the vault address should be the vault server api endpint and should have connectivity [use telnet to confirm before hand]
This agent config has ```exit_after_auth = true``` argument which means once it succesfully authenticated with vault server, it will exit and would not run as a service/daemon 
Sink file location are the places where it tells vault agent to place the authenticated token, which can then be used for vault operations. 
After this command is run, you should see the following output if the vault client is successully authenticated with vault server 
```
[ec2-user@ip-172-31-17-255 ~]$ vault agent -config=vault-agent.hcl -log-level=debug
==> Vault server started! Log data will stream in below:

==> Vault agent configuration:

                     Cgo: disabled
               Log Level: debug
                 Version: Vault v1.4.0

2020-04-24T16:00:15.607Z [INFO]  sink.file: creating file sink
2020-04-24T16:00:15.607Z [INFO]  sink.file: file sink configured: path=/home/ec2-user/vault-token-via-agent mode=-rw-r-----
2020-04-24T16:00:15.618Z [INFO]  auth.handler: starting auth handler
2020-04-24T16:00:15.618Z [INFO]  auth.handler: authenticating
2020-04-24T16:00:15.618Z [INFO]  template.server: starting template server
2020-04-24T16:00:15.618Z [INFO]  template.server: no templates found
2020-04-24T16:00:15.618Z [INFO]  template.server: template server stopped
2020-04-24T16:00:15.618Z [INFO]  sink.server: starting sink server
2020-04-24T16:00:15.925Z [INFO]  auth.handler: authentication successful, sending token to sinks
2020-04-24T16:00:15.926Z [INFO]  auth.handler: starting renewal process
2020-04-24T16:00:15.926Z [INFO]  sink.file: token written: path=/home/ec2-user/vault-token-via-agent
2020-04-24T16:00:15.926Z [INFO]  sink.server: sink server stopped
2020-04-24T16:00:15.926Z [INFO]  sinks finished, exiting
```

Now we should be able to use this token, and read into the kv secret engine on vault server 
```
[ec2-user@ip-172-31-17-255 ~]$ curl --header "X-Vault-Token: $(cat vault-token-via-agent)" http://3.101.73.161:8200/v1/secret/myapp/config | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   219  100   219    0     0   5093      0 --:--:-- --:--:-- --:--:--  5093
{
  "request_id": "2d46af28-0858-4353-ee49-b5a732ab8747",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 30,
  "data": {
    "password": "suP3rsec(et!",
    "ttl": "30s",
    "username": "appuser"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

Note: if you would like extra security where this token is not displayed as a file on the location, we can use the vault wrap/unwrap function to consume the hashed token instead.
To use the hash value, change the sink file config block in vault-agent.hcl as followed 
```
    sink "file" {
        wrap_ttl = "5m"
        config = {
            path = "/home/ubuntu/vault-token-via-agent"
        }
```
Instead of a token value, you now have a JSON object containing a wrapping token as well as some additional metadata. In order to get to the true token, you need to first perform an ```unwrap``` operation.
Now in this case, actual token is never hardcoded or existed on the file systems 
```
[ec2-user@ip-172-31-17-255 ~]$ curl --header "X-Vault-Token: $(vault unwrap -address="http://3.101.73.161:8200" -field=token $(jq -r '.token' /home/ec2-user/vault-token-via-agent-wrapped))" http://3.101.73.161:8200/v1/secret/myapp/config | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   219  100   219    0     0   5214      0 --:--:-- --:--:-- --:--:--  5214
{
  "request_id": "6f0c20ab-9b0a-f33e-411f-18ef28d2b749",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 30,
  "data": {
    "password": "suP3rsec(et!",
    "ttl": "30s",
    "username": "appuser"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

## Example of using EC2 method AWS auth 
Now, consider the situation where you could only interact with Ec2 instances and could not rely on the IAM roles to help authenticate to Vault. In this case, you would need to rely on the ec2 metadata which can be signed by AWS authorities 

The signature used to authenticate to Vault is a PKCS7 certificate that is part of the AWS Instance Identity Document. This certificate can be fetched from the EC2 metadata API with $(curl -s http://169.254.169.254/latest/dynamic/instance-identity/pkcs7 | tr -d '\n') and will then be part of the body of data sent with the login request.

## AWS ec2 auth configs [demo running on AWS]
On the same vault server we enabled IAM aws auth, let's create create another role in aws to authenticate using ec2 method  
```
vault write auth/aws/role/gitlab-role-ec2 auth_type=ec2 policies=myapp max_ttl=500h bound_ec2_instance_id=<instance_id>
```
We are giving the ec2 role the same permission as our IAM role to read into myapp secret engine. Please note that the bound_instance id attribute is the filed that vault server looking for when authenticating vault requests. Alternatively you could also use other bounc variables such as account names or AMIs 

Now on the client side, create the following agent file 
```
[ec2-user@ip-172-31-17-255 ~]$ cat ec2-vault-agent.hcl
exit_after_auth = true
pid_file = "./pidfile"

auto_auth {
   method "aws" {
       mount_path = "auth/aws"
       config = {
           type = "ec2"
           role = "gitlab-role-ec2"
       }
   }

   sink "file" {
       config = {
           path = "/home/ec2-user/vault-token-ec2"
       }
   }
}

vault {
   address = "http://3.101.73.161:8200"
}
```

After running the vault agent, it will generate a token file similar to the previous example 
```
[ec2-user@ip-172-31-17-255 ~]$ vault agent -config=ec2-vault-agent.hcl  -log-level=debug
==> Vault server started! Log data will stream in below:

==> Vault agent configuration:

                     Cgo: disabled
               Log Level: debug
                 Version: Vault v1.4.0

2020-04-27T14:11:23.029Z [INFO]  sink.file: creating file sink
2020-04-27T14:11:23.029Z [INFO]  sink.file: file sink configured: path=/home/ec2-user/vault-token-ec2 mode=-rw-r-----
2020-04-27T14:11:23.029Z [INFO]  template.server: starting template server
2020-04-27T14:11:23.029Z [INFO]  template.server: no templates found
2020-04-27T14:11:23.029Z [INFO]  template.server: template server stopped
2020-04-27T14:11:23.029Z [INFO]  auth.handler: starting auth handler
2020-04-27T14:11:23.029Z [INFO]  auth.handler: authenticating
2020-04-27T14:11:23.030Z [INFO]  sink.server: starting sink server
2020-04-27T14:11:23.233Z [INFO]  auth.handler: authentication successful, sending token to sinks
2020-04-27T14:11:23.233Z [INFO]  auth.handler: starting renewal process
2020-04-27T14:11:23.234Z [INFO]  sink.file: token written: path=/home/ec2-user/vault-token-ec2
2020-04-27T14:11:23.234Z [INFO]  sink.server: sink server stopped
2020-04-27T14:11:23.234Z [INFO]  sinks finished, exiting
```

Finally the token can be used to login to vault server or used for vault requests
```
[ec2-user@ip-172-31-17-255 ~]$ curl --header "X-Vault-Token: $(cat vault-token-ec2)" http://3.101.73.161:8200/v1/secret/myapp/config | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   219  100   219    0     0   5093      0 --:--:-- --:--:-- --:--:--  5093
{
  "request_id": "c65220dd-2404-38cd-8c2f-229e7533e1cf",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 30,
  "data": {
    "password": "suP3rsec(et!",
    "ttl": "30s",
    "username": "appuser"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

If you try to reauthenticate with vault with the same method, it will fail as vault has a TOFU model. Using vault agent aut-auth with ec2 is not recommended in this case. 

Note that since the ec2 auth is relying on the pkcs7 signature, any user logged in to the server can sign the signature and use that info to login to vault. 

First delete the whitelist client id. Not doing so will make all subsequent vault login fail due to vault's Trust On First Use (TOFU) model used in the ec2 method

```
vault list auth/aws/identity-whitelist
vault delete auth/aws/identity-whitelist/<instance_id>
```

Now impose the pkcs7 signature
```
pkcs7=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/pkcs7 | tr -d '\n'

data=$(cat <<EOF
{
  "role": "gitlab-role-ec2",
  "pkcs7": "$pkcs7"
}
EOF
)
```
login with the data above 
```
curl --request POST --data "$data" "http://3.101.73.161:8200/v1/auth/aws/login"
{"request_id":"a35cce4a-cd1c-e57d-59d7-6b8b6db8a129","lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"warnings":["TTL of \"768h\" exceeded the effective max_ttl of \"500h\"; TTL value is capped accordingly"],"auth":{"client_token":"s.dBB0UpR1tlDJFo9mYMw9RUu9","accessor":"MFEPIkWJ8Fr8g3k14bK7L8rU","policies":["default","myapp"],"token_policies":["default","myapp"],"metadata":{"account_id":"794824571486","ami_id":"ami-0d6621c01e8c2de2c","instance_id":"i-0d62dd456abb15b60","nonce":"56a1749e-e916-f55b-37ee-3c4e597149dc","region":"us-west-2","role":"gitlab-role-ec2","role_tag_max_ttl":"0s"},"lease_duration":1800000,"renewable":true,"entity_id":"0e0a7d83-4604-3678-83f9-c7ace66b30e8","token_type":"service","orphan":true}}
```
Note that the request response contains the token which can be use for subsequent vault requests



