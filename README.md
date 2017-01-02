# OpenUnison Kubernetes Quickstart with Active Directory

This quickstart will provide an identity provider and optionally provide self service user provisioning for RBAC roles.  This quickstart provides:

1. Authentication using LDAP and Active Directory via a "portal"
2. SSO integration with Kubernetes via the OpenID Connect identity provider integrated into OpenUnison
3. Generation of session specific client_secret to avoid sharing client_secrets for use with kubectl
4. SSO into the Kubernetes Dashboard

For more details about how Kubernetes and OpenID Connect work to provide authentication see https://www.tremolosecurity.com/wiki/#!kubernetes.md.

Do you want to use an OpenID Connect identity provider like Google, AzureAD or others for authentication?  See our OpenID Connect quick start - https://github.com/TremoloSecurity/openunison-qs-kubernetes.

## Parts List

Before starting you'll need to determine:

1.  Active Directory server information - We'll cover this in more detail in the next section but you'll need a read-only service account for your Active Directory, server names and a certificate if using LDAPS
2.  How to deploy - OpenUnison is a J2EE application that will run on almost any Java Servlet container.  The OpenUnison documentation describes how to get started with Tomcat 8 (https://www.tremolosecurity.com/docs/tremolosecurity-docs/1.0.8/openunison/openunison-manual.html#_deploying_with_apache_maven) but you can also try using our source2image builder which will deploy OpenUnison directly into a hardened Tomcat 8 server on a docker container for you (https://hub.docker.com/r/tremolosecurity/openunisons2idocker/).  The examples here will assume you are using the Source2Image builder.
3.  Database - OpenUnison needs a relational database for audit and session data.  Any of the databases listed in the support matrix will work (https://www.tremolosecurity.com/wiki/#!UnisonMatrix108.md).  This quickstart assumes mariadb/mysql but can be easily changed.
4.  Email Server (Optional) - If using this quickstart for user provisioning, an SMTP server will be needed to send email
5.  Server / Service - Depending on your decision for #1 above, you'll need to deploy somewhere.  The output of the source2image process is a docker container that can be run on Kubernetes or any other server running Docker.

## Preparation Work

Before getting started we'll need to do a few things:

1.  Download the source2image binaries for your platform (https://github.com/openshift/source-to-image/releases) (note, you'll need access to a docker service for s2i to work)
2.  Create your database and get administrative credentials.  Don't worry about specific table creation, OpenUnison will take care of that on your first startup
3.  Create a keystore with keys and certificates
4.  Collect the information for each environment variable
5.  Fork this repository - You probably will want to make changes once you have gotten the process down (ie logos, links, etc)

### Environment Variables

This project is designed to be safe for managing in source control (ie git) and for resulting docker images to be safe for public repositories (ie dockerhub) so there is NO confidential or environment specific information stored in the configuration.  Everything that is environment specific or private is stored in environment variables that will be passed into docker:

| Variable | Description | Example |
| -------- | ----------- | ------- |
| OU_HOST | The host name users will use to access the site | oidcidp.tremolo.lan |
| OU_HIBERNATE_DIALECT | The hibernate dialect for your database (https://docs.jboss.org/hibernate/orm/4.2/javadocs/org/hibernate/dialect/package-summary.html) | org.hibernate.dialect.MySQL5Dialect |
| OU_JDBC_DRIVER | JDBC driver for your database, make sure that the driver is a dependency in your POM file | com.mysql.jdbc.Driver |
| OU_JDBC_URL | The connection URL for the OpenUnison audit database | jdbc:mysql://mariadb:3306/unison?useSSL=true |
| OU_JDBC_USER | User used to connect to the audit database | root |
| OU_JDBC_PASSWORD | Password used to connect to the audit database | ***** |
| OU_JDBC_VALIDATION | A query for validating connections on checkout | SELECT 1 |
| SMTP_HOST | Host for the SMTP server | smtp.gmail.com |
| SMTP_PORT | Port for the SMTP Server | 587 |
| SMTP_FROM | The "From" subject of emails to approvers | You have approvals waiting |
| SMTP_USER | User name for accessing the email server | user@domain.com |
| SMTP_PASSWORD | Password for the user for the email server | ***** |
| SMTP_TLS | true/false if the SMTP server uses TLS | true |
| JAVA_OPTS | List of Java system properties, MUST include unisonKeystorePassword | -Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom -DunisonKeystorePassword=start123 |
| K8S_DASHBOARD_URL | The URL used for accessing the dashboard, usually this is the API server's secure port | https://kubemaster.tremolo.lan:6443 |
| K8S_URL | The URL for the API server's secure port | https://kubemaster.tremolo.lan:8443 |
| K8S_CLIENT_SECRET | An OIDC client secret that can be used by consumers of the openid connect trust between Kubernetes and OpenUnison, this should be a long random string but is not used for any configuration options in Kubernetes | XXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXX |
| AD_HOST | The IP or host name for Active Directory | ad.mydomain.com |
| AD_PORT | The port to use to connect to, usually 389 for plain text and 636 for encrypted traffic | 636 |
| AD_BASE_DN | Where in your domain to start searches from | CN=Users,DC=domain,DC=com |
| AD_BIND_DN | The Distinguished Name of your service account | CN=openunison,CN=Users,DC=domain,DC=COM |
| AD_BIND_PASSWORD | The password for your read-only service account |
| AD_CON_TYPE | ldap or ldaps depending on if using an ecrypted connection | ldaps |

### Building a Keystore

OpenUnison encrypts or signs everything that leaves it such as JWTs, workflow requests, session cookies, etc.  To do this, we need to create a Java keystore that can be used to store these keys as well as the certificates used for TLS by Tomcat.  When working with Kubernetes something to take note of is Go does NOT work with self signed certificates no matter how many ways you trust it.  In order to use a self signed certificate you have to create a self signed certificate authority and THEN create a certificate signed by that CA.  This can be done using Java's keytool but I like using OpenSSL better.  To make this easier, the makecerts.sh script in this repository (adapted from a similar script from CoreOS) will do this for you.  Just make sure to change the subject in the script first

#### Build the TLS certificate

```
$ sh makecerts.sh
$ cd ssl
$ openssl pkcs12 -export -chain -inkey key.pem -in cert.pem -CAfile ca.pem -out openunison.p12
Enter Export Password:
Verifying - Enter Export Password:
$ keytool -importkeystore -srckeystore ./openunison.p12 -srcstoretype PKCS12 -alias 1 -destKeystore ./unisonKeyStore.jks -deststoretype JCEKS -destalias unison-tls
Enter destination keystore password:  
Re-enter new password:
Enter source keystore password:
```

#### Create Static Keys

```
$ keytool -genseckey -alias session-unison -keyalg AES -keysize 256 -storetype JCEKS -keystore ./unisonKeyStore.jks
$ keytool -genseckey -alias lastmile-k8s -keyalg AES -keysize 256 -storetype JCEKS -keystore ./unisonKeyStore.jks
```

#### Trust Kubernetes' CA

Depending on how you deploy Kubernetes you will need to trust Kubernetes' CA.  For kubeadm deployments, the CA file is ```/etc/kubernetes/pki/ca.pem```.  You'll need to import that file into your keystore.  Assuming it's copied to the file k8s-ca.pem in the ssl directory:

```
$ keytool -import -alias trusted-k8sca -trustcacerts -rfc -file ./k8s-ca.pem -storetype JCEKS -keystore ./unisonKeyStore.jks
Enter keystore password:  
Owner: CN=kubernetes
Issuer: CN=kubernetes
Serial number: 0
Valid from: Wed Dec 28 21:05:49 EST 2016 until: Sat Dec 26 21:05:49 EST 2026
Certificate fingerprints:
	 MD5:  16:77:AF:F6:F5:6A:98:99:72:0C:6A:9A:BD:EF:AA:1D
	 SHA1: B7:FA:C8:0E:14:66:43:BE:86:C1:05:DA:E8:EC:EE:7E:6F:8C:10:09
	 SHA256: 2A:C9:AE:04:88:CD:9F:8C:21:B9:D8:15:C7:AD:0E:D0:FA:4B:20:90:E2:BE:D0:E2:D2:E4:87:89:C5:E0:C6:1F
	 Signature algorithm name: SHA256withRSA
	 Version: 3

Extensions:

#1: ObjectId: 2.5.29.19 Criticality=true
BasicConstraints:[
  CA:true
  PathLen:2147483647
]

#2: ObjectId: 2.5.29.15 Criticality=true
KeyUsage [
  DigitalSignature
  Key_Encipherment
  Key_CertSign
]

Trust this certificate? [no]:  yes
Certificate was added to keystore
```

#### Trust Active Directory's CA

If using LDAPS (and please, use LDAPS) you'll need to trust your domain's CA.  The easiest way to get your domain's CA is using OpenSSL's s_client utility to get the certificate:

```
$ openssl s_client -showcerts -connect '192.168.2.75:636'
CONNECTED(00000003)
depth=0 CN = ADFS.ENT2K12.DOMAIN.COM
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 CN = ADFS.ENT2K12.DOMAIN.COM
verify error:num=21:unable to verify the first certificate
verify return:1
---
Certificate chain
 0 s:/CN=ADFS.ENT2K12.DOMAIN.COM
   i:/CN=ADFS.ENT2K12.DOMAIN.COM
-----BEGIN CERTIFICATE-----
MIIDNDCCAhygAwIBAgIQbRNj6RKqtqVPvW65qZxXXjANBgkqhkiG9w0BAQUFADAi
MSAwHgYDVQQDDBdBREZTLkVOVDJLMTIuRE9NQUlOLkNPTTAeFw0xNDAzMjgwMTA1
MzNaFw0yNDAzMjUwMTA1MzNaMCIxIDAeBgNVBAMMF0FERlMuRU5UMksxMi5ET01B
SU4uQ09NMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2s9JkeNAHOkQ
1QYJgjefUwcaogEMcaW/koA+bu9xbr4rHy/2gN/kc8OkoPuwJ/nNlOIO+s+MbnXS
L9mUTC4OK7trkEjiKXB+D+VSYy6imXh6zpBtNbeZyx+rdBnaOv3ByZRnnEB8LmhM
vHA+4f/t9fx/2vt6wPx//VgIq9yuYYUQRLm1WjyUBFrZeGoSpPm0Kewm+B0bhmMb
dyC+3fhaKC+Uk1NPodE2973jLBZJelZxsZY40Ww8zYQwdGYIbXqoTc+1a/x4f1En
m4ANqggHtw+Nq8zhss3yTtY+UYKDRBILdLVZQhHJExe0kAeisgMxI/bBwO1HbrFV
+zSnk+nvgQIDAQABo2YwZDAzBgNVHSUELDAqBggrBgEFBQcDAQYIKwYBBQUHAwIG
CisGAQQBgjcUAgIGCCsGAQUFBwMDMB0GA1UdDgQWBBTyJUfY66zYbm9i0xeYHuFI
4MN7uDAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQEFBQADggEBAM5kz9OKNSuX
8w4NOgnfIFdazd0nPlIUbvDVfQoNy9Q0S1SFUVMekIPNiVhfGzya9IwRtGb1VaBQ
AQ2ORIzHr8A2r5UNLx3mFjpJmeOxQwlV0X+g8s+253KVFxOpRE6yyagn/BxxptTL
a1Z4qeQJLD42ld1qGlRwFtVRmVFZzVXVrpu7NuFd3vlnnO/qKWXU+uMsfXtsl13n
ec1kw1Ewq2jnK8WImKTQ7/9WbaIY0gx8mowCJSOsRq0TE7zK/N55drN1wXJVxWe5
4N32eCqotXy9j9lzdkNa7awb9q38nWVxP+va5jqNIDlljB6tExy5n3s7t6KK6g5j
TZgVqrZ3+ms=
-----END CERTIFICATE-----
---
Server certificate
subject=/CN=ADFS.ENT2K12.DOMAIN.COM
issuer=/CN=ADFS.ENT2K12.DOMAIN.COM
---
Acceptable client certificate CA names
/DC=com/DC=domain/DC=ent2k12/CN=ent2k12-ADFS-CA
/CN=ADFS.ENT2K12.DOMAIN.COM
/CN=adfs.ent2k12.domain.com
/C=US/ST=Virginia/L=Arlington/O=Tremolo Security Inc./OU=ADFS/CN=idp.ent2k12.domain.com
/CN=idp.ent2k12.domain.com
/C=SE/O=AddTrust AB/OU=AddTrust External TTP Network/CN=AddTrust External CA Root
/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5
/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
/C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority
/C=US/O=GTE Corporation/OU=GTE CyberTrust Solutions, Inc./CN=GTE CyberTrust Global Root
/C=IE/O=Baltimore/OU=CyberTrust/CN=Baltimore CyberTrust Root
/C=US/O=GeoTrust Inc./CN=GeoTrust Global CA
/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Root Certificate Authority 2010
/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Root Certificate Authority 2011
/OU=Copyright (c) 1997 Microsoft Corp./OU=Microsoft Corporation/CN=Microsoft Root Authority
/DC=com/DC=microsoft/CN=Microsoft Root Certificate Authority
/CN=NT AUTHORITY
Client Certificate Types: RSA sign, DSA sign, ECDSA sign
Requested Signature Algorithms: RSA+SHA256:RSA+SHA384:RSA+SHA1:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA1:DSA+SHA1
Shared Requested Signature Algorithms: RSA+SHA256:RSA+SHA384:RSA+SHA1:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA1:DSA+SHA1
---
SSL handshake has read 2733 bytes and written 678 bytes
---
New, TLSv1/SSLv3, Cipher is AES128-SHA256
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : AES128-SHA256
    Session-ID: 0536000019363502B0E0FC388E44B042371775C23AB4B4AB68B3708AC6088C1F
    Session-ID-ctx:
    Master-Key: BF0A4AEF1D3CEDF00A59692D394CE441FE81D554165D2A49B261CF74386220DD64781BAB3595351512CE8B2BBF50BF44
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1483370074
    Timeout   : 300 (sec)
    Verify return code: 21 (unable to verify the first certificate)
---
```

Put the parts between `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` (inclusively) into a file (ie `adcert.pem`) which would look like:

```
-----BEGIN CERTIFICATE-----
MIIDNDCCAhygAwIBAgIQbRNj6RKqtqVPvW65qZxXXjANBgkqhkiG9w0BAQUFADAi
MSAwHgYDVQQDDBdBREZTLkVOVDJLMTIuRE9NQUlOLkNPTTAeFw0xNDAzMjgwMTA1
MzNaFw0yNDAzMjUwMTA1MzNaMCIxIDAeBgNVBAMMF0FERlMuRU5UMksxMi5ET01B
SU4uQ09NMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2s9JkeNAHOkQ
1QYJgjefUwcaogEMcaW/koA+bu9xbr4rHy/2gN/kc8OkoPuwJ/nNlOIO+s+MbnXS
L9mUTC4OK7trkEjiKXB+D+VSYy6imXh6zpBtNbeZyx+rdBnaOv3ByZRnnEB8LmhM
vHA+4f/t9fx/2vt6wPx//VgIq9yuYYUQRLm1WjyUBFrZeGoSpPm0Kewm+B0bhmMb
dyC+3fhaKC+Uk1NPodE2973jLBZJelZxsZY40Ww8zYQwdGYIbXqoTc+1a/x4f1En
m4ANqggHtw+Nq8zhss3yTtY+UYKDRBILdLVZQhHJExe0kAeisgMxI/bBwO1HbrFV
+zSnk+nvgQIDAQABo2YwZDAzBgNVHSUELDAqBggrBgEFBQcDAQYIKwYBBQUHAwIG
CisGAQQBgjcUAgIGCCsGAQUFBwMDMB0GA1UdDgQWBBTyJUfY66zYbm9i0xeYHuFI
4MN7uDAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQEFBQADggEBAM5kz9OKNSuX
8w4NOgnfIFdazd0nPlIUbvDVfQoNy9Q0S1SFUVMekIPNiVhfGzya9IwRtGb1VaBQ
AQ2ORIzHr8A2r5UNLx3mFjpJmeOxQwlV0X+g8s+253KVFxOpRE6yyagn/BxxptTL
a1Z4qeQJLD42ld1qGlRwFtVRmVFZzVXVrpu7NuFd3vlnnO/qKWXU+uMsfXtsl13n
ec1kw1Ewq2jnK8WImKTQ7/9WbaIY0gx8mowCJSOsRq0TE7zK/N55drN1wXJVxWe5
4N32eCqotXy9j9lzdkNa7awb9q38nWVxP+va5jqNIDlljB6tExy5n3s7t6KK6g5j
TZgVqrZ3+ms=
-----END CERTIFICATE-----
```

Finally, import the certificate into our keystore:

```
keytool -import -alias trusted-activedirectory -trustcacerts -rfc -file ./adcert.pem -storetype JCEKS -keystore ./unisonKeyStore.jks
Enter keystore password:  
Owner: CN=ADFS.ENT2K12.DOMAIN.COM
Issuer: CN=ADFS.ENT2K12.DOMAIN.COM
Serial number: 6d1363e912aab6a54fbd6eb9a99c575e
Valid from: Thu Mar 27 21:05:33 EDT 2014 until: Sun Mar 24 21:05:33 EDT 2024
Certificate fingerprints:
	 MD5:  60:14:E9:20:0D:0E:04:D0:65:2C:6B:E4:03:66:DB:16
	 SHA1: 70:EC:25:1C:89:19:19:4F:3B:F1:43:36:10:B9:BB:D0:BA:DA:9D:1A
	 SHA256: 65:CD:B5:F8:2C:6E:E5:0C:B1:46:D0:39:2F:82:C4:B2:D0:92:FE:66:8A:47:17:A0:35:4F:F8:24:6C:E6:70:04
	 Signature algorithm name: SHA1withRSA
	 Version: 3

Extensions:

#1: ObjectId: 2.5.29.37 Criticality=false
ExtendedKeyUsages [
  serverAuth
  clientAuth
  1.3.6.1.4.1.311.20.2.2
  codeSigning
]

#2: ObjectId: 2.5.29.15 Criticality=true
KeyUsage [
  Key_Encipherment
]

#3: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: F2 25 47 D8 EB AC D8 6E   6F 62 D3 17 98 1E E1 48  .%G....nob.....H
0010: E0 C3 7B B8                                        ....
]
]

Trust this certificate? [no]:  yes
Certificate was added to keystore
```

## Deployment

This will be very specific to your own environment.  This part offers up how to deploy OpenUnison using the source2image builder on a standalone server running docker.

### Build The OpenUnison Image

The easiest way to build the image is against a git repository (either remote or local).  If you want to build OpenUnison's war locally first you can do that too by providing a directory with the OpenUnison war file in it.

```
$ ./s2i build https://github.com/TremoloSecurity/openunison-qs-kubernetes-activedirectory.git tremolosecurity/openunisons2idocker:1.0.8 myrepo/k8sopenunison
$ docker push myrepo/k8sopenunison
```

### Deploy The OpenUnison Image

Assuming you have docker running on your server:

1.  Create a directory called /etc/openunison
2.  Copy the ```unisonKeyStore.jks``` file to /etc/openunison
3.  Create a file for environment variables called ```docker.env``` (see below for an example)
4.  Run the image ```docker run -d --name openunison -p 8080:8080 -p 8443:8443 --env-file /etc/openunison/docker.env -v /etc/openunison:/etc/openunison:Z myrepo/k8sopenunison```

```
U_HOST=oidcidp.tremolo.lan
K8S_DASHBOARD_URL=https://kubemaster.tremolo.lan:6443
OU_JDBC_DRIVER=com.mysql.jdbc.Driver
OU_JDBC_URL=jdbc:mysql://mariadb/unison
OU_JDBC_USER=unison
OU_JDBC_PASSWORD=start123
OU_HIBERNATE_DIALECT=org.hibernate.dialect.MySQL5Dialect
OU_JDBC_VALIDATION=SELECT 1
K8S_URL=https://kubemaster.tremolo.lan:8443
K8S_CLIENT_SECRET=4d4af469-0f8f-4d91-9048-dae716721ce2
JAVA_OPTS=-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom -DunisonKeystorePassword=start123
SMTP_HOST=smtp
SMTP_PORT=25
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=donotreply@k8s-idm.com
SMTP_TLS=false
AD_HOST=192.168.2.75
AD_PORT=636
AD_BASE_DN=CN=Users,DC=ENT2K12,DC=DOMAIN,DC=COM
AD_BIND_DN=CN=openunison,CN=Users,DC=ENT2K12,DC=DOMAIN,DC=COM
AD_BIND_PASSWORD=XXXXXXX
AD_CON_TYPE=ldaps
```

Once started, you can see the logs by running ```docker logs -f openunison```

### Integrating with Kubernetes

This will vary based on your Kubernetes deployment method.  For kubeadm you'll want to add your parameters to ```/etc/kubernetes/manifests/kube-apiserver.json```.

## Use and Testing

Once integrated, you'll want to make sure that the api-server isn't generating errors because it can't connect to OpenUnison.  Also, do a quick liveness test by going to https://OU_HOST:8443/auth/idp/OidcIdP/.well-known/openid-configuration where you'll see something like:

```
{
  "issuer": "https://oidcidp.tremolo.lan:8443/auth/idp/OidcIdP",
  "authorization_endpoint": "https://oidcidp.tremolo.lan:8443/auth/idp/OidcIdP/auth",
  "token_endpoint": "https://oidcidp.tremolo.lan:8443/auth/idp/OidcIdP/token",
  "userinfo_endpoint": "https://oidcidp.tremolo.lan:8443/auth/idp/OidcIdP/userinfo",
  "revocation_endpoint": "https://oidcidp.tremolo.lan:8443/auth/idp/OidcIdP/revoke",
  "jwks_uri": "https://oidcidp.tremolo.lan:8443/auth/idp/OidcIdP/certs",
  "response_types_supported": [
    "code",
    "token",
    "id_token",
    "code token",
    "code id_token",
    "token id_token",
    "code token id_token",
    "none"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ],
  "scopes_supported": [
    "openid",
    "email",
    "profile"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_post"
  ],
  "claims_supported": [
    "sub",
    "aud",
    "iss",
    "exp",
    "sub",
    "email_verified",
    "first_name",
    "family_name",
    "email"
  ],
  "code_challenge_methods_supported": [
    "plain",
    "S256"
  ]
}
```

Then you can go straight to https://OU_HOST:8443 where you should be redirected to your identity provider for authentication and brought to a screen that shows you links for the dashboard and your tokens.  If you click on the dashboard link and see the dashboard, you know the API server is configured correctly.  Click on the token and use the id_token, refresh_token and client_secret in your kubectl configuration and kubectl should work too.
