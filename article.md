# Vanilla Kubernetes User Authentication and Authorization in Depth
## Introduction
When you're managing vanilla K8s clusters, you need to solve some problems like Ingress Service, Load Balancing, Distributed Storage and User Management, in this article we will focus on those topics later.

User [authentication & authorization](https://auth0.com/docs/authorization/authentication-and-authorization), in simple terms, consists on verifying who a user is and verifying what they have access to, we will be using [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) for authorization in our clusters.

Kubernetes can use client-certificates, bearer tokens, a proxy or HTTP basic auth, all of these methods will be validated by the API server, the attributes of the API server uses for authentication are the following:
- Username: This is a string that identifies the user, should be unique among all of them, (e.g. admin@example.com, my-user-id, x24diausu=,  etc.)
- UID: Serves the same purpose as the Username but this attempts to be more consistent than the later, if possible you should be putting the same value on both of them
- Groups: A set of strings, this indicates a membership in logical manner to a collection of users in K8s, common usage of this is to prefix the groups, for example `system:masters` or `oidc:devs`
- Extra fields: A map of strings that contains extra information that could be used by plugins, connectors, etc.

The kubernetes docs recommend using at least two methods:
- Service account tokens for service accounts attached to pods
- At least another method for user authentication. Luckily, we will cover 3 methods.

Enough blahbery, let's cut to the chase.

## Resources
We will be using the [repo](https://github.com/JorgeReus/k8s-user-auth), so, clone it!


## Certificate Signing Request
This method allows a client to ask for and X.509 certificate to be issued by the CA and delivered to the user, you can check the code in the **csr** dir in the repo 
### Manual process
For a test environment spin up minikube instance with `minikube start`, this was tested with `minikube version: v1.13.0`
1. Create your private key
`openssl genrsa -out myUsername.key 2048`
2. Create the CSR file
`openssl req -new -key myUsername.key -out myUsername.csr -subj "O=admin/CN=myUsername"`
3. Create a certificate request using kubectl
```
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  # This has to match the id that you will use
  name: myUsername
spec:
  groups:
  # This means we want to add this csr to all of the authenticated users
  - system:authenticated
  request: $(cat myUsername.csr | base64 | tr -d "\n")
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
EOF
```
3. As an admin, approve the request with `kubectl certificate approve MyUsername`.
4. Get the certificate with `kubectl get csr/MyUsername -o jsonpath="{.status.certificate}" | base64 -d > myUsername.crt`.
5. Create a clusterrole binding for the admin group.
```
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: admin-binding
subjects:
- kind: Group
  # This value is the one that k8s uses to define group membership
  # Must be the same in the openssl subject
  name: admin
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```
6. Add the new credentials to the kubeconfig with `kubectl config set-credentials myUsername --client-key=myUsername.key --client-certificate=myUsername.crt --embed-certs=true`.
7. Add the context with `kubectl config set-context myContext--cluster=minikube --user=myUsername`.
8. Use the context with `kubectl config use-context myContext`.  
You should have admin access to your cluster.
### Using go k8s client
1. Create the rsa private key
```
func getPrivateKeyPEMBytes(key *rsa.PrivateKey) *[]byte {
	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	var b bytes.Buffer
	err := pem.Encode(&b, privateKey)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		panic(err)
	}
	var rsaBytes = b.Bytes()
	return &rsaBytes
}
```
2. Create the CSR
```
type RSAData struct {
	Csr *[]byte
	Key *[]byte
}

func getCsrBytes(commonName string, organization string) *RSAData {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	keyBytes := getPrivateKeyPEMBytes(key)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		panic(err)
	}

	subj := pkix.Name{
		CommonName:   commonName,
		Organization: []string{organization},
	}

	templateCsr := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	var b bytes.Buffer
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &templateCsr, key)
	err = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	sliceAddr := b.Bytes()
	var result = RSAData{
		Csr: &sliceAddr,
		Key: keyBytes,
	}
	return &result
}
```
3. Create the CSR in the cluster
```
var csr = k8sCertsV1.CertificateSigningRequest{}
csr.Name = user
csr.Spec.Groups = []string{"system:authenticated"}
csr.Spec.Usages = []k8sCertsV1.KeyUsage{"client auth"}
csr.Spec.Request = *rsaData.Csr
csr.Spec.SignerName = "kubernetes.io/kube-apiserver-client"
_, err := k8sClient.CertificatesV1().CertificateSigningRequests().Create(ctx, &csr, k8sMetaV1.CreateOptions{})
check(err)
```
4. Approve the CSR
```
func approveCsr(ctx context.Context, k8sClient *kubernetes.Clientset, csr k8sCertsV1.CertificateSigningRequest) {
	csr.Status.Conditions = append(csr.Status.Conditions, k8sCertsV1.CertificateSigningRequestCondition{
		Type:           k8sCertsV1.CertificateApproved,
		Reason:         "Approved by CICD",
		Message:        "This CSR was approved by CICD",
		Status:         "True",
		LastUpdateTime: k8sMetaV1.Now(),
	})
	_, err := k8sClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, &csr, k8sMetaV1.UpdateOptions{})
	check(err)
}
```
5. Create the kubeconfig
```
func createKubeConfig(data KubeConfigData) {
	t, err := template.New("kubeconfig").Parse(kubeConfigTemplate)
	check(err)
	resultFile := fmt.Sprintf("/tmp/%v.kubeconfig", data.UserEmail)
	f, err := os.Create(resultFile)
	check(err)
	w := bufio.NewWriter(f)
	err = t.Execute(w, data)
	check(err)
	err = w.Flush()
	check(err)
}
```
This is the template:
```
apiVersion: v1
kind: Config
clusters:
- cluster:
    {{ .CAKey }}: {{ .ClusterCA }}
    server: {{ .ClusterEndpoint }}
  name: {{ .ClusterName }}
users:
- name: {{ .UserEmail }}
  user:
    client-certificate-data: {{ .ClientCertificateData }}
    client-key-data: {{ .ClientKeyData }}
contexts:
- context:
    cluster: {{ .ClusterName }}
    user: {{ .UserEmail }}
  name: {{ .User }}-{{ .ClusterName }}
current-context: {{ .User }}-{{ .ClusterName }}
```
## Webhook token
For demo purposes we use `k3d versionk3d version v3.0.1` and `k3s version v1.18.6-k3s1 (default)`  in this example. You can check the code in the **webhook** dir
This method allows authentication by verifying bearer tokens.  For this you need a service that handles a token that is provided by kubernetes once a user sends a request to the API server. We will specify the process bellow:


1. Create a file with the following contents and save it as `webhook-config.yaml`
```
apiVersion: v1
kind: Config
clusters:
  # The name of the service
  - name: myServiceName
    cluster:
      server: http://localhost:3000/authenticate
users:
  # The api configuration for the webhook
  - name: apiUsername
    user:
      token: secret
contexts:
  - name: webhook
    context:
      cluster: myServiceName
      user: apiUsername
current-context: webhook
```
2. For this part we need an aplication that handles the bearer token in some way and tells the api server that the user is authenticated. The api server expects that your application has an endpoint at `/authenticate` with the POST method, following we have an example for this in GO
```

type AuthResponseStatus struct {
	Authenticated bool                    `json:"authenticated"`
	User          *AuthResponseStatusUser `json:"user,omitempty"`
}

type AuthResponseStatusUser struct {
	Username string   `json:"username"`
	Uid      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

type AuthResponse struct {
	ApiVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Status     AuthResponseStatus `json:"status"`
}

func authenticate(w http.ResponseWriter, r *http.Request) {
  # Accepts json
	w.Header().Set("Content-Type", "application/json")

  # Read the body as text
	reqBody, _ := ioutil.ReadAll(r.Body)
	var authRequest AuthRequest

  # Unmarshal the text into json
	err := json.Unmarshal(reqBody, &authRequest)

	if err != nil {
		json.NewEncoder(w).Encode(unauthorizedRespose)
		log.Printf("User : %v Cause: %v, ", reqBody, err)
		return
	}
	// Query github data username and groups of an org
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: authRequest.Spec.Token},
	)

  // Create and oauth2 client to connect to github
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)
	req, _, err := client.Users.Get(context.Background(), "")

	if err != nil {
		json.NewEncoder(w).Encode(unauthorizedRespose)
		log.Printf("Cause: %v, ", err)
		return
	}

	user := *req.Login
  
  // Query the membership of the user to an specified organization
	membership, _, err := client.Organizations.GetOrgMembership(context.Background(), "", ",MY_GITHUB_ORGANIZATION>")

	if err != nil {
		json.NewEncoder(w).Encode(unauthorizedRespose)
		log.Printf("User : %v Cause: %v, ", user, err)
		return
	}
  
  // This is what kubernetes expects. See https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication
	authRespose := AuthResponse{
		ApiVersion: authRequest.ApiVersion,
		Kind:       authRequest.Kind,
		Status: AuthResponseStatus{
			Authenticated: true,
			User: &AuthResponseStatusUser{
				Username: user,
				Uid:      user,
				Groups:   []string{*membership.Role},
			},
		},
	}
	json.NewEncoder(w).Encode(authRespose)
	log.Printf("User %v authenticated sucessfully", user)
}
```
3. Build the image with docker (e.g. `docker build -t webhook-app:v1 -f app/Dockerfile ./app`)
4. Create a k3d cluster:
```
# Notice that authentication-token-webhook-config-file flag points to the file create previously
k3d cluster create webhook \
-v $PWD/config:/etc/webhook \
--k3s-server-arg "--kube-apiserver-arg=authentication-token-webhook-config-file=/etc/webhook/webhook-config.yaml"
```
5. Import the webhook service image into k3d: `k3d image import webhook-app:v1 -c webhook`
6. Create a daemonset with this app
```
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    k8s-app: webhook-app
  name: webhook-app
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: webhook-app
  template:
    metadata:
      labels:
        k8s-app: webhook-app
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      tolerations:
      # Allow the pods to be runned in master nodes (when the api server lives)
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - image: webhook-app:v1
        name: webhook-app
        ports:
        - containerPort: 3000
          hostPort: 3000
          protocol: TCP
      # This is for accessing it as localhost
      hostNetwork: true
      restartPolicy: Always
EOF
```
7. Create a github token with profile access(This is and example to showcase the felixibility, you can implement another auth method, the important thing it's that you return the json to the API server specifying that the user is authenticated or not)
8. Add the new credentials to the kubeconfig with `kubectl config set-credentials webhook --token=YOUR_GITHUB_TOKEN`.
7. Add the context with `kubectl config set-context myWHContext --cluster=webhook --user=webhook`.
9. Use the context with `kubectl config use-context myWHContext`.  
So now kubernetes uses your github token to verify that you belong to an organization.

## OIDC (OpenId Connect)
For demo purposes, we use `k3d versionk3d version v3.0.1` and `k3s version v1.18.6-k3s1 (default)` in this example. You can check the code in the **idc** dir.

K8s allows an OIDC provider as an Identity provider; This is an excellent sequence diagram from the official docs.

![OIDC Sequence Diagram](https://d33wubrfki0l68.cloudfront.net/d65bee40cabcf886c89d1015334555540d38f12e/c6a46/images/docs/admin/k8s_oidc_login.svg)

As you can see, the magic happens when you, as an user, login to the IDP to get and `id token` and then the token is used as a bearer token with the kubectl commands.

In this example, we will be spinning up our own [Dex](https://github.com/dexidp/dex) instance that has access to Gitlab as an upstream provider.

### Why Dex?
Because Dex can have multiple upstream providers and showcases a more complex example for OIDC authentication


### Terraform code
```
# A keypair for ssh provisioning, this uses your default public key
resource "aws_key_pair" "ssh-key" {
  key_name_prefix = "dex"
  public_key      = file("~/.ssh/id_rsa.pub")
}

locals {
  dex-config = {
    record-name      = "dex"
    domain-name      = "dex.mydomain.com"
    dex-home-path    = "/home/ubuntu/dex"
    gitlab-client-id = var.gitlab-client-id
    gitlab-secret    = var.gitlab-secret
    gitlab-groups    = var.gitlab-groups
  }
}

# An static ip
resource "aws_eip_association" "eip_assoc" {
  instance_id   = aws_instance.dex.id
  allocation_id = data.aws_eip.selected.id
}

# An EC2 instance containing dex
resource "aws_instance" "dex" {
  ami                    = data.aws_ami.ubuntu.id
  vpc_security_group_ids = [aws_security_group.allow_dex.id]
  key_name               = aws_key_pair.ssh-key.key_name
  instance_type          = "t3.micro"

  provisioner "remote-exec" {
    inline = ["mkdir -p /home/ubuntu/dex"]
    connection {
      type = "ssh"
      user = "ubuntu"
      host = self.public_ip
    }
  }

  # Dex config
  provisioner "file" {
    content     = templatefile("./templates/dex-server-config.yml", local.dex-config)
    destination = "${local.dex-config.dex-home-path}/server-config.yaml"
    connection {
      type = "ssh"
      user = "ubuntu"
      host = self.public_ip
    }
  }

  # Ssl certificates for dex
  provisioner "file" {
    source      = "certs"
    destination = "${local.dex-config.dex-home-path}/certs"
    connection {
      type = "ssh"
      user = "ubuntu"
      host = self.public_ip
    }
  }
}


# Privision the dex instance sincrououlsy
resource "null_resource" "provisioner" {
  depends_on = [aws_instance.dex]
  provisioner "remote-exec" {
    script = "${path.root}/init.sh"
    connection {
      type = "ssh"
      user = "ubuntu"
      host = data.aws_eip.selected.public_ip
    }
  }
}
```
### Provisioner code
```
#!/bin/bash

# Dependecies
export GOPATH=/home/ubuntu/go
sudo apt update
sudo apt update
sudo apt install -y golang make
go get github.com/dexidp/dex
cd $GOPATH/src/github.com/dexidp/dex
make
mv web /home/ubuntu/dex/
sudo mv bin/dex /usr/bin/

# Systemd Service
sudo tee /etc/systemd/system/dex.service > /dev/null <<'EOF'
[Unit]
Description=Dex service k8s OICD authentication
[Service]
ExecStart=/usr/bin/dex serve /home/ubuntu/dex/server-config.yaml
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl start dex
```

As you can see the script is very simple it builds dex and creates a systemd service for dex.

### Dex config
```
# Use sqlite as the backend
issuer: https://${domain-name}/dex
storage:
  type: sqlite3
  config:
    file: ${dex-home-path}/dex.db

# web & TLS config
web:
  https: 0.0.0.0:443
  tlsCert: ${dex-home-path}/certs/cert.pem
  tlsKey: ${dex-home-path}/certs/key.pem

# html, css and js files
frontend:
  dir: ${dex-home-path}/web

# Configuration for telemetry
telemetry:
  http: 0.0.0.0:5558
  
expiry:
  signingKeys: "10m"
  idTokens: "30m"

logger:
  level: "debug"
  format: "json" 

oauth2:
  responseTypes: ["code", "token", "id_token"]
  skipApprovalScreen: true


# Use gitlab as an example for oidc in here we need to use the group's id's for authentication
connectors:
  - type: gitlab
    id: gitlab
    name: GitLab
    config:
      baseURL: https://gitlab.com
      clientID: ${gitlab-client-id}
      clientSecret: ${gitlab-secret}
      redirectURI: https://${domain-name}/dex/callback
      useLoginAsID: false
      groups:
  %{ for group in gitlab-groups ~}
    - ${group} 
  %{ endfor ~}

enablePasswordDB: True


# Secret id and clientID for the kubelogin client
- id: kube-login-client
  name: Kube Login Client
  secret: qgODwpzNk7NmyxrXINFAHf1R
  redirectURIs:
    - http://localhost:8000
    - http://localhost:18000

```

This is a basic configuration for dex, it supports gitlab groups and you can map them into groups in k8s

### Run the terraform
You just need to do a `terraform apply --auto-approve` and the you can test if it works using **terratest**, just run `go test` in the tests folder, if the tests don't fail, dex is up and running!

### K8s Config
Once you have dex (you can use a different oidc provider), you need to update the api server flags to support it:
- oidc-issuer-url:  This is the url of the dex issuer
- oidc-username-claim: This is the claim that k8s will use to identify an user
- oidc-client-id: This is the identifier of the client application, this identifies the application as a whole, in this case, the k8s cluster
- oidc-ca-file: The certificate authority pem file of dex, typically CA.pem
- oidc-groups-claim: The claims that k8s will use to define group membership, this is used in the rolebindings
- oidc-groups-prefix: An optional prefix to not collide with predefined groups in k8s like `system:`
- oidc-username-prefix: Server the same purpose as the previous one, but for users.  

An example in k3d would be
```
k3d cluster create oidc \
-v /tmp/certs:/etc/self-ssl/ \
--k3s-server-arg "--kube-apiserver-arg=oidc-issuer-url=<your-dex-url>" \
--k3s-server-arg "--kube-apiserver-arg=oidc-username-claim=email" \
--k3s-server-arg "--kube-apiserver-arg=oidc-client-id=<your-dex-client-id>" \
--k3s-server-arg "--kube-apiserver-arg=oidc-ca-file=/etc/self-ssl/ca.pem" \
--k3s-server-arg "--kube-apiserver-arg=oidc-groups-claim=groups" \
--k3s-server-arg "--kube-apiserver-arg=oidc-groups-prefix=oidc:" \
--k3s-server-arg "--kube-apiserver-arg=oidc-username-prefix=oidc:"

```
Notice the volume where the dex certs are

### Kubectl config
1. Download install kube-login with `kubectl krew install odic-login`
2. Run :
```
kubectl config set-credentials test-oidc --exec-api-version=client.authentication.k8s.io/v1beta1 \
--exec-api-version=client.authentication.k8s.io/v1beta1 \
--exec-command=kubectl \
--exec-arg=oidc-login \
--exec-arg=get-token \
--exec-arg=--oidc-issuer-url=<your-dex-url> \
--exec-arg=--oidc-client-id=<your-dex-client-id> \
--exec-arg=--oidc-client-secret=<your-client-secret> \
--exec-arg=--insecure-skip-tls-verify \
--exec-arg=--oidc-extra-scope="groups email" \
--exec-arg=--v=0
```
3. Test it with `kubectl get secret --user=test-oidc`

## Conclusion
As we can se, k8s has a lot of flexibility regarding user authentication and authorization. 
You can implement anything as you want as long as k8s is able to reach it.
Be sure to test your solution, using tools like terratest, ansible tests and/or unittests!

As a summary,
1. Use Certificates Requests(CRD) if you do not have any IDP included so you don't have to worry about rotation.
2. If you have User OIDC and IDP which supports it, that means you have a lot of users using several IDP's and you want to enforce **bephemeral tokens**.
3. Use WAF token authentication if you have your own authentication and authorization methods or you want to have full control over them token lifecycle.

As an extra tip, you can use OIDC in managed environments, like EKS, GKE, etc. using  [kube-oidc-proxy](https://github.com/jetstack/kube-oidc-proxy).

### Keep Rocking 


