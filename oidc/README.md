# OIDC authentication method for k8s
Tested with 
```
k3d version v3.0.1
k3s version v1.18.6-k3s1 (default)
```


## How does this works?
K8s gives us the ability to define an [OpenId Connect Provider ](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens) as and Identity Provider. Once we have configured this IDP we, as and user, can obtain short lived tokens to authenticate to the k8s cluster

## Instructions
### Run the terraform for dex, remember tu apply your variables
1. `terraform apply --auto-approve`
2. Check if it's working with `go test -v` in the tests folder
### Create the k3d cluster
1. Copy the certs to a temp dir `cp -r dex/certs /tmp`
2. Create the cluster with 
```
k3d cluster create rbac \
-v /tmp/certs:/etc/self-ssl/ \
--k3s-server-arg "--kube-apiserver-arg=oidc-issuer-url=<your-dex-url>" \
--k3s-server-arg "--kube-apiserver-arg=oidc-username-claim=email" \
--k3s-server-arg "--kube-apiserver-arg=oidc-client-id=<your-dex-client-id>" \
--k3s-server-arg "--kube-apiserver-arg=oidc-ca-file=/etc/self-ssl/ca.pem" \
--k3s-server-arg "--kube-apiserver-arg=oidc-groups-claim=groups" \
--k3s-server-arg "--kube-apiserver-arg=oidc-groups-prefix=oidc:" \
--k3s-server-arg "--kube-apiserver-arg=oidc-username-prefix=oidc:"
```
3. Create the roles with `kubectl apply -f roles.yaml`
### Configure the user
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

### Install oidc-login
1- `kubectl krew install oidc-login`

### Test it!
1. `kubectl get secret --user=test-oidc`
