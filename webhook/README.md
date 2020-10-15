# Webhook authentication & authorization k8s method
Tested with 
```
k3d version v3.0.1
k3s version v1.18.6-k3s1 (default)
```

## How this works
K8s gives your the possibility to define a service in which you can send authentication request from users and decide if their credentials are valid, this example uses the github API to authenticate users via personal access tokens also it knows which roles for the organizations you're in. You just need to build a reachable service and follow the protocol defined in [Webhook authentication in k8s](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication)

## Instructions

### Get yourself a github token
1. Go to settings -> Developer Settings -> Personal access tokens
2. Create a token with the `read:user`, `user:email` and `read:org`
3. Set and env var named `GITHUB_TOKEN`
### Run the test cluster
1. Run the script `start.sh`
2. Wait for the `webhook-auth` daemon set to start i.e. `kubectl get ds -n kube-system -w`
### Create an user in your kubeconfig
`kubectl config set-credentials webhook --token=$GITHUB\_TOKEN`
### Test it!
`kubectl get secret --user=webhook`
