# Certificate Signing request k8s auth method
Tested with `minikube version: v1.13.0`

## How does this work?
Using the CA of the cluster we, as admins, can create certificate requests, keys and certs for the developers who want to use the cluster, the name of the csr must be the user and the organization must be the group that you want to have access to.
The Go program creates PKI CSR's, it talks with your k8s API, wait's for them to be approved, creates the client.key and the cert.key, and it sends them to the smtp server.

## Instructions
1. Start minikube `minikube start`
2. Start a fake smtp server with `fake-smtp-server` from [An awesome npm package](https://www.npmjs.com/package/fake-smtp-server)
3. Do a `go run main.go` and wait until it finishes
4. Apply the roles with `kubectl apply -f roles.yaml`
5. Download the kubeconfigs from the browser in `localhost:1025`
6. Run `export KUBECONFIG=~/Downloads/x.kubeconfig`
7. Test it!
