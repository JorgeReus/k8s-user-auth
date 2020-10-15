#!/bin/bash

set -e

docker build -t webhook-auth:v1 -f app/Dockerfile ./app

k3d cluster create webhook \
-v $PWD/config:/etc/webhook \
--k3s-server-arg "--kube-apiserver-arg=authentication-token-webhook-config-file=/etc/webhook/webhook-config.yaml"

kubectl apply -f manifests/roles.yaml

k3d image import webhook-auth:v1 -c webhook

kubectl apply -f manifests/daemonset.yaml
