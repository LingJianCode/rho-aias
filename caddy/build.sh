#!/bin/bash
# build
docker build -t docker.cnb.cool/makecnbgreatagain/rho-aias/rho-aias-caddy . 
# push
docker push docker.cnb.cool/makecnbgreatagain/rho-aias/rho-aias-caddy 
