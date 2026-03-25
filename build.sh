#!/bin/bash
# build
docker build --no-cache -t docker.cnb.cool/makecnbgreatagain/rho-aias/rho-aias .
# push
docker push docker.cnb.cool/makecnbgreatagain/rho-aias/rho-aias 
