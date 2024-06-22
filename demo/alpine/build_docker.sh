#!/bin/bash

docker kill demo-alpine
cp ../demo.c .
docker build . -t demo_alpine
rm demo.c 
docker run --rm -d --name demo-alpine demo_alpine