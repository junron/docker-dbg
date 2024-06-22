#!/bin/bash

docker kill demo-ubuntu
cp ../demo .
docker build . -t demo_ubuntu
rm demo
docker run --rm -d --name demo-ubuntu demo_ubuntu