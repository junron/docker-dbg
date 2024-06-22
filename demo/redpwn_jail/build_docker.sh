#!/bin/bash

docker kill demo-jail
cp ../demo .
docker build . -t demo_jail
rm demo
docker run --rm --privileged -d --name demo-jail -p 34569:5000 demo_jail
