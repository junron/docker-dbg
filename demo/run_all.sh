#!/bin/bash

cd redpwn_jail
./build_docker.sh
python3 demo.py
cd ..


cd ubuntu
./build_docker.sh
python3 demo.py
cd ..

cd alpine
./build_docker.sh
python3 demo.py
cd ..


docker kill demo-jail
docker kill demo-ubuntu
docker kill demo-alpine
