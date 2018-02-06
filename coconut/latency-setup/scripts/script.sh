#!/bin/bash

sudo apt update; sudo apt -y upgrade;
sudo apt -y install git;
git clone https://github.com/asonnino/coconut.git;
sudo apt -y install python-dev libssl-dev libffi-dev;
sudo apt -y install python3-pip;
sudo pip3 install petlib;
sudo pip3 install bplib;
sudo pip3 install numpy; sudo pip3 install flask;
sudo python3 ~/coconut/coconut/latency-setup/server.py 80;