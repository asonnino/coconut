#!/usr/bin/env python
import boto3
import requests
from json  import loads, dumps

ec2 = boto3.resource('ec2', region_name='us-east-2')

for instance in ec2.instances.all():
	print(instance.id, instance.state)
	print(instance.public_dns_name)

	r = requests.get("http://"+instance.public_dns_name+'/')
	print(loads(r.text)["status"])