import sys
import boto3
from botocore.exceptions import ClientError
import paramiko


# ======================================================
# 
# ======================================================
class Network():
	# colors
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'


	# ==================================================
	# init
	# ==================================================
	def __init__(self):
		self.ec2 = boto3.client('ec2', region_name='us-east-2')

	
	# ==================================================
	# start vm
	# ==================================================
	def start(self, instance_id):
		self._log_info(instance_id, 'Starting instance...')
		try:
		    response = self.ec2.start_instances(InstanceIds=[instance_id], DryRun=False)
		    self._log_info(instance_id, 'Instance started.')
		except ClientError as e:
		    self._log_error(instance_id, e)


	# ==================================================
	# stop vm
	# ==================================================
	def stop(self, instance_id):
		self._log_info(instance_id, 'Stopping instance...')
		try:
		    response = self.ec2.stop_instances(InstanceIds=[instance_id], DryRun=False)
		    self._log_info(instance_id, 'Instance stopped.')
		except ClientError as e:
		    self._log_error(instance_id, e)


	# ==================================================
	# ssh connect
	# ==================================================
	def connect(self, instance_id, address, username, keyfile):
		self._log_info(instance_id, 'Connecting to server...')

		self.ssh = paramiko.SSHClient()
		self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		key = paramiko.RSAKey.from_private_key_file(keyfile)
		self.ssh.connect(address, username=username, pkey = key)
		stdin, stdout, stderr = self.ssh.exec_command("uptime")
		stdin.flush(); 
		self._log_ssh(instance_id, stdout, stderr)
		self._log_info(instance_id, 'Connection established.')


	# ==================================================
	# ssh connect
	# ==================================================
	def disconnect(self):
		self._log_info(instance_id, 'Disconnecting...')
		self.ssh.close()
		self._log_info(instance_id, 'Connection closed.')


	# ==================================================
	# print
	# ==================================================
	def _log(self, instance_id, message):
		sys.stdout.write('[{}] {}\n'.format(instance_id, message))

	def _log_info(self, instance_id, message):
		sys.stdout.write('[' +Network.OKGREEN+ 'INFO'+Network.ENDC+']') 
		self._log(instance_id, message)

	def _log_warning(self, instance_id, message):
		sys.stdout.write('[' +Network.WARNING+ 'WARNING'+Network.ENDC+']') 
		self._log(instance_id, message)

	def _log_error(self, instance_id, message):
		sys.stdout.write('[' +Network.FAIL+ 'ERROR'+Network.ENDC+']') 
		self._log(instance_id, message)

	def _log_ssh(self, instance_id, stdout, stderr):
		for message in iter(stdout.readline, ''):
			try:
				self._log_info(instance_id, message.rstrip())
			except Exception:
				pass
		for message in stderr.readlines():
			try:
				self._log_warning(instance_id, message.rstrip())
			except Exception:
				pass


	# ==================================================
	# install software
	# ==================================================
	def install(self, instance_id):
		self._log_info(instance_id, 'Installing software...')

		# update and downalod software
		command = 'sudo apt update; sudo apt upgrade;'
		command += 'sudo apt -y install git;'
		command += 'git clone https://github.com/asonnino/coconut.git;'

		# install petlib
		command += 'sudo apt -y install python-dev libssl-dev libffi-dev;'
		command += 'sudo apt -y install python3-pip;'
		command += 'sudo pip3 install petlib;'

		# install bplib
		command += 'cd aggregate_signature/aggregate_signature/bplib-master;'
		command += 'sudo python3 setup.py install;'

		# execute 
		stdin, stdout, stderr = self.ssh.exec_command(command)
		stdin.flush(); 
		self._log_ssh(instance_id, stdout, stderr)
		self._log_info(instance_id, 'Installation compleated')


	# ==================================================
	# cleanup vm
	# ==================================================
	def cleanup(self, instance_id):
		command = 'sudo rm -r *;'
		stdin, stdout, stderr = self.ssh.exec_command(command)
		stdin.flush(); 
		self._log_ssh(instance_id, stdout, stderr)
		self._log_info(instance_id, 'Instance cleaned up.')


	# ==================================================
	# cleanup vm
	# ==================================================
	def update(self, instance_id):
		self._log_info(instance_id, 'Updating...')
		self.cleanup(instance_id)
		self.install(instance_id)
		self._log_info(instance_id, 'Update compleated.')


	# ==================================================
	# execute arbitrary command 
	# ==================================================
	def exec(self, instance_id, command):
		self._log_info(instance_id, 'Executing: '+command)

		# execute 
		stdin, stdout, stderr = self.ssh.exec_command(command)
		stdin.flush(); 
		self._log_ssh(instance_id, stdout, stderr)
		self._log_info(instance_id, 'Installation compleated')



# ======================================================
# entry point
# ======================================================
if __name__ == '__main__':

	# param
	instance_id = 'i-0cdc943c545a4cfae'
	address = 'ec2-18-219-97-113.us-east-2.compute.amazonaws.com'
	username = 'ubuntu'
	keyfile = '/Users/alberto/.ssh/alberto-aws.pem'


	network = Network()

	network.start(instance_id)
	network.connect(instance_id, address, username, keyfile)
	network.install(instance_id)


	network.exec(instance_id, 'ls')

	network.cleanup(instance_id)
	network.disconnect()
	network.stop(instance_id)


