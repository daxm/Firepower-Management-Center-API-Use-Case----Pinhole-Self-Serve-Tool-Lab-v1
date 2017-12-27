from flask import Flask
app = Flask(__name__)
app.config.from_object('config')

from flask import render_template, request, flash, url_for, redirect


@app.route("/", methods=["GET", "POST"])
def index():
	import time
	import random
	import fmcapi
	# from fmcapi import FMC, IPAddresses, IPHost, IPNetwork, IPRange, URL, VlanTag, VariableSet, ProtocolPort, SecurityZone, Device, IntrusionPolicy, AccessControlPolicy, ACPRule

	title='Pinhole SelfServe Tool'

	if request.method == "GET":
		pinhole_lifetime = 600
		dev_port = random.randint(1024, 65535)
		dev_host_ip = '172.16.100.250'
		dev_names = ['John', 'Paul', 'George', 'Ringo']
		dev_name = random.choice(dev_names)
		# Hard coding Protocol.
		dev_protocol = 'TCP'

	if request.method == "POST":
		# User Inputted Data
		pinhole_lifetime = int(request.form.get("pinhole_lifetime"))
		if pinhole_lifetime > 3600:
			pinhole_lifetime = 3600
			flash('Duration time set too long. Reseting to 3600 seconds.')
		if pinhole_lifetime < 300:
			pinhole_lifetime = 300
			flash('Duration time set too short. Reseting to 300 seconds.')
		dev_name = request.form.get("dev_name")
		dev_host_ip = request.form.get("dev_host_ip")
		dev_port = request.form.get("dev_port")
		dev_protocol = request.form.get("dev_protocol")
		if int(dev_port) < 1 or int(dev_port) > 65534:
			dev_port = 12345
			flash('TCP ports need to be within a range of 1 - 65534.  Resetting your port to 12345.')

		# FMC Server Info.
		username = 'apiscript'
		password = 'Admin123'
		serverIP = '172.16.100.100'


		# Hard Coded FMC Objects Used
		acp_name = 'HQ'
		ips_policy_name = 'Security Over Connectivity'
		dst_zone_name = 'IN'
		src_zone_name = 'OUT'

		autodeploy = True
		now_timestamp = int(time.time())
		name = 'Dev-{}-{}'.format(dev_name, now_timestamp)
		# name = f'Dev-{dev_name}-{now_timestamp}' # If/when I get python3.6

		# ########################################### Main Program ####################################################

		def cleanup_expired_dev_entries(**kwargs):
			"""
			This method checks for any "expired" host, port, and acp rule objects based on a timestamp
			value in their name.
			"""

			# Get all rules for this ACP.

			all_acp_rules = fmcapi.ACPRule(fmc=fmc1, acp_name=acp_name)
			all_rules = all_acp_rules.get()
			if all_rules.get('items', '') is '':
				pass
			else:
				for item in all_rules['items']:
					if 'Dev-' in item['name']:
						namesplit = item['name'].split('-')
						if int(namesplit[2]) < kwargs['threshold_time']:
							flash('Deleting {} ACP Rule.'.format(item['name']))
							tmp_rule = None
							tmp_rule = fmcapi.ACPRule(fmc=fmc1, acp_name=acp_name)
							tmp_rule.get(name=item['name'])
							tmp_rule.delete()
			# Now Delete any expired Host objects.
			all_ips = fmcapi.IPAddresses(fmc=fmc1)
			all_hosts = all_ips.get()
			for item in all_hosts['items']:
				if 'Dev-' in item['name']:
					namesplit = item['name'].split('-')
					if int(namesplit[2]) < kwargs['threshold_time']:
						flash('Deleting {} Host Object.'.format(item['name']))
						tmp_rule = None
						tmp_rule = fmcapi.IPHost(fmc=fmc1)
						tmp_rule.get(name=item['name'])
						tmp_rule.delete()
			# Finally Delete any expired Port objects.
			all_ports = fmcapi.ProtocolPort(fmc=fmc1)
			response = all_ports.get()
			for item in response['items']:
				if 'Dev-' in item['name']:
					namesplit = item['name'].split('-')
					if int(namesplit[2]) < kwargs['threshold_time']:
						flash('Deleting {} Port Object.'.format(item['name']))
						tmp_rule = None
						tmp_rule = fmcapi.ProtocolPort(fmc=fmc1)
						tmp_rule.get(name=item['name'])
						tmp_rule.delete()

		with fmcapi.FMC(host=serverIP, username=username, password=password, autodeploy=autodeploy) as fmc1:
			# Remove timed out entries. (This will remove acprules, hostips, and protocolports. Remove entries that are older than 'dev_maxlife' seconds
			expired_timestamp = int(time.time() - pinhole_lifetime)
			cleanup_expired_dev_entries(threshold_time=expired_timestamp, acp_name=acp_name, fmc=fmc1)

			# Create Host.
			host_ip = fmcapi.IPHost(fmc=fmc1, name=name, value=dev_host_ip)
			host_ip.post()
			flash('Created {} host object.'.format(name))

			# Create Port.
			pport = fmcapi.ProtocolPort(fmc=fmc1, name=name, port=dev_port, protocol=dev_protocol)
			pport.post()
			flash('Created {} port object.'.format(name))

			# Occasionally the FMC is still "sync'ing" the newly added items and this can cause the use of them in
			#  the createacprule() command to fail.  Let's wait a bit before continuing.
			# time.sleep(5)

			# Create ACP Rule
			acp_rule = fmcapi.ACPRule(fmc=fmc1, name=name, acp_name=acp_name, action='ALLOW', enabled=True, logBegin=True, logEnd=True)
			acp_rule.intrusion_policy(action='set', name='Security Over Connectivity')
			acp_rule.source_zone(action='add', name=src_zone_name)
			acp_rule.destination_zone(action='add', name=dst_zone_name)
			acp_rule.destination_network(action='add', name=name)
			acp_rule.destination_port(action='add', name=name)
			acp_rule.post()
			flash('Created {} Access Control Policy Rule.'.format(name))

		flash('The new pinhole will be available to use in around 5 minutes.')
		flash('  It will be valid until {}.'.format(time.asctime( time.localtime(int( time.time() + pinhole_lifetime)))))

	return render_template("index.html", title=title, dev_name=dev_name, dev_port=dev_port, dev_protocol=dev_protocol, dev_host_ip=dev_host_ip, pinhole_lifetime=pinhole_lifetime)

@app.route("/<path:path>")
def catchall(path):
	return render_template("NoneShallPass.html")


if __name__ == "__main__":
	app.run(host='0.0.0.0')
