# heartbeat server for HIE (no SDN setup)

import socket
import urllib2
from scapy.all import IP, UDP, Raw, send, hexdump
import json,time,copy
import hashlib
from threading import Timer
import sys
import ssl

# class to handle PUT with urllib2
# https://stackoverflow.com/questions/21243834/doing-put-using-python-urllib2
class PutRequest(urllib2.Request):
    def __init__(self, *args, **kwargs):
        return urllib2.Request.__init__(self, *args, **kwargs)

    def get_method(self, *args, **kwargs):
        return 'PUT'

# function for returning the salt and timestamp of the HIE server
def authenticate():
	url = 'https://10.0.0.1:8080/authenticate/root@openhim.org'

	req = urllib2.Request(url)
	req.add_header("Accept", "application/json")
	req.add_header("Content-Type", "application/json")

	server_resp = urllib2.urlopen(req,context=ctx)
	try:
		parsed_server_resp = json.loads(server_resp.read())
		parsed_server_resp['udp_status'] = 'success'
		resp = json.dumps(parsed_server_resp)
	except:
		resp = '{"udp_status":"failed"}'

	return resp

# function for updating dictionary with dictionary input (try this pls)
def upd_dict(old_dict, new_dict):
	for i in new_dict:
		if isinstance(new_dict[i],dict)==False:
			new_dict[i] = new_dict[i]
		else:
			return upd_dict(old_dict[i],new_dict[i])


# function for updating the channel
# requests a list of channels
# then updates it
def update_channel(old_s,new_s):
	auth = json.loads(authenticate())
	channels_data = False
	if auth['udp_status'] == 'success':
		passhash = hashlib.sha512(auth['salt']+hie_pass).hexdigest()
		token = hashlib.sha512(passhash+auth['salt']+auth['ts']).hexdigest()

		url = 'https://10.0.0.1:8080/channels'

		req = urllib2.Request(url)
		req.add_header("Accept", "application/json")
		req.add_header("Content-Type", "application/json")
		req.add_header("auth-username",hie_user)
		req.add_header("auth-ts",auth['ts'])
		req.add_header("auth-salt",auth['salt'])
		req.add_header("auth-token",token)

		server_resp = urllib2.urlopen(req,context=ctx)

		try:
			old_recv_data = json.loads(server_resp.read())
			#print old_recv_data
			channels_data = True
		except:
			channels_data = False
	if channels_data == True:
		url = 'https://10.0.0.1:8080/channels/'+old_recv_data[0]['_id']

		old_channel_data = copy.deepcopy(old_recv_data[0])
		new_channel_data = {}
		new_channel_data['routes'] = copy.deepcopy(old_channel_data['routes'])
		old_channel_data['routes'][0]['host'] = old_s
		new_channel_data['routes'][0]['host'] = new_s


		udp_data = {}
		udp_data['old_data'] = old_channel_data
		udp_data['new_data'] = new_channel_data

		old_data = udp_data['old_data']
		new_data = udp_data['new_data']

		# trial function to update dict
		# send_data = upd_dict(old_data,new_data)
		# print json.dumps(send_data,indent=4)

		print "<< From ", old_data['routes'][0]['host'], " to ", new_data['routes'][0]['host'], " >>"
		# also try this
		# from https://stackoverflow.com/questions/15277307/update-a-dictionary-with-another-dictionary-but-only-non-none-values
		old_data.update((k, new_data[k]) for k in old_data.viewkeys() & new_data.viewkeys())
		send_data = json.dumps(old_data,indent=4)
		# make the data send old_data instead if gonna try above

		req = PutRequest(url,data = send_data)
		
		req.add_header("Accept", "application/json")
		req.add_header("Content-Type", "application/json")
		req.add_header("auth-username",hie_user)
		req.add_header("auth-ts",auth['ts'])
		req.add_header("auth-salt",auth['salt'])
		req.add_header("auth-token",token)

		server_resp = urllib2.urlopen(req,context=ctx)

		try:
			if server_resp.getcode() == 200:
				#parsed_server_resp = json.loads(server_resp.read())
				parsed_server_resp = {}
				parsed_server_resp['udp_status'] = 'success'
				parsed_server_resp['message_type'] = 'channel_update'
				resp = json.dumps(parsed_server_resp)
			else:
				resp = '{"udp_status":"failed"}'
		except:
			resp = '{"udp_status":"failed"}'

# function for timeout check
def check_heartbeats(timeout):
	global lastHeartbeat,starttime,curr_service
	timer = Timer(1, check_heartbeats,[timeout])
	timer.start()
	currTime = time.time()
	# for service in lastHeartbeat:
	# 	if lastHeartbeat[service]+1.5 <= currTime-starttime:
	# 		print service+' is down'
	if '10.0.0.2' in lastHeartbeat:
		if lastHeartbeat['10.0.0.2']+1.5 <= currTime-starttime and curr_service=='10.0.0.2':
			print "10.0.0.2 down"
			print 'Update 10.0.0.2 to 10.0.0.5'
		 	update_channel('10.0.0.2','10.0.0.5')
		 	curr_service = '10.0.0.5'
		elif lastHeartbeat['10.0.0.2']+1.5 > currTime-starttime and curr_service=='10.0.0.5':
			print "10.0.0.5 up"
			print 'Update 10.0.0.5 to 10.0.0.2'
			update_channel('10.0.0.5','10.0.0.2')
			curr_service = '10.0.0.2'


# OpenHIE credentials are written below
hie_user = "root@openhim.org"
hie_pass = "password"
hie_ip_addr = "10.0.0.1"

# IP addr of server
UDP_IP_ADDRESS = hie_ip_addr
UDP_PORT_NO = 6969

# declare timeout (in seconds)
timeout = 1.5
# declare dictionary for saving last timestamps of heartbeats
lastHeartbeat = {}

# original service IP
orig_service = '10.0.0.2'
# back up service IP
back_service = '10.0.0.5'
# current service
curr_service = '10.0.0.2'

# declare our serverSocket upon which
# we will be listening for UDP messages
serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSock.bind((UDP_IP_ADDRESS, UDP_PORT_NO))

#ssl validation stop
ctx = ssl.create_default_context()
ctx.check_hostname=False
ctx.verify_mode = ssl.CERT_NONE

print "Server running on IP: ", UDP_IP_ADDRESS, " Port: ", UDP_PORT_NO

starttime = time.time()
check_heartbeats(1.5)
while True:
	data_raw, addr = serverSock.recvfrom(2048)

	# part below is if it receives a udp with no json payload
	# can also check addr if si controller kausap niya?
	try:
		data = json.loads(data_raw)
	except:
		print "error"
		continue

	if data['heartbeat'] == 'False':
		# the client is done sending
		# exit the program
		serverSock.close()
		break

	if data['heartbeat'] == 'True':
		lastHeartbeat[addr[0]] = time.time() - starttime
		print lastHeartbeat

sys.exit()