import socket
import urllib2
from scapy.all import IP, UDP, Raw, send, hexdump
import json
import hashlib
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

# OpenHIE credentials are written below
hie_user = "root@openhim.org"
hie_pass = "password"
hie_ip_addr = "10.0.0.1"
dummy_controller_ip = "10.0.0.2"

# IP addr of server
UDP_IP_ADDRESS = hie_ip_addr
UDP_PORT_NO = 6789

# declare our serverSocket upon which
# we will be listening for UDP messages
serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# One difference is that we will have to bind our declared IP address
# and port number to our newly declared serverSock
serverSock.bind((UDP_IP_ADDRESS, UDP_PORT_NO))

print "Server running on IP: ", UDP_IP_ADDRESS, " Port: ", UDP_PORT_NO


#ssl validation stop
ctx = ssl.create_default_context()
ctx.check_hostname=False
ctx.verify_mode = ssl.CERT_NONE
while True:
	data_raw, addr = serverSock.recvfrom(2048)

	# part below is if it receives a udp with no json payload
	# can also check addr if si controller kausap niya?
	try:
		data = json.loads(data_raw)
	except:
		print "error"
		continue

	print data['req'], " request received from ", addr
	if data['req'] == "auth":
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

		packet = IP(dst="10.0.0.2")/UDP(sport=2152,dport=2152)/Raw(load=resp)
		send(packet)

	if data['req'] == "req_all_channels":
		print "wat"
		# important for all the things
		auth = json.loads(authenticate())
		print auth
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

			print req
			server_resp = urllib2.urlopen(req,context=ctx)
			print server_resp

			try:
				parsed_server_resp = json.loads(server_resp.read())
				parsed_server_resp[0]['udp_status'] = 'success'
				parsed_server_resp[0]['message_type'] = 'channels_data'
				resp = json.dumps(parsed_server_resp[0])
			except:
				resp = '{"udp_status":"failed"}'
			print server_resp
			packet = IP(dst="10.0.0.2")/UDP(sport=2152,dport=2152)/Raw(load=resp)
			send(packet)

	if data['req'] == "update_channel":
		# make sure it has required data
		cont = False
		if 'channel_id' and 'old_data' and 'new_data' in data:
			cont = True
		if cont == True:
			# important for all the things
			auth = json.loads(authenticate())
			if auth['udp_status'] == 'success':
				passhash = hashlib.sha512(auth['salt']+hie_pass).hexdigest()
				token = hashlib.sha512(passhash+auth['salt']+auth['ts']).hexdigest()

				url = 'https://10.0.0.1:8080/channels/'+data['channel_id']

				old_data = data['old_data']
				new_data = data['new_data']

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

				packet = IP(dst="10.0.0.2")/UDP(sport=2152,dport=2152)/Raw(load=resp)
				send(packet)
		else:
			resp = '{"udp_status":"failed"}'

			packet = IP(dst="10.0.0.2")/UDP(sport=2152,dport=2152)/Raw(load=resp)
			send(packet)

	print data['req'], 'request',json.loads(resp)['udp_status']
# while True:
# 	data, addr = serverSock.recvfrom(1024)

# 	if data == "auth":
# 		#send http req to self
# 		url = 'https://10.0.0.1:8080/authenticate/root@openhim.org'

# 		req = urllib2.Request(url)
# 		req.add_header("Accept", "application/json")
# 		req.add_header("Content-Type", "application/json")

# 		server_resp = urllib2.urlopen(req)
# 		try:
# 			parsed_server_resp = json.loads(server_resp.read())
# 			parsed_server_resp['status'] = 'success'
# 			resp = json.dumps(parsed_server_resp)
# 		except:
# 			resp = '{"status":"failed"}'
# 		print thing

# 		packet = IP(dst="10.0.0.2",len=201)/UDP(sport=2152,dport=2152)/Raw(load=resp)
# 		send(packet)

# 	if data == "thing"
