# heartbeat client for HIE (no SDN setup)
import socket
import time
import json

runTime = 40 # how many seconds the heartbeat_client will run
pause = 41 # at which time the script will "pause"
pause_len = 0 # length of "pause"
timer = 1 # sends per timer

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# dummy ip of controller
# port number that heartbeat_server listens to
dst = ('10.0.0.1',6969)

msg_raw = { 'heartbeat' : 'True'}
msg = json.dumps(msg_raw)

timestart = time.time()
currTime = time.time()
while currTime < timestart+runTime:
	currTime = time.time()
	if currTime >= timestart + runTime:
		# end loop
		msg_raw = { 'heartbeat' : 'False'}
		msg = json.dumps(msg_raw)
		client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		client.sendto(msg,dst)
		client.close()
		break
	if (currTime >= timestart + pause) and (currTime < timestart + pause + pause_len):
		# skip iteration
		continue
	client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	client.sendto(msg,dst)
	print "[Heartbeat sent]"
	time.sleep(timer)