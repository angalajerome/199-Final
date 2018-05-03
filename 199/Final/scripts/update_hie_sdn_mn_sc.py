import json
import sys

def getopts(argv):
    opts = {}  # Empty dictionary to store key-value pairs.
    while argv:  # While there are arguments left to parse...
        if argv[0][0] == '-':  # Found a "-name value" pair.
            opts[argv[0]] = argv[1]  # Add key and value to the dictionary.
        argv = argv[1:]  # Reduce the argument list by copying it starting from index 1.
    return opts

if __name__ == '__main__':
	from sys import argv
	myargs = getopts(argv)
	run_no = int(myargs['-run'])
	mn_base = str(myargs['-mn_dir'])
	with open('/home/ndsg/Desktop/199/Final/scripts/json_files/running_test_data.json','r') as test_thing:
		setup_config = json.load(test_thing)

	for name in range(len(setup_config["services_directory"])):
		deleteindex = setup_config["services_directory"][name].find("run")
		inputindex = setup_config["services_directory"][name].find(".csv")
		if deleteindex != -1:
			deleteindex +=3
			new_name = setup_config["services_directory"][name][:deleteindex]+str(run_no)+setup_config["services_directory"][name][inputindex:]
		else:
			new_name = setup_config["services_directory"][name][:inputindex]+'run'+str(run_no)+setup_config["services_directory"][name][inputindex:]
		setup_config["services_directory"][name] = new_name

	deleteindex = setup_config["curl_directory"].find("run")
	inputindex = setup_config["curl_directory"].find(".csv")
	if deleteindex != -1:
		deleteindex +=3
		curl_filename = setup_config["curl_directory"][:deleteindex]+str(run_no)+setup_config["curl_directory"][inputindex:]
	else:
		curl_filename = setup_config["curl_directory"][:inputindex]+'run'+str(run_no)+setup_config["curl_directory"][inputindex:]
	setup_config["curl_directory"] = curl_filename

	deleteindex = setup_config["cont_logs_dir"].find("run")
	inputindex = setup_config["cont_logs_dir"].find(".txt")
	if deleteindex != -1:
		deleteindex +=3
		cont_logs_filename = setup_config["cont_logs_dir"][:deleteindex]+str(run_no)+setup_config["cont_logs_dir"][inputindex:]
	else:
		cont_logs_filename = setup_config["cont_logs_dir"][:inputindex]+'run'+str(run_no)+setup_config["cont_logs_dir"][inputindex:]
	setup_config["cont_logs_dir"] = cont_logs_filename
	
	with open('scripts/json_files/running_test_data.json','w') as update_config:
		update_config.write(json.dumps(setup_config,indent=4))
	

	with open('/home/ndsg/Desktop/199/Final/scripts/json_files/running_test_data.json','r') as test_thing:
		setup_config = json.load(test_thing)

	mn_script_base = open(mn_base,"r")
	mn_script = open("/home/ndsg/Desktop/199/Final/scripts/mininet_script","w")
	for i in mn_script_base.readlines():
		if i == "[CURL THING]\n":
			#mn_script.write(i)
			mn_script.write("h3 sudo bash ./hie_sdn_client_curl_script.sh > \""+setup_config["curl_directory"]+"\" & \n")
		elif "[SERVICE DIRECTORY 1]" in i:
			insertIndex = i.find("[")
			deleteIndex = i.find("]") + 1
			writeThis =  i[:insertIndex]+"\""+setup_config["services_directory"][0]+"\""+i[deleteIndex:]
			mn_script.write(writeThis)
		elif "[SERVICE DIRECTORY 2]" in i:
			ndex = i.find("[")
			deleteIndex = i.find("]") + 1
			writeThis =  i[:insertIndex]+"\""+setup_config["services_directory"][1]+"\""+i[deleteIndex:]
			mn_script.write(writeThis)
		elif "[HEARTBEAT CLIENT DIRECTORY]" in i:
			insertIndex = i.find("[")
			deleteIndex = i.find("]") + 1
			writeThis =  i[:insertIndex]+"\""+setup_config["heartbeat_client_dir"]+"\""+i[deleteIndex:]
			mn_script.write(writeThis)
		else:
			mn_script.write(i)		