# python script for creating the test script

import json
from pprint import pprint

with open('scripts/json_files/config.json','r') as config_file:
	config = json.load(config_file)

test_name_dir = config["working_directory"]+config["test_name_file"]
with open(test_name_dir,'r') as test_name_file:
	test_names = json.load(test_name_file)

test_dirs = []
result_dirs=[]
for system in test_names["test_directories"]:
	for test in test_names["test_directories"][system]:
		test_dir = config["working_directory"]+'/scripts/mininet_test_scripts/'+system+'_'+test
		test_dirs.append(test_dir)
		result_dir = config["working_directory"]+config["results_directory"]+"/"+system+'/'+test
		result_dirs.append(result_dir)

num_tests = str(config["runs_per_test"])
topo_dir = config["topology_directory"]
with open('scripts/run.sh','w') as write_file:
	final_write = "#!/bin/bash\n"
	for test in test_dirs:
		test_index = test_dirs.index(test)
		dir_upd = "python \"scripts/update_running_json.py\" -dir " +result_dirs[test_index] +";\n"
		if "no_hie" in test:
			mn_upd = "python \"scripts/update_no_hie_mn_sc.py\" -run $i -mn_dir "+test+";\n"
			mn_sc = "sudo mn --custom \"scripts/topology.py\" --topo mytopo --switch lxbr,stp=1 --link tc --mac --post scripts/mininet_script --test=none;\n"
		elif "hie_no_sdn" in test:
			mn_upd = "python \"scripts/update_hie_no_sdn_mn_sc.py\" -run $i -mn_dir "+test+";\n"
			mn_sc = "sudo mn --custom \"scripts/topology.py\" --topo mytopo --switch lxbr,stp=1 --link tc --mac --post scripts/mininet_script --test=none;\n"
		elif "hie_sdn" in test:
			mn_upd = "python \"scripts/update_hie_sdn_mn_sc.py\" -run $i -mn_dir "+test+";\n"
			mn_sc = "sudo mn --switch ovsk --controller remote --custom \"scripts/topology.py\" --topo mytopo --link tc --mac --post scripts/mininet_script --test=none;\n"
		write_this = (	"for i in `seq 1 " + num_tests +	"`;\n"+
						"do\n"+
						"	sudo mn -c\n"+
						"	"+dir_upd+
						"	"+mn_upd + 
						"	"+mn_sc + 
						"	sleep 5;\n"+
						"done\n"+
					"\n\n\n")
		final_write = final_write + write_this
	final_write = final_write + "echo \"done\""
	write_file.write(final_write)