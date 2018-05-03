#!/bin/bash
for i in `seq 1 30`;
do
	sudo mn -c
	python "scripts/update_running_json.py" -dir /home/ndsg/Desktop/199/Final/results/hie_sdn_chnl_mod/base;
	python "scripts/update_hie_sdn_mn_sc.py" -run $i -mn_dir /home/ndsg/Desktop/199/Final/scripts/mininet_test_scripts/hie_sdn_chnl_mod_base;
	sudo mn --switch ovsk --controller remote --custom "scripts/topology.py" --topo mytopo --link tc --mac --post scripts/mininet_script --test=none;
	sleep 5;
done



echo "done"