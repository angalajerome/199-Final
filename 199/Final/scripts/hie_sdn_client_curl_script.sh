#!/bin/bash

end=$((SECONDS+40));
echo "request_num, curr_time,time_total, time_namelookup, time_connect, time_appconnect, time_pretransfer, time_redirect, time_starttransfer, http_code";
#for i in `seq 1 1000`;
((i = 1));
while [ $SECONDS -lt $end ];
	do
		printf "%d" "$i";
		printf ",";
		printf "%d" "$SECONDS";
		printf ",";
		curl -w "@curl-format-better.txt" -o /dev/null -s -k -u tut:tut http://10.0.0.1:5001/encounters/1;
		((i++));
	done
echo "EOF"