############################ Description ###################################
###Prerequisites: 
###1.A running server
###2.An existing folder named 'data_collection' (a folder named 'logs' inside)
###3.Make sure the current path is in 'secretstroll/'
############################################################################

echo "################################################"
echo "                 START RUNNING                  "
echo "################################################"
OUTPUT_MSG="Capture failed cases (no logs been recorded): "

#Query every grid with step = 1
for i in {1..100}
    do
        trace_name=$(date +"data_collection/logs/network_logs_grid_$i.pcap")
        echo "Start write $trace_name ..."
        # only the first 64 bytes (contains all headers and 3 bytes of the envrypted data) and remove basically removes packets having no tcp payload)
        # keeps only tcp packets to network traffics
        tcpdump -w $trace_name -s 64 greater 55 and tcp &
        PID=$!
        # makes sure capture is setup
        sleep 1
        # queries for cell i
        python3 client.py grid $i -T restaurant -t
        query_status=$?
        sleep 3.5
        kill -2 $PID
        sleep 0.3
        if [ $query_status != 0 ]
        then
            OUTPUT_MSG="$OUTPUT_MSG$i "
            echo "Delete $trace_name"
            rm $trace_name
        fi
    done

echo "Final results:"
echo $OUTPUT_MSG
echo "################################################"
echo "                  STOP CLIENT                   "
echo "################################################"
cd data_collection