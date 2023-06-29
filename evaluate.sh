############################ Description ###################################
###Prerequisites: 
###1.A running server
###2.A existing folder named 'data_collection' (a folder named 'logs' inside)
###3.Make sure the current path is in 'secretstroll/'
############################################################################

echo "################################################"
echo "                 START RUNNING                  "
echo "################################################"
OUTPUT_MSG="Evaluate failed at case:"
EVALUATE_WITH_TOR="Time cost with tor (per seconds):\n"
EVALUATE_WITHOUT_TOR="Time cost without tor (per seconds):\n"
for i in {30..60}
    do
        # !!! requires apt-get install bc (for sub second precision)
        start=$(date +%s.%N)
        # queries for cell i with tor
        python3 client.py grid $i -T restaurant -t
        query_status=$?
        if [ $query_status != 0 ]
        then
            echo "(with tor) $OUTPUT_MSG: $i"
            echo -e $EVALUATE_WITH_TOR > evaluate_with_tor_2.txt

            # we don't want to continue a failed test
            cd data_collection
            exit 1
        else
            end=$(date +%s.%N)
            duration=$(echo "$(date +%s.%N) - $start" | bc)
            EVALUATE_WITH_TOR="$EVALUATE_WITH_TOR\n$i:$duration"
        fi
        # makes sure previous finished
        sleep 1
        start=$(date +%s.%N)
        # queries for cell i without tor
        python3 client.py grid $i -T restaurant
        query_status=$?
        if [ $query_status != 0 ]
        then
            echo "(without tor) $OUTPUT_MSG: $i"
            echo -e $EVALUATE_WITHOUT_TOR > evaluate_without_tor_2.txt
            
            # we don't want to continue a failed test
            cd data_collection
            exit 1
        else
            end=$(date +%s.%N)
            duration=$(echo "$(date +%s.%N) - $start" | bc)
            EVALUATE_WITHOUT_TOR="$EVALUATE_WITHOUT_TOR\n$i:$duration"
        fi
        # makes sure previous finished
        sleep 1
    done
echo $OUTPUT_MSG
echo "################################################"
echo "               STOP EVUALUATION                 "
echo "################################################"
cd data_collection
# -e makes sure the \n are line return
echo -e $EVALUATE_WITHOUT_TOR > evaluate_without_tor_2.txt
echo -e $EVALUATE_WITH_TOR > evaluate_with_tor_2.txt
exit 0