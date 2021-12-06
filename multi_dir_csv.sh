#!/usr/bin/bash

if [ "$#" -eq 2 ] && [[ -d $1 ]] && [[ -d $2 ]]; then
	
	IN_DIR=$(cd "$1" && pwd -P)
	OUT_DIR=$(cd "$2" && pwd -P)
		
	for d in $IN_DIR/*/ ; do
		OUT_FILE=$OUT_DIR/$(basename $d)
		./siggregator.sh $d $OUT_FILE.json
		siggregator/results_to_csv.py $OUT_FILE.json $OUT_FILE.csv 
		printf "\n"
	done

else
	echo "Usage: multi_dir_csv.sh IN_DIR OUT_DIR"
fi
