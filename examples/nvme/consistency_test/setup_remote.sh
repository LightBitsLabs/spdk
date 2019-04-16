#!/bin/bash
LOG_FILE=".setup_remote.log"

SOURCE_LIST=()
SOURCE_LIST+=("consistency_test")
SOURCE_LIST+=("setup.sh")
SOURCE_LIST+=("README")
SOURCE_LIST+=("$WORKSPACE_TOP/spdk/include/spdk/pci_ids.h")
#SOURCE_LIST+=("write_pattern.sh")

function run_cmd {
	echo "$@"
	sshpass -p light ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$server "$@" 2>> $LOG_FILE
}

function copy_to_server {
	local from=$1
	local to=$2
	sshpass -p light scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r $from root@$server:/$to 2>> $LOG_FILE
}

#function modify_setup_script {
#
#	cmd="cat $WORKSPACE_TOP/spdk/scripts/setup.sh "
#	cmd+="| sed 's/\$rootdir\/include\/spdk\/pci_ids.h/pci_ids.h/g' "
#	cmd+="| sed 's/\$rootdir\/scripts\/common.sh/common.sh/g'"
#	eval $cmd > setup.sh
#}



function usage {
	echo "-h	--help 		:	print this message"
	echo "-s	--server	:	default none"
	echo "-n	--numa		:	default 0"
	echo "-d	--max_n_dev	:	default all"
}

function parser {
	numa=0
	max_n_dev=64
	while [ $1 ]; do
		case $1 in
			-h | --help)
				usage
				exit
				;;
			-n | --numa)
				numa=$2
				if [ ! $2 ]; then usage; exit; fi
				shift 2
				;;
			-d | --max_n_dev)
				max_n_dev=$2
				if [ ! $2 ]; then usage; exit; fi
				shift 2
				;;
			-s | --server)
				server=$2
				if [ ! $2 ]; then usage; exit; fi
				shift 2
				;;
			*)
				echo "unknown input $1"
				usage
				exit
				;;
		esac
	done
	if [ ! $server ]; then
		echo "Error: server was not specified"
		usage
		exit
	fi
}
echo "log file: $LOG_FILE"
echo `date` >> $LOG_FILE

parser $@
echo "Creating modified setup.sh script"

for s in ${SOURCE_LIST[@]}; do
	echo "Copying $s to root@$server:/root/"
	copy_to_server $s /root/
done

run_cmd chmod +x setup.sh
#run_cmd chmod +x write_pattern.sh
#run_cmd "./write_pattern.sh"
run_cmd "./setup.sh config $numa $max_n_dev"
