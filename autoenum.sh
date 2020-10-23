#!/bin/bash

# written by @ncroy13 && tdssec & updated by Rob Hughes & Nate Johnson

RED="\033[01;31m"
GREEN="\033[01;32m"
YELLOW="\033[01;33m"
BLUE="\033[01;34m"
BOLD="\033[01;01m"
RESET="\033[00m"

source ./nseScans.sh
#-- check for root or exit
if [ $EUID != 0 ]
then
    echo -e "\n[${RED}!${RESET}] must be ${RED}root${RESET}"
    exit 1
fi

declare -a tools=("masscan" "dig" "curl" "nmap" "ike-scan" "nbtscan" "wfuzz")

# check all prerequisite tools are installed, or quit
for tool in ${tools[*]}
do
    #echo ${tool[*]}
    if ! which "$tool" > /dev/null
    then
	echo -e "\n[${RED}!${RESET}] $tool ${RED}not${RESET} found"
	echo -e "\n[${RED}!${RESET}] Ensure the following tools are installed: ${tools[*]}"
	exit 1
    fi
done
# populate files and folders
declare -a files=("./targets.ip" "./exclude.ip")
declare -a folders=("scans" "open-ports" "nse_scans" "masscan/scans/" "nmap/scans/")

for file in ${files[*]}
do
    if [ ! -f "$file" ]
    then
	touch $file
        echo -e "\n[${GREEN}+${RESET}] Populate the ${YELLOW} $file ${RESET} file"
	exit 1
    fi
done

for folder  in ${folders[*]}
do
    if [ ! -d "$folder" ]
    then
	mkdir -p $folder         
    fi
done

#-- Nmap variables
MINHOST=$1
if  [[ -z "$MINHOST" ]]; then
    MINHOST=50
fi

MINRATE=$2
if  [[ -z "$MINRATE" ]]; then
    MINRATE=500
fi

#-- port variables
PORTRANGE=$3
if  [[ -z "$PORTRANGE" ]]; then
    PORTRANGE=1-65535
fi
MINPORT=$(echo $PORTRANGE | cut -d '-' -f 1)
MAXPORT=$(echo $PORTRANGE | cut -d '-' -f 2)

#-- scan functions
#-- masscan
masscanResolver(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}masscan${RESET} scans"
    echo -e "\n[${GREEN}+${RESET}] Resolving all ${YELLOW}hostnames${RESET} in targets.ip"
    for item in $(cat ./targets.ip);
    do
	if [[ $item =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || [[ $item =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$ ]];
	then
	    echo $item >> masscan/resolv.ip
	else
	    echo -e "$(dig +short $item | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u | tr -s ' ' '\n')" >> masscan/resolv.ip
	    echo -e "$(dig +short $item | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}' | sort -u | tr -s ' ' '\n')" >> masscan/resolv.ip
	fi
    done
}

massscanPortScan(){
    MAXRATE=
    if  [[ -z "$MAXRATE" ]]; then
	read -p "[!] Set Masscans value for --max-rate (500): " MAXRATE
    fi
    if [[ -z "$MAXRATE" ]];
    then
	MAXRATE=500
    fi
    echo -e "\n[+] ${BOLD}Masscan Starting"
    echo -e "\n[${GREEN}+${RESET}] Running a ${YELLOW}port scan${RESET} for all IPs in masscan/alive.ip"
    masscan --open -iL masscan/resolv.ip \
	    --excludefile exclude.ip \
	    -oG masscan/scans/$PORTRANGE.gnmap -v \
	    -p $PORTRANGE \
	    --max-rate=$MAXRATE
}

#-- nmap
pingSweep(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}nmap${RESET} scans"
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap ping sweep${RESET} for all ip in targets.ip"
    nmap --open -sn -PE -iL targets.ip \	 -PS3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157 -PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,996-999,1434,1701,1900,3283,4500,5353,49152-49154 \
	 -oA nmap/scans/PingSweep --excludefile exclude.ip --min-hostgroup $MINHOST --min-rate=$MINRATE
    grep "Up" nmap/scans/PingSweep.gnmap | cut -d " " -f2 | sort -u > nmap/alive.ip
}

nmapPortScan(){
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap port scan${RESET} for all ip in nmap/alive.ip"
    nmap --open -iL nmap/alive.ip \
	 -sU -sT -sV -O -Pn -n -T4 -oA nmap/scans/portscan -v \
	 -p T:$PORTRANGE,U:53,69,111,123,135,137,138,161,177,259,445,500,513,1434,1604,2049,2433,32771,4045,32822 \
	 --min-hostgroup $MINHOST --min-rate=$MINRATE
}

#-- combining masscan and nmap results
combiner(){
    echo -e "\n[${GREEN}+${RESET}] Combining ${YELLOW}nmap${RESET} and ${YELLOW}masscan${RESET} scans"
    touch alive.ip
    touch masscan/alive.ip
    cp masscan/scans/* scans
    cp nmap/scans/* scans
    cat masscan/scans/$PORTRANGE.gnmap | head -n -1 | tail -n +3 | cut -d ' ' -f 2 | sort -u > masscan/alive.ip
    cat masscan/alive.ip nmap/alive.ip | sort -u >> alive.ip
}

#progress bar
prog() {
    local w=80 p=$1;  shift
    # create a string of spaces, then change them to dots
    printf -v dots "%*s" "$(( $p*$w/$MAXPORT ))" ""; dots=${dots// /#};
    # print those dots on a fixed-width space plus the percentage etc. 
    printf "\r\e[K|%-*s| %3d  %s" "$w" "$dots" "$p" "$*"; 
}

parser(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}parser${RESET} for ${YELLOW}nse${RESET} scans"
 
    for n in $(seq $MINPORT $MAXPORT);   
    do
	if [ $(cat scans/*.gnmap | egrep " $n\/open\/tcp/" | cut -d " " -f 2 | wc -l) -eq '0' ];
	then
	    prog "$n" out of $MAXPORT TCP ports...
	   # sleep .1 	
	else
	    cat scans/*.gnmap | egrep " $n\/open\/tcp/" | cut -d " " -f 2 >> open-ports/$n.txt
	fi
	if [ $(cat scans/*.gnmap | egrep " $n\/open\/udp/" | cut -d " " -f 2 | wc -l) -eq '0' ];
	then
	    prog "$n" out of $MAXPORT UDP ports...
	   # sleep .1 
	else
	    cat scans/*.gnmap | egrep " $n\/open\/udp/" | cut -d " " -f 2 >> open-ports/$n.txt
	fi
    done
    #for x in $(ls ./open-ports); do
	#cat ./open-ports/$x | uniq | tee ./open-ports/$x;
    #done
}

#-- summary
summary(){
    echo -e "\n[${GREEN}+${RESET}] Generating a summary of the scans..."
    for ip in $(cat ./alive.ip); do
	echo -e $ip > ./open-ports/$ip.txt
	awk \/$ip\/ masscan/scans/$PORTRANGE.gnmap | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> ./open-ports/$ip.txt
	awk \/$ip\/ nmap/scans/portscan.gnmap | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> ./open-ports/$ip.txt
    done
    echo -e "\n[${GREEN}+${RESET}] there are $(cat ./alive.ip | wc -l ) ${YELLOW}alive hosts${RESET} and $(egrep -o '[0-9]*/open/' scans/*.gnmap | cut -d ':' -f 2 | sort | uniq | wc -l) ${YELLOW}unique ports/services${RESET}" | tee -a discovered_ports.txt
}


menuChoice(){
    read -p "Choose an option: " choice
    case "$choice" in
	1 ) echo "[1] selected, running -- Masscan|Nmap|NSEs"
	    masscanResolver
	    massscanPortScan
	    pingSweep
	    nmapPortScan
	    combiner
	    parser
	    nse
	    otherScans
	    summary;;
	2 ) echo "[2] selected, running -- Masscan | Nmap | NSEs | Dictionary attacks!"
	    masscanResolver
	    massscanPortScan
	    pingSweep
	    nmapPortScan
	    combiner
	    parser
	    nse
	    otherScans
	    discoveryScans # for dictionary attacks
	    summary;;
	3 ) echo "[3] selected, running -- Nmap|NSEs"
	    pingSweep
	    nmapPortScan
	    combiner
	    parser
	    nse
	    otherScans
	    summary;;
	* ) echo "[!] Incorrect choice - Quitting!"
	    exit 1;;
    esac
}

#Start the script
if (( "$#" < 3 )); #If not provided the 3 arguments - show usage
then
    MINHOST=50
    MINRATE=500
    PORTRANGE=1-1024
    echo -e "[!] Not entered all 3 arguments - Setting default values as shown in the usage example below!"
    echo -e "Usage Example: sudo bash ./autoenum.sh 50 500 1-1024"
    echo -e "./autoenum.sh [Nmap min hostgroup] [Nmap min rate] [Port range]\n"
    echo -e "[1] Continue Default Scans (Masscan, Nmap and Nse's)? "
    echo -e "[2] Run everything including dictionary attacks? "
    echo -e "[3] No masscan or dictionary attacks "
    menuChoice
elif (( "$#" == 3 ));
then
    echo -e "Arguments taken:"
    echo -e "--min-hostgroup: " $1
    echo -e "--min-rate: " $2
    echo -e "--port-range: " $3
    echo -e "\n[1] Continue Default Scans (Masscan, Nmap and Nse's)? "
    echo -e "[2] Run everything including dictionary attacks? "
    echo -e "[3] No masscan or dictionary attacks "
    menuChoice 
fi
