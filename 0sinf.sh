#!/usr/bin/env bash

# Author: Jhony Alavez
# Date: 2023-02-14

### TODO:
# test w/o simplyemail throughouly
# looks for simplyemail solution
# segment into functions
# create a menu with functions

# if not refactor to python3
# update domain argument and menu to python3
# implement simply email within python3 - as the last section

####

# Variables

####
RED="\e[31m"
GREEN="\e[32m"
GREY="\e[37m"
YELLOW="\e[33m"
END="\e[0m"




###### prompt #####

read -p $'\e[31mEnter in the target domain (i.e. [www.]example.com): \e[0m' domain

#####

# File variables

#####
output_subfinder="subfinder-$domain-output.txt"
output_fierce="fierce-$domain-output.txt"
output_simplymail="simplymail-$domain-output.txt"
output_hibp="hibp-$domain-output.txt"

### Check for dependencies
sleep 1
#### subfinder ####
if ! command -v go &> /dev/null
then
    echo -e "${RED}[+] go installation required. Proceeding...\n${GREY}"
    sleep 1
    sudo apt-get -o DPkg::Lock::Timeout=3 update 
    sudo apt-get -o DPkg::Lock::Timeout=3 -y install golang
    sleep 2
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    sleep 2
    echo -e "${RED}[!] Done.${END}"
else
    echo -e "${GREEN}[!] go already installed!${END}"
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
fi
sleep 2
if ! command -v subfinder &> /dev/null
then 
    echo -e "${RED}[+] subfinder installation required. Proceeding...\n${GREY}"
    sleep 1
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    sleep 2
    if [ $? -ne 0 ]; then
        echo "${RED}[!] Error: subfinder installation failed.${END}"
    else
        echo -e "${RED}[!] Done.${END}"
    fi
else
    echo -e "${GREEN}[!] subfinder already installed!${END}"
fi
sleep 2
#### fierce ####
if ! command -v fierce &> /dev/null
then
    echo -e "${RED}[+] fierce installation required. Proceeding...\n${GREY}"
    sleep 1
    sudo apt-get -o DPkg::Lock::Timeout=3 -y install fierce
    if [ $? -ne 0 ]; then
        echo "${RED}[!] Error: fierce installation failed.${END}"
    else
        echo "${RED}[!] Done.${END}"
    fi
else
    echo -e "${GREEN}[!] fierce already installed!${END}"
fi
sleep 2
#### whois ####

if ! command -v whois &> /dev/null
then
    echo -e "${RED}[+] whois installation required. Proceeding...\n${GREY}"
    sleep 1
    sudo apt-get -o DPkg::Lock::Timeout=3 -y install whois
    if [ $? -ne 0 ]; then
        echo "${RED}[!] Error: whois installation failed.${END}"
    else
        echo "${RED}[!] Done.${END}"
    fi
else
    echo -e "${GREEN}[!] whois already installed!${END}"
fi
sleep 2
<<SKIPPING
#### simplymail ####
# docker
sudo apt -q -y install docker.io
if [ $? -ne 0 ]; then
    echo "Error: docker installation failed."
else
    echo "[+] docker installed successfully."
fi
sudo systemctl enable docker --now
sudo usermod -aG docker $USER
sudo systemctl restart docker
# simply email
sudo docker pull simplysecurity/simplyemail


# NOTE:: This needs to be redone since there are various dependency
# issues. 
# Most notably when setting up from git source it leverages python2
# Also when pulling the docker container, it continues to reference
# python2 errors and library errors. 

# The tool needs to be refactored into python3
# or there needs to be another tool to substitute this
SKIPPING

<<SKIPPING
#### checkedpwnemails ####
https://github.com/Techno-Hwizrdry/checkpwnedemails.git
if [ $? -ne 0 ]; then
    echo "Error: checkedpwnedemails installation failed."
else
    echo "[+] checkedpwnedemails installed successfully."
fi

### NOTE: HIBP depends on SimplyEmail
SKIPPING



#### Main functions #####

<<DESCRIPTION
This begins the functionality of the script.
This will generate output files, which the filenames are listed above.
This will go in the following order:

1. subfinder
2. fierce
3. fierce domain data manipulation
4. nslookup
5. whois
6. simplyemail
6. HIBP
7. Summary of Results

DESCRIPTION

## subfinder
#if [-e "$output_subfinder"]; then
#    i=1
#    while [-e "$output_subfinder-$i.bkp"]; do
#        let i++
#    done
#    output_subfinder="$output_subfinder-$i"
#fi
echo -e "${RED}0 in on subdomains... ${END}"
sleep 2
subfinder -v -d $domain -o $output_subfinder
sleep 2
sort -u $output_subfinder > tmp-subfinder && mv tmp-subfinder $output_subfinder
echo -e "${RED}[*]${GREEN} $output_subfinder ${RED}file created.${END}"
sleep 3
## fierce
echo -e "\n${RED} Fiercely 0 in on subdomains...${END}"
sleep 2
fierce --domain $domain > $output_fierce
sleep 2
grep $domain $output_fierce > tmp-fierce && mv tmp-fierce $output_fierce
echo -e "${YELLOW}[*]${GREEN} $output_fierce ${RED}file created. ${END}"
sleep 3
## domain parsing
echo -e "\n${RED}[!] Parsing subdomain data...${END}"
sleep 2
## parsing Found domains
grep "Found" $output_fierce | awk '{print $2}' | sed 's/\.$//g' > tmp-fierce-domains-1

## parsing other domains returned (not by Found)
grep -v "Found" $output_fierce | tr -d "{}'," | awk -F: '{print $2}' | sed 's/\.$//g' > tmp-fierce-domains-2
sleep 1
echo -e "${RED}[!] Done.${END}"
sleep 2

echo -e "\n${RED}[!] 0 in on all subdomains.${END}"
## compiling all target subdomains
cat $output_sublist3r tmp-fierce-domains-1 tmp-fierce-domains-2 > tmp-all-domains.txt

## stripping whitespace and ANSI characters from tools output
sed -E "s/"$'\E'"\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]//g" tmp-all-domains.txt | tr -d " \t" > tmp-all-domains-2.txt

## sort unique
sort -u tmp-all-domains-2.txt > all-domains.txt
echo -e "${YELLOW}[*]${GREEN} all-domains.txt ${RED}file created.${END}" 
## clean up tmps 
rm tmp*
echo -e "${RED}[!] Done."

## nslookup
echo -e "\n${RED}[!] 0 in on hostname resolution...${END}"
sleep 2

# NOTE: for now it only provides a file of all resolved IP address and only outputs IP addresses
# you will need to manually cross references IP addresses to the subdomain.
# However it's all alphabetically sorted before it gets here. 
# Only issue is the distinction between when a new domain resolution begins...

# TODO: provide additional 2 files: x1 that captures output to be implemented
# Resolved Addresses:
# me.example.com    10.10.10.10
# you.example.com   10.10.10.20
# etc.

# AND x1 file of all UNRESOLVED addresses - for example:
# nothere.example.com
# nope.example.com

# nslookup list of domains > inserts them into a csv as:
# 10.10.10.10 
# 10.10.10.11 a.example.com
# 192.168.100.10 b.example.com
# etc...
echo "Network,Domain,Registrant" > tmp-csv

for subdomain in $(\cat all-domains.txt); do
    ip=$(nslookup "$subdomain" | awk '/^Address: /{ip=$2; if(ip !~ /^192\.168\./ && ip !~ /^10\./ && ip !~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./) print ip}')
if [ -n "$ip" ]; then
    echo "$ip,$subdomain," >> tmp-csv
fi
done
sleep 2
awk '{if(substr($0,length($0)) != ",") gsub(/$/, ",,"); print}' tmp-csv > cleanup-csv
sleep 2
#### Sorting via IPv4 addreses must be done later -> as this affects the grouping of IPv4 addresses
#### related to the same subdomains.
## storing as csv for deliverable and later ingest
#sort -t. -n -k1,1 -k2,2 -k3,3 -k4,4 tmp-resolved-subdomain-ips.txt > resolved-subdomain-ips-only-sorted.txt
#\cat resolved-subdomain-ips-only.txt >> tmp-csv
echo -e "${RED}[!] Done.${END}"
sleep 2


## whois
echo -e "\n${RED}[!] 0 in on who the domain belongs to...${END}"
sleep 2
awk -F ',' 'BEGIN {OFS = FS} NR == 1 {print $0; next} {
    cmd = "whois " $1 " | awk -F\":\" \"/Registrant|Organization/ {print \\$2}\" | tr -d \",\""
    cmd | getline output
    close(cmd)
    if (output != "") { sub(/^,/, "", output)
        print $1, $2, output
    } else {
        print $1, $2, ","
    }
}' cleanup-csv > tmp-whois.csv

cp tmp-whois.csv domain-$domain.csv

echo -e "${YELLOW}[*] ${GREEN}domain-$domain.csv ${RED}file created.${END}"


## SimplyEmail - Skipping for now - tool doesn't work.


## HIBP depends on Simply Email - Skipping for now


## File and Data cleanup

rm tmp-*


echo -e "${RED}[!] Done.\n${END}"

echo -e "\n\n${RED}[*] Files ready for review: ${GREEN}"
ls *.txt *.csv