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

read -p "Enter in the target domain (i.e. [www.]example.com): " domain


### Check for dependencies
sleep 1
#### subfinder ####
if ! command -v go &> /dev/null
then
    echo -e "[+] go installation required. Proceeding...\n"
    sleep 1
    sudo apt-get -q update 
    sudo apt-get -q -y install golang > /dev/null
    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
else
    echo -e "[+] go already installed."
fi
sleep 2
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
if [ $? -ne 0 ]; then
    echo "Error: subfinder installation failed."
else
    echo "[+] subfinder installed successfully."
fi
sleep 2
#### fierce ####
sudo apt-get -q -y install fierce > /dev/null
if [ $? -ne 0 ]; then
    echo "Error: fierce installation failed."
else
    echo "[+] fierce installed successfully."
fi
sleep 2
#### whois ####
sudo apt-get -q -y install whois > /dev/null
if [ $? -ne 0 ]; then
    echo "Error: whois installation failed."
else
    echo "[+] whois installed successfully."
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



####

Variables

####

output_subfinder="subfinder-$domain-output.txt"
output_fierce="fierce-$domain-output.txt"
output_simplymail="simplymail-$domain-output.txt"
output_hibp="hibp-$domain-output.txt"

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

subfinder -v -d $domain -o $output_subfinder
sleep 2
sort -u $output_subfinder > tmp-subfinder && mv tmp-subfinder $output_subfinder


## fierce

fierce --domain $domain > $output_fierce
sleep 2
grep $domain $output_fierce > tmp-fierce && mv tmp-fierce $output_fierce

## domain parsing
sleep 1
echo -e "\n[!] Parsing domain data..."

## parsing Found domains
grep "Found" test-fierce-output.txt | awk '{print $2}' | sed 's/\.$//g' > tmp-fierce-domains-1

## parsing other domains returned (not by Found)
grep -v "Found" test-fierce-output.txt | tr -d "{}'," | awk -F: '{print $2}' | sed 's/\.$//g' > tmp-fierce-domains-2
sleep 1
## compiling all target subdomains
## compiling all target subdomains
cat $output_sublist3r tmp-fierce-domains-1 tmp-fierce-domains-2 > tmp-all-domains.txt

## stripping whitespace and ANSI characters from tools output
sed -E "s/"$'\E'"\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]//g" tmp-all-domains.txt | tr -d " \t" > tmp-all-domains-2.txt

## sort unique
sort -u tmp-all-domains-2.txt > all-domains.txt

## clean up tmps 
rm tmp*


## nslookup
echo -e "\n[!] Nslookup"


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

for subdomain in $(\cat small-sample.txt); do
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


## whois
echo -e "\n[!] Whois"
sleep 1

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



## SimplyEmail - Skipping for now - tool doesn't work.


## HIBP depends on Simply Email - Skipping for now


## File and Data cleanup

rm tmp-*


echo -e "[!] Done.\n"