#!/bin/bash
#
# Gr@ve_Rose's Offensive PCap Enumeration
# GROPE
#
VER="0.2"

# Start with a clear screen
clear

# Check for required programs
echo ""
echo -e "\e[32m\e[4m\e[1mGROPE v.$VER\e[0m\e[24m\e[21m"
echo ""


# Show help
show_help () {

	echo ""
	echo "Usage:"
	echo "grope.sh -i <input file> -o <output_file> -e <enumerators>"
	echo ""
	echo "-i: [Required] Set the input PCap file to enumerate through."
	echo "-o: [Required] Set the output file to save the report to."
	echo "-e: [Optional] Set the enumerators to use. By default, all will be used. Example: -e arp,lldp"
	echo "-h: [Optional] Show this help text."
	echo ""
	echo "Current Enumerators:"
	echo "--------------------"
	echo ""
	echo "arp - IPv4 Address Resolution Protocol"
	echo "dhcp - IPv4 DHCP Reqeusts"
	echo "dhcpv6 - IPv6 DHCP Requests"
	echo "dropbox - Dropbox LAN Browser Requests"
	echo "lldp - Link-Local Discovery Protocol"
	echo "nbnsb - NetBIOS Name Service Browser information"
	echo "ospf - Open Shortest Path First Routing"
	echo ""
	echo "Packet Capture Example Syntax"
	echo "-----------------------------"
	echo ""
	echo "Use the following command to use as a baseline to create a packet capture usable by grope:"
	echo ""
	echo "tcpdump -nn -vvv -e -s 0 -X -c 1000 -w outfile.pcap -i \$interface"
	echo ""
	echo "This will capture 1000 packets on interface \$interface and save them to the file \"outfile.pcap\". Adjust accordingly."
	echo ""
	exit 0

}

# Enumeration Modules
# Set the default
ENUM=("arp" "dhcp" "dhcpv6" "dropbox" "lldp" "nbnsb" "ospf")

#
# Source MAC, VLAN ID, Source IPv4, Dest IPv4, Source IPv6, Dest IPv6, Hostname
#
# ARP
arp () {

	echo -ne "Processing \e[32mARP\e[0m ... "

	# echo "ARP" >> $OUTPUT
	# echo "Source MAC,Source IP" >> $OUTPUT.arp
	$TSHARK -V -T fields -E separator=\| -e arp.src.hw_mac -e vlan.id -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 -r $INPUT arp  | $AWK -F '|' '{print $1"|"$2"|"$3}' | $SORT -n | $UNIQ >> $OUTPUT.arp

	# echo "Requested IPv4 Addresses" >> $OUTPUT
	# tshark -V -T fields -E separator=, -e arp.dst.proto_ipv4 -r $INPUT arp  | $AWK -F ',' '{print $1}' | $SORT -n | $UNIQ >> $OUTPUT

	echo "Done"
}

# DHCP (uses "bootp")
dhcp () {

	echo -ne "Processing \e[32mDHCP\e[0m ... "

	$TSHARK -V -T fields -E separator=\| -e eth.src -e vlan.id -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e dhcp.option.hostname -e dhcp.fqdn.name -e dhcp.option.requested_ip_address -e dhcp.option.dhcp_server_id -e dhcp.option.vendor_class_id -r $INPUT dhcp | $SORT -n | $UNIQ >> $OUTPUT.dhcp

	echo "Done"

}

# DHCPv6
dhcpv6 () {

	echo -ne "Processing \e[32mDHCPv6\e[0m ... "

	# echo "DHCPv6" >> $OUTPUT
	# echo "Source MAC,Source Link-Local,Hostname,vendor-class-data" >> $OUTPUT.dhcpv6
	$TSHARK -V -T fields -E separator=\| -e eth.src -e vlan.id -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e dhcpv6.client_fqdn -e dhcpv6.vendorclass.data -r $INPUT dhcpv6 | $AWK -F '|' '$1!=""' | $SORT -n | $UNIQ >> $OUTPUT.dhcpv6

	echo "Done"

}

# Dropbox-LAN
dropbox () {

	echo -ne "Processing \e[32mDropbox\e[0m ... "

	# echo "Dropbox LAN" >> $OUTPUT
	# echo "Source MAC,Source IP,Broadcast Address" >> $OUTPUT.dropbox
	$TSHARK -V -T fields -E separator=\| -e eth.addr -e vlan.id -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -r $INPUT db-lsp-disc | $GREP -v "255.255.255.255" | $SORT -n | $UNIQ | $AWK -F '|' '{print $2"|"$3"|"$4}' >> $OUTPUT.dropbox

	echo "Done"

}

# LLDP
lldp () {

	echo -ne "Processing \e[32mLLDP\e[0m ... "

	# echo "" >> $OUTPUT
	# echo "LLDP" >> $OUTPUT.lldp
	$TSHARK -V -T fields -E separator=\| -e eth.src -e vlan.id -e lldp.mgn.addr.ip4 -e ip.dst -e lldp.mgn.addr.ip6 -e ipv6.dst -e lldp.tlv.system.name -e lldp.tlv.system.desc -e lldp.tlv.system_cap -e lldp.tlv.enable_system_cap -e lldp.ieee.802_3.pmd_auto_neg_advertised_caps -r $INPUT lldp | $UNIQ >> $OUTPUT.lldp

	echo "Done"

}
# NBNS (Browser)
nbnsb () {

	echo -ne "Processing \e[32mNBNS\e[0m ... "

	# echo "" >> $OUTPUT
	# echo "NBNS" >> $OUTPUT.nbnsb
	$TSHARK -V -T fields -E separator=\| -e eth.src -e vlan.id -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e browser.server -e browser.windows_version -e browser.os_major -e browser.os_minor -e browser.server_type -e nbns.count.queries -r $INPUT browser  | $UNIQ >> $OUTPUT.nbnsb

	# Clean up and add Windows version tags
	$AWK -F '|' '{ ($8 = ($9 == "10" && $10 == "0" ? "Windows Server 2018, Windows Server 2016 or Windows 10" : $8)) ($8 = ($9 == "6" && $10 == "3" ? "Windows Server 2012R2 or Windows 8.1" : $8)) ($8 = ($9 == "6" && $10 == "2" ? "Windows Server 2012 or Windows 8" : $8)) ($8 = ($9 == "6" && $10 == "1" ? "Windows Server 2008R2 or Windows 7" : $8)) ($8 = ($9 == "6" && $10 == "0" ? "Windows Vista or Windows Server 2008" : $8)) ($8 = ($9 == "5" && $10 == "2" ? "Windows XP 64-bit, Windows Server 2003 or Windows Server 2003R2" : $8)) ($8 = ($9 == "5" && $10 == "1" ? "Windows XP" : $8)) ($8 = ($9 == "5" && $10 == "0" ? "Windows 2000" : $8)) ($8 = ($9 == "4" && $10 == "9" ? "Windows ME" : $8)) ($8 = ($9 == "4" && $10 == "1" ? "Windows 98" : $8)) ($8 = ($9 == "4" && $10 == "0" ? "Windows NT 4.0 or Winodws 95" : $8)) } 1' OFS=\| $OUTPUT.nbnsb > $OUTPUT.nbnsb1
	mv $OUTPUT.nbnsb1 $OUTPUT.nbnsb

	echo "Done"

}
# OSPF
ospf () {

	echo -ne "Processing \e[32mOSPF\e[0m ... "

	# echo "" >> $OUTPUT
	# echo "OSPF" >> $OUTPUT.ospf
	$TSHARK -V -T fields -E separator=\| -e eth.src -e vlan.id -e ip.src -e ipv6.src -e ospf.area_id -e ospf.auth.type -e ospf.hello.network_mask -e ospf.srcrouter -r $INPUT ospf  | $UNIQ >> $OUTPUT.ospf

	echo "Done"

}

# VLAN

# run (main program)
run () {

	echo "----------------------------------"
	echo "| Checking for required programs |"
	echo "----------------------------------"
	echo ""
	echo -n "Checking for tshark ...... "
	TSHARK=$(which tshark)
	if [ -z $TSHARK ]; then
		echo -e "\e[31mError!\e[0m tshark not found. Please install tshark before continuing."
		echo ""
		exit 1
	else
		echo -e "\e[32mFound! \e[0m($TSHARK)"
	fi

	echo -n "Checking for uniq ........ "
	UNIQ=$(which uniq)
	if [ -z $UNIQ ]; then
		echo -e "\e[3mError!\e[0m uniq not found. Please install uinq before continuing."
		echo ""
		exit 1
	else
		echo -e "\e[32mFound! \e[0m($UNIQ)"
	fi

	echo -n "Checking for awk ......... "
	AWK=$(which awk)
	if [ -z $AWK ]; then
		echo -e "\e[3mError!\e[0m awk not found. Please install awk before continuing."
		echo ""
		exit 1
	else
		echo -e "\e[32mFound! \e[0m($AWK)"
	fi

	echo -n "Checking for sed ......... "
	SED=$(which sed)
	if [ -z $SED ]; then
		echo -e "\e[3mError!\e[0m sed not found. Please install sed before continuing."
		echo ""
		exit 1
	else
		echo -e "\e[32mFound! \e[0m($SED)"
	fi

	echo -n "Checking for sort ........ "
	SORT=$(which sort)
	if [ -z $SORT ]; then
		echo -e "\e[3mError!\e[0m sort not found. Please install sort before continuing."
		echo ""
		exit 1
	else
		echo -e "\e[32mFound! \e[0m($SORT)"
	fi

	echo -n "Checking for grep ........ "
	GREP=$(which grep)
	if [ -z $GREP ]; then
		echo -e "\e[3mError!\e[0m grep not found. Please install grep before continuing."
		echo ""
		exit 1
	else
		echo -e "\e[32mFound! \e[0m($GREP)"
	fi

	rm -f $OUTPUT
	rm -f $OUTPUT.*
	echo ""
	echo -e "Processing file <-- \e[32m$INPUT\e[0m"
	echo -e "Saving to file -->  \e[32m$OUTPUT\e[0m"
	echo -n "Using Enumerators: "

	# Get "-e" flag
	if [ -z "${ENUM1}" ]; then
		ENUM1=("arp" "dhcp" "dhcpv6" "dropbox" "lldp" "nbnsb" "ospf")
	fi

	for i in "${ENUM[@]}"; do
		if [[ "${ENUM1[*]}" =~ "$i" ]]; then
			echo  -ne "[\e[32m$i\e[0m] "
		else
			echo -ne "[\e[31m$i\e[0m] "
		fi
	done

	# Present a warning for the one module bug
	if [ ${#ENUM1[@]} == 1 ]; then
		echo ""
		echo -ne "\e[33mWarning!\e[0m Currently there is a bug where using only one (1) enumeration module causes the output to be shifted incorrectly. You will manually have to move the first column to be part of the second column."
		echo ""
		read -p "Do you want to continue? [Y/n] " PROCEED
		case $PROCEED in
			n|N)
				echo "Exiting on user request..."
				echo ""
				exit 128
				;;
			*)
				echo "Proceeding"
				;;
			esac
	fi

	# echo -e "\e[32m${ENUM1[@]}\e[0m"
	echo ""
	for i in "${ENUM1[@]}"; do
		$i
	done

	echo ""
	echo "Module|Source MAC|VLAN ID|Source IPv4|Destination IPv4|Source IPv6|Destination IPv6|Hostname|Info" > $OUTPUT
	echo "Enumerating PCaps"
	echo "-----------------"

	# Get a list of unique MAC addresses
	awk -F '|' '{print $1}' $OUTPUT.* | $SORT -n | $UNIQ > mac.$OUTPUT

	# Loop through the MAC addresses and see where they show up

	TOTAL=$(wc -l ./mac.$OUTPUT | $AWK -F ' ' '{print $1}')
	z=1

	while read p; do
		$GREP $p $OUTPUT.* >> $OUTPUT
		echo -ne "Phase 1: $z/$TOTAL\r"
		z=$((z+1))
	done < mac.$OUTPUT
	echo ""
	echo -ne "Phase 1: \e[32mDone!\e[0m"
	echo ""

	# If we're only using one module, don't cut
	if [ ${#ENUM1[@]} != 1 ]; then
		
		# Cut the first bit of the module
		$SED -i -e "s/^$OUTPUT\.//g" $OUTPUT

		# Replace the : after the module with a pipe
		$SED -i -e "s/:/\|/" $OUTPUT
	fi
	# Find out where each MAC address was used
	TOTAL=$(wc -l $OUTPUT | $AWK -F ' ' '{print $1}')
	z=1

	while read p; do
		$AWK -F '|' '{print $2}' $OUTPUT | $GREP -v Source | $UNIQ > mac.list
		echo -ne "Phase 2: $z/$TOTAL\r"
		z=$((z+1))
	done < $OUTPUT

	echo ""
	echo -ne "Phase 2: \e[32mDone!\e[0m"
	echo ""

	# Create a tmp directory unless it already exists
	if [ ! -d tmp/ ]; then
		mkdir tmp
	fi

	# Found out where each MAC is used
	while read p; do
		$GREP $p $OUTPUT > tmp/$OUTPUT.$p
		
	done < mac.list

	# Go through each file and make better notes. :)
	TOTAL=$(ls tmp/ | wc -l)
	z=1

	for filename in tmp/$OUTPUT.*; do
		[ -e "$filename" ] || continue
		echo "Device Info" >> "$OUTPUT.txt"
		echo -n "MAC Address: " >> "$OUTPUT.txt"
		echo $($AWK -F '|' '{print $2}' $filename | $UNIQ) >> "$OUTPUT.txt"
		echo -n "VLAN ID: " >> "$OUTPUT.txt"
		echo $($AWK -F '|' '{print $3}' $filename | $UNIQ) >> "$OUTPUT.txt"
		echo -n "IPv4 Address: " >> "$OUTPUT.txt"
		echo $($AWK -F '|' '{print $4}' $filename | $SORT | $UNIQ) >> "$OUTPUT.txt"
		echo -n "IPv4 Destinations: " >> "$OUTPUT.txt"
		echo $($AWK -F '|' '{print $5}' $filename | $UNIQ) >> "$OUTPUT.txt"
		echo -n "IPv6 Address: " >> "$OUTPUT.txt"
		echo $($AWK -F '|' '{print $6}' $filename | $UNIQ) >> "$OUTPUT.txt"
		echo -n "IPv6 Destinations: " >> "$OUTPUT.txt"
		echo $($AWK -F '|' '{print $7}' $filename | $UNIQ) >> "$OUTPUT.txt"
		echo -n "Hostname Info: " >> "$OUTPUT.txt"
		echo $($AWK -F '|' '{print $8}' $filename | $UNIQ) >> "$OUTPUT.txt"
		echo -n "Operating System Info: " >> "$OUTPUT.txt"
		echo $($AWK -F '|' '{print $9}' $filename | $UNIQ) >> "$OUTPUT.txt"
		echo -n "Modules Matched: " >> "$OUTPUT.txt"
		echo $($AWK -F '|' '{print $1}' $filename | $UNIQ) >> "$OUTPUT.txt"
		echo "" >> "$OUTPUT.txt"
		echo -ne "Phase 3: $z/$TOTAL\r"
		z=$((z+1))
	done
	echo ""
	echo -ne "Phase 3: \e[32mDone!\e[0m"
	echo ""

	echo ""
	echo -e "\e[32mEnumeration Complete!\e[0m"
	echo ""
	echo -n "Cleaning-up ... "
	mv $OUTPUT.txt txt.$OUTPUT
	rm -f $OUTPUT.*
	mv txt.$OUTPUT $OUTPUT.txt
	rm -Rf tmp/
	rm -f mac.$OUTPUT
	rm -f mac.list
	# rm -Rf tmp/
	echo -e "\e[32mDone!\e[0m"
	echo ""
	echo -e "Report \e[32m$OUTPUT\e[0m (CSV) and \e[32m$OUTPUT.txt\e[0m (TXT) saved"
	echo ""
	exit 0

}

# Get options
# while getopts "he:i:o:" OPT; do
while getopts "he:i:o:" OPT; do

	case "${OPT}" in
		h)
			show_help
			;;
		i)
			INPUT=${OPTARG}
			;;
		o)
			OUTPUT=${OPTARG}
			;;
		e)
			IFS=','
			# NEED TO VERIFY USER INPUT WITH ENUM ARRAY
			ENUM1=($OPTARG)
			;;
		*)
			echo "Invalid arguments. Use \"-h\" for help."
			exit 255
			;;
	esac

done

shift $((OPTIND -1))

if [ -z $INPUT ]; then
	echo "Missing input file! Specify with \"-i \$file\""
	exit 1
fi

if [ -z $OUTPUT ]; then
	echo "Missing output file! Specify with \"-o \$file\""
	exit 1
fi

run

# EOF
