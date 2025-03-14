# Gr@ve_Rose's Offensive PCap Enumerator (grope)

A shell script to enumerate hosts based on a passive packet capture.

## Pupose

By taking a packet capture in promiscuous mode, you will capture information which is not necessarily destined for your host which will allow you to obtain packets from other hosts which use "noisy" protocols such as ARP, DHCP, LLDP and more. Once you have a packet capture, you can run it through *grope* which will then parse the PCap and extract useful information which can then be used for offensive security or whatever else you want.

## Usage

First, take a packet capture and save it. For example: `tcpdump -nn -vvv -e -s 0 -X -c 100 -w output.pcap -i eth0`

Next, import that into *grope* and specify an output file: `grope.sh -i output.cap -o mylist.csv`

Once done, you will have two new files: `mylist.csv` and `mylist.csv.txt` The first file is a CSV using the pipe (`|`) character as the delimeter. This is useful to import into a spreadsheet program or used with `awk` to obtain information. The second file is a text file formatted for ease-of-reading which is helpful when on a RedTeam engagement as you don't have to generate network traffic transferring the file to read it.
