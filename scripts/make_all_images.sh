#!/bin/bash

# Helper script to recompile the tool and build all the images. Of course it
# won't work because there are not pcaps attached.

set -eu
set -x

go install
(cd bdp-plot; go install)

bdp=~/go/bin/bdp
plot=~/go/bin/bdp-plot

rm -rfv tmp/
mkdir -p tmp/


function plot_pcap {
    local fname=$(basename "$1" .pcap)
    local title="$2"
    local ip_local=$3
    local ip_remote=$4
    local xrange=$5
    local yrange=$6

    csv=tmp/$fname.csv
    $bdp -i data/$fname.pcap -l $ip_local -r $ip_remote  2> /dev/null > $csv
    $plot -i $csv -o tmp/$fname.png -t "$title"
    $plot -i $csv -o tmp/$fname.thumb.png -strip
    convert tmp/$fname.thumb.png -resize 160x120 tmp/$fname.thumb.png 
    $plot -i $csv -o tmp/$fname.log.png -log -xrange $xrange -yrange $yrange -t "$title"
    $plot -i $csv -o tmp/$fname.log.thumb.png -log -xrange $xrange -yrange $yrange -strip
    convert tmp/$fname.log.thumb.png -resize 160x120 tmp/$fname.log.thumb.png
}

plot_pcap upload_gmail_5m_1.pcap gmail.com 192.168.2.135 216.58.209.69  8e2:2e3 1e2:5e2
plot_pcap upload_gmail_5m_2.pcap gmail.com 192.168.2.135 216.58.209.69  8e2:2e3 1e2:5e2
plot_pcap upload_gmail_5m_3.pcap gmail.com 192.168.2.135 216.58.209.69  8e2:2e3 1e2:5e2

plot_pcap files.fm_1.pcap files.fm 192.168.2.135 78.129.241.197 8e2:1.5e3 1.5e2:4e2
plot_pcap files.fm_2.pcap files.fm 192.168.2.135 80.232.243.188 8e2:1.5e3 1.5e2:4e2 
plot_pcap files.fm_3.pcap files.fm 192.168.2.135 78.129.241.197 8e2:1.5e3 1.5e2:4e2

plot_pcap speedtest.net_1.pcap speedtest.net 192.168.2.135 185.24.196.194 1e1:3e3 1e1:3e3
plot_pcap speedtest.net_2.pcap speedtest.net 192.168.2.135 185.24.196.194 1e1:3e3 1e1:3e3
plot_pcap speedtest.net_3.pcap speedtest.net 192.168.2.135 185.24.196.194 1e1:3e3 1e1:3e3

plot_pcap uploadfiles.io_1.pcap uploadfiles.net 192.168.2.135 217.182.136.95 5e2:1e3 1.5e2:4e2
plot_pcap uploadfiles.io_2.pcap uploadfiles.net 192.168.2.135 217.182.136.95 5e2:1e3 1.5e2:4e2
plot_pcap uploadfiles.io_3.pcap uploadfiles.net 192.168.2.135 217.182.136.95 5e2:1e3 1.5e2:4e2


rm -rfv images/
mkdir -p images/
cp -v tmp/*.png images/

