# netband-monitor
yum install libpcap-devel.x86_64

go build -ldflags '-w -s' netband-monitor

Parameters:

-i eth1:　network interface device name

-f "tcp and port 80" : pcap filter

-s "10.0.29.0/24 10.0.31.0/24": separate network to display

-t 60: flush log files every 60s

./netband-monitor -i eth1 -f "net 10.0.0.0/8" -s "10.0.29.0/24 10.0.31.0/24" -t 5 
