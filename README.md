# netband-monitor
yum install libpcap-devel.x86_64

go build -ldflags '-w -s' netband-monitor



./netband-monitor -i eth1 -f "net 10.0.0.0/8" -s "10.0.29.0/24 10.0.31.0/24" -t 5 
