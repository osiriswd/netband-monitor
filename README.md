# netband-monitor
yum install libpcap-devel.x86_64
go build -ldflags '-w -s' netband-monitor

./netband-monitor -i eth1 -f "tcp and port 80"
