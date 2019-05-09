# netband-monitor
yum install libpcap-devel.x86_64

go build -ldflags '-w -s' netband-monitor

Parameters:

-i interface:　Listen to packets on interface.

-f "filter code" : Use  filter code to select the packets to count.

-s "net1/mask1 net2/mask2": separate networks to display

-t seconds: flush log files every t seconds

Example:

./netband-monitor -i eth1 -f "net 10.0.0.0/8" -s "10.0.29.0/24 10.0.31.0/24" -t 5
