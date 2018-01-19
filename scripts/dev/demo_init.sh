# Set up the baseband demo
# NOTE On error, restarting the phone helps sometimes
if [ $# -lt 1 ];
then
    echo "$0: <BP interface>"
    exit 1
fi

BPIF=$1
APIF=ril0

sudo tunctl -t ${APIF}

sudo ip link set up ${BPIF}
sudo ip link set up ${APIF}

sudo setcap cap_net_raw=eip /usr/bin/python3.6
