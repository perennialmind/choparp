#!/bin/sh

#
# Functional tests. Do NOT run this on a production system or any environment
# not devoted to testing. This script is normally run from linux-ns-unshare.sh
# which configures a sandbox. Docker, GitLab, autopkgtest, etc are fine too.
# Just don't run this script casually.
#

set -x

if [ -z "$AM_BUILDDIR" ]
then
	echo "1..0 # Skipped: missing \$AM_BUILDDIR"
	echo "# Did you run me under 'make check'? "
	exit
fi

if ! ip link add is-at type veth peer name who-has ||
	! ip addr add 192.168.1.200/24 dev who-has     ||
	! ip link set is-at up                         ||
	! ip link set who-has up
then
	echo "1..0 # Skipped: unable to set up private veth interfaces"
	exit
fi

# Allow this many seconds for choparp start-up before sending test arp requests
startup_grace=2

# Allow this many seconds for choparp to cleanly shut-down before checking results
shutdown_grace=4

# Any arbitrary value should do, but might as well switch it up between runs
rnd_byte="$(dd if=/dev/urandom bs=1 count=1 2>/dev/null | od -A n -t d)"

lladdr() {
	printf '02:00:c0:a8:%02x:%02x' "$rnd_byte" "$1"
}

ipaddr() {
	printf '192.168.%d.%d' "$rnd_byte" "$1"
}

hex_ipaddr() {
	printf '0xc0a8%02x%02x' "$rnd_byte" "$1"
}

arp_for() {
	(
		for i
		do
			ping -I who-has -c 1 -w 1 $(ipaddr $i) &
		done
		wait # for all jobs in this subshell
	) > /dev/null
}

found() {
	ip -4 neigh show dev who-has | \
		grep -i -q "$(ipaddr $1) lladdr ${2:-.*} REACHABLE"
}

stop_process() {
	pid=$1
	comm="${2:-choparp}"
	i=$shutdown_grace
	sig=TERM
	while ps -p "$pid" -o "comm=" | grep -q "$comm"
	do
		[ $i -gt 1 ] || sig=KILL
		kill -s $sig "$pid"
		[ $i -gt 1 ] || return
		sleep 1
		: $(( i-=1 ))
	done
	true
}

#######################################################################

echo "1..12"

#######################################################################

test_desc="1 - Base case, static hardware address and single-host"
"$AM_BUILDDIR"/choparp is-at $(lladdr 1) $(ipaddr 1) &
chopid=$!
sleep $startup_grace

arp_for 1
stop_process $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! found 1
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="2 - Target IP by legacy subnet"
"$AM_BUILDDIR"/choparp is-at $(lladdr 2) $(ipaddr 2)/255.255.255.254 &
chopid=$!
sleep $startup_grace

arp_for 2 3
stop_process $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! (found 2 && found 3)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="3 - Target IP by BSD-style hex"
"$AM_BUILDDIR"/choparp is-at $(lladdr 4) $(hex_ipaddr 4)/0xfffffffe &
chopid=$!
sleep $startup_grace

arp_for 4
arp_for 5
stop_process $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! (found 4 && found 5)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="4 - Target IP by IP list"
"$AM_BUILDDIR"/choparp is-at $(lladdr 6) $(ipaddr 6) $(ipaddr 7) &
chopid=$!
sleep $startup_grace

arp_for 6 7
stop_process $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! (found 6 && found 7)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="5 - Target IP by CIDR subnet and exclusion"
"$AM_BUILDDIR"/choparp is-at $(lladdr 8) $(ipaddr 8)/30 -$(ipaddr 10) &
chopid=$!
sleep $startup_grace

arp_for 8 9 10 11
stop_process $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! (found 8 && found 9 && ! found 10 && found 11)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="6 - Hardware address detection by \"auto\" keyword"
"$AM_BUILDDIR"/choparp is-at auto $(ipaddr 12) &
chopid=$!
sleep $startup_grace

arp_for 12
stop_process $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! found 12
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="7 - Hardware address by \"vhid\" keyword, decimal"
"$AM_BUILDDIR"/choparp is-at vhid:13 $(ipaddr 13) &
chopid=$!
sleep $startup_grace

arp_for 13
stop_process $chopid

ip neigh show dev who-has

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! found 13 00:00:5e:00:01:0d
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="8 - Hardware address by \"vhid\" keyword, hex"
"$AM_BUILDDIR"/choparp is-at vhid:0x0e $(ipaddr 14) &
chopid=$!
sleep $startup_grace

arp_for 14
stop_process $chopid

ip neigh show dev who-has

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! found 14 00:00:5e:00:01:0e
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="9 - Pidfile with -p"
pidfile=$(mktemp /tmp/choparp.pid-XXXXXXXX)
"$AM_BUILDDIR"/choparp -p $pidfile is-at auto $(ipaddr 15) &
chopid=$!
sleep $startup_grace

chopid_from_file=$(cat "$pidfile")
arp_for 15
stop_process $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! found 15
then
	echo "not ok $test_desc # MAC resolution failure"
elif ! [ "$chopid" -eq "$chopid_from_file" ]
then
	echo "not ok $test_desc # invalid pidfile"
elif [ -f "$pidfile" ]
then
	echo "not ok $test_desc # pidfile not removed after exit"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="10 - Daemon by flag"
pidfile=$(mktemp /tmp/choparp.pid-XXXXXXXX)
timeout --kill-after 1s ${startup_grace}s \
	"$AM_BUILDDIR"/choparp -d -v -v -p "$pidfile" is-at auto $(ipaddr 16)
sleep $startup_grace
timeout_status=$?

chopid_from_file=$(cat "$pidfile")
arp_for 16

if [ "$timeout_status" -eq 124 ] || [ "$timeout_status" -eq 137 ]
then
	echo "not ok $test_desc # daemon timeout (failed to detach)"
elif ! [ "$timeout_status" -eq 0 ]
then
	echo "not ok $test_desc # abnormal exit $timeout_status"
elif ! found 16
then
	echo "not ok $test_desc # MAC resolution failure"
elif ! (
	[ -n "$chopid_from_file" ] && [ "$chopid_from_file" -gt 0 ] &&
	ps -p $chopid_from_file -o "comm=" | grep -q choparp
)
then
	echo "not ok $test_desc # invalid pidfile"
else
	if ! stop_process "$chopid_from_file"
	then
		echo "not ok $test_desc # daemon still running after SIGTERM"
	elif [ -f "$pidfile" ]
	then
		echo "not ok $test_desc # pidfile not removed after exit"
	else
		echo "ok $test_desc"
	fi
fi

#######################################################################

test_desc="11 - Daemon by name"
pidfile=$(mktemp /tmp/choparp.pid-XXXXXXXX)
timeout --kill-after 1s ${startup_grace}s \
	"$AM_BUILDDIR"/choparpd -v -v -p "$pidfile" is-at auto $(ipaddr 17)
sleep $startup_grace
timeout_status=$?

chopid_from_file=$(cat "$pidfile")
arp_for 17

if [ "$timeout_status" -eq 124 ] || [ "$timeout_status" -eq 137 ]
then
	echo "not ok $test_desc # daemon timeout (failed to detach)"
elif ! [ "$timeout_status" -eq 0 ]
then
	echo "not ok $test_desc # abnormal exit $timeout_status"
elif ! found 17
then
	echo "not ok $test_desc # MAC resolution failure"
elif ! (
	[ -n "$chopid_from_file" ] && [ "$chopid_from_file" -gt 0 ] &&
	ps -p $chopid_from_file -o "comm=" | grep -q choparpd
)
then
	echo "not ok $test_desc # invalid pidfile"
else
	if ! stop_process "$chopid_from_file"
	then
		echo "not ok $test_desc # daemon still running after SIGTERM"
	elif [ -f "$pidfile" ]
	then
		echo "not ok $test_desc # pidfile not removed after exit"
	else
		echo "ok $test_desc"
	fi
fi

#######################################################################

test_desc="12 - Systemd daemon Type=notify"
for i in once; do
	if ! grep -q "define HAVE_LIBSYSTEMD" "$AM_BUILDDIR/config.h"; then
		echo "ok $test_desc # SKIP systemd support not enabled"
		break
	fi
	sockd="$(mktemp -d /tmp/choparp.sock-XXXXXXXX)"
	socat UNIX-RECVFROM:$sockd/sock $sockd/msg &
	socat_pid=$!
	sleep $startup_grace
	if ! [ -S $sockd/sock ]
	then
		echo "ok $test_desc # SKIP socat socket setup failed"
		break
	fi
	NOTIFY_SOCKET="$sockd/sock" "$AM_BUILDDIR"/choparp is-at auto $(ipaddr 18) &
	chopid=$!
	sleep $startup_grace
	
	arp_for 18
	stop_process $chopid
	stop_process $socat_pid socat
	
	if ! wait $chopid
	then
		echo "not ok $test_desc # abnormal exit $?"
	elif ! found 18
	then
		echo "not ok $test_desc # MAC resolution failure"
	elif ! wait "$socat_pid" || ! grep -q 'READY=1' $sockd/msg
	then
		echo "not ok $test_desc # failed to confirm sd_notify support"
	else
		echo "ok $test_desc"
	fi
	rm $sockd/{msg,sock}
	rmdir $sockd
done

#######################################################################

# Cleanup
ip link delete is-at

exit 0
