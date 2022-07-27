#! /bin/bash

score=0
tests=0


echo -n "Check PASS_MAX_DAYS = 30"
result=$(awk '/^PASS_MAX_DAYS/ && $2==30' /etc/login.defs)
if [ ! -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Check PASS_MIN_DAYS = 0"
result=$(awk '/^PASS_MIN_DAYS/ && $2==0' /etc/login.defs)
if [ ! -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Check LOGIN_RETRIES = 5"
result=$(awk '/^LOGIN_RETRIES/ && $2==5' /etc/login.defs)
if [ ! -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Check if user campadmin exists"
result=$(id campadmin 2>/dev/null)
if [ $? = 0 ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Check if user student exists"
result=$(id student 2>/dev/null)
if [ $? = 0 ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Check if user campadmin is in the sudo group"
result=$(groups campadmin | grep sudo 2>/dev/null)
if [ ! -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]


echo -n "Check if group campers exists"
result=$(getent group campers 2>/dev/null)
if [ $? = 0 ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Check if user campadmin is in the campers group"
result=$(groups campadmin | grep campers 2>/dev/null)
if [ ! -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Check if user student is in the campers group"
result=$(groups student | grep campers 2>/dev/null)
if [ ! -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Check if the ssh service is disabled"
result=$(systemctl is-enabled sshd 2>/dev/null)
if [ -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Check if the sshd process is running"
result=$(ps ax | grep sshd | grep listener 2>/dev/null)
if [ -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Check if the firewall is enabled"
result=$(sudo ufw status | grep "Status: active" 2>/dev/null)
if [ ! -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Create a firewall rule the blocks incoming Telnet"
result=$(sudo ufw status | grep "^23.*DENY" 2>/dev/null)
if [ ! -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]

echo -n "Create a firewall rule the blocks outgoing SSH"
result=$(sudo ufw status | grep "^22.*DENY OUT" 2>/dev/null)
if [ ! -z "$result" ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi

echo -n "Check if user rot is removed"
result=$(id rot 2>/dev/null)
if [ $? = 1 ]; then
	score=$[ $score + 1 ]
	echo ": Passed"
else
	echo ": Failed"
fi
tests=$[ $tests + 1 ]


echo "Score $score / $tests"
