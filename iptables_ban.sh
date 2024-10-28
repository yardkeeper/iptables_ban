#!/bin/bash

MAX_ATTEMPTS=10
LOG_FILE="/var/log/auth.log"
IPTABLES="/sbin/iptables"
BLACKLIST_FILE="/var/log/blocked_ips.blacklist"
UNBLOCK_FILE="/var/log/unblock_ips.tmp"

unblock_ips() {
    if [[ -f $UNBLOCK_FILE ]]; then
        while IFS='|' read -r BLOCK_IP LOG_USER BLOCK_TIME; do
            BLOCK_TIME_SEC=$(date -d "$BLOCK_TIME" +%s)
            CURRENT_TIME_SEC=$(date +%s)
            TIME_DIFF=$((CURRENT_TIME_SEC - BLOCK_TIME_SEC))

            
            if [[ $TIME_DIFF -ge 86400 ]]; then
                echo "Unblocking IP: $BLOCK_IP"
                $IPTABLES -D INPUT -s $BLOCK_IP -j DROP
                # Remove the entry from the unblock file
                sed -i "/^$BLOCK_IP|/d" $UNBLOCK_FILE
            fi
        done < $UNBLOCK_FILE
    fi
}
 export -f unblock_ips


while true; do
    unblock_ips  # Check for IPs to unblock
    IP=$(tail -n 100 $LOG_FILE | grep "Failed password for" | awk '{print $(NF-1), $(NF)}' | sort | uniq -c | sort -nr | awk -v max_attempts=$MAX_ATTEMPTS '$1 > max_attempts {print $(NF-1), $NF}')

    for line in $IP; do
        LOG_USER=$(echo $line | awk '{print $1}') 
        BLOCK_IP=$(echo $line | awk '{print $2}') 
        
        # Check if IP is not already blocked
        if ! $IPTABLES -C INPUT -s $BLOCK_IP -j DROP 2>/dev/null; then
            echo "Blocking IP: $BLOCK_IP with user: $LOG_USER"
            $IPTABLES -A INPUT -s $BLOCK_IP -j DROP
            
            # Log the blocked IP, user, and time to the blacklist file
            echo "$BLOCK_IP|$LOG_USER|$(date +'%Y-%m-%d %H:%M:%S')" >> $BLACKLIST_FILE
            
            # Log the blocked IP and time to the unblock file
            echo "$BLOCK_IP|$LOG_USER|$(date +'%Y-%m-%d %H:%M:%S')" >> $UNBLOCK_FILE
        fi
    done

    sleep 60 
done
