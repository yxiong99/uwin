#!/bin/bash
#
# This script is designed for Linux computer to work as UWIN router
#
#***************#
# Util Function #
#***************#
kill_all()
{
    local i
    local p
    local pid
    p=$1
    pid=$(ps -ef | grep $p | awk '{print $2}')
    for i in $pid; do
        if [ $i -ne $$ ]; then
            kill -9 $i > /dev/null 2>&1
            sleep 1
        fi
    done
}

kill_one()
{
    local f
    local pid
    f=$1
    if [ -e $f ]; then
        pid=$(cat $f)
        if [ -n "$pid" ]; then
            kill -9 $pid > /dev/null 2>&1
        fi
        rm -f $f
    fi
}

del_addr()
{
    local iface
    local addr
    iface=$1
    for addr in $(ip addr show $iface | grep 'inet ' | awk '{print $2}'); do
        ip addr del dev $iface $addr > /dev/null 2>&1
    done
}

del_route()
{
    local iface
    local route
    iface=$1
    for route in $(ip route | grep dev.*${iface} | awk '{print $1}'); do
        ip route del $route dev $iface > /dev/null 2>&1
    done
}

del_default_route()
{
    local route
    local iface
    local gw
    iface=$1
    gw=$2
    if [ -z "$gw" ]; then
        for route in $(ip route | grep default | grep $iface | awk '{print $3}'); do
            if [ -n "$route" ]; then
                ip route del default via $route dev $iface > /dev/null 2>&1
            fi
        done
    else
        for route in $(ip route | grep default | awk '{print $3}'); do
            if [ "$route" = "$gw" ]; then
                ip route del default via $gw dev $iface > /dev/null 2>&1
            fi
        done
    fi
}

add_public_dns()
{
    local dns
    if [ ! -e "$RESCONF" ]; then
        echo "nameserver 8.8.8.8" >> $RESCONF
        echo "nameserver 8.8.4.4" >> $RESCONF
    else
        dns=$(cat $RESCONF | grep '8.8.8.8')
        if [ -z "$dns" ]; then
            sed -i '1inameserver 8.8.8.8\' $RESCONF
        fi
    fi
}

#*********************#
# IP & ARP Management #
#*********************#
set_proxy_arp()
{
    proxy=$(cat /proc/sys/net/ipv4/conf/all/proxy_arp)
    if [ $proxy -eq 0 ]; then
        sysctl -w net.ipv4.conf.all.proxy_arp=1
    fi
}

set_ip_forward()
{
    forward=$(cat /proc/sys/net/ipv4/ip_forward)
    if [ $forward -eq 0 ]; then
        sysctl -w net.ipv4.ip_forward=1
    fi
}

set_ip_tables()
{
    iptables -F
    iptables -X
    chain=$(iptables -nL | grep wifi_forw)
    if [ -n "$chain" ]; then
        iptables -D FORWARD -j wifi_forw
        iptables -F wifi_forw
        iptables -X wifi_forw
    fi
    iptables -N wifi_forw
    iptables -A FORWARD -j wifi_forw
    if [ "$LAN_OP" = "1" ]; then
        iptables -A wifi_forw -i $LAN_IF -o $LAN_IF -j ACCEPT
        if [ "$BRI_OP" != "0" ]; then
            iptables -A wifi_forw -i $LAN_IF -o $BRI_IF -j ACCEPT
            iptables -A wifi_forw -i $BRI_IF -o $LAN_IF -j ACCEPT
        else
            if [ "$ETH_OP" = "1" ]; then
                iptables -A wifi_forw -i $LAN_IF -o $ETH_IF -j ACCEPT
                iptables -A wifi_forw -i $ETH_IF -o $LAN_IF -j ACCEPT
            fi
            if [ "$STA_OP" = "1" ]; then
                iptables -A wifi_forw -i $LAN_IF -o $STA_IF -j ACCEPT
                iptables -A wifi_forw -i $STA_IF -o $LAN_IF -j ACCEPT
            fi
        fi
        iptables -A INPUT -i $LAN_IF -j ACCEPT
    fi
    iptables -t nat -F
    iptables -t nat -X
    chain=$(iptables -t nat -nL | grep wifi_post)
    if [ -n "$chain" ]; then
        iptables -t nat -D POSTROUTING -j wifi_post
        iptables -t nat -F wifi_post
        iptables -t nat -X wifi_post
    fi
    iptables -t nat -N wifi_post
    iptables -t nat -A POSTROUTING -j wifi_post
    if [ "$BRI_OP" != "0" ]; then
        iptables -t nat -A wifi_post -o $BRI_IF -j MASQUERADE
    else
        if [ "$ETH_OP" = "1" ]; then
            iptables -t nat -A wifi_post -o $ETH_IF -j MASQUERADE
        fi
        if [ "$STA_OP" = "1" ]; then
            iptables -t nat -A wifi_post -o $STA_IF -j MASQUERADE
        fi
    fi
}

#**********************#
# LAN Bridge Operation #
#**********************#
del_vap_lan()
{
    if [ -n "$LAN_MAC" ] && [ -n "$VAP_IF" ]; then
        brif=$(brctl show $LAN_IF | grep $VAP_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $LAN_IF $VAP_IF
        fi
    fi
 }

del_wln_lan()
{
    if [ -n "$LAN_MAC" ] && [ -n "$WLN_IF" ]; then
        brif=$(brctl show $LAN_IF | grep $WLN_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $LAN_IF $WLN_IF
        fi
    fi
 }

del_sap_lan()
{
    if [ -n "$LAN_MAC" ] && [ -n "$SAP_IF" ]; then
        brif=$(brctl show $LAN_IF | grep $SAP_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $LAN_IF $SAP_IF
        fi
    fi
}

del_enx_lan()
{
    if [ -n "$LAN_MAC" ] && [ -n "$ENX_IF" ]; then
        brif=$(brctl show $LAN_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $LAN_IF $ENX_IF
        fi
    fi
}

add_enx_lan()
{
    brif=$(brctl show $LAN_IF | grep $ENX_IF) > /dev/null 2>&1
    if [ -z "$brif" ]; then
        brctl addif $LAN_IF $ENX_IF
    fi
}

del_usb_lan()
{
    if [ -n "$LAN_MAC" ] && [ -n "$USB_IF" ]; then
        brif=$(brctl show $LAN_IF | grep $USB_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $LAN_IF $USB_IF
        fi
    fi
}

add_usb_lan()
{
    brif=$(brctl show $LAN_IF | grep $USB_IF) > /dev/null 2>&1
    if [ -z "$brif" ]; then
        brctl addif $LAN_IF $USB_IF
    fi
}

del_eth_lan()
{
    if [ -n "$LAN_MAC" ] && [ -n "$ETH_IF" ]; then
        brif=$(brctl show $LAN_IF | grep $ETH_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $LAN_IF $ETH_IF
        fi
    fi
}

add_eth_lan()
{
    brif=$(brctl show $LAN_IF | grep $ETH_IF) > /dev/null 2>&1
    if [ -z "$brif" ]; then
        brctl addif $LAN_IF $ETH_IF
    fi    
}

dump_lan()
{
    echo -n > $LAN_INFO
    {
        echo "LAN info:"
        echo "  LAN_IF=$LAN_IF"
        echo "  LAN_MAC=$LAN_MAC"
        echo "  LAN_IP=$LAN_IP"
        echo "  LAN_START=$LAN_START"
        echo "  LAN_END=$LAN_END"
        echo "  LAN_GW=$LAN_GW"
    } >> $LAN_INFO
}

conf_lan()
{
    DNSMASQ_ARGS=${DNSMASQ_ARGS}" $@"
}

start_lan()
{
    old_ip=$(ip addr show $LAN_IF | grep 'inet ' | head -n1 | awk '{print $2}')
    if [ -n "$old_ip" ]; then
        del_addr $LAN_IF
        del_route $LAN_IF
    fi
    ip addr add dev $LAN_IF $lan_ip broadcast $lan_brd
    DNSMASQ_ARGS="-o -f -b -K -D -Q 2007"
    conf_lan "--dhcp-sequential-ip --dhcp-leasefile=$LAN_DHCP_LEASE"
    conf_lan "--clear-on-reload --dhcp-option=6,8.8.8.8,8.8.4.4"
    conf_lan "-i $LAN_IF -F $LAN_IF,$lan_start,$lan_end,3600"
    $DHCPSRV $DNSMASQ_ARGS
}

stop_lan()
{
    kill_all "$DHCPSRV"
    if [ -e "$LAN_DHCP_LEASE" ]; then
        rm -f $LAN_DHCP_LEASE
    fi
    if [ -n "$LAN_MAC" ]; then
        ifconfig $LAN_IF down 
        del_route $LAN_IF
        del_addr $LAN_IF
        del_eth_lan
        del_enx_lan
        del_usb_lan
        del_sap_lan
        del_wln_lan
        del_vap_lan
    fi
}

init_lan()
{
    if [ -z "$LAN_IF" ]; then
        return
    fi
    LAN_MAC=""
    lan_if=$(ifconfig -a | grep $LAN_IF | awk '{print $1}')
    if [ -n "$lan_if" ]; then
        LAN_MAC=$(ip addr show dev $LAN_IF | grep 'link/' | awk '{print $2}')
    fi
    stop_lan
    if [ "$LAN_OP" = "1" ]; then
        mac2=$(echo $ETH_MAC | cut -d ':' -f2)
        mac3=$(echo $ETH_MAC | cut -d ':' -f3)
        mac4=$(echo $ETH_MAC | cut -d ':' -f4)
        mac5=$(echo $ETH_MAC | cut -d ':' -f5)
        mac6=$(echo $ETH_MAC | cut -d ':' -f6)
        mac="fe:$mac2:$mac3:$mac4:$mac5:$mac6"
        if [ "$LAN_MAC" != "$mac" ]; then
            if [ -n "$LAN_MAC" ]; then
                brctl delbr $LAN_IF > /dev/null 2>&1
            fi
            LAN_MAC="$mac"
            brctl addbr $LAN_IF > /dev/null 2>&1
            brctl setfd $LAN_IF 1 > /dev/null 2>&1
            ip link set dev $LAN_IF address $LAN_MAC > /dev/null 2>&1
        fi
        ifconfig $LAN_IF 0.0.0.0 up
        lan_ip="$LAN_IP"
        lan_brd="$LAN_BRD"
        lan_gw="$LAN_GW"
        lan_start="$LAN_START"
        lan_end="$LAN_END"
        start_lan
        logger "LAN info ($LAN_IF): $LAN_IP (gateway $LAN_GW)"
        dump_lan
    fi
}

#*******************#
# Monitor Operation #
#*******************#
start_mon()
{
    iw dev $WIFI_IF interface add $MON_IF type monitor > /dev/null 2>&1
    MON_MAC=$(ip addr show dev $MON_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -n "$MON_MAC" ]; then
        ifconfig $MON_IF up
        sleep 1
        logger "MON info ($MON_IF): ready to start wireshark..."
    fi
}

stop_mon()
{
    kill_all "wireshark"
    if [ -n "$MON_MAC" ]; then
        ifconfig $MON_IF down
    fi
}

init_mon()
{
    if [ -z "$MON_IF" ]; then
        return
    fi
    MON_MAC=$(ip addr show dev $MON_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    stop_mon
    if [ "$MON_OP" = "1" ]; then
        if [ "$STA_OP" = "0" ] && [ "$WLN_OP" = "0" ]; then      
            iw dev $MON_IF set channel $WIFI_CHAN HT20
            start_mon
        fi
    fi
}

#****************#
# WLAN Operation #
#****************#
dump_wln()
{
    echo -n > $WLN_INFO
    {
        echo "WLN info:"
        echo "  WLN_IF=$WLN_IF"
        echo "  WLN_MAC=$WLN_MAC"
        if [ -n "$WLN_SSID" ]; then
            echo "  WLN_SSID=\"$WLN_SSID\""
            echo "  WLN_CHAN=$WLN_CHAN"
            if [ "$VAP_OP" = "1" ]; then
                echo "  VAP_IF=$VAP_IF"
                echo "  VAP_MAC=$VAP_MAC"
                echo "  VAP_SSID=\"$VAP_SSID\""
            fi
        fi
    } >> $WLN_INFO
}

ssid_wln()
{
    wif=$1
    SSID=""
    SSID1=$(iw dev $wif info | grep ssid | awk '{print $2}') > /dev/null 2>&1
    SSID2=$(iw dev $wif info | grep ssid | awk '{print $3}') > /dev/null 2>&1
    SSID3=$(iw dev $wif info | grep ssid | awk '{print $4}') > /dev/null 2>&1
    if [ -n "$SSID1" ]; then
        SSID="$SSID1"
        if [ -n "$SSID2" ]; then
            SSID="$SSID $SSID2"
            if [ -n "$SSID3" ]; then
                SSID="$SSID $SSID3"
            fi
        fi
    fi
    echo $SSID
}

reset_wln()
{
    stop_wln
    WLN_STATE="STARTING"
    WLN_SSID=""
    dump_wln
}

check_wln()
{
    WLN_MAC=$(ip addr show dev $WLN_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$WLN_MAC" ]; then
        if [ -e "$WLN_INFO" ]; then
            rm -f $WLN_INFO
        fi
        stop_wln
        WLN_OP=0
        WLN_IF=""
        sleep 1
        return
    fi
    pid=$(ps -e | grep hostapd | awk '{print $1}')
    if [ -z "$pid" ]; then
        reset_wln
        return
    fi
    ssid=$(ssid_wln $WLN_IF)
    if [ -z "$ssid" ]; then
        reset_wln
        return
    fi
    wln_phy=$(cat /sys/class/net/$WLN_IF/operstate) > /dev/null 2>&1
    if [ "$wln_phy" = "down" ]; then
        ifconfig $WLN_IF up
        return
    fi
    if [ -n "$WLN_POWER_TX" ]; then
        return
    fi
    if [ "$WLN_TOGGLE_TEST" = "1" ]; then
        WLN_TOGGLE_COUNT=$(($WLN_TOGGLE_COUNT - 1))
        if [ $WLN_TOGGLE_COUNT -eq 0 ]; then
            stop_wln
            sleep $WLN_TOGGLE_OFF
        fi
    elif [ "$WLN_SWING_TEST" = "1" ]; then
        if [ $WLN_SWING_COUNT -eq $WLN_SWING_DWELL ]; then
            logger "WLN info ($WLN_IF): set Tx power $WLN_SWING_LEVEL dBm"
            iwconfig $WLN_IF txpower $WLN_SWING_LEVEL
        fi
        WLN_SWING_COUNT=$(($WLN_SWING_COUNT - 1))
        if [ $WLN_SWING_COUNT -eq 0 ]; then
            WLN_SWING_COUNT=$WLN_SWING_DWELL
            if [ $WLN_SWING_CLIMB -eq 0 ]; then
                WLN_SWING_LEVEL=$(($WLN_SWING_LEVEL - $WLN_SWING_STEP))
                if [ $WLN_SWING_LEVEL -lt $WLN_SWING_LOW ]; then
                    WLN_SWING_LEVEL=$WLN_SWING_LOW
                    WLN_SWING_CLIMB=1
                fi
            else
                WLN_SWING_LEVEL=$(($WLN_SWING_LEVEL + $WLN_SWING_STEP))
                if [ $WLN_SWING_LEVEL -gt $WLN_SWING_HIGH ]; then
                    WLN_SWING_LEVEL=$WLN_SWING_HIGH
                    WLN_SWING_CLIMB=0
                fi
            fi
        fi
    fi
}

link_wln()
{
    pid=$(ps -e | grep hostapd | awk '{print $1}')
    if [ -n "$pid" ]; then
        ssid=$(ssid_wln $WLN_IF)
        if [ -n "$ssid" ]; then
            logger "WLN info ($WLN_IF): \"$ssid\" (bssid $WLN_MAC channel $WLN_CHAN)"
            WLN_STATE="COMPLETED"
            WLN_SSID="$ssid"
            if [ "$VAP_OP" = "1" ]; then
                VAP_MAC=$(ip addr show dev $VAP_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
                VAP_SSID=$(ssid_wln $VAP_IF)
                logger "VAP info ($VAP_IF): \"$VAP_SSID\" (bssid $VAP_MAC)"
            fi
            dump_wln
            if [ "$MON_OP" = "1" ]; then
                start_mon
            fi
            if [ -n "$WLN_POWER_TX" ]; then
                iwconfig $WLN_IF txpower $WLN_POWER_TX
            elif [ "$WLN_TOGGLE_TEST" = "1" ]; then
                WLN_TOGGLE_COUNT=$WLN_TOGGLE_ON
            elif [ "$WLN_SWING_TEST" = "1" ]; then
                WLN_SWING_COUNT=$WLN_SWING_DWELL
                WLN_SWING_LEVEL=$WLN_SWING_HIGH
                WLN_SWING_CLIMB=0
            fi
            return
        fi
    fi
    if [ $WLN_LINK_COUNT -gt 0 ]; then
        WLN_LINK_COUNT=$(($WLN_LINK_COUNT - 1))
    fi
    if [ $WLN_LINK_COUNT -eq 0 ]; then
        stop_wln
        WLN_STATE="STARTING"
    fi
}

start_wln()
{
    ifconfig $WLN_IF 0.0.0.0 up
    WLN_CHAN=$(cat $WLN_CONF | grep 'channel=' | cut -d '=' -f2)
    if [ "$WLN_DBG" = "1" ]; then
        $HOSTAPD -B -t -f $WLN_LOG $WLN_CONF > /dev/null 2>&1
    elif [ "$WLN_DBG" = "2" ]; then
        $HOSTAPD -B -t -f $WLN_LOG -d $WLN_CONF > /dev/null 2>&1
    elif [ "$WLN_DBG" = "3" ]; then
        $HOSTAPD -B -t -f $WLN_LOG -d -K $WLN_CONF > /dev/null 2>&1
    else
        $HOSTAPD -B -t $WLN_CONF > /dev/null 2>&1
    fi
    WLN_STATE="STARTED"
    WLN_LINK_COUNT=10
}

stop_wln()
{
    kill_all "$HOSTAPD"
    if [ -e $WLN_CTRL ]; then
        rm -rf $WLN_CTRL
    fi
    if [ -n "$WLN_MAC" ]; then
        ifconfig $WLN_IF down
    fi
}

init_wln()
{
    if [ -z "$WLN_IF" ]; then
        return
    fi
    WLN_MAC=$(ip addr show dev $WLN_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$WLN_MAC" ]; then
        logger "Cannot find WLN interface $WLN_IF"
        WLN_OP=0
        WLN_IF=""
        return
    fi
    stop_wln
    if [ "$WLN_OP" = "1" ]; then
        WLN_STATE="STARTING"
    fi
}

#*******************#
# Soft AP Operation #
#*******************#
dump_lan_sap()
{
    echo -n > $LAN_INFO
    {
        echo "LAN info:"
        echo "  LAN_IF=$LAN_IF"
        echo "  LAN_MAC=$LAN_MAC"
        echo "  LAN_IP=$SAP_IP"
        echo "  LAN_START=$SAP_START"
        echo "  LAN_END=$SAP_END"
        echo "  LAN_GW=$SAP_GW"
    } >> $LAN_INFO
}

dhcp_sap()
{
    kill_all "$DHCPSRV"
    lan_ip=$SAP_IP
    lan_brd=$SAP_BRD
    lan_gw=$SAP_GW
    lan_start=$SAP_START
    lan_end=$SAP_END
    start_lan
    logger "LAN info ($SAP_IF): $SAP_IP (gateway $SAP_GW)"
    dump_lan_sap
}

update_sap()
{
    if [ "$SAP_BR" = "0" ]; then
        gw1=$(echo $SAP_GW | cut -d '.' -f1)
        gw2=$(echo $SAP_GW | cut -d '.' -f2)
        gw3=$(echo $SAP_GW | cut -d '.' -f3)
        gw4=$(echo $SAP_GW | cut -d '.' -f4)
        if [ $gw4 -eq 177 ]; then
            ping_test="$gw1.$gw2.$gw3.161"
            ping -I $STA_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                SAP_IP="192.168.120.161/27"
                SAP_BRD="192.168.120.191"
                SAP_GW="192.168.120.161"
                SAP_START="192.168.120.162"
                SAP_END="192.168.120.174"
                dhcp_sap
            fi
        elif [ $gw4 -eq 241 ]; then
            ping_test="$gw1.$gw2.$gw3.225"
            ping -I $STA_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                SAP_IP="192.168.120.225/27"
                SAP_BRD="192.168.120.255"
                SAP_GW="192.168.120.225"
                SAP_START="192.168.120.226"
                SAP_END="192.168.120.238"
                dhcp_sap
            fi
        fi
    fi
}

config_sap()
{
    if [ "$SAP_BR" = "0" ]; then
        del_addr $LAN_IF
        del_route $LAN_IF
        gw1=$(echo $STA_WAN_GW | cut -d '.' -f1)
        gw2=$(echo $STA_WAN_GW | cut -d '.' -f2)
        gw3=$(echo $STA_WAN_GW | cut -d '.' -f3)
        gw4=$(echo $STA_WAN_GW | cut -d '.' -f4)
        if [ $gw4 -eq 129 ]; then
            ping_test="$gw1.$gw2.$gw3.161"
            ping -I $STA_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                gw4=161
            fi
        elif [ $gw4 -eq 193 ]; then
            ping_test="$gw1.$gw2.$gw3.225"
            ping -I $STA_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                gw4=225
            fi
        fi
        if [ $gw4 -eq 1 ]; then
            SAP_IP="192.168.120.113/28"
            SAP_BRD="192.168.120.127"
            SAP_GW="192.168.120.113"
            SAP_START="192.168.120.114"
            SAP_END="192.168.120.126"
        elif [ $gw4 -eq 129 ]; then
            SAP_IP="192.168.120.161/27"
            SAP_BRD="192.168.120.191"
            SAP_GW="192.168.120.161"
            SAP_START="192.168.120.162"
            SAP_END="192.168.120.174"
        elif [ $gw4 -eq 161 ]; then
            SAP_IP="192.168.120.177/28"
            SAP_BRD="192.168.120.191"
            SAP_GW="192.168.120.177"
            SAP_START="192.168.120.178"
            SAP_END="192.168.120.190"
        elif [ $gw4 -eq 193 ]; then
            SAP_IP="192.168.120.225/27"
            SAP_BRD="192.168.120.255"
            SAP_GW="192.168.120.225"
            SAP_START="192.168.120.226"
            SAP_END="192.168.120.238"
        else
            SAP_IP="192.168.120.241/28"
            SAP_BRD="192.168.120.255"
            SAP_GW="192.168.120.241"
            SAP_START="192.168.120.242"
            SAP_END="192.168.120.254"
        fi
        dhcp_sap
    fi
}

dump_sap()
{
    echo -n > $SAP_INFO
    {
        echo "SAP info:"
        echo "  SAP_IF=$SAP_IF"
        echo "  SAP_MAC=$SAP_MAC"
        if [ -n "$SAP_SSID" ]; then
            echo "  SAP_SSID=\"$SAP_SSID\""
        fi
    } >> $SAP_INFO
}

ssid_sap()
{
    SSID=""
    SSID1=$(iw dev $SAP_IF info | grep ssid | awk '{print $2}') > /dev/null 2>&1
    SSID2=$(iw dev $SAP_IF info | grep ssid | awk '{print $3}') > /dev/null 2>&1
    SSID3=$(iw dev $SAP_IF info | grep ssid | awk '{print $4}') > /dev/null 2>&1
    if [ -n "$SSID1" ]; then
        SSID="$SSID1"
        if [ -n "$SSID2" ]; then
            SSID="$SSID $SSID2"
            if [ -n "$SSID3" ]; then
                SSID="$SSID $SSID3"
            fi
        fi
    fi
    echo $SSID
}

reset_sap()
{
    stop_sap
    SAP_SSID=""
    SAP_CHAN=0
    dump_sap
}

link_sap()
{
    if [ -n "$SAP_SSID" ]; then
        reset_sap
        SAP_COUNT=5
        return
    fi
    if [ $SAP_COUNT -gt 0 ]; then
        SAP_COUNT=$(($SAP_COUNT - 1))
    fi
    if [ $SAP_COUNT -eq 0 ]; then
        start_sap
    fi
}

check_sap()
{
    SAP_MAC=$(ip addr show dev $SAP_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$SAP_MAC" ]; then
        if [ -e "$SAP_INFO" ]; then
            rm -f $SAP_INFO
        fi
        stop_sap
        SAP_OP=0
        SAP_IF=""
        sleep 1
        return
    fi
    pid=$(ps -e | grep hostapd | awk '{print $1}')
    if [ -z "$pid" ]; then
        link_sap
        return
    fi
    ssid=$(ssid_sap)
    if [ -z "$ssid" ]; then
        link_sap
        return
    fi
    if [ -z "$SAP_SSID" ]; then
        logger "SAP info ($SAP_IF): \"$ssid\" (bssid $SAP_MAC)"
        SAP_SSID="$ssid"
        dump_sap
        if [ -n "$SAP_POWER_TX" ]; then
            iwconfig $SAP_IF txpower $SAP_POWER_TX
        fi
        return
    fi
    sap_phy=$(cat /sys/class/net/$SAP_IF/operstate) > /dev/null 2>&1
    if [ "$sap_phy" = "down" ]; then
        ifconfig $SAP_IF up
        return
    fi
}

start_sap()
{
    if [ $SAP_CHAN -ne $STA_CHAN ]; then
        sed '/channel=/d' $SAP_CONF > /tmp/hostapd-sap0.conf
        mv -f /tmp/hostapd-sap0.conf $SAP_CONF
        echo channel=$STA_CHAN >> $SAP_CONF
        SAP_CHAN=$STA_CHAN
    fi
    if [ "$SAP_DBG" = "1" ]; then
        $HOSTAPD -B -t -f $SAP_LOG $SAP_CONF > /dev/null 2>&1
    elif [ "$SAP_DBG" = "2" ]; then
        $HOSTAPD -B -t -f $SAP_LOG -d $SAP_CONF > /dev/null 2>&1
    elif [ "$SAP_DBG" = "3" ]; then
        $HOSTAPD -B -t -f $SAP_LOG -d -K $SAP_CONF > /dev/null 2>&1
    else
        $HOSTAPD -B -t $SAP_CONF > /dev/null 2>&1
    fi
    SAP_COUNT=10
}

stop_sap()
{
    kill_all "$HOSTAPD"
    if [ -e $SAP_CTRL ]; then
        rm -rf $SAP_CTRL
    fi
    if [ -n "$SAP_MAC" ]; then
        ifconfig $SAP_IF down
    fi
}

init_sap()
{
    if [ -z "$SAP_IF" ] || [ -z "$STA_MAC" ]; then
        return
    fi
    SAP_MAC=""
    sap_if=$(ifconfig -a | grep $SAP_IF | awk '{print $1}')
    if [ -n "$sap_if" ]; then
        SAP_MAC=$(ip addr show dev $SAP_IF | grep 'link/' | awk '{print $2}')
    fi
    stop_sap
    if [ "$SAP_OP" = "1" ]; then
        mac2=$(echo $WIFI_MAC | cut -d ':' -f2)
        mac3=$(echo $WIFI_MAC | cut -d ':' -f3)
        mac4=$(echo $WIFI_MAC | cut -d ':' -f4)
        mac5=$(echo $WIFI_MAC | cut -d ':' -f5)
        mac6=$(echo $WIFI_MAC | cut -d ':' -f6)
        mac="fe:$mac2:$mac3:$mac4:$mac5:$mac6"
        if [ "$SAP_MAC" != "$mac" ]; then
            if [ -n "$SAP_MAC" ]; then
                iw dev $SAP_IF del
            fi
            SAP_MAC="$mac"
            iw dev $WIFI_IF interface add $SAP_IF type managed > /dev/null 2>&1
            ip link set dev $SAP_IF address $SAP_MAC
        fi
        ifconfig $SAP_IF 0.0.0.0 up
        SAP_IP="$LAN_IP"
        SAP_BRD="$LAN_BRD"
        SAP_GW="$LAN_GW"
        SAP_START="$LAN_START"
        SAP_END="$LAN_END"
        SAP_SSID=""
        SAP_CHAN=0
    fi
}

#***************#
# STA Operation #
#***************#
dump_wan_sta()
{
    if [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
        eth_gw=$(ip route show dev $ETH_IF | grep default | awk '{print $3}')
        if [ -n "$eth_gw" ]; then
            dump_wan_eth
            return
        fi
    fi
    echo -n > $WAN_INFO
    {
        echo "WAN info:"
        if [ "$BRI_OP" = "2" ]; then
            echo "  WAN_IF=$BRI_IF"
            echo "  WAN_MAC=$BRI_MAC"
        else
            echo "  WAN_IF=$STA_IF"
            echo "  WAN_MAC=$STA_MAC"
        fi
        if [ -n "$STA_WAN_GW" ]; then
            echo "  WAN_GW=$STA_WAN_GW"
        fi
        if [ -n "$STA_WAN_IP" ]; then
            echo "  WAN_IP=$STA_WAN_IP"
        fi
        if [ -n "$STA_WAN_NET" ]; then
            echo "  WAN_NET=$STA_WAN_NET"
        fi
    } >> $WAN_INFO
}

ssid_sta()
{
    SSIDNum=0
    SSIDSeq=""
    SSIDExt=""
    SSIDArg=""
    cat $STA_CONF | grep 'ssid="' | cut -d '"' -f2 > tmpssids
    cat $STA_CONF | grep 'disabled=' | cut -d '=' -f2 > tmpdisabs
    while [ 1 ]; do
        if [ $SSIDNum -ge 4 ]; then
            break
        fi
        ssid1=$(cat tmpssids | head -n1)
        if [ -n "$ssid1" ]; then
            disab=$(cat tmpdisabs | head -n1)
            if [ -z "$disab" ] || [ "$disab" = "0" ]; then
                ssid2=$(echo $ssid1 | cut -d ' ' -f2)
                if [ "$ssid2" = "$ssid1" ]; then
                    SSIDSeq=${SSIDSeq}" \"$ssid1\""
                    SSIDArg=${SSIDArg}" ssid $ssid1"
                    SSIDNum=$(($SSIDNum + 1))
                elif [ -z "$SSIDExt" ]; then
                    SSIDExt="$ssid1"
                    SSIDNum=$(($SSIDNum + 1))
                fi
            fi
            sed '1d' tmpssids > modssids
            mv modssids tmpssids
            sed '1d' tmpdisabs > moddisabs
            mv moddisabs tmpdisabs
        else
            break
        fi
    done
    rm -f tmpssids
    rm -f tmpdisabs
    if [ $SSIDNum -eq 0 ]; then
        logger "Cannot find any configured Wi-Fi WAN network (no SSID)"
        exit 0
    fi
    if [ -z "$SSIDExt" ]; then
        logger "STA info ($STA_IF): configured network(s) $SSIDSeq"
    elif [ $SSIDNum -eq 1 ]; then
        logger "STA info ($STA_IF): configured network \"$SSIDExt\""
    else
        logger "STA info ($STA_IF): configured network(s) $SSIDSeq \"$SSIDExt\""
    fi
}

ping_sta()
{
    if [ "$BRI_OP" = "2" ] && [ -n "$BRI_PING_IP" ]; then
        ping -I $STA_WAN_IF "$BRI_PING_IP" -c 1 -W 5 -s 20 > /dev/null 2>&1
    elif [ "$BRI_OP" != "2" ] && [ -n "$STA_PING_IP" ]; then
        ping -I $STA_WAN_IF "$STA_PING_IP" -c 1 -W 5 -s 20 > /dev/null 2>&1
    elif [ $STA_PING_PUBLIC -eq 0 ]; then
        ping -I $STA_WAN_IF "$STA_WAN_GW" -c 1 -W 5 -s 20 > /dev/null 2>&1
    else
        ping -I $STA_WAN_IF "8.8.8.8" -c 1 -W 10 -s 20 > /dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then
        STA_PING_PUBLIC=0
        STA_PING_COUNT=3
    else
        if [ $STA_PING_PUBLIC -eq 0 ]; then
            STA_PING_PUBLIC=1
            STA_PING_COUNT=3
        else
            STA_PING_COUNT=$(($STA_PING_COUNT - 1))
            if [ $STA_PING_COUNT -le 0 ]; then
                if [ $STA_PING_PUBLIC -eq 0 ]; then
                    STA_PING_PUBLIC=1
                    STA_PING_COUNT=3
                    return 0
                fi
                return 1
            fi
        fi
    fi
    return 0
}

dump_sta()
{
    echo -n > $STA_INFO
    {
        echo "STA info:"
        echo "  STA_IF=$STA_IF"
        echo "  STA_MAC=$STA_MAC"
        if [ -n "$STA_BSSID" ]; then
            echo "  STA_CHAN=$STA_CHAN"
            echo "  STA_SSID=\"$STA_SSID\""
            echo "  STA_BSSID=$STA_BSSID"
        fi
    } >> $STA_INFO
}

clean_sta()
{
    if [ "$BRI_OP" = "2" ]; then
        brif=$(brctl show $BRI_IF | grep $STA_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            return
        fi
        kill_one "$BRI_DHCP_PID"
        if [ -e "$BRI_DHCP_LEASE" ]; then
            rm -f $BRI_DHCP_LEASE
        fi
        del_sta_bri
    else
        kill_one "$STA_DHCP_PID"
        if [ -e $STA_DHCP_LEASE ]; then
            rm -f $STA_DHCP_LEASE
        fi
    fi
    if [ -e "$WAN_INFO" ]; then
        rm -f $WAN_INFO
    fi
    del_default_route $STA_WAN_IF
    del_route $STA_WAN_IF
    del_addr $STA_WAN_IF
    STA_WAN_GW=""
}

static_sta()
{
    clean_sta
    if [ "$BRI_OP" = "2" ]; then
        ip addr add dev $BRI_IF $BRI_IP broadcast $BRI_BRD > /dev/null 2>&1
        ip route add default via $BRI_GW dev $BRI_IF > /dev/null 2>&1
    else
        ip addr add dev $STA_IF $STA_IP broadcast $STA_BRD > /dev/null 2>&1
        ip route add default via $STA_GW dev $STA_IF > /dev/null 2>&1
    fi
    STA_DHCP_STARTED=0
}

dynamic_sta()
{
    clean_sta
    if [ "$BRI_OP" = "2" ]; then
        $DHCPCLI -nw -1 -q -pf $BRI_DHCP_PID -lf $BRI_DHCP_LEASE $BRI_IF > /dev/null 2>&1
    else
        $DHCPCLI -nw -1 -q -pf $STA_DHCP_PID -lf $STA_DHCP_LEASE $STA_IF > /dev/null 2>&1
    fi
    STA_DHCP_COUNT=12
    STA_DHCP_STARTED=1
}

config_sta()
{
    if [ "$BRI_OP" = "2" ] && [ "$BRI_CONFIG" = "0" ]; then
        static_sta
    elif [ "$BRI_OP" != "2" ] && [ "$STA_CONFIG" = "0" ]; then
        static_sta
    else
        if [ $STA_DHCP_STARTED -eq 1 ]; then
            if [ $STA_DHCP_COUNT -gt 0 ]; then
                STA_DHCP_COUNT=$(($STA_DHCP_COUNT - 1))
                return
            fi
            static_sta
        else
            dynamic_sta
        fi
    fi
}

bssid_sta()
{
    STA_BSSID="$1"
    sta_ssid=$(iw dev $STA_IF link | grep 'SSID:' | awk '{print $2}') > /dev/null 2>&1
    sta_ssid2=$(iw dev $STA_IF link | grep 'SSID:' | awk '{print $3}') > /dev/null 2>&1
    if [ -n "$sta_ssid" ] && [ -n "$sta_ssid2" ]; then
        ssid="$sta_ssid $sta_ssid2"
    fi
    if [ "$sta_ssid" != "$STA_SSID" ]; then
        if [ -n "$STA_SSID" ]; then
            clean_sta
        fi
        STA_SSID="$sta_ssid"
    fi
    STA_CHAN=$(iw dev $STA_IF info | grep channel | awk '{print $2}') > /dev/null 2>&1
    logger "STA info ($STA_IF): \"$STA_SSID\" (bssid $STA_BSSID channel $STA_CHAN)"
    STA_RSSI=""
    STA_WAN_GW=""
    STA_WAN_IP=""
    STA_WAN_NET=""
    STA_DHCP_COUNT=0
    STA_DHCP_STARTED=0
}

lost_sta()
{
    logger "STA info ($STA_IF): lost AP (bssid $STA_BSSID)"
    if [ "$ETH_OP" = "1" ] && [ $ETH_PHY_UP -eq 1 ]; then
        ETH_STATE="ATTACHED"
    fi
    if [ "$SAP_OP" = "1" ]; then
        reset_sap
    fi
    STA_BSSID=""
    clean_sta
}

check_sta()
{
    STA_MAC=$(ip addr show dev $STA_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$STA_MAC" ]; then
        if [ -e "$WAN_INFO" ]; then
            rm -f $WAN_INFO
        fi
        if [ -e "$SAP_INFO" ]; then
            rm -f $SAP_INFO
        fi
        stop_sta
        STA_OP=0
        STA_IF=""
        sleep 1
        return
    fi
    pid=$(ps -e | grep wpa_supplicant | awk '{print $1}')
    if [ -z "$pid" ]; then
        if [ -n "$STA_BSSID" ]; then
            lost_sta
        fi
        stop_sta
        STA_STATE="STARTING"
        return
    fi
    bssid=$(iw dev $STA_IF link | grep Connected | awk '{print $3}') > /dev/null 2>&1
    if [ -z "$bssid" ]; then
        if [ -n "$STA_BSSID" ]; then
            lost_sta
        fi
        return
    fi
    if [ "$bssid" != "$STA_BSSID" ]; then
        bssid_sta "$bssid"
        dump_sta
        if [ -n "$STA_WAN_GW" ] && [ "$STA_PING" = "1" ]; then
            STA_PING_PUBLIC=1
            STA_PING_COUNT=1
            STA_WAN_COUNT=0
        fi
    fi
    rssi=$(iw dev $STA_IF link | grep 'signal:' | awk '{print $2}') > /dev/null 2>&1    
    if [ -z "$rssi" ]; then
        if [ -n "$STA_BSSID" ]; then
            lost_sta
        fi
        return
    fi
    if [ -z "$STA_RSSI" ]; then
        STA_RSSI=$rssi
        logger "STA info ($STA_IF): rssi $rssi dBm"
        STA_RSSI_2=$STA_RSSI
        STA_RSSI_1=$STA_RSSI
        STA_RSSI_0=$STA_RSSI
        STA_ROAM_FULL_SCAN=50
        STA_ROAM_FAST_SCAN=0
        if [ "$SAP_OP" = "1" ]; then
            start_sap
        fi
    fi
    STA_RSSI_3=$STA_RSSI_2
    STA_RSSI_2=$STA_RSSI_1
    STA_RSSI_1=$STA_RSSI_0
    STA_RSSI_0=$rssi
    rssi=$((($STA_RSSI_3 + (2 * $STA_RSSI_2) + (2 * $STA_RSSI_1) + (3 * $STA_RSSI_0)) / 8))
    if [ $rssi -gt $(($STA_RSSI + $STA_RSSI_STEP)) ] || [ $rssi -lt $(($STA_RSSI - $STA_RSSI_STEP)) ]; then
        STA_RSSI=$rssi
        logger "STA info ($STA_IF): rssi $rssi dBm"
    fi
    if [ "$STA_ROAM_OFF" = "0" ]; then
        STA_ROAM_FULL_SCAN=$(($STA_ROAM_FULL_SCAN + 1))
        STA_ROAM_FAST_SCAN=$(($STA_ROAM_FAST_SCAN + 1))
        if [ $STA_ROAM_FULL_SCAN -ge 55 ] && [ $STA_ROAM_FAST_SCAN -ge 5 ]; then
            STA_ROAM_FULL_SCAN=0
            STA_ROAM_FAST_SCAN=0
            logger "STA info ($STA_IF): start roam full scan (rssi $rssi dBm)"
            wpa_cli -p $STA_CTRL scan > /dev/null 2>&1
            return
        fi
        if [ $rssi -le -75 ] && [ $STA_ROAM_FAST_SCAN -ge 5 ] && [ $STA_ROAM_FULL_SCAN -ge 10 ]; then
            STA_ROAM_FAST_SCAN=0
        elif [ $rssi -le -65 ] && [ $STA_ROAM_FAST_SCAN -ge 10 ]; then
            STA_ROAM_FAST_SCAN=0
        fi
        if [ $STA_ROAM_FAST_SCAN -eq 0 ]; then
            logger "STA info ($STA_IF): start roam fast scan (rssi $rssi dBm)"
            if [ -n "$SSIDArg" ]; then
                wpa_cli -p $STA_CTRL scan $SSIDArg > /dev/null 2>&1
            else
                wpa_cli -p $STA_CTRL scan > /dev/null 2>&1
            fi
            return
        fi
    fi
    sta_phy=$(cat /sys/class/net/$STA_IF/operstate) > /dev/null 2>&1
    if [ "$sta_phy" = "down" ]; then
        ifconfig $STA_IF up
        return
    fi
    if [ "$SAP_OP" = "1" ]; then
        check_sap
    fi
    if [ "$BRI_OP" = "1" ]; then
        sta_ip=$(ip addr show $STA_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$sta_ip" ]; then
            config_sta
            return
        fi
        sta_gw=$(ip route show dev $STA_IF | grep default | awk '{print $3}')
        if [ -n "$sta_gw" ]; then
            del_default_route $STA_IF
        fi
        return
    fi
    if [ "$BRI_OP" = "2" ]; then
        add_sta_bri
        sta_ip=$(ip addr show $BRI_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$sta_ip" ]; then
            config_sta
            return
        fi
    else
        if [ "$ENX_OP" = "1" ] && [ $ENX_PHY_UP -eq 1 ]; then
            enx_gw=$(ip route show dev $ENX_IF | grep default | awk '{print $3}')
            if [ -n "$enx_gw" ]; then
                del_default_route $ENX_IF
                ENX_WAN_GW=""
            fi
        fi
        if [ "$USB_OP" = "1" ] && [ $USB_PHY_UP -eq 1 ]; then
            usb_gw=$(ip route show dev $USB_IF | grep default | awk '{print $3}')
            if [ -n "$usb_gw" ]; then
                del_default_route $USB_IF
                USB_WAN_GW=""
            fi
        fi
        if [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
            if [ "$STA_PRI" = "1" ]; then
                ETH_STATE="DETACHED"
                ETH_WAN_DUMMY=0
                clean_eth
            fi
            return
        fi
        sta_ip=$(ip addr show $STA_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$sta_ip" ]; then
            if [ -n "$STA_WAN_IP" ]; then
                ip addr add dev $STA_IF $STA_WAN_IP broadcast $STA_WAN_BRD > /dev/null 2>&1
                STA_WAN_IP=""
                return
            fi
            if [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
                if [ "$BRI_OP" != "1" ] && [ "$STA_PRI" = "1" ]; then
                    ETH_STATE="DETACHED"
                    ETH_WAN_DUMMY=0
                    clean_eth
                    return
                fi
            fi
            config_sta
            return
        fi
    fi
    if [ "$sta_ip" != "$STA_WAN_IP" ]; then
        STA_DHCP_STARTED=0
        STA_WAN_IP="$sta_ip"
        STA_WAN_BRD=$(ip addr show dev $STA_WAN_IF | grep $STA_WAN_IP | head -n1 | awk '{print $4}')
        STA_WAN_NET=""
        sta_routes=$(ip route show dev $STA_WAN_IF | awk '{print $1}')
        for sta_net in $sta_routes; do
            if [ "$sta_net" = "default" ]; then
                continue
            fi
            STA_WAN_NET=${sta_net}" $STA_WAN_NET"
        done
        if [ "$ENX_OP" = "1" ] && [ $ENX_PHY_UP -eq 1 ]; then
            for enx_route in $(ip route | grep dev.*$ENX_IF | awk '{print $1}'); do
                for enx_route in $STA_WAN_NET; do
                    ip route del $enx_route dev $ENX_IF > /dev/null 2>&1
                done
            done
        fi
        if [ "$USB_OP" = "1" ] && [ $USB_PHY_UP -eq 1 ]; then
            for usb_route in $(ip route | grep dev.*$USB_IF | awk '{print $1}'); do
                for usb_route in $STA_WAN_NET; do
                    ip route del $usb_route dev $USB_IF > /dev/null 2>&1
                done
            done
        fi
        dump_wan_sta
    fi
    if [ "$BRI_OP" = "0" ] && [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
        if [ "$STA_PRI" = "1" ]; then
            ETH_STATE="DETACHED"
            ETH_WAN_DUMMY=0
            clean_eth
            return
        else
            eth_ip=$(ip addr show $ETH_IF | grep 'inet ' | head -n1 | awk '{print $2}')
            if [ -n "$eth_ip" ]; then
                return
            fi
        fi
    fi
    sta_gw=$(ip route show dev $STA_WAN_IF | grep default | head -n1 | awk '{print $3}')
    if [ -z "$sta_gw" ]; then
        if [ "$BRI_OP" = "0" ]; then
            sta_net=$(ip route show dev $STA_IF | head -n1 | awk '{print $1}')
            if [ -z "$sta_net" ]; then
                if [ -n "$STA_WAN_GW" ] && [ -n "$STA_WAN_NET" ]; then
                    for sta_net in $STA_WAN_NET; do
                        ip route add $sta_net dev $STA_IF > /dev/null 2>&1
                    done
                    ip route add default via $STA_WAN_GW dev $STA_IF > /dev/null 2>&1
                    STA_WAN_GW=""
                    STA_WAN_NET=""
                    return
                fi
            fi
        fi
        config_sta
        return
    fi
    if [ "$sta_gw" != "$STA_WAN_GW" ]; then
        STA_DHCP_STARTED=0
        STA_WAN_GW="$sta_gw"
        logger "WAN info ($STA_WAN_IF): $STA_WAN_IP (gateway $STA_WAN_GW)"
        STA_PING_PUBLIC=1
        STA_PING_COUNT=3
        STA_WAN_COUNT=15
        add_public_dns
        dump_wan_sta
        if [ "$SAP_OP" = "1" ] && [ "$SAP_CONFIG" = "1" ]; then
            config_sap
        fi
    fi
    if [ ! -e "$WAN_INFO" ]; then
        dump_wan_sta
    fi
    if [ $STA_WAN_COUNT -gt 0 ]; then
        STA_WAN_COUNT=$(($STA_WAN_COUNT - 1))
        return
    fi
    STA_WAN_COUNT=4
    if [ "$SAP_OP" = "1" ] && [ "$SAP_CONFIG" = "1" ]; then
        update_sap
    fi
    if [ -n "$STA_WAN_GW" ] && [ "$STA_PING" = "1" ]; then
        ping_sta
        if [ $? -eq 1 ]; then
            logger "WAN info ($STA_WAN_IF): lost IP connection (local $STA_WAN_IP)"
            if [ "$BRI_OP" = "0" ] && [ "$ETH_OP" = "1" ] && [ $ETH_PHY_UP -eq 1 ]; then
                ETH_STATE="ATTACHED"
                clean_sta
            else
                config_sta
                dump_wan_sta
            fi
        fi
    fi
}

link_sta()
{
    pid=$(ps -e | grep wpa_supplicant | awk '{print $1}')
    if [ -n "$pid" ]; then
        bssid=$(iw dev $STA_IF link | grep Connected | awk '{print $3}') > /dev/null 2>&1
        if [ -n "$bssid" ]; then
            bssid_sta "$bssid"
            dump_sta
            STA_STATE="COMPLETED"
            if [ "$MON_OP" = "1" ]; then
                start_mon
            fi
            return
        fi
    fi
    if [ $STA_LINK_COUNT -gt 0 ]; then
        STA_LINK_COUNT=$(($STA_LINK_COUNT - 1))
        return
    fi
    stop_sta
    STA_STATE="STARTING"
}

start_sta()
{
    ifconfig $STA_IF 0.0.0.0 up
    if [ "$BRI_OP" = "2" ]; then
        if [ "$STA_DBG" = "1" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -b $BRI_IF -t -f $STA_LOG -c $STA_CONF > /dev/null 2>&1
        elif [ "$STA_DBG" = "2" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -b $BRI_IF -t -f $STA_LOG -d -c $STA_CONF > /dev/null 2>&1
        elif [ "$STA_DBG" = "3" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -b $BRI_IF -t -f $STA_LOG -d -K -c $STA_CONF > /dev/null 2>&1
        else
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -b $BRI_IF -t -s -c $STA_CONF > /dev/null 2>&1
        fi
    else
        if [ "$STA_DBG" = "1" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -t -f $STA_LOG -c $STA_CONF > /dev/null 2>&1
        elif [ "$STA_DBG" = "2" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -t -f $STA_LOG -d -c $STA_CONF > /dev/null 2>&1
        elif [ "$STA_DBG" = "3" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -t -f $STA_LOG -d -K -c $STA_CONF > /dev/null 2>&1
        else
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -t -s -c $STA_CONF > /dev/null 2>&1
        fi
    fi
    STA_CHAN=0
    STA_SSID=""
    STA_STATE="STARTED"
    STA_LINK_COUNT=30
}

stop_sta()
{
    kill_all "$WPASUPP"
    if [ -e $STA_CTRL ]; then
        rm -rf $STA_CTRL
    fi
    kill_one "$STA_DHCP_PID"
    if [ -e $STA_DHCP_LEASE ]; then
        rm -f $STA_DHCP_LEASE
    fi
    if [ -n "$STA_MAC" ]; then
        ifconfig $STA_IF down
        del_default_route $STA_IF
        del_route $STA_IF
        del_addr $STA_IF
    fi
}

init_sta()
{
    if [ -z "$STA_IF" ]; then
        return
    fi
    STA_MAC=$(ip addr show dev $STA_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$STA_MAC" ]; then
        logger "Cannot find STA interface $STA_IF"
        STA_OP=0
        STA_IF=""
        return
    fi
    stop_sta
    if [ "$STA_OP" = "1" ]; then
        ssid_sta
        if [ "$BRI_OP" = "2" ]; then
            STA_WAN_IF=$BRI_IF
        else
            STA_WAN_IF=$STA_IF
        fi
        STA_STATE="STARTING"
    fi
}

#***************#
# ENX Operation #
#***************#
dump_wan_enx()
{
    if [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
        eth_gw=$(ip route show dev $ETH_IF | grep default | awk '{print $3}')
        if [ -n "$eth_gw" ]; then
            dump_wan_eth
            return
        fi
    fi
    if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
        sta_gw=$(ip route show dev $STA_IF | grep default | awk '{print $3}')
        if [ -n "$sta_gw" ]; then
            dump_wan_sta
            return
        fi
    fi
    echo -n > $WAN_INFO
    {
        echo "WAN info:"
        echo "  WAN_IF=$ENX_IF"
        echo "  WAN_MAC=$ENX_MAC"
        if [ -n "$ENX_WAN_GW" ]; then
            echo "  WAN_GW=$ENX_WAN_GW"
        fi
        if [ -n "$ENX_WAN_IP" ]; then
            echo "  WAN_IP=$ENX_WAN_IP"
        fi
        if [ -n "$ENX_WAN_NET" ]; then
            echo "  WAN_NET=$ENX_WAN_NET"
        fi
    } >> $WAN_INFO
}

ping_enx()
{
    if [ -n "$ENX_PING_IP" ]; then
        ping -I $ENX_IF "$ENX_PING_IP" -c 1 -W 5 -s 20 > /dev/null 2>&1
    elif [ $ENX_PING_PUBLIC -eq 0 ]; then
        ping -I $ENX_IF "$ENX_WAN_GW" -c 1 -W 2 -s 20 > /dev/null 2>&1
    else
        ping -I $ENX_IF "8.8.8.8" -c 1 -W 4 -s 20 > /dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then
        ENX_PING_PUBLIC=0
        ENX_PING_COUNT=3
    else
        if [ $ENX_PING_PUBLIC -eq 0 ]; then
            ENX_PING_PUBLIC=1
            ENX_PING_COUNT=3
        else
            ENX_PING_COUNT=$(($ENX_PING_COUNT - 1))
            if [ $ENX_PING_COUNT -le 0 ]; then
                if [ $ENX_PING_PUBLIC -eq 0 ]; then
                    ENX_PING_PUBLIC=1
                    ENX_PING_COUNT=3
                    return 0
                fi
                return 1
            fi
        fi
    fi
    return 0
}

clean_enx()
{
    kill_one "$ENX_DHCP_PID"
    if [ -e "$ENX_DHCP_LEASE" ]; then
        rm -f $ENX_DHCP_LEASE
    fi
    del_default_route $ENX_IF
    del_route $ENX_IF
    del_addr $ENX_IF
    ENX_WAN_GW=""
}

static_enx()
{
    clean_enx
    ip addr add dev $ENX_IF $ENX_IP broadcast $ENX_BRD > /dev/null 2>&1
    ip route add default via $ENX_GW dev $ENX_IF > /dev/null 2>&1
    ENX_DHCP_STARTED=0
}

dynamic_enx()
{
    clean_enx
    $DHCPCLI -nw -1 -q -pf $ENX_DHCP_PID -lf $ENX_DHCP_LEASE $ENX_IF > /dev/null 2>&1
    ENX_DHCP_COUNT=8
    ENX_DHCP_STARTED=1
}

config_enx()
{
    if [ "$ENX_CONFIG" = "0" ]; then
        static_enx
    else
        if [ $ENX_DHCP_STARTED -eq 1 ]; then
            if [ $ENX_DHCP_COUNT -gt 0 ]; then
                ENX_DHCP_COUNT=$(($ENX_DHCP_COUNT - 1))
                return
            fi
            static_enx
        else
            dynamic_enx
        fi
    fi
}

check_enx()
{
    if [ "$ENX_OP" = "2" ]; then
        if [ "$ETH_VLAN" = "1" ] && [ "$ENX_VLAN" = "1" ]; then
            add_enx_eth
        elif [ "$ENX_BR" = "1" ]; then
            add_enx_bri
        else
            add_enx_lan
        fi
        return
    fi
    if [ "$BRI_OP" != "0" ]; then
        enx_ip=$(ip addr show $ENX_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$enx_ip" ]; then
            config_enx
            return
        fi
        enx_gw=$(ip route show dev $ENX_IF | grep default | awk '{print $3}')
        if [ -n "$enx_gw" ]; then
            del_default_route $ENX_IF
        fi
        return
    fi
    enx_ip=$(ip addr show $ENX_IF | grep 'inet ' | head -n1 | awk '{print $2}')
    if [ -z "$enx_ip" ]; then
        config_enx
        return
    fi 
    if [ "$enx_ip" != "$ENX_WAN_IP" ]; then
        ENX_DHCP_STARTED=0
        ENX_WAN_IP="$enx_ip"
        ENX_WAN_BRD=$(ip addr show dev $ENX_IF | grep $ENX_WAN_IP | awk '{print $4}')
        ENX_WAN_NET=""
        enx_routes=$(ip route show dev $ENX_IF | awk '{print $1}')
        for enx_net in $enx_routes; do
            if [ "$enx_net" = "default" ]; then
                continue
            fi
            ENX_WAN_NET=${enx_net}" $ENX_WAN_NET"
        done
        dump_wan_enx
    fi
    if [ "$BRI_OP" = "0" ] && [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
        eth_ip=$(ip addr show $ETH_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$eth_ip" ]; then
            return
        fi
    fi
    if [ "$BRI_OP" = "0" ] && [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
        sta_ip=$(ip addr show $STA_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$sta_ip" ]; then
            return
        fi
    fi
    enx_gw=$(ip route show dev $ENX_IF | grep default | head -n1 | awk '{print $3}')
    if [ -z "$enx_gw" ]; then
        config_enx
        return
    fi
    if [ "$enx_gw" != "$ENX_WAN_GW" ]; then
        ENX_DHCP_STARTED=0
        ENX_WAN_GW="$enx_gw"
        logger "WAN info ($ENX_IF): $ENX_WAN_IP (gateway $ENX_WAN_GW)"
        ENX_PING_PUBLIC=1
        ENX_PING_COUNT=3
        ENX_WAN_COUNT=15
        add_public_dns
        dump_wan_enx
    fi
    if [ ! -e "$WAN_INFO" ]; then
        dump_wan_enx
    fi
    if [ $ENX_WAN_COUNT -gt 0 ]; then
        ENX_WAN_COUNT=$(($ENX_WAN_COUNT - 1))
        return
    fi
    ENX_WAN_COUNT=4
    if [ -n "$ENX_WAN_GW" ] && [ "$ENX_PING" = "1" ]; then
        ping_enx
        if [ $? -eq 1 ]; then
            logger "WAN info ($ENX_IF): lost IP connection (local $ENX_WAN_IP)"
            config_enx
            dump_wan_enx
        fi
    fi
}

link_enx()
{
    enx_if=$(ifconfig -a | grep $ENX_IF | awk '{print $1}')
    if [ -z "$enx_if" ]; then
        if [ "$ENX_STATE" = "ATTACHED" ]; then
            ENX_PHY_UP=0
            ENX_STATE="DETACHED"
        fi
        return
    fi
    if [ -z "$ENX_MAC" ]; then
        ENX_MAC=$(ip addr show dev $ENX_IF | grep 'link/' | awk '{print $2}')
    fi
    enx_phy=$(cat /sys/class/net/$ENX_IF/operstate) > /dev/null 2>&1
    if [ "$enx_phy" = "down" ]; then
        ifconfig $ENX_IF up
        if [ $ENX_PHY_UP -eq 1 ]; then
            ENX_PHY_UP=0
            ENX_STATE="DETACHED"
            if [ "$ENX_OP" = "1" ]; then
                clean_enx
                ENX_WAN_IP=""
                ENX_WAN_NET=""
            elif [ "$ENX_OP" = "2" ]; then
                if [ "$ETH_VLAN" = "1" ] && [ "$ENX_VLAN" = "1" ]; then
                    del_enx_eth
                elif [ "$ENX_BR" = "1" ]; then
                    del_enx_bri
                else
                    del_enx_lan
                fi
            fi
        fi
        return
    fi
    if [ $ENX_PHY_UP -eq 0 ]; then  
        ENX_PHY_UP=1
        ENX_STATE="ATTACHED"
    fi
}

start_enx()
{
    if [ "$ENX_OP" = "1" ]; then
        ENX_DHCP_STARTED=0
        ENX_DHCP_COUNT=0
        ENX_WAN_GW=""
        ENX_WAN_IP=""
        ENX_WAN_NET=""
    fi
    ENX_PHY_UP=0
    ENX_STATE="STARTED"
}

stop_enx()
{
    kill_one "$ENX_DHCP_PID"
    if [ -e "$ENX_DHCP_LEASE" ]; then
        rm -f $ENX_DHCP_LEASE
    fi
    if [ -n "$ENX_MAC" ]; then
        del_default_route $ENX_IF
        del_route $ENX_IF
        del_addr $ENX_IF
    fi
}

init_enx()
{
    if [ -z "$ENX_IF" ]; then
        return
    fi
    ENX_MAC=""
    enx_if=$(ifconfig -a | grep $ENX_IF | awk '{print $1}')
    if [ -n "$enx_if" ]; then
        ENX_MAC=$(ip addr show dev $ENX_IF | grep 'link/' | awk '{print $2}')
        stop_enx
        if [ "$ENX_OP" != "0" ]; then
            ifconfig $ENX_IF 0.0.0.0 up
        else
            ifconfig $ENX_IF down
            logger "ENX info ($ENX_IF): interface disabled"
        fi
    fi
    ENX_STATE="STARTING"
}

#***************#
# USB Operation #
#***************#
dump_wan_usb()
{
    if [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
        eth_gw=$(ip route show dev $ETH_IF | grep default | awk '{print $3}')
        if [ -n "$eth_gw" ]; then
            dump_wan_eth
            return
        fi
    fi
    if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
        sta_gw=$(ip route show dev $STA_IF | grep default | awk '{print $3}')
        if [ -n "$sta_gw" ]; then
            dump_wan_sta
            return
        fi
    fi
    echo -n > $WAN_INFO
    {
        echo "WAN info:"
        echo "  WAN_IF=$USB_IF"
        echo "  WAN_MAC=$USB_MAC"
        if [ -n "$USB_WAN_GW" ]; then
            echo "  WAN_GW=$USB_WAN_GW"
        fi
        if [ -n "$USB_WAN_IP" ]; then
            echo "  WAN_IP=$USB_WAN_IP"
        fi
        if [ -n "$USB_WAN_NET" ]; then
            echo "  WAN_NET=$USB_WAN_NET"
        fi
    } >> $WAN_INFO
}

ping_usb()
{
    if [ -n "$USB_PING_IP" ]; then
        ping -I $USB_IF "$USB_PING_IP" -c 1 -W 5 -s 20 > /dev/null 2>&1
    elif [ $USB_PING_PUBLIC -eq 0 ]; then
        ping -I $USB_IF "$USB_WAN_GW" -c 1 -W 2 -s 20 > /dev/null 2>&1
    else
        ping -I $USB_IF "8.8.8.8" -c 1 -W 4 -s 20 > /dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then
        USB_PING_PUBLIC=0
        USB_PING_COUNT=3
    else
        if [ $USB_PING_PUBLIC -eq 0 ]; then
            USB_PING_PUBLIC=1
            USB_PING_COUNT=3
        else
            USB_PING_COUNT=$(($USB_PING_COUNT - 1))
            if [ $USB_PING_COUNT -le 0 ]; then
                if [ $USB_PING_PUBLIC -eq 0 ]; then
                    USB_PING_PUBLIC=1
                    USB_PING_COUNT=3
                    return 0
                fi
                return 1
            fi
        fi
    fi
    return 0
}

clean_usb()
{
    kill_one "$USB_DHCP_PID"
    if [ -e "$USB_DHCP_LEASE" ]; then
        rm -f $USB_DHCP_LEASE
    fi
    del_default_route $USB_IF
    del_route $USB_IF
    del_addr $USB_IF
    USB_WAN_GW=""
}

static_usb()
{
    clean_usb
    ip addr add dev $USB_IF $USB_IP broadcast $USB_BRD > /dev/null 2>&1
    ip route add default via $USB_GW dev $USB_IF > /dev/null 2>&1
    USB_DHCP_STARTED=0
}

dynamic_usb()
{
    clean_usb
    $DHCPCLI -nw -1 -q -pf $USB_DHCP_PID -lf $USB_DHCP_LEASE $USB_IF > /dev/null 2>&1
    USB_DHCP_COUNT=8
    USB_DHCP_STARTED=1
}

config_usb()
{
    if [ "$USB_CONFIG" = "0" ]; then
        static_usb
    else
        if [ $USB_DHCP_STARTED -eq 1 ]; then
            if [ $USB_DHCP_COUNT -gt 0 ]; then
                USB_DHCP_COUNT=$(($USB_DHCP_COUNT - 1))
                return
            fi
            static_usb
        else
            dynamic_usb
        fi
    fi
}

check_usb()
{
    if [ "$USB_OP" = "2" ]; then
        if [ "$ETH_VLAN" = "1" ] && [ "$USB_VLAN" = "1" ]; then
            add_usb_eth
        elif [ "$USB_BR" = "1" ]; then
            add_usb_bri
        else
            add_usb_lan
        fi
        return
    fi
    if [ "$BRI_OP" != "0" ]; then
        usb_ip=$(ip addr show $USB_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$usb_ip" ]; then
            config_usb
            return
        fi
        usb_gw=$(ip route show dev $USB_IF | grep default | awk '{print $3}')
        if [ -n "$usb_gw" ]; then
            del_default_route $USB_IF
        fi
        return
    fi
    usb_ip=$(ip addr show $USB_IF | grep 'inet ' | head -n1 | awk '{print $2}')
    if [ -z "$usb_ip" ]; then
        config_usb
        return
    fi 
    if [ "$usb_ip" != "$USB_WAN_IP" ]; then
        USB_DHCP_STARTED=0
        USB_WAN_IP="$usb_ip"
        USB_WAN_BRD=$(ip addr show dev $USB_IF | grep $USB_WAN_IP | awk '{print $4}')
        USB_WAN_NET=""
        usb_routes=$(ip route show dev $USB_IF | awk '{print $1}')
        for usb_net in $usb_routes; do
            if [ "$usb_net" = "default" ]; then
                continue
            fi
            USB_WAN_NET=${usb_net}" $USB_WAN_NET"
        done
        dump_wan_usb
    fi
    if [ "$BRI_OP" = "0" ] && [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
        eth_ip=$(ip addr show $ETH_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$eth_ip" ]; then
            return
        fi
    fi
    if [ "$BRI_OP" = "0" ] && [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
        sta_ip=$(ip addr show $STA_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$sta_ip" ]; then
            return
        fi
    fi
    usb_gw=$(ip route show dev $USB_IF | grep default | head -n1 | awk '{print $3}')
    if [ -z "$usb_gw" ]; then
        config_usb
        return
    fi
    if [ "$usb_gw" != "$USB_WAN_GW" ]; then
        USB_DHCP_STARTED=0
        USB_WAN_GW="$usb_gw"
        logger "WAN info ($USB_IF): $USB_WAN_IP (gateway $USB_WAN_GW)"
        USB_PING_PUBLIC=1
        USB_PING_COUNT=3
        USB_WAN_COUNT=15
        add_public_dns
        dump_wan_usb
    fi
    if [ ! -e "$WAN_INFO" ]; then
        dump_wan_usb
    fi
    if [ $USB_WAN_COUNT -gt 0 ]; then
        USB_WAN_COUNT=$(($USB_WAN_COUNT - 1))
        return
    fi
    USB_WAN_COUNT=4
    if [ -n "$USB_WAN_GW" ] && [ "$USB_PING" = "1" ]; then
        ping_usb
        if [ $? -eq 1 ]; then
            logger "WAN info ($USB_IF): lost IP connection (local $USB_WAN_IP)"
            config_usb
            dump_wan_usb
        fi
    fi
}

link_usb()
{
    usb_if=$(ifconfig -a | grep $USB_IF | awk '{print $1}')
    if [ -z "$usb_if" ]; then
        if [ "$USB_STATE" = "ATTACHED" ]; then
            USB_PHY_UP=0
            USB_STATE="DETACHED"
        fi
        return
    fi
    if [ -z "$USB_MAC" ]; then
        USB_MAC=$(ip addr show dev $USB_IF | grep 'link/' | awk '{print $2}')
    fi
    usb_phy=$(cat /sys/class/net/$USB_IF/operstate) > /dev/null 2>&1
    if [ "$usb_phy" = "down" ]; then
        ifconfig $USB_IF up
        if [ $USB_PHY_UP -eq 1 ]; then
            USB_PHY_UP=0
            USB_STATE="DETACHED"
            if [ "$USB_OP" = "1" ]; then
                clean_usb
                USB_WAN_IP=""
                USB_WAN_NET=""
            elif [ "$USB_OP" = "2" ]; then
                if [ "$ETH_VLAN" = "1" ] && [ "$USB_VLAN" = "1" ]; then
                    del_usb_eth
                elif [ "$USB_BR" = "1" ]; then
                    del_usb_bri
                else
                    del_usb_lan
                fi
            fi
        fi
        return
    fi
    if [ $USB_PHY_UP -eq 0 ]; then  
        USB_PHY_UP=1
        USB_STATE="ATTACHED"
    fi
}

start_usb()
{
    if [ "$USB_OP" = "1" ]; then
        USB_DHCP_STARTED=0
        USB_DHCP_COUNT=0
        USB_WAN_GW=""
        USB_WAN_IP=""
        USB_WAN_NET=""
    fi
    USB_PHY_UP=0
    USB_STATE="DETACHED"
}

stop_usb()
{
    kill_one "$USB_DHCP_PID"
    if [ -e "$USB_DHCP_LEASE" ]; then
        rm -f $USB_DHCP_LEASE
    fi
    if [ -n "$USB_MAC" ]; then
        del_default_route $USB_IF
        del_route $USB_IF
        del_addr $USB_IF
    fi
}

init_usb()
{
    if [ -z "$USB_IF" ]; then
        return
    fi
    USB_MAC=""
    usb_if=$(ifconfig -a | grep $USB_IF | awk '{print $1}')
    if [ -n "$usb_if" ]; then
        USB_MAC=$(ip addr show dev $USB_IF | grep 'link/' | awk '{print $2}')
        stop_usb
        if [ "$USB_OP" != "0" ]; then
            ifconfig $USB_IF 0.0.0.0 up
        else
            ifconfig $USB_IF down
            logger "USB info ($USB_IF): interface disabled"
        fi
    fi
    USB_STATE="STARTING"
}

#***************#
# ETH Operation #
#***************#
del_vap_eth()
{
    if [ -n "$VAP_BRV_IF" ] && [ -n "$VAP_IF" ]; then
        brif=$(brctl show $VAP_BRV_IF | grep $VAP_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $VAP_BRV_IF $VAP_IF
        fi
    fi
}

add_vap_eth()
{
    if [ -n "$VAP_BRV_IF" ] && [ -n "$VAP_IF" ]; then
        brif=$(brctl show $VAP_BRV_IF | grep $VAP_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $VAP_BRV_IF $VAP_IF
        fi
    fi
}

vlan_vap_eth()
{
    if [ "$VAP_OP" = "1" ] && [ "$VAP_VLAN" = "1" ]; then
        VAP_VLAN_IF="$ETH_IF.$VAP_VLAN_ID"
        ip link add link $ETH_IF $VAP_VLAN_IF type vlan id $VAP_VLAN_ID
        eif=$(ip link show | grep $VAP_VLAN_IF | awk '{print $2}' | cut -d '@' -f1) > /dev/null 2>&1
        if [ -z "$eif" ]; then
            logger "Cannot create a tagged interface on $ETH_IF for $VAP_IF"
            return
        fi
        VAP_BRV_IF="brv$VAP_VLAN_ID"
        brctl addbr $VAP_BRV_IF > /dev/null 2>&1
        VAP_BRV_MAC="8e:$mac2:$mac3:$mac4:$mac5:$mac6"
        ip link set dev $VAP_BRV_IF address $VAP_BRV_MAC > /dev/null 2>&1
        ifconfig $VAP_BRV_IF 0.0.0.0 up
        brctl addif $VAP_BRV_IF $VAP_VLAN_IF > /dev/null 2>&1
        ifconfig $VAP_VLAN_IF 0.0.0.0 up
    fi
}

del_wln_eth()
{
    if [ -n "$BRV_IF" ] && [ -n "$WLN_IF" ]; then
        brif=$(brctl show $BRV_IF | grep $WLN_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $BRV_IF $WLN_IF
        fi
    fi
}

add_wln_eth()
{
    if [ -n "$WLN_BRV_IF" ] && [ -n "$WLN_IF" ]; then
        brif=$(brctl show $WLN_BRV_IF | grep $WLN_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $WLN_BRV_IF $WLN_IF
        fi
    fi
}

vlan_wln_eth()
{
    if [ "$WLN_OP" = "1" ] && [ "$WLN_VLAN" = "1" ]; then
        WLN_VLAN_IF="$ETH_IF.$WLN_VLAN_ID"
        ip link add link $ETH_IF $WLN_VLAN_IF type vlan id $WLN_VLAN_ID
        eif=$(ip link show | grep $WLN_VLAN_IF | awk '{print $2}' | cut -d '@' -f1) > /dev/null 2>&1
        if [ -z "$eif" ]; then
            logger "Cannot create a tagged interface on $ETH_IF for $WLN_IF"
            return
        fi
        WLN_BRV_IF="brv$WLN_VLAN_ID"
        brctl addbr $WLN_BRV_IF > /dev/null 2>&1
        WLN_BRV_MAC="8a:$mac2:$mac3:$mac4:$mac5:$mac6"
        ip link set dev $WLN_BRV_IF address $WLN_BRV_MAC > /dev/null 2>&1
        ifconfig $WLN_BRV_IF 0.0.0.0 up
        brctl addif $WLN_BRV_IF $WLN_VLAN_IF > /dev/null 2>&1
        ifconfig $WLN_VLAN_IF 0.0.0.0 up
    fi
}

del_sap_eth()
{
    if [ -n "$SAP_BRV_IF" ] && [ -n "$SAP_IF" ]; then
        brif=$(brctl show $SAP_BRV_IF | grep $SAP_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $SAP_BRV_IF $SAP_IF
        fi
    fi
}

add_sap_eth()
{
    if [ -n "$SAP_BRV_IF" ] && [ -n "$SAP_IF" ]; then
        brif=$(brctl show $SAP_BRV_IF | grep $SAP_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $SAP_BRV_IF $SAP_IF
        fi
    fi
}

vlan_sap_eth()
{
    if [ "$SAP_OP" = "1" ] && [ "$SAP_VLAN" = "1" ]; then
        SAP_VLAN_IF="$ETH_IF.$SAP_VLAN_ID"
        ip link add link $ETH_IF $SAP_VLAN_IF type vlan id $SAP_VLAN_ID
        eif=$(ip link show | grep $SAP_VLAN_IF | awk '{print $2}' | cut -d '@' -f1) > /dev/null 2>&1
        if [ -z "$eif" ]; then
            logger "Cannot create a tagged interface on $ETH_IF for $SAP_IF"
            return
        fi
        SAP_BRV_IF="brv$SAP_VLAN_ID"
        brctl addbr $SAP_BRV_IF > /dev/null 2>&1
        SAP_BRV_MAC="86:$mac2:$mac3:$mac4:$mac5:$mac6"
        ip link set dev $SAP_BRV_IF address $SAP_BRV_MAC > /dev/null 2>&1
        ifconfig $SAP_BRV_IF 0.0.0.0 up
        brctl addif $SAP_BRV_IF $SAP_VLAN_IF > /dev/null 2>&1
        ifconfig $SAP_VLAN_IF 0.0.0.0 up
    fi
}

del_enx_eth()
{
    if [ -n "$ENX_BRV_IF" ] && [ -n "$ENX_IF" ]; then
        brif=$(brctl show $ENX_BRV_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $ENX_BRV_IF $ENX_IF
        fi
    fi
}

add_enx_eth()
{
    if [ -n "$ENX_BRV_IF" ] && [ -n "$ENX_IF" ]; then
        brif=$(brctl show $ENX_BRV_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $ENX_BRV_IF $ENX_IF
        fi
    fi
}

vlan_enx_eth()
{
    if [ "$ENX_OP" = "2" ] && [ "$ENX_VLAN" = "1" ]; then
        ENX_VLAN_IF="$ETH_IF.$ENX_VLAN_ID"
        ip link add link $ETH_IF $ENX_VLAN_IF type vlan id $ENX_VLAN_ID
        eif=$(ip link show | grep $ENX_VLAN_IF | awk '{print $2}' | cut -d '@' -f1) > /dev/null 2>&1
        if [ -z "$eif" ]; then
            logger "Cannot create a tagged interface on $ETH_IF for $ENX_IF"
            return
        fi
        ENX_BRV_IF="brv$ENX_VLAN_ID"
        brctl addbr $ENX_BRV_IF > /dev/null 2>&1
        ENX_BRV_MAC="62:$mac2:$mac3:$mac4:$mac5:$mac6"
        ip link set dev $ENX_BRV_IF address $ENX_BRV_MAC > /dev/null 2>&1
        ifconfig $ENX_BRV_IF 0.0.0.0 up
        brctl addif $ENX_BRV_IF $ENX_VLAN_IF > /dev/null 2>&1
        ifconfig $ENX_VLAN_IF 0.0.0.0 up
    fi
}

del_usb_eth()
{
    if [ -n "$USB_BRV_IF" ] && [ -n "$USB_IF" ]; then
        brif=$(brctl show $USB_BRV_IF | grep $USB_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $USB_BRV_IF $USB_IF
        fi
    fi
}

add_usb_eth()
{
    if [ -n "$USB_BRV_IF" ] && [ -n "$USB_IF" ]; then
        brif=$(brctl show $USB_BRV_IF | grep $USB_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $USB_BRV_IF $USB_IF
        fi
    fi
}

vlan_usb_eth()
{
    if [ "$USB_OP" = "2" ] && [ "$USB_VLAN" = "1" ]; then
        USB_VLAN_IF="$ETH_IF.$USB_VLAN_ID"
        ip link add link $ETH_IF $USB_VLAN_IF type vlan id $USB_VLAN_ID
        eif=$(ip link show | grep $USB_VLAN_IF | awk '{print $2}' | cut -d '@' -f1) > /dev/null 2>&1
        if [ -z "$eif" ]; then
            logger "Cannot create a tagged interface on $ETH_IF for $USB_IF"
            return
        fi
        USB_BRV_IF="brv$USB_VLAN_ID"
        brctl addbr $USB_BRV_IF > /dev/null 2>&1
        USB_BRV_MAC="82:$mac2:$mac3:$mac4:$mac5:$mac6"
        ip link set dev $USB_BRV_IF address $USB_BRV_MAC > /dev/null 2>&1
        ifconfig $USB_BRV_IF 0.0.0.0 up
        brctl addif $USB_BRV_IF $USB_VLAN_IF > /dev/null 2>&1
        ifconfig $USB_VLAN_IF 0.0.0.0 up
    fi
}

dump_wan_eth()
{
    if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
        sta_gw=$(ip route show dev $STA_IF | grep default | awk '{print $3}')
        if [ -n "$sta_gw" ]; then
            dump_wan_sta
            return
        fi
    fi
    echo -n > $WAN_INFO
    {
        echo "WAN info:"
        if [ "$BRI_OP" = "1" ]; then
            echo "  WAN_IF=$BRI_IF"
            echo "  WAN_MAC=$BRI_MAC"
        else
            echo "  WAN_IF=$ETH_IF"
            echo "  WAN_MAC=$ETH_MAC"
        fi
        if [ -n "$ETH_WAN_GW" ]; then
            echo "  WAN_GW=$ETH_WAN_GW"
        fi
        if [ -n "$ETH_WAN_IP" ]; then
            echo "  WAN_IP=$ETH_WAN_IP"
        fi
        if [ -n "$ETH_WAN_NET" ]; then
            echo "  WAN_NET=$ETH_WAN_NET"
        fi
    } >> $WAN_INFO
}

ping_eth()
{
    if [ "$BRI_OP" = "1" ] && [ -n "$BRI_PING_IP" ]; then
        ping -I $ETH_WAN_IF "$BRI_PING_IP" -c 1 -W 5 -s 20 > /dev/null 2>&1
    elif [ "$BRI_OP" != "1" ] && [ -n "$ETH_PING_IP" ]; then
        ping -I $ETH_WAN_IF "$ETH_PING_IP" -c 1 -W 5 -s 20 > /dev/null 2>&1
    elif [ $ETH_PING_PUBLIC -eq 0 ]; then
        ping -I $ETH_WAN_IF "$ETH_WAN_GW" -c 1 -W 2 -s 20 > /dev/null 2>&1
    else
        ping -I $ETH_WAN_IF "8.8.8.8" -c 1 -W 4 -s 20 > /dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then
        ETH_PING_PUBLIC=0
        ETH_PING_COUNT=3
    else
        if [ $ETH_PING_PUBLIC -eq 0 ]; then
            ETH_PING_PUBLIC=1
            ETH_PING_COUNT=3
        else
            ETH_PING_COUNT=$(($ETH_PING_COUNT - 1))
            if [ $ETH_PING_COUNT -le 0 ]; then
                if [ $ETH_PING_PUBLIC -eq 0 ]; then
                    ETH_PING_PUBLIC=1
                    ETH_PING_COUNT=3
                    return 0
                fi
                return 1
            fi
        fi
    fi
    return 0
}

clean_eth()
{
    if [ "$BRI_OP" = "1" ]; then
        brif=$(brctl show $BRI_IF | grep $ETH_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            return
        fi
        kill_one "$BRI_DHCP_PID"
        if [ -e "$BRI_DHCP_LEASE" ]; then
            rm -f $BRI_DHCP_LEASE
        fi
        del_eth_bri
    else
        kill_one "$ETH_DHCP_PID"
        if [ -e "$ETH_DHCP_LEASE" ]; then
            rm -f $ETH_DHCP_LEASE
        fi
    fi
    if [ -e "$WAN_INFO" ]; then
        rm -f $WAN_INFO
    fi
    del_default_route $ETH_WAN_IF
    del_route $ETH_WAN_IF
    del_addr $ETH_WAN_IF
    ETH_WAN_GW=""
}

static_eth()
{
    clean_eth
    if [ "$BRI_OP" = "1" ]; then
        ip addr add dev $BRI_IF $BRI_IP broadcast $BRI_BRD > /dev/null 2>&1
        ip route add default via $BRI_GW dev $BRI_IF > /dev/null 2>&1
    else
        ip addr add dev $ETH_IF $ETH_IP broadcast $ETH_BRD > /dev/null 2>&1
        ip route add default via $ETH_GW dev $ETH_IF > /dev/null 2>&1
    fi
    ETH_DHCP_STARTED=0
}

dynamic_eth()
{
    clean_eth
    if [ "$BRI_OP" = "1" ]; then
        $DHCPCLI -nw -1 -q -pf $BRI_DHCP_PID -lf $BRI_DHCP_LEASE $BRI_IF > /dev/null 2>&1
    else
        $DHCPCLI -nw -1 -q -pf $ETH_DHCP_PID -lf $ETH_DHCP_LEASE $ETH_IF > /dev/null 2>&1
    fi
    ETH_DHCP_COUNT=8
    ETH_DHCP_STARTED=1
}

config_eth()
{
    if [ "$BRI_OP" = "1" ] && [ "$BRI_CONFIG" = "0" ]; then
        static_eth
    elif [ "$BRI_OP" != "1" ] && [ "$ETH_CONFIG" = "0" ]; then
        static_eth
    else
        if [ $ETH_DHCP_STARTED -eq 1 ]; then
            if [ $ETH_DHCP_COUNT -gt 0 ]; then
                ETH_DHCP_COUNT=$(($ETH_DHCP_COUNT - 1))
                return
            fi
            if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
                ETH_STATE="DETACHED"
                ETH_WAN_DUMMY=0
                clean_eth
                return
            fi
            static_eth
        else
            dynamic_eth
        fi
    fi
}

check_eth()
{
    if [ "$ETH_OP" = "2" ]; then
        if [ "$ETH_BR" = "1" ]; then
            add_eth_bri
        else
            add_eth_lan
        fi
        return
    fi
    if [ "$BRI_OP" = "2" ]; then
        eth_ip=$(ip addr show $ETH_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$eth_ip" ]; then
            config_eth
            return
        fi
        eth_gw=$(ip route show dev $ETH_IF | grep default | awk '{print $3}')
        if [ -n "$eth_gw" ]; then
            del_default_route $ETH_IF
        fi
        return
    fi
    if [ "$BRI_OP" = "1" ]; then
        add_eth_bri
        eth_ip=$(ip addr show $BRI_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$eth_ip" ]; then
            config_eth
            return
        fi
    else
        if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
            if [ "$STA_PRI" = "1" ]; then
                ETH_STATE="DETACHED"
                ETH_WAN_DUMMY=0
                clean_eth
                return
            fi
        fi
        eth_ip=$(ip addr show $ETH_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$eth_ip" ]; then
            if [ "$ENX_OP" = "1" ] && [ $ENX_PHY_UP -eq 1 ]; then
                enx_gw=$(ip route show dev $ENX_IF | grep default | awk '{print $3}')
                if [ -n "$enx_gw" ]; then
                    ENX_WAN_GW="enx_gw"
                    del_default_route $ENX_IF
                fi
            fi
            if [ "$USB_OP" = "1" ] && [ $USB_PHY_UP -eq 1 ]; then
                usb_gw=$(ip route show dev $USB_IF | grep default | awk '{print $3}')
                if [ -n "$usb_gw" ]; then
                    USB_WAN_GW="usb_gw"
                    del_default_route $USB_IF
                fi
            fi
            if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
                sta_gw=$(ip route show dev $STA_IF | grep default | awk '{print $3}')
                if [ -n "$sta_gw" ]; then
                    STA_WAN_GW="$sta_gw"
                    del_default_route $STA_IF
                fi
            fi
            config_eth
            return
        fi
    fi
    if [ "$eth_ip" != "$ETH_WAN_IP" ]; then
        ETH_DHCP_STARTED=0
        ETH_WAN_IP="$eth_ip"
        ETH_WAN_BRD=$(ip addr show dev $ETH_WAN_IF | grep $ETH_WAN_IP | awk '{print $4}')
        ETH_WAN_NET=""
        eth_routes=$(ip route show dev $ETH_WAN_IF | awk '{print $1}')
        for eth_net in $eth_routes; do
            if [ "$eth_net" = "default" ]; then
                continue
            fi
            ETH_WAN_NET=${eth_net}" $ETH_WAN_NET"
        done
        if [ "$ENX_OP" = "1" ] && [ $ENX_PHY_UP -eq 1 ]; then
            for enx_route in $(ip route | grep dev.*$ENX_IF | awk '{print $1}'); do
                for enx_route in $ETH_WAN_NET; do
                    ip route del $enx_route dev $ENX_IF > /dev/null 2>&1
                done
            done
        fi
        if [ "$USB_OP" = "1" ] && [ $USB_PHY_UP -eq 1 ]; then
            for usb_route in $(ip route | grep dev.*$USB_IF | awk '{print $1}'); do
                for usb_route in $ETH_WAN_NET; do
                    ip route del $usb_route dev $USB_IF > /dev/null 2>&1
                done
            done
        fi
        if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
            for sta_route in $(ip route | grep dev.*$STA_IF | awk '{print $1}'); do
                for sta_route in $ETH_WAN_NET; do
                    ip route del $sta_route dev $STA_IF > /dev/null 2>&1
                done
            done
        fi
        dump_wan_eth
    fi
    if [ "$BRI_OP" = "0" ] && [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
        if [ "$STA_PRI" = "1" ]; then
            sta_ip=$(ip addr show $STA_IF | grep 'inet ' | head -n1 | awk '{print $2}')
            if [ -n "$sta_ip" ]; then
                ETH_STATE="DETACHED"
                ETH_WAN_DUMMY=0
                clean_eth
                return
            fi
        else
            sta_gw=$(ip route show dev $STA_IF | grep default | awk '{print $3}')
            if [ -n "$sta_gw" ]; then
                STA_WAN_GW="$sta_gw"
                del_default_route $STA_IF
                return
            fi
        fi
    fi
    eth_gw=$(ip route show dev $ETH_WAN_IF | grep default | awk '{print $3}')
    if [ -z "$eth_gw" ]; then
        config_eth
        return
    fi
    if [ "$eth_gw" != "$ETH_WAN_GW" ]; then
        ETH_DHCP_STARTED=0
        ETH_WAN_GW="$eth_gw"
        logger "WAN info ($ETH_WAN_IF): $ETH_WAN_IP (gateway $ETH_WAN_GW)"
        ETH_PING_PUBLIC=1
        ETH_PING_COUNT=3
        ETH_WAN_COUNT=15
        add_public_dns
        dump_wan_eth
    fi
    if [ ! -e "$WAN_INFO" ]; then
        dump_wan_eth
    fi
    if [ $ETH_WAN_COUNT -gt 0 ]; then
        ETH_WAN_COUNT=$(($ETH_WAN_COUNT - 1))
        return
    fi
    ETH_WAN_COUNT=4
    if [ -n "$ETH_WAN_GW" ] && [ "$ETH_PING" = "1" ]; then
        ping_eth
        if [ $? -eq 1 ]; then
            logger "WAN info ($ETH_WAN_IF): lost IP connection (local $ETH_WAN_IP)"
            if [ "$BRI_OP" = "0" ] && [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
                ETH_STATE="DETACHED"
                ETH_WAN_DUMMY=0
                clean_eth
            else
                dynamic_eth
                dump_wan_eth
            fi
        fi
    fi
}

dummy_eth()
{
    if [ "$ETH_OP" = "2" ]; then
        if [ "$LAN_OP" = "1" ]; then
            del_eth_lan
        elif [ "$BRI_OP" = "1" ]; then
            del_eth_bri
        fi
        return
    fi
    if [ $ETH_WAN_DUMMY -eq 1 ]; then
        return
    fi
    if [ "$BRI_OP" = "0" ] && [ $ETH_PHY_UP -eq 1 ]; then
        if [ -n "$ETH_WAN_IP" ]; then
            ip addr add dev $ETH_IF $ETH_WAN_IP broadcast $ETH_WAN_BRD > /dev/null 2>&1
        else
            ip addr add dev $ETH_IF $ETH_IP broadcast $ETH_BRD > /dev/null 2>&1
        fi
        del_route $ETH_IF
    fi
    ETH_DHCP_STARTED=0
    ETH_DHCP_COUNT=0
    ETH_WAN_DUMMY=1
}

link_eth()
{
    eth_phy=$(cat /sys/class/net/$ETH_IF/operstate) > /dev/null 2>&1
    if [ "$eth_phy" = "down" ]; then
        ifconfig $ETH_IF up
        if [ $ETH_PHY_UP -eq 1 ]; then
            ETH_PHY_UP=0
            ETH_STATE="DETACHED"
            if [ "$ETH_OP" = "1" ]; then
                ETH_WAN_DUMMY=0
                clean_eth
                ETH_WAN_IP=""
                ETH_WAN_NET=""
            fi
        fi
        return
    fi
    if [ $ETH_PHY_UP -eq 0 ]; then
        ETH_PHY_UP=1
        ETH_STATE="ATTACHED"
    fi
}

start_eth()
{
    if [ "$ETH_OP" = "1" ]; then
        if [ "$BRI_OP" = "1" ]; then
            ETH_WAN_IF=$BRI_IF
        else
            ETH_WAN_IF=$ETH_IF
        fi
        ETH_DHCP_STARTED=0
        ETH_DHCP_COUNT=0
        ETH_WAN_DUMMY=0
        ETH_WAN_GW=""
        ETH_WAN_IP=""
        ETH_WAN_NET=""
    fi
    ETH_PHY_UP=0
    ETH_STATE="DETACHED"
}

stop_eth()
{
    eif=$(ip link show | grep @$ETH_IF | awk '{print $2}' | cut -d '@' -f1) > /dev/null 2>&1
    for e in $eif; do
        if [ -n "$e" ]; then
            ifconfig $e down
            ip link del dev $e > /dev/null 2>&1
        fi
    done
    del_vap_eth
    del_wln_eth
    del_sap_eth
    del_enx_eth
    del_usb_eth
    bif=$(ip link show | grep 'brv' | awk '{print $2}' | grep 'brv' | cut -d ':' -f1) > /dev/null 2>&1
    for b in $bif; do
        if [ -n "$b" ]; then
            ifconfig $b down
            brctl delbr $b > /dev/null 2>&1
        fi
    done
    kill_one "$ETH_DHCP_PID"
    if [ -e "$ETH_DHCP_LEASE" ]; then
        rm -f $ETH_DHCP_LEASE
    fi
    if [ -n "$ETH_MAC" ]; then
        del_default_route $ETH_IF
        del_route $ETH_IF
        del_addr $ETH_IF
    fi
}

init_eth()
{
    if [ -z "$ETH_IF" ]; then
        return
    fi
    ETH_MAC=$(ip addr show dev $ETH_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$ETH_MAC" ]; then
        logger "Cannot find ETH interface $ETH_IF"
        exit 0
    fi
    stop_eth
    if [ "$ETH_OP" != "0" ]; then
        if [ "$ETH_VLAN" = "1" ]; then
            mac2=$(echo $BASE_MAC | cut -d ':' -f2)
            mac3=$(echo $BASE_MAC | cut -d ':' -f3)
            mac4=$(echo $BASE_MAC | cut -d ':' -f4)
            mac5=$(echo $BASE_MAC | cut -d ':' -f5)
            mac6=$(echo $BASE_MAC | cut -d ':' -f6)
            vlan_usb_eth
            vlan_enx_eth
            vlan_sap_eth
            vlan_wln_eth
            vlan_vap_eth
        fi
        ifconfig $ETH_IF 0.0.0.0 up
        ETH_STATE="STARTING"
    else
        ifconfig $ETH_IF down
        logger "ETH info ($ETH_IF): interface disabled"
    fi
}

#**********************#
# WAN Bridge Operation #
#**********************#
del_vap_bri()
{
    if [ -n "$BRI_MAC" ] && [ -n "$VAP_IF" ]; then
        brif=$(brctl show $BRI_IF | grep $VAP_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $BRI_IF $VAP_IF
        fi
    fi
}

del_wln_bri()
{
    if [ -n "$BRI_MAC" ] && [ -n "$WLN_IF" ]; then
        brif=$(brctl show $BRI_IF | grep $WLN_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $BRI_IF $WLN_IF
        fi
    fi
}

del_sap_bri()
{
    if [ -n "$BRI_MAC" ] && [ -n "$SAP_IF" ]; then
        brif=$(brctl show $BRI_IF | grep $SAP_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $BRI_IF $SAP_IF
        fi
    fi
}

del_sta_bri()
{
    if [ -n "$BRI_MAC" ] && [ -n "$STA_IF" ]; then
        brif=$(brctl show $BRI_IF | grep $STA_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $BRI_IF $STA_IF
        fi
    fi
}

add_sta_bri()
{
    brif=$(brctl show $BRI_IF | grep $STA_IF) > /dev/null 2>&1
    if [ -z "$brif" ]; then
        brctl addif $BRI_IF $STA_IF
    fi
}

del_enx_bri()
{
    if [ -n "$BRI_MAC" ] && [ -n "$ENX_IF" ]; then
        enx_if=$(brctl show $BRI_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -n "$enx_if" ]; then
            brctl delif $BRI_IF $ENX_IF
        fi
    fi
}

add_enx_bri()
{
    enx_if=$(brctl show $BRI_IF | grep $ENX_IF) > /dev/null 2>&1
    if [ -z "$enx_if" ]; then
        brctl addif $BRI_IF $ENX_IF
    fi
}

del_usb_bri()
{
    if [ -n "$BRI_MAC" ] && [ -n "$USB_IF" ]; then
        usb_if=$(brctl show $BRI_IF | grep $USB_IF) > /dev/null 2>&1
        if [ -n "$usb_if" ]; then
            brctl delif $BRI_IF $USB_IF
        fi
    fi
}

add_usb_bri()
{
    usb_if=$(brctl show $BRI_IF | grep $USB_IF) > /dev/null 2>&1
    if [ -z "$usb_if" ]; then
        brctl addif $BRI_IF $USB_IF
    fi
}

del_eth_bri()
{
    if [ -n "$BRI_MAC" ] && [ -n "$ETH_IF" ]; then
        eth_if=$(brctl show $BRI_IF | grep $ETH_IF) > /dev/null 2>&1
        if [ -n "$eth_if" ]; then
            brctl delif $BRI_IF $ETH_IF
        fi
    fi
}

add_eth_bri()
{
    eth_if=$(brctl show $BRI_IF | grep $ETH_IF) > /dev/null 2>&1
    if [ -z "$eth_if" ]; then
        brctl addif $BRI_IF $ETH_IF
    fi
}

stop_bri()
{
    kill_one "$BRI_DHCP_PID"
    if [ -e "$BRI_DHCP_LEASE" ]; then
        rm -f $BRI_DHCP_LEASE
    fi
    if [ -n "$BRI_MAC" ]; then
        ifconfig $BRI_IF down
        del_default_route $BRI_IF
        del_route $BRI_IF
        del_addr $BRI_IF
        del_eth_bri
        del_enx_bri
        del_usb_bri
        del_sta_bri
        del_sap_bri
        del_wln_bri
        del_vap_bri
    fi
}

init_bri()
{
    if [ -z "$BRI_IF" ]; then
        return
    fi
    BRI_MAC=""
    bri_if=$(ifconfig -a | grep $BRI_IF | awk '{print $1}')
    if [ -n "$bri_if" ]; then
        BRI_MAC=$(ip addr show dev $BRI_IF | grep 'link/' | awk '{print $2}')
    fi
    stop_bri
    if [ "$BRI_OP" != "0" ]; then
        mac2=$(echo $BASE_MAC | cut -d ':' -f2)
        mac3=$(echo $BASE_MAC | cut -d ':' -f3)
        mac4=$(echo $BASE_MAC | cut -d ':' -f4)
        mac5=$(echo $BASE_MAC | cut -d ':' -f5)
        mac6=$(echo $BASE_MAC | cut -d ':' -f6)
        mac="02:$mac2:$mac3:$mac4:$mac5:$mac6"
        if [ "$BRI_MAC" != "$mac" ]; then
            if [ -n "$BRI_MAC" ]; then
                brctl delbr $BRI_IF > /dev/null 2>&1
            fi
            BRI_MAC="$mac"
            brctl addbr $BRI_IF > /dev/null 2>&1
            brctl setfd $BRI_IF 1 > /dev/null 2>&1
            ip link set dev $BRI_IF address $BRI_MAC > /dev/null 2>&1
        fi
        ifconfig $BRI_IF 0.0.0.0 up
    fi
}

#****************#
# Initialization #
#****************#
init_iface()
{
    init_bri
    init_eth
    init_usb
    init_enx
    init_sta
    init_sap
    init_wln
    init_mon
    init_lan
}

init_wifi()
{
    if [ -z "$WIFI_IF" ]; then
        return
    fi
    ath=$(lsmod | grep ath9k | head -n1 | awk '{print $1}')
    if [ "$WIFI_IF" = "wlan0" ]; then
        if [ -z "$ath" ]; then
            logger "Probing Wi-Fi module ath9k"
            modprobe ath9k > /dev/null 2>&1
        fi
    else
        if [ -n "$ath" ]; then
            logger "Removing Wi-Fi module ath9k"
            rmmod ath9k > /dev/null 2>&1
        fi
    fi
    iwl=$(lsmod | grep iwldvm | head -n1 | awk '{print $1}')
    if [ "$WIFI_IF" = "wlp3s0" ]; then
        if [ -z "$iwl" ]; then
            logger "Probing Wi-Fi module iwldvm"
            modprobe iwldvm > /dev/null 2>&1
        fi
    else
        if [ -n "$iwl" ]; then
            logger "Removing Wi-Fi module iwldvm"
            rmmod iwldvm > /dev/null 2>&1
        fi
    fi
    if [ -n "$WIFI_BR" ]; then
        WIFI_MAC=$(ip addr show dev $WIFI_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
        if [ -n "$WIFI_MAC" ]; then
            iw dev $WIFI_IF del
        fi
        WIFI_PHY=$(iw phy | grep Wiphy | awk '{print $2}') > /dev/null 2>&1
        if [ -z "$WIFI_PHY" ]; then
            logger "Cannot find Wi-Fi radio device supporting for $WIFI_IF"
            exit 0
        else
            if [ "$WIFI_BR" = "1" ] && [ "$STA_OP" = "1" ] && [ "$BRI_OP" = "2" ]; then
                iw phy $WIFI_PHY interface add $WIFI_IF type managed 4addr on > /dev/null 2>&1
            else
                iw phy $WIFI_PHY interface add $WIFI_IF type managed > /dev/null 2>&1
            fi
        fi
    fi
    if [ "$STA_OP" = "0" ] && [ "$WLN_OP" = "0" ] && [ "$MON_OP" = "0" ]; then
        WIFI_MAC=$(ip addr show dev $WIFI_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
        if [ -n "$WIFI_MAC" ]; then
            ifconfig $WIFI_IF down
            logger "UWIN info: Wi-Fi interface removed"
        fi
    fi
}

clean_all()
{
    pid=$(ps -e | grep NetworkManager | awk '{print $1}')
    if [ -n "$pid" ] && [ $pid -ne $$ ]; then
        systemctl stop NetworkManager.service
    fi
    kill_all "hostapd"
    kill_all "wpa_supplicant"
    if [ -n "$DHCPSRV" ]; then
        kill_all "$DHCPSRV"
    fi
    if [ -n "$DHCPCLI" ]; then
        kill_all "$DHCPCLI"
    fi
    if [ -e "$WLN_LOG" ]; then
        rm -f $WLN_LOG
    fi
    if [ -e "$SAP_LOG" ]; then
        rm -f $SAP_LOG
    fi
    if [ -e "$STA_LOG" ]; then
        rm -f $STA_LOG
    fi
    if [ -e "$WAN_INFO" ]; then
        rm -f $WAN_INFO
    fi
    if [ -e "$STA_INFO" ]; then
        rm -f $STA_INFO
    fi
    if [ -e "$SAP_INFO" ]; then
        rm -f $SAP_INFO
    fi
    if [ -e "$WLN_INFO" ]; then
        rm -f $WLN_INFO
    fi
    if [ -e "$LAN_INFO" ]; then
        rm -f $LAN_INFO
    fi
    if [ -d "$OPT_DIR" ]; then
        rm -fr $OPT_DIR
    fi
    mkdir -p $OPT_DIR
}

set_opmode()
{
    BRI_OP=0
    ETH_OP=0
    USB_OP=0
    ENX_OP=0
    STA_OP=0
    SAP_OP=0
    WLN_OP=0
    VAP_OP=0
    MON_OP=0
    LAN_OP=0
    ETH_BR=0
    USB_BR=0
    ENX_BR=0
    SAP_BR=0
    WLN_BR=0
    VAP_BR=0
    BRI_CONFIG=0
    ETH_CONFIG=0
    USB_CONFIG=0
    ENX_CONFIG=0
    STA_CONFIG=0
    if [ "$BRI_PHY" = "2" ] && [ -n "$STA_IF" ]; then
        BRI_OP=2
        if [ "$WIFI_BR" = "1" ]; then
            STA_OP=1
            logger "UWIN info: STA Mode --> Bridge PHY"
            if [ -n "$SAP_IF" ]; then
                SAP_OP=1
                if [ "$SAP_MODE" = "1" ]; then
                    SAP_BR=1
                    logger "UWIN info: SAP Mode --> Bridge"
                else
                    LAN_OP=1
                    logger "UWIN info: SAP Mode --> Router"
                fi
            fi
        else
            logger "Wi-Fi device does not support 4-address mode"
            exit 0
        fi
    elif [ "$BRI_PHY" = "1" ] && [ -n "$ETH_IF" ]; then
        BRI_OP=1
        ETH_OP=1
        logger "UWIN info: ETH Mode --> Bridge PHY"
    fi
    if [ "$BRI_OP" != "0" ] && [ "$BRI_MODE" = "1" ]; then
        BRI_CONFIG=1
    fi
    if [ "$BRI_OP" != "1" ] && [ -n "$ETH_IF" ]; then
        if [ "$ETH_MODE" = "3" ]; then
            if [ "$BRI_OP" != "0" ]; then
                ETH_BR=1
                ETH_OP=2
                logger "UWIN info: ETH Mode --> Bridge"
            else
                logger "No WAN bridge found for ETH interface"
                exit 0
            fi
        elif [ "$ETH_MODE" = "2" ]; then
            LAN_OP=1
            ETH_OP=2
            logger "UWIN info: ETH Mode --> Server"
        elif [ "$ETH_MODE" = "1" ]; then
            ETH_OP=1
            ETH_CONFIG=1
            logger "UWIN info: ETH Mode --> Client"
        else
            ETH_OP=1
            logger "UWIN info: ETH Mode --> Static"
        fi
    fi
    if [ -n "$USB_IF" ]; then
        if [ "$USB_MODE" = "3" ]; then
            if [ "$BRI_OP" != "0" ]; then
                USB_BR=1
                USB_OP=2
                logger "UWIN info: USB Mode --> Bridge"
            else
                logger "No WAN bridge found for USB interface"
                exit 0
            fi
        elif [ "$USB_MODE" = "2" ]; then
            LAN_OP=1
            USB_OP=2
            logger "UWIN info: USB Mode --> Server"
        elif [ "$USB_MODE" = "1" ]; then
            USB_OP=1
            USB_CONFIG=1
            logger "UWIN info: USB Mode --> Client"
        else
            USB_OP=1
            logger "UWIN info: USB Mode --> Static"
        fi
    fi
    if [ -n "$ENX_IF" ]; then
        if [ "$ENX_MODE" = "3" ]; then
            if [ "$BRI_OP" != "0" ]; then
                ENX_BR=1
                ENX_OP=2
                logger "UWIN info: ENX Mode --> Bridge"
            else
                logger "No WAN bridge found for ENX interface"
                exit 0
            fi
        elif [ "$ENX_MODE" = "2" ]; then
            LAN_OP=1
            ENX_OP=2
            logger "UWIN info: ENX Mode --> Server"
        elif [ "$ENX_MODE" = "1" ]; then
            ENX_OP=1
            ENX_CONFIG=1
            logger "UWIN info: ENX Mode --> Client"
        else
            ENX_OP=1
            logger "UWIN info: ENX Mode --> Static"
        fi
    fi
    if [ "$BRI_OP" != "2" ] && [ -n "$WIFI_IF" ]; then
        if [ "$WIFI_MODE" = "2" ] && [ -n "$WLN_IF" ]; then
            WLN_OP=1
            if [ "$WLN_MODE" = "1" ]; then
                if [ "$BRI_OP" != "0" ]; then
                    WLN_BR=1
                    logger "UWIN info: WLN Mode --> Bridge"
                else
                    logger "No WAN bridge found for WLN interface"
                    exit 0
                fi
            else
                LAN_OP=1
                logger "UWIN info: WLN Mode --> Router"
            fi
            if [ -n "$VAP_IF" ]; then
                VAP_OP=1
                if [ "$VAP_MODE" = "1" ]; then
                    if [ "$BRI_OP" != "0" ]; then
                        VAP_BR=1
                        logger "UWIN info: VAP Mode --> Bridge"
                    else
                        logger "No WAN bridge found for VAP interface"
                        exit 0
                    fi
                else
                    LAN_OP=1
                    logger "UWIN info: VAP Mode --> Router"
                fi
            fi
        fi
        if [ "$WIFI_MODE" = "1" ] && [ -n "$STA_IF" ]; then
            STA_OP=1
            STA_CONFIG=1
            STA_MODE="UWIN info: STA Mode --> Client"
        elif [ "$WIFI_MODE" = "0" ] && [ -n "$STA_IF" ]; then
            STA_OP=1
            STA_MODE="UWIN info: STA Mode --> Static"
        fi
        if [ "$STA_OP" = "1" ]; then
            if [ "$BRI_OP" = "0" ] && [ "$ETH_OP" = "1" ]; then
                if [ "$STA_PRI" = "1" ]; then
                    STA_MODE=${STA_MODE}" (higher priority)"
                else
                    STA_MODE=${STA_MODE}" (lower priority)"
                fi
            fi
            logger "$STA_MODE"
            if [ -n "$SAP_IF" ]; then
                SAP_OP=1
                if [ "$SAP_MODE" = "1" ]; then
                    if [ "$BRI_OP" != "0" ]; then
                        SAP_BR=1
                        logger "UWIN info: SAP Mode --> Bridge"
                    else
                        logger "No WAN bridge found for SAP interface"
                        exit 0
                    fi
                else
                    LAN_OP=1
                    logger "UWIN info: SAP Mode --> Router"
                fi
            fi
        fi
    fi
    if [ -n "$MON_IF" ] && [ -n "$WIFI_IF" ]; then
        MON_OP=1
        logger "UWIN info: MON Mode --> enabled"
    fi
}

#***********#
# Main Loop #
#***********#
BASE_IF=""
WIFI_IF=""
WIFI_BR=""
BRI_IF=""
ETH_IF=""
BRV_IF=""
USB_IF=""
ENX_IF=""
STA_IF=""
SAP_IF=""
WLN_IF=""
VAP_IF=""
MON_IF=""
LAN_IF=""
WPASUPP=""
HOSTAPD=""
DHCPCLI=""
DHCPSRV=""

kill_all $0
if [ ! -e "/etc/uwin.conf" ]; then
    logger "Cannot find configuration file /etc/uwin.conf"
    exit 0
fi
source "/etc/uwin.conf"
set_opmode
if [ "$STA_OP" = "1" ] && [ ! -e "$STA_CONF" ]; then
    logger "Cannot find configuration file $STA_CONF"
    exit 0
fi
if [ "$SAP_OP" = "1" ] && [ ! -e "$SAP_CONF" ]; then
    logger "Cannot find configuration file $SAP_CONF"
    exit 0
fi
if [ "$WLN_OP" = "1" ] && [ ! -e "$WLN_CONF" ]; then
    logger "Cannot find configuration file $WLN_CONF"
    exit 0
fi
if [ -n "$BASE_IF" ]; then
    BASE_MAC=$(ip addr show dev $BASE_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$BASE_MAC" ]; then
        logger "Cannot find primary wired interface $BASE_IF"
        exit 0
    fi
fi
logger "UWIN network manager version $UWINVER"

clean_all
init_wifi
init_iface
set_ip_tables
set_ip_forward
set_proxy_arp

while [ 1 ]; do
    if [ "$STA_OP" = "1" ]; then
        if [ "$STA_STATE" = "STARTING" ]; then
            start_sta
        elif [ "$STA_STATE" = "STARTED" ]; then
            link_sta
        elif [ "$STA_STATE" = "COMPLETED" ]; then
            check_sta
        fi
    elif [ "$WLN_OP" = "1" ]; then
        if [ "$WLN_STATE" = "STARTING" ]; then
            start_wln
        elif [ "$WLN_STATE" = "STARTED" ]; then
            link_wln
        elif [ "$WLN_STATE" = "COMPLETED" ]; then
            check_wln
        fi
    fi
    if [ "$ETH_OP" != "0" ]; then
        if [ "$ETH_STATE" = "STARTING" ]; then
            start_eth
        else
            link_eth
            if [ "$ETH_STATE" = "DETACHED" ]; then
                dummy_eth
            elif [ "$ETH_STATE" = "ATTACHED" ]; then
                check_eth
            fi
        fi
    fi
    if [ "$USB_OP" != "0" ]; then
        if [ "$USB_STATE" = "STARTING" ]; then
            start_usb
        else
            link_usb
            if [ "$USB_STATE" = "ATTACHED" ]; then
                check_usb
            fi
        fi
    fi
    if [ "$ENX_OP" != "0" ]; then
        if [ "$ENX_STATE" = "STARTING" ]; then
            start_enx
        else
            link_enx
            if [ "$ENX_STATE" = "ATTACHED" ]; then
                check_enx
            fi
        fi
    fi
    sleep 1
done

exit 0
