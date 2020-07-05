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

add_network_dns()
{
    if [ -n "$RESCONF" ]; then
        if [ ! -e "$RESCONF" ]; then
            echo "nameserver 8.8.8.8" >> $RESCONF
            echo "nameserver 8.8.4.4" >> $RESCONF
        else
            rm $RESCONF
            if [ -z "$DNSADDR" ]; then
                echo "nameserver 8.8.8.8" >> $RESCONF
                echo "nameserver 8.8.4.4" >> $RESCONF
            else
                echo "nameserver 8.8.8.8" >> $RESCONF
                sed -i '1inameserver '$DNSADDR'' $RESCONF
            fi
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
            if [ "$STX_OP" = "1" ]; then
                iptables -A wifi_forw -i $LAN_IF -o $STX_IF -j ACCEPT
                iptables -A wifi_forw -i $STX_IF -o $LAN_IF -j ACCEPT
            fi
            if [ "$ENX_OP" = "1" ]; then
                iptables -A wifi_forw -i $LAN_IF -o $ENX_IF -j ACCEPT
                iptables -A wifi_forw -i $ENX_IF -o $LAN_IF -j ACCEPT
            fi
            if [ "$USB_OP" = "1" ]; then
                iptables -A wifi_forw -i $LAN_IF -o $USB_IF -j ACCEPT
                iptables -A wifi_forw -i $USB_IF -o $LAN_IF -j ACCEPT
            fi
        fi
        iptables -A INPUT -i $LAN_IF -j ACCEPT
    else
        if [ "$BRI_OP" != "0" ]; then
            iptables -A wifi_forw -i $BRI_IF -o $BRI_IF -j ACCEPT
            iptables -A INPUT -i $BRI_IF -j ACCEPT
        else
            if [ "$ETH_OP" = "1" ]; then
                iptables -A INPUT -i $ETH_IF -j ACCEPT
            fi
            if [ "$STA_OP" = "1" ]; then
                iptables -A INPUT -i $STA_IF -j ACCEPT
            fi
        fi
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
        if [ "$STX_OP" = "1" ]; then
            iptables -t nat -A wifi_post -o $STX_IF -j MASQUERADE
        fi
        if [ "$ENX_OP" = "1" ]; then
            iptables -t nat -A wifi_post -o $ENX_IF -j MASQUERADE
        fi
        if [ "$USB_OP" = "1" ]; then
            iptables -t nat -A wifi_post -o $USB_IF -j MASQUERADE
        fi
    fi
}

#**********************#
# SON Bridge Operation #
#**********************#
del_enx_son()
{
    if [ -n "$SON_MAC" ] && [ -n "$ENX_IF" ]; then
        brif=$(brctl show $SON_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $SON_IF $ENX_IF
            logger "LAN ($ENX_IF) info: interface removed from $SON_IF"
        fi
    fi
}

add_enx_son()
{
    if [ -n "$SON_WAN_IF" ] && [ -n "$SON_WAN_GW" ]; then
        brif=$(brctl show $SON_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $SON_IF $ENX_IF
            logger "LAN ($ENX_IF) info: interface added to $SON_IF"
        fi
    fi
}

del_usb_son()
{
    if [ -n "$SON_MAC" ] && [ -n "$USB_IF" ]; then
        brif=$(brctl show $SON_IF | grep $USB_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $SON_IF $USB_IF
            logger "LAN ($USB_IF) info: interface removed from $SON_IF"
        fi
    fi
}

add_usb_son()
{
    if [ -n "$SON_WAN_IF" ] && [ -n "$SON_WAN_GW" ]; then
        brif=$(brctl show $SON_IF | grep $USB_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $SON_IF $USB_IF
            logger "LAN ($USB_IF) info: interface added to $SON_IF"
        fi
    fi
}

del_eth_son()
{
    if [ -n "$SON_MAC" ] && [ -n "$ETH_IF" ]; then
        brif=$(brctl show $SON_IF | grep $ETH_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $SON_IF $ETH_IF
            logger "LAN ($ETH_IF) info: interface removed from $SON_IF"
        fi
    fi
}

add_eth_son()
{
    if [ -n "$SON_WAN_IF" ] && [ -n "$SON_WAN_GW" ]; then
        brif=$(brctl show $SON_IF | grep $ETH_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $SON_IF $ETH_IF
            logger "LAN ($ETH_IF) info: interface added to $SON_IF"
        fi
    fi    
}

dump_son()
{
    echo -n > $LAN_INFO
    {
        echo "LAN info:"
        echo "  LAN_IF=$SON_IF"
        echo "  LAN_MAC=$SON_MAC"
        echo "  LAN_IP=$SON_IP"
        echo "  LAN_START=$SON_START"
        echo "  LAN_END=$SON_END"
        echo "  LAN_GW=$SON_GW"
    } >> $LAN_INFO
}

conf_son()
{
    DNSMASQ_ARGS=${DNSMASQ_ARGS}" $@"
}

start_son()
{
    ifconfig $SON_IF 0.0.0.0 up
    old_ip=$(ip addr show $SON_IF | grep 'inet ' | head -n1 | awk '{print $2}')
    if [ -n "$old_ip" ]; then
        del_addr $SON_IF
        del_route $SON_IF
    fi
    ip addr add dev $SON_IF $son_ip broadcast $son_brd
    DNSMASQ_ARGS="-o -f -b -K -D -Q 2007"
    conf_son "--dhcp-sequential-ip --dhcp-leasefile=$LAN_DHCP_LEASE2"
    conf_son "--clear-on-reload --dhcp-option=6,8.8.8.8,8.8.4.4"
    conf_son "-i $SON_IF -F $SON_IF,$son_start,$son_end,3600"
    $DNSMASQ $DNSMASQ_ARGS
}

dnsmasq_son()
{
    kill_all "$DNSMASQ"
    son_ip=$SON_IP
    son_brd=$SON_BRD
    son_gw=$SON_GW
    son_start=$SON_START
    son_end=$SON_END
    start_son
    logger "LAN ($SON_IF) info: $SON_IP (gateway: $SON_GW)"
    dump_son
}

update_son()
{
    gw1=$(echo $SON_WAN_GW | cut -d '.' -f1)
    gw2=$(echo $SON_WAN_GW | cut -d '.' -f2)
    gw3=$(echo $SON_WAN_GW | cut -d '.' -f3)
    gw4=$(echo $SON_WAN_GW | cut -d '.' -f4)
    if [ "$gw4" = "1" ]; then
        ping_test="$gw1.$gw2.$gw3.129"
        ping -I $SON_WAN_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
        if [ "$?" != "0" ]; then
            SON_IP="$gw1.$gw2.$gw3.129/25"
            SON_BRD="$gw1.$gw2.$gw3.255"
            SON_GW="$gw1.$gw2.$gw3.129"
            SON_START="$gw1.$gw2.$gw3.131"
            SON_END="$gw1.$gw2.$gw3.158"
            dnsmasq_son
        else
            ping_test="$gw1.$gw2.$gw3.65"
            ping -I $SON_WAN_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
            if [ "$?" != "0" ]; then
                SON_IP="$gw1.$gw2.$gw3.65/26"
                SON_BRD="$gw1.$gw2.$gw3.127"
                SON_GW="$gw1.$gw2.$gw3.65"
                SON_START="$gw1.$gw2.$gw3.67"
                SON_END="$gw1.$gw2.$gw3.94"
                dnsmasq_son
            else
                ping_test="$gw1.$gw2.$gw3.33"
                ping -I $SON_WAN_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
                if [ "$?" != "0" ]; then
                    SON_IP="$gw1.$gw2.$gw3.33/27"
                    SON_BRD="$gw1.$gw2.$gw3.63"
                    SON_GW="$gw1.$gw2.$gw3.33"
                    SON_START="$gw1.$gw2.$gw3.35"
                    SON_END="$gw1.$gw2.$gw3.62"
                    dnsmasq_son
                fi
            fi
        fi
    elif [ "$gw4" = "65" ]; then
        ping_test="$gw1.$gw2.$gw3.97"
        ping -I $SON_WAN_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
        if [ "$?" != "0" ]; then
            SON_IP="$gw1.$gw2.$gw3.97/27"
            SON_BRD="$gw1.$gw2.$gw3.127"
            SON_GW="$gw1.$gw2.$gw3.97"
            SON_START="$gw1.$gw2.$gw3.99"
            SON_END="$gw1.$gw2.$gw3.126"
            dnsmasq_son
        fi
    elif [ "$gw4" = "129" ]; then
        ping_test="$gw1.$gw2.$gw3.193"
        ping -I $SON_WAN_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
        if [ "$?" != "0" ]; then
            SON_IP="$gw1.$gw2.$gw3.193/25"
            SON_BRD="$gw1.$gw2.$gw3.255"
            SON_GW="$gw1.$gw2.$gw3.193"
            SON_START="$gw1.$gw2.$gw3.195"
            SON_END="$gw1.$gw2.$gw3.222"
            dnsmasq_son
        else
            ping_test="$gw1.$gw2.$gw3.161"
            ping -I $SON_WAN_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
            if [ "$?" != "0" ]; then
                SON_IP="$gw1.$gw2.$gw3.161/27"
                SON_BRD="$gw1.$gw2.$gw3.191"
                SON_GW="$gw1.$gw2.$gw3.161"
                SON_START="$gw1.$gw2.$gw3.163"
                SON_END="$gw1.$gw2.$gw3.190"
                dnsmasq_son
            fi
        fi
    elif [ "$gw4" = "193" ]; then
        ping_test="$gw1.$gw2.$gw3.225"
        ping -I $SON_WAN_IF "$ping_test" -c 1 -W 5 -s 20 > /dev/null 2>&1
        if [ "$?" != "0" ]; then
            SON_IP="$gw1.$gw2.$gw3.225/27"
            SON_BRD="$gw1.$gw2.$gw3.255"
            SON_GW="$gw1.$gw2.$gw3.225"
            SON_START="$gw1.$gw2.$gw3.227"
            SON_END="$gw1.$gw2.$gw3.254"
            dnsmasq_son
        fi
    fi
}

check_son()
{
    if [ "$1" != "$SON_WAN_IF" ] || [ "$2" != "$SON_WAN_GW" ]; then
        SON_WAN_IF=$1
        SON_WAN_GW=$2
        update_son
    fi
}

stop_son()
{
    kill_all "$DNSMASQ"
    if [ -e "$LAN_DHCP_LEASE2" ]; then
        rm -f $LAN_DHCP_LEASE2
    fi
    if [ -n "$SON_MAC" ]; then
        ifconfig $SON_IF down 
        del_route $SON_IF
        del_addr $SON_IF
        del_eth_son
        del_enx_son
        del_usb_son
    fi
    SON_WAN_IF=""
    SON_WAN_GW=""
}

init_son()
{
    SON_IF="$LAN_IF"
    if [ -z "$SON_IF" ]; then
        return
    fi
    SON_MAC=""
    son_if=$(ifconfig -a | grep $SON_IF | awk '{print $1}')
    if [ -n "$son_if" ]; then
        SON_MAC=$(ip addr show dev $SON_IF | grep 'link/' | awk '{print $2}')
    fi
    stop_son
    if [ "$SON_OP" = "1" ]; then
        mac2=$(echo $ETH_MAC | cut -d ':' -f2)
        mac3=$(echo $ETH_MAC | cut -d ':' -f3)
        mac4=$(echo $ETH_MAC | cut -d ':' -f4)
        mac5=$(echo $ETH_MAC | cut -d ':' -f5)
        mac6=$(echo $ETH_MAC | cut -d ':' -f6)
        mac="ee:$mac2:$mac3:$mac4:$mac5:$mac6"
        if [ "$SON_MAC" != "$mac" ]; then
            if [ -n "$SON_MAC" ]; then
                brctl delbr $SON_IF > /dev/null 2>&1
            fi
            SON_MAC="$mac"
            brctl addbr $SON_IF > /dev/null 2>&1
            brctl setfd $SON_IF 1 > /dev/null 2>&1
            ip link set dev $SON_IF address $SON_MAC > /dev/null 2>&1
        fi
    fi
}

#**********************#
# LAN Bridge Operation #
#**********************#
del_enx_lan()
{
    if [ -n "$LAN_MAC" ] && [ -n "$ENX_IF" ]; then
        brif=$(brctl show $LAN_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $LAN_IF $ENX_IF
            logger "LAN ($ENX_IF) info: interface removed from $LAN_IF"
        fi
    fi
}

add_enx_lan()
{
    brif=$(brctl show $LAN_IF | grep $ENX_IF) > /dev/null 2>&1
    if [ -z "$brif" ]; then
        brctl addif $LAN_IF $ENX_IF
        logger "LAN ($ENX_IF) info: interface added to $LAN_IF"
    fi
}

del_usb_lan()
{
    if [ -n "$LAN_MAC" ] && [ -n "$USB_IF" ]; then
        brif=$(brctl show $LAN_IF | grep $USB_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $LAN_IF $USB_IF
            logger "LAN ($USB_IF) info: interface removed from $LAN_IF"
        fi
    fi
}

add_usb_lan()
{
    brif=$(brctl show $LAN_IF | grep $USB_IF) > /dev/null 2>&1
    if [ -z "$brif" ]; then
        brctl addif $LAN_IF $USB_IF
        logger "LAN ($USB_IF) info: interface added to $LAN_IF"
    fi
}

del_eth_lan()
{
    if [ -n "$LAN_MAC" ] && [ -n "$ETH_IF" ]; then
        brif=$(brctl show $LAN_IF | grep $ETH_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $LAN_IF $ETH_IF
            logger "LAN ($ETH_IF) info: interface removed from $LAN_IF"
        fi
    fi
}

add_eth_lan()
{
    brif=$(brctl show $LAN_IF | grep $ETH_IF) > /dev/null 2>&1
    if [ -z "$brif" ]; then
        brctl addif $LAN_IF $ETH_IF
        logger "LAN ($ETH_IF) info: interface added to $LAN_IF"
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

start_lan()
{
    ip addr add dev $LAN_IF $LAN_IP broadcast $LAN_BRD
    ifconfig $LAN_IF up
    sleep 1
    if [ ! -e $LAN_DHCP_LEASE ]; then
        touch $LAN_DHCP_LEASE
    fi
    chown root:root $LAN_DHCP_LEASE
    $DHCPSRV -user root -group root -q -4 --no-pid -lf $LAN_DHCP_LEASE -cf $LAN_DHCP_CONF $LAN_IF
    logger "LAN ($LAN_IF) info: $LAN_IP (gateway: $LAN_GW)"
    dump_lan
}

config_lan()
{
    echo -n > $LAN_DHCP_CONF
    {
        if [ -n "$DNSADDR" ]; then
            echo "option domain-name-servers 8.8.8.8, $DNSADDR;"
        else
            echo "option domain-name-servers 8.8.8.8, 8.8.4.4;"
        fi
        echo "default-lease-time 600;"
        echo "max-lease-time 7200;"
        echo "subnet $LAN_NET netmask $LAN_MASK {"
        echo "  range $LAN_START $LAN_END;"
        echo "  option routers $LAN_GW;"
        echo "}"
    } >> $LAN_DHCP_CONF
}

check_lan()
{
    lan_if=$(ifconfig | grep $LAN_IF | awk '{print $1}')
    if [ -z "$lan_if" ]; then
        stop_lan
    fi
    if [ ! -e "$LAN_DHCP_LEASE" ]; then
        config_lan
        start_lan
    fi
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
    fi
}

#*******************#
# Monitor Operation #
#*******************#
start_mon()
{
    if [ -z "$MON_MAC" ]; then
        $IWUTILS dev $WIFI_PCI interface add $MON_IF type monitor > /dev/null 2>&1
        sleep 1
        logger "MON ($MON_IF) info: monitor interface created"
    fi
    MON_MAC=$(ip addr show dev $MON_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -n "$MON_MAC" ]; then
        ifconfig $MON_IF up
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
    MON_MAC=""
    mon_if=$(ifconfig -a | grep $MON_IF | awk '{print $1}')
    if [ -n "$mon_if" ]; then
        MON_MAC=$(ip addr show dev $MON_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    fi
    if [ "$MON_OP" = "0" ]; then
        stop_mon
        return
    fi
    start_mon
    if [ "$STA_OP" = "0" ] && [ "$WLN_OP" = "0" ]; then
        $IWUTILS dev $MON_IF set channel $MON_CHAN HT20
        logger "MON ($MON_IF) info: wireless monitor (channel: $MON_CHAN)"
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
            if [ "$VAP_OP" = "1" ]; then
                echo "  VAP_IF=$VAP_IF"
                echo "  VAP_MAC=$VAP_MAC"
                echo "  VAP_SSID=\"$VAP_SSID\""
            fi
            echo "  WLN_SSID=\"$WLN_SSID\""
            echo "  WLN_CHAN=$WLN_CHAN"
            echo "  WLN_WDS=$WLN_WDS"
        fi
    } >> $WLN_INFO
}

ssid_wln()
{
    wif=$1
    SSID=$($IWUTILS dev $wif info | grep ssid | awk '{print $2}') > /dev/null 2>&1
    if [ -n "$SSID" ]; then
        SSID1=$($IWUTILS dev $wif info | grep ssid | awk '{print $3}') > /dev/null 2>&1
        if [ -n "$SSID1" ]; then
            SSID2=$($IWUTILS dev $wif info | grep ssid | awk '{print $4}') > /dev/null 2>&1
            if [ -n "$SSID2" ]; then
                SSID3=$($IWUTILS dev $wif info | grep ssid | awk '{print $5}') > /dev/null 2>&1
                if [ -n "$SSID3" ]; then
                    echo "$SSID $SSID1 $SSID2 $SSID3"
                else
                    echo "$SSID $SSID1 $SSID2"
                fi
            else
                echo "$SSID $SSID1"
            fi
        else
            echo "$SSID"
        fi
    else
        echo ""
    fi
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
        if [ "$WLN_TOGGLE_TEST" = "1" ]; then
            if [ $WLN_TOGGLE_COUNT -gt 0 ]; then
                WLN_TOGGLE_COUNT=$(($WLN_TOGGLE_COUNT - 1))
                if [ $WLN_TOGGLE_COUNT -eq 0 ]; then
                    logger "WLN ($WLN_IF) info: toggle interface up..."
                    start_wln
                fi
                return
            fi
        fi
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
    if [ "$LAN_OP" = "1" ]; then
        check_lan
    fi
    if [ -n "$WLN_POWER_TX" ]; then
        return
    fi
    if [ "$WLN_SWING_TEST" = "1" ]; then
        if [ $WLN_SWING_COUNT -eq $WLN_SWING_DWELL ]; then
            logger "WLN ($WLN_IF) info: Tx power $WLN_SWING_LEVEL dBm"
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
    elif [ "$WLN_TOGGLE_TEST" = "1" ]; then
        WLN_TOGGLE_COUNT=$(($WLN_TOGGLE_COUNT - 1))
        if [ $WLN_TOGGLE_COUNT -eq 0 ]; then
            logger "WLN ($WLN_IF) info: toggle interface down..."
            WLN_TOGGLE_COUNT=$WLN_TOGGLE_OFF
            stop_wln
            WLN_SSID=""
            dump_wln
        fi
    fi
}

link_wln()
{
    pid=$(ps -e | grep hostapd | awk '{print $1}')
    if [ -n "$pid" ]; then
        ssid=$(ssid_wln $WLN_IF)
        if [ -n "$ssid" ]; then
            logger "WLN ($WLN_IF) info: \"$ssid\" (bssid: $WLN_MAC channel: $WLN_CHAN)"
            WLN_STATE="COMPLETED"
            WLN_SSID="$ssid"
            if [ "$VAP_OP" = "1" ]; then
                VAP_MAC=$(ip addr show dev $VAP_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
                VAP_SSID=$(ssid_wln $VAP_IF)
                logger "VAP ($VAP_IF) info: \"$VAP_SSID\" (bssid: $VAP_MAC)"
            fi
            dump_wln
            if [ -n "$WLN_POWER_TX" ]; then
                iwconfig $WLN_IF txpower $WLN_POWER_TX
            elif [ "$WLN_SWING_TEST" = "1" ]; then
                WLN_SWING_COUNT=$WLN_SWING_DWELL
                WLN_SWING_LEVEL=$WLN_SWING_HIGH
                WLN_SWING_CLIMB=0
            elif [ "$WLN_TOGGLE_TEST" = "1" ]; then
                WLN_TOGGLE_COUNT=$WLN_TOGGLE_ON
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
    if [ "$VAP_OP" = "1" ]; then
        if [ "$WLN_WAN" = "1" ] && [ "$VAP_WAN" = "1" ]; then
            wln_conf=$VAP_CONF22
        elif [ "$WLN_WAN" = "1" ]; then
            wln_conf=$VAP_CONF21
        elif [ "$WLN_WAN" = "0" ] && [ "$VAP_WAN" = "1" ]; then
            wln_conf=$VAP_CONF12
        else
            wln_conf=$VAP_CONF11
        fi
    else
        if [ "$WLN_WDS" = "1" ] && [ "$WLN_WAN" = "1" ]; then
            wln_conf=$WLN_CONF22
        elif [ "$WLN_WDS" = "1" ]; then
            wln_conf=$WLN_CONF21
        elif [ "$WLN_WDS" = "0" ] && [ "$WLN_WAN" = "1" ]; then
            wln_conf=$WLN_CONF12
        else
            wln_conf=$WLN_CONF11
        fi
    fi
    WLN_CHAN=$(cat $wln_conf | grep 'channel=' | cut -d '=' -f2)
    if [ "$WLN_DBG" = "1" ]; then
        $HOSTAPD -B -t -f $WLN_LOG $wln_conf > /dev/null 2>&1
    elif [ "$WLN_DBG" = "2" ]; then
        $HOSTAPD -B -t -f $WLN_LOG -d $wln_conf > /dev/null 2>&1
    elif [ "$WLN_DBG" = "3" ]; then
        $HOSTAPD -B -t -f $WLN_LOG -d -K $wln_conf > /dev/null 2>&1
    else
        $HOSTAPD -B -t $wln_conf > /dev/null 2>&1
    fi
    WLN_STATE="STARTED"
    WLN_LINK_COUNT=10
    WLN_SWING_COUNT=0
    WLN_TOGGLE_COUNT=0
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
dump_sap()
{
    echo -n > $SAP_INFO
    {
        echo "SAP info:"
        echo "  SAP_IF=$SAP_IF"
        echo "  SAP_MAC=$SAP_MAC"
        if [ -n "$SAP_SSID" ]; then
            echo "  SAP_SSID=\"$SAP_SSID\""
            echo "  SAP_CHAN=$SAP_CHAN"
            echo "  SAP_WDS=$SAP_WDS"
        fi
    } >> $SAP_INFO
}

ssid_sap()
{
    SSID=$($IWUTILS dev $SAP_IF info | grep ssid | awk '{print $2}') > /dev/null 2>&1
    if [ -n "$SSID" ]; then
        SSID1=$($IWUTILS dev $SAP_IF info | grep ssid | awk '{print $3}') > /dev/null 2>&1
        if [ -n "$SSID1" ]; then
            SSID2=$($IWUTILS dev $SAP_IF info | grep ssid | awk '{print $4}') > /dev/null 2>&1
            if [ -n "$SSID2" ]; then
                SSID3=$($IWUTILS dev $SAP_IF info | grep ssid | awk '{print $5}') > /dev/null 2>&1
                if [ -n "$SSID3" ]; then
                    echo "$SSID $SSID1 $SSID2 $SSID3"
                else
                    echo "$SSID $SSID1 $SSID2"
                fi
            else
                echo "$SSID $SSID1"
            fi
        else
            echo "$SSID"
        fi
    else
        echo ""
    fi
}

reset_sap()
{
    stop_sap
    SAP_SSID=""
    SAP_CHAN=0
    dump_sap
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
        if [ "$SAP_TOGGLE_TEST" = "1" ]; then
            if [ $SAP_TOGGLE_COUNT -gt 0 ]; then
                SAP_TOGGLE_COUNT=$(($SAP_TOGGLE_COUNT - 1))
                if [ $SAP_TOGGLE_COUNT -eq 0 ]; then
                    logger "SAP ($SAP_IF) info: toggle interface up..."
                    start_sap
                fi
                return
            fi
        fi
        link_sap
        return
    fi
    ssid=$(ssid_sap)
    if [ -z "$ssid" ]; then
        link_sap
        return
    fi
    if [ -z "$SAP_SSID" ]; then
        logger "SAP ($SAP_IF) info: \"$ssid\" (bssid: $SAP_MAC)"
        SAP_SSID="$ssid"
        dump_sap
        if [ -n "$SAP_POWER_TX" ]; then
            iwconfig $SAP_IF txpower $SAP_POWER_TX
        elif [ "$SAP_SWING_TEST" = "1" ]; then
            SAP_SWING_COUNT=$SAP_SWING_DWELL
            SAP_SWING_LEVEL=$SAP_SWING_HIGH
            SAP_SWING_CLIMB=0
        elif [ "$SAP_TOGGLE_TEST" = "1" ]; then
            SAP_TOGGLE_COUNT=$SAP_TOGGLE_ON
        fi
        return
    fi
    sap_phy=$(cat /sys/class/net/$SAP_IF/operstate) > /dev/null 2>&1
    if [ "$sap_phy" = "down" ]; then
        ifconfig $SAP_IF up
        return
    fi
    if [ "$LAN_OP" = "1" ]; then
        check_lan
    fi
    if [ -n "$SAP_POWER_TX" ]; then
        return
    fi
    if [ "$SAP_SWING_TEST" = "1" ]; then
        if [ $SAP_SWING_COUNT -eq $SAP_SWING_DWELL ]; then
            logger "SAP ($SAP_IF) info: Tx power $SAP_SWING_LEVEL dBm"
            iwconfig $SAP_IF txpower $SAP_SWING_LEVEL
        fi
        SAP_SWING_COUNT=$(($SAP_SWING_COUNT - 1))
        if [ $SAP_SWING_COUNT -eq 0 ]; then
            SAP_SWING_COUNT=$SAP_SWING_DWELL
            if [ $SAP_SWING_CLIMB -eq 0 ]; then
                SAP_SWING_LEVEL=$(($SAP_SWING_LEVEL - $SAP_SWING_STEP))
                if [ $SAP_SWING_LEVEL -lt $SAP_SWING_LOW ]; then
                    SAP_SWING_LEVEL=$SAP_SWING_LOW
                    SAP_SWING_CLIMB=1
                fi
            else
                SAP_SWING_LEVEL=$(($SAP_SWING_LEVEL + $SAP_SWING_STEP))
                if [ $SAP_SWING_LEVEL -gt $SAP_SWING_HIGH ]; then
                    SAP_SWING_LEVEL=$SAP_SWING_HIGH
                    SAP_SWING_CLIMB=0
                fi
            fi
        fi
    elif [ "$SAP_TOGGLE_TEST" = "1" ]; then
        SAP_TOGGLE_COUNT=$(($SAP_TOGGLE_COUNT - 1))
        if [ $SAP_TOGGLE_COUNT -eq 0 ]; then
            logger "SAP ($SAP_IF) info: toggle interface down..."
            SAP_TOGGLE_COUNT=$SAP_TOGGLE_OFF
            stop_sap
            SAP_SSID=""
            dump_sap
        fi
    fi
}

link_sap()
{
    if [ -n "$SAP_SSID" ]; then
        reset_sap
        SAP_LINK_COUNT=5
        return
    fi
    if [ $SAP_LINK_COUNT -gt 0 ]; then
        SAP_LINK_COUNT=$(($SAP_LINK_COUNT - 1))
    fi
    if [ $SAP_LINK_COUNT -eq 0 ]; then
        start_sap
    fi
}

start_sap()
{
    if [ "$SAP_WDS" = "1" ] && [ "$SAP_WAN" = "1" ]; then
       sap_conf=$SAP_CONF22
    elif [ "$SAP_WDS" = "1" ]; then
        sap_conf=$SAP_CONF21
    elif [ "$SAP_WDS" = "0" ] && [ "$SAP_WAN" = "1" ]; then
        sap_conf=$SAP_CONF12
    else
        sap_conf=$SAP_CONF11
    fi
    if [ $SAP_CHAN -ne $STA_CHAN ]; then
        sed '/channel=/d' $sap_conf > /tmp/hostapd-sap0.conf
        mv -f /tmp/hostapd-sap0.conf $sap_conf
        echo channel=$STA_CHAN >> $sap_conf
        SAP_CHAN=$STA_CHAN
    fi
    if [ "$SAP_DBG" = "1" ]; then
        $HOSTAPD -B -t -f $SAP_LOG $sap_conf > /dev/null 2>&1
    elif [ "$SAP_DBG" = "2" ]; then
        $HOSTAPD -B -t -f $SAP_LOG -d $sap_conf > /dev/null 2>&1
    elif [ "$SAP_DBG" = "3" ]; then
        $HOSTAPD -B -t -f $SAP_LOG -d -K $sap_conf > /dev/null 2>&1
    else
        $HOSTAPD -B -t $sap_conf > /dev/null 2>&1
    fi
    SAP_LINK_COUNT=10
    SAP_SWING_COUNT=0
    SAP_TOGGLE_COUNT=0
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
        mac2=$(echo $STA_MAC | cut -d ':' -f2)
        mac3=$(echo $STA_MAC | cut -d ':' -f3)
        mac4=$(echo $STA_MAC | cut -d ':' -f4)
        mac5=$(echo $STA_MAC | cut -d ':' -f5)
        mac6=$(echo $STA_MAC | cut -d ':' -f6)
        mac="fe:$mac2:$mac3:$mac4:$mac5:$mac6"
        if [ "$SAP_MAC" != "$mac" ]; then
            if [ -n "$SAP_MAC" ]; then
                $IWUTILS dev $SAP_IF del
            fi
            SAP_MAC="$mac"
            $IWUTILS dev $STA_IF interface add $SAP_IF type managed > /dev/null 2>&1
            ip link set dev $SAP_IF address $SAP_MAC
        fi
        ifconfig $SAP_IF 0.0.0.0 up
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
        if [ $STA_DHCP_COUNT -eq 0 ]; then
            echo "  WAN_DHCP=0"
        else
            echo "  WAN_DHCP=1"
        fi
    } >> $WAN_INFO
}

ssid_sta()
{
    SSIDNum=0
    SSIDSeq=""
    SSIDExt=""
    SSIDSta=""
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
                    SSIDSta=${SSIDSta}" ssid $ssid1"
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
        logger "STA ($STA_IF) info: configured network(s) $SSIDSeq"
    elif [ $SSIDNum -eq 1 ]; then
        logger "STA ($STA_IF) info: configured network \"$SSIDExt\""
    else
        logger "STA ($STA_IF) info: configured network(s) $SSIDSeq \"$SSIDExt\""
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
            echo "  STA_SSID=\"$STA_SSID\""
            echo "  STA_BSSID=$STA_BSSID"
            if [ "$WIFI_PCI" = "wlp12s0" ]; then
                echo "  STA_FREQ=$STA_CHAN"
            else
                echo "  STA_CHAN=$STA_CHAN"
            fi
            echo "  STA_WDS=$SAP_WDS"
        fi
    } >> $STA_INFO
}

clean_sta()
{
    if [ "$SON_OP" = "1" ]; then
        stop_son
    fi
    if [ "$BRI_OP" = "2" ]; then
        brif=$(brctl show $BRI_IF | grep $STA_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            return
        fi
        kill_one "$BRI_DHCP_PID"
        if [ -e "$BRI_DHCP_LEASE" ]; then
            rm -f $BRI_DHCP_LEASE
        fi
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
    sta_ssid=$($IWUTILS dev $STA_IF link | grep 'SSID:' | awk '{print $2}') > /dev/null 2>&1
    if [ -n "$sta_ssid" ]; then
        sta_ssid1=$($IWUTILS dev $STA_IF link | grep 'SSID:' | awk '{print $3}') > /dev/null 2>&1
        if [ -n "$sta_ssid1" ]; then
            sta_ssid="$sta_ssid $sta_ssid1"
            sta_ssid2=$($IWUTILS dev $STA_IF link | grep 'SSID:' | awk '{print $4}') > /dev/null 2>&1
            if [ -n "$sta_ssid2" ]; then
                sta_ssid="$sta_ssid $sta_ssid2"
                sta_ssid3=$($IWUTILS dev $STA_IF link | grep 'SSID:' | awk '{print $5}') > /dev/null 2>&1
                if [ -n "$sta_ssid3" ]; then
                    sta_ssid="$sta_ssid $sta_ssid3"
                fi
            fi
        fi
    fi
    if [ "$sta_ssid" != "$STA_SSID" ]; then
        if [ -n "$STA_SSID" ]; then
            clean_sta
        fi
        STA_SSID="$sta_ssid"
    fi
    if [ "$WIFI_PCI" = "wlp12s0" ]; then
        STA_CHAN=$($IWUTILS dev $STA_IF link | grep freq | awk '{print $2}') > /dev/null 2>&1
        logger "STA ($STA_IF) info: \"$STA_SSID\" (bssid: $STA_BSSID freq: $STA_CHAN)"
    else
        STA_CHAN=$($IWUTILS dev $STA_IF info | grep channel | awk '{print $2}') > /dev/null 2>&1
        logger "STA ($STA_IF) info: \"$STA_SSID\" (bssid: $STA_BSSID channel: $STA_CHAN)"
    fi
    STA_RSSI=""
    STA_WAN_GW=""
    STA_WAN_IP=""
    STA_WAN_NET=""
    STA_DHCP_COUNT=0
    STA_DHCP_STARTED=0
}

lost_sta()
{
    logger "STA ($STA_IF) info: lost AP (bssid: $STA_BSSID)"
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
    wpa_sta=$(ps -ef | grep wpa_supplicant-$STA | awk '{print $2}')
    if [ -z "$wpa_sta" ]; then
        if [ -n "$STA_BSSID" ]; then
            lost_sta
        fi
        stop_sta
        STA_STATE="STARTING"
        return
    fi
    bssid=$($IWUTILS dev $STA_IF link | grep Connected | awk '{print $3}') > /dev/null 2>&1
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
    rssi=$($IWUTILS dev $STA_IF link | grep 'signal:' | awk '{print $2}') > /dev/null 2>&1    
    if [ -z "$rssi" ]; then
        if [ -n "$STA_BSSID" ]; then
            lost_sta
        fi
        return
    fi
    if [ -z "$STA_RSSI" ]; then
        STA_RSSI=$rssi
        logger "STA ($STA_IF) info: rssi $rssi dBm"
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
        logger "STA ($STA_IF) info: rssi $rssi dBm"
    fi
    if [ "$STA_ROAM_OFF" = "0" ]; then
        STA_ROAM_FULL_SCAN=$(($STA_ROAM_FULL_SCAN + 1))
        STA_ROAM_FAST_SCAN=$(($STA_ROAM_FAST_SCAN + 1))
        if [ $STA_ROAM_FULL_SCAN -ge 55 ] && [ $STA_ROAM_FAST_SCAN -ge 5 ]; then
            STA_ROAM_FULL_SCAN=0
            STA_ROAM_FAST_SCAN=0
            logger "STA ($STA_IF) info: start roam full scan (rssi: $rssi dBm)"
            wpa_cli -p $STA_CTRL scan > /dev/null 2>&1
            return
        fi
        if [ $rssi -le -75 ] && [ $STA_ROAM_FAST_SCAN -ge 5 ] && [ $STA_ROAM_FULL_SCAN -ge 10 ]; then
            STA_ROAM_FAST_SCAN=0
        elif [ $rssi -le -65 ] && [ $STA_ROAM_FAST_SCAN -ge 10 ]; then
            STA_ROAM_FAST_SCAN=0
        fi
        if [ $STA_ROAM_FAST_SCAN -eq 0 ]; then
            logger "STA ($STA_IF) info: start roam fast scan (rssi: $rssi dBm)"
            if [ -n "$SSIDSta" ]; then
                wpa_cli -p $STA_CTRL scan $SSIDSta > /dev/null 2>&1
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
        if [ "$ENX_OP" = "1" ] && [ "$ENX_STATE" = "ATTACHED" ]; then
            enx_gw=$(ip route show dev $ENX_IF | grep default | awk '{print $3}')
            if [ -n "$enx_gw" ]; then
                ENX_WAN_GW="$enx_gw"
                del_default_route $ENX_IF
            fi
        fi
        if [ "$USB_OP" = "1" ] && [ "$USB_STATE" = "ATTACHED" ]; then
            usb_gw=$(ip route show dev $USB_IF | grep default | awk '{print $3}')
            if [ -n "$usb_gw" ]; then
                USB_WAN_GW="$usb_gw"
                del_default_route $USB_IF
            fi
        fi
        if [ "$STX_OP" = "1" ] && [ "$STX_STATE" = "COMPLETED" ]; then
            stx_gw=$(ip route show dev $STX_IF | grep default | awk '{print $3}')
            if [ -n "$stx_gw" ]; then
                STX_WAN_GW="$stx_gw"
                del_default_route $STX_IF
            fi
        fi
        if [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ] && [ "$STA_PRI" = "1" ]; then
            eth_gw=$(ip route show dev $ETH_IF | grep default | awk '{print $3}')
            if [ -n "$eth_gw" ]; then
                ETH_WAN_GW="$eth_gw"
                del_default_route $ETH_IF
            fi
        fi
        sta_ip=$(ip addr show $STA_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$sta_ip" ]; then
            if [ -n "$STA_WAN_IP" ]; then
                ip addr add dev $STA_IF $STA_WAN_IP broadcast $STA_WAN_BRD > /dev/null 2>&1
                STA_WAN_IP=""
                return
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
        dump_wan_sta
    fi
    if [ "$BRI_OP" = "0" ] && [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
        if [ "$STA_PRI" = "0" ]; then
            eth_ip=$(ip addr show $ETH_IF | grep 'inet ' | head -n1 | awk '{print $2}')
            if [ -n "$eth_ip" ]; then
                return
            fi
        else
            eth_gw=$(ip route show dev $ETH_IF | grep default | awk '{print $3}')
            if [ -n "$eth_gw" ]; then
                ETH_WAN_GW="$eth_gw"
                del_default_route $ETH_IF
                config_sta
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
        logger "WAN ($STA_WAN_IF) info: $STA_WAN_IP (gateway: $STA_WAN_GW)"
        STA_PING_PUBLIC=1
        STA_PING_COUNT=3
        STA_WAN_COUNT=15
        add_network_dns
        dump_wan_sta
        if [ "$SON_OP" = "1" ]; then
            check_son "$STA_WAN_IF" "$STA_WAN_GW"
        fi
    fi
    if [ "$ENX_OP" = "1" ] && [ "$ENX_STATE" = "ATTACHED" ]; then
        for enx_route in $(ip route | grep dev.*$ENX_IF | awk '{print $1}'); do
            for enx_route in $STA_WAN_NET; do
                ip route del $enx_route dev $ENX_IF > /dev/null 2>&1
            done
        done
    fi
    if [ "$USB_OP" = "1" ] && [ "$USB_STATE" = "ATTACHED" ]; then
        for usb_route in $(ip route | grep dev.*$USB_IF | awk '{print $1}'); do
            for usb_route in $STA_WAN_NET; do
                ip route del $usb_route dev $USB_IF > /dev/null 2>&1
            done
        done
    fi
    if [ "$STX_OP" = "1" ] && [ "$STX_STATE" = "COMPLETED" ]; then
        for stx_route in $(ip route | grep dev.*$STX_IF | awk '{print $1}'); do
            for stx_route in $STA_WAN_NET; do
                ip route del $stx_route dev $STX_IF > /dev/null 2>&1
            done
        done
    fi
    if [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ] && [ "$STA_PRI" = "1" ]; then
        for eth_route in $(ip route | grep dev.*$ETH_IF | awk '{print $1}'); do
            for eth_route in $STA_WAN_NET; do
                ip route del $eth_route dev $ETH_IF > /dev/null 2>&1
            done
        done
    fi
    if [ ! -e "$WAN_INFO" ]; then
        dump_wan_sta
    fi
    if [ $STA_WAN_COUNT -gt 0 ]; then
        STA_WAN_COUNT=$(($STA_WAN_COUNT - 1))
        return
    fi
    STA_WAN_COUNT=4
    if [ -n "$STA_WAN_GW" ] && [ "$STA_PING" = "1" ]; then
        ping_sta
        if [ $? -eq 1 ]; then
            logger "WAN ($STA_WAN_IF) info: lost connection (ip: $STA_WAN_IP gw: $STA_WAN_GW)"
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
        bssid=$($IWUTILS dev $STA_IF link | grep Connected | awk '{print $3}') > /dev/null 2>&1
        if [ -n "$bssid" ]; then
            bssid_sta "$bssid"
            dump_sta
            STA_STATE="COMPLETED"
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

#****************#
# WLX Operation #
#****************#
dump_wlx()
{
    echo -n > $WLX_INFO
    {
        echo "WLX info:"
        echo "  WLX_IF=$WLX_IF"
        echo "  WLX_MAC=$WLX_MAC"
        if [ -n "$WLX_SSID" ]; then
            echo "  WLX_SSID=\"$WLX_SSID\""
            echo "  WLX_CHAN=$WLX_CHAN"
            echo "  WLX_WDS=$WLX_WDS"
        fi
    } >> $WLX_INFO
}

ssid_wlx()
{
    wif=$1
    SSID=$($IWUTILS dev $wif info | grep ssid | awk '{print $2}') > /dev/null 2>&1
    if [ -n "$SSID" ]; then
        SSID1=$($IWUTILS dev $wif info | grep ssid | awk '{print $3}') > /dev/null 2>&1
        if [ -n "$SSID1" ]; then
            SSID2=$($IWUTILS dev $wif info | grep ssid | awk '{print $4}') > /dev/null 2>&1
            if [ -n "$SSID2" ]; then
                SSID3=$($IWUTILS dev $wif info | grep ssid | awk '{print $5}') > /dev/null 2>&1
                if [ -n "$SSID3" ]; then
                    echo "$SSID $SSID1 $SSID2 $SSID3"
                else
                    echo "$SSID $SSID1 $SSID2"
                fi
            else
                echo "$SSID $SSID1"
            fi
        else
            echo "$SSID"
        fi
    else
        echo ""
    fi
}

reset_wlx()
{
    stop_wlx
    WLX_STATE="STARTING"
    WLX_SSID=""
    dump_wlx
}

check_wlx()
{
    WLX_MAC=$(ip addr show dev $WLX_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$WLX_MAC" ]; then
        if [ -e "$WLX_INFO" ]; then
            rm -f $WLX_INFO
        fi
        stop_wlx
        WLX_OP=0
        WLX_IF=""
        sleep 1
        return
    fi
    pid=$(ps -e | grep hostapd | awk '{print $1}')
    if [ -z "$pid" ]; then
        if [ "$WLX_TOGGLE_TEST" = "1" ]; then
            if [ $WLX_TOGGLE_COUNT -gt 0 ]; then
                WLX_TOGGLE_COUNT=$(($WLX_TOGGLE_COUNT - 1))
                if [ $WLX_TOGGLE_COUNT -eq 0 ]; then
                    logger "WLX ($WLX_IF) info: toggle interface up..."
                    start_wlx
                fi
                return
            fi
        fi
        reset_wlx
        return
    fi
    ssid=$(ssid_wlx $WLX_IF)
    if [ -z "$ssid" ]; then
        reset_wlx
        return
    fi
    wlx_phy=$(cat /sys/class/net/$WLX_IF/operstate) > /dev/null 2>&1
    if [ "$wlx_phy" = "down" ]; then
        ifconfig $WLX_IF up
        return
    fi
    if [ "$LAN_OP" = "1" ]; then
        check_lan
    fi
    if [ "$WLX_TOGGLE_TEST" = "1" ]; then
        WLX_TOGGLE_COUNT=$(($WLX_TOGGLE_COUNT - 1))
        if [ $WLX_TOGGLE_COUNT -eq 0 ]; then
            logger "WLX ($WLX_IF) info: toggle interface down..."
            WLX_TOGGLE_COUNT=$WLX_TOGGLE_OFF
            stop_wlx
            WLX_SSID=""
            dump_wlx
        fi
    fi
}

link_wlx()
{
    pid=$(ps -e | grep hostapd | awk '{print $1}')
    if [ -n "$pid" ]; then
        ssid=$(ssid_wlx $WLX_IF)
        if [ -n "$ssid" ]; then
            logger "WLX ($WLX_IF) info: \"$ssid\" (bssid: $WLX_MAC channel: $WLX_CHAN)"
            WLX_STATE="COMPLETED"
            WLX_SSID="$ssid"
            dump_wlx
            if [ "$WLX_TOGGLE_TEST" = "1" ]; then
                WLX_TOGGLE_COUNT=$WLX_TOGGLE_ON
            fi
            return
        fi
    fi
    if [ $WLX_LINK_COUNT -gt 0 ]; then
        WLX_LINK_COUNT=$(($WLX_LINK_COUNT - 1))
    fi
    if [ $WLX_LINK_COUNT -eq 0 ]; then
        stop_wlx
        WLX_STATE="STARTING"
    fi
}

start_wlx()
{
    ifconfig $WLX_IF 0.0.0.0 up
    if [ "$WLX_WAN" = "1" ]; then
        wlx_conf=$WLX_CONF2
    else
        wlx_conf=$WLX_CONF1
    fi
    WLX_CHAN=$(cat $wlx_conf | grep 'channel=' | cut -d '=' -f2)
    if [ "$WLX_DBG" = "1" ]; then
        $HOSTAPD -B -t -f $WLX_LOG $wlx_conf > /dev/null 2>&1
    elif [ "$WLX_DBG" = "2" ]; then
        $HOSTAPD -B -t -f $WLX_LOG -d $wlx_conf > /dev/null 2>&1
    elif [ "$WLX_DBG" = "3" ]; then
        $HOSTAPD -B -t -f $WLX_LOG -d -K $wlx_conf > /dev/null 2>&1
    else
        $HOSTAPD -B -t $wlx_conf > /dev/null 2>&1
    fi
    WLX_STATE="STARTED"
    WLX_LINK_COUNT=10
    WLX_SWING_COUNT=0
    WLX_TOGGLE_COUNT=0
}

stop_wlx()
{
    kill_all "$HOSTAPD"
    if [ -e $WLX_CTRL ]; then
        rm -rf $WLX_CTRL
    fi
    if [ -n "$WLX_MAC" ]; then
        ifconfig $WLX_IF down
    fi
}

init_wlx()
{
    if [ -z "$WLX_IF" ]; then
        return
    fi
    WLX_MAC=$(ip addr show dev $WLX_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$WLX_MAC" ]; then
        logger "Cannot find WLX interface $WLX_IF"
        WLX_OP=0
        WLX_IF=""
        return
    fi
    stop_wlx
    if [ "$WLX_OP" = "1" ]; then
        WLX_STATE="STARTING"
    fi
}

#***************#
# STX Operation #
#***************#
dump_wan_stx()
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
        echo "  WAN_IF=$STX_IF"
        echo "  WAN_MAC=$STX_MAC"
        if [ -n "$STX_WAN_GW" ]; then
            echo "  WAN_GW=$STX_WAN_GW"
        fi
        if [ -n "$STX_WAN_IP" ]; then
            echo "  WAN_IP=$STX_WAN_IP"
        fi
        if [ -n "$STX_WAN_NET" ]; then
            echo "  WAN_NET=$STX_WAN_NET"
        fi
        if [ $STX_DHCP_COUNT -eq 0 ]; then
            echo "  WAN_DHCP=0"
        else
            echo "  WAN_DHCP=1"
        fi
    } >> $WAN_INFO
}

ssid_stx()
{
    SSIDNum=0
    SSIDSeq=""
    SSIDExt=""
    SSIDStx=""
    cat $STX_CONF | grep 'ssid="' | cut -d '"' -f2 > tmpssids
    cat $STX_CONF | grep 'disabled=' | cut -d '=' -f2 > tmpdisabs
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
                    SSIDStx=${SSIDStx}" ssid $ssid1"
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
        logger "STX ($STX_IF) info: configured network(s) $SSIDSeq"
    elif [ $SSIDNum -eq 1 ]; then
        logger "STX ($STX_IF) info: configured network \"$SSIDExt\""
    else
        logger "STX ($STX_IF) info: configured network(s) $SSIDSeq \"$SSIDExt\""
    fi
}

ping_stx()
{
    if [ -n "$STX_PING_IP" ]; then
        ping -I $STX_WAN_IF "$STX_PING_IP" -c 1 -W 5 -s 20 > /dev/null 2>&1
    elif [ $STX_PING_PUBLIC -eq 0 ]; then
        ping -I $STX_WAN_IF "$STX_WAN_GW" -c 1 -W 5 -s 20 > /dev/null 2>&1
    else
        ping -I $STX_WAN_IF "8.8.8.8" -c 1 -W 10 -s 20 > /dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then
        STX_PING_PUBLIC=0
        STX_PING_COUNT=3
    else
        if [ $STX_PING_PUBLIC -eq 0 ]; then
            STX_PING_PUBLIC=1
            STX_PING_COUNT=3
        else
            STX_PING_COUNT=$(($STX_PING_COUNT - 1))
            if [ $STX_PING_COUNT -le 0 ]; then
                if [ $STX_PING_PUBLIC -eq 0 ]; then
                    STX_PING_PUBLIC=1
                    STX_PING_COUNT=3
                    return 0
                fi
                return 1
            fi
        fi
    fi
    return 0
}

dump_stx()
{
    echo -n > $STX_INFO
    {
        echo "STX info:"
        echo "  STX_IF=$STX_IF"
        echo "  STX_MAC=$STX_MAC"
        if [ -n "$STX_BSSID" ]; then
            echo "  STX_SSID=\"$STX_SSID\""
            echo "  STX_BSSID=$STX_BSSID"
            echo "  STX_FREQ=$STX_CHAN"
            echo "  STX_WDS=$STX_WDS"
        fi
    } >> $STX_INFO
}

clean_stx()
{
    if [ "$SON_OP" = "1" ]; then
        stop_son
    fi
    kill_one "$STX_DHCP_PID"
    if [ -e $STX_DHCP_LEASE ]; then
        rm -f $STX_DHCP_LEASE
    fi
    if [ -e "$WAN_INFO" ]; then
        rm -f $WAN_INFO
    fi
    del_default_route $STX_WAN_IF
    del_route $STX_WAN_IF
    del_addr $STX_WAN_IF
    STX_WAN_GW=""
}

static_stx()
{
    clean_stx
    ip addr add dev $STX_IF $STX_IP broadcast $STX_BRD > /dev/null 2>&1
    ip route add default via $STX_GW dev $STX_IF > /dev/null 2>&1
    STX_DHCP_STARTED=0
}

dynamic_stx()
{
    clean_stx
    $DHCPCLI -nw -1 -q -pf $STX_DHCP_PID -lf $STX_DHCP_LEASE $STX_IF > /dev/null 2>&1
    STX_DHCP_COUNT=12
    STX_DHCP_STARTED=1
}

config_stx()
{
    if [ "$STX_CONFIG" = "0" ]; then
        static_stx
    else
        if [ $STX_DHCP_STARTED -eq 1 ]; then
            if [ $STX_DHCP_COUNT -gt 0 ]; then
                STX_DHCP_COUNT=$(($STX_DHCP_COUNT - 1))
                return
            fi
            static_stx
        else
            dynamic_stx
        fi
    fi
}

bssid_stx()
{
    STX_BSSID="$1"
    stx_ssid=$($IWUTILS dev $STX_IF link | grep 'SSID:' | awk '{print $2}') > /dev/null 2>&1
    if [ -n "$stx_ssid" ]; then
        stx_ssid1=$($IWUTILS dev $STX_IF link | grep 'SSID:' | awk '{print $3}') > /dev/null 2>&1
        if [ -n "$stx_ssid1" ]; then
            stx_ssid="$stx_ssid $stx_ssid1"
            stx_ssid2=$($IWUTILS dev $STX_IF link | grep 'SSID:' | awk '{print $4}') > /dev/null 2>&1
            if [ -n "$stx_ssid2" ]; then
                stx_ssid="$stx_ssid $stx_ssid2"
                stx_ssid3=$($IWUTILS dev $STX_IF link | grep 'SSID:' | awk '{print $5}') > /dev/null 2>&1
                if [ -n "$stx_ssid3" ]; then
                    stx_ssid="$stx_ssid $stx_ssid3"
                fi
            fi
        fi
    fi
    if [ "$stx_ssid" != "$STX_SSID" ]; then
        if [ -n "$STX_SSID" ]; then
            clean_stx
        fi
        STX_SSID="$stx_ssid"
    fi
    STX_CHAN=$($IWUTILS dev $STX_IF link | grep freq | awk '{print $2}') > /dev/null 2>&1
    logger "STX ($STX_IF) info: \"$STX_SSID\" (bssid: $STX_BSSID freq: $STX_CHAN)"
    STX_RSSI=""
    STX_WAN_GW=""
    STX_WAN_IP=""
    STX_WAN_NET=""
    STX_DHCP_COUNT=0
    STX_DHCP_STARTED=0
}

lost_stx()
{
    logger "STX ($STX_IF) info: lost AP (bssid: $STX_BSSID)"
    STX_BSSID=""
    clean_stx
}

check_stx()
{
    STX_MAC=$(ip addr show dev $STX_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$STX_MAC" ]; then
        if [ -e "$WAN_INFO" ]; then
            rm -f $WAN_INFO
        fi
        stop_stx
        STX_OP=0
        STX_IF=""
        sleep 1
        return
    fi
    wpa_stx=$(ps -ef | grep wpa_supplicant-$STX | awk '{print $2}')
    if [ -z "$wpa_stx" ]; then
        if [ -n "$STX_BSSID" ]; then
            lost_stx
        fi
        stop_stx
        STX_STATE="STARTING"
        return
    fi
    bssid=$($IWUTILS dev $STX_IF link | grep Connected | awk '{print $3}') > /dev/null 2>&1
    if [ -z "$bssid" ]; then
        if [ -n "$STX_BSSID" ]; then
            lost_stx
        fi
        return
    fi
    if [ "$bssid" != "$STX_BSSID" ]; then
        bssid_stx "$bssid"
        dump_stx
        if [ -n "$STX_WAN_GW" ] && [ "$STX_PING" = "1" ]; then
            STX_PING_PUBLIC=1
            STX_PING_COUNT=1
            STX_WAN_COUNT=0
        fi
    fi
    rssi=$($IWUTILS dev $STX_IF link | grep 'signal:' | awk '{print $2}') > /dev/null 2>&1    
    if [ -z "$rssi" ]; then
        if [ -n "$STX_BSSID" ]; then
            lost_stx
        fi
        return
    fi
    if [ -z "$STX_RSSI" ]; then
        STX_RSSI=$rssi
        logger "STX ($STX_IF) info: rssi $rssi dBm"
        STX_RSSI_2=$STX_RSSI
        STX_RSSI_1=$STX_RSSI
        STX_RSSI_0=$STX_RSSI
        STX_ROAM_FULL_SCAN=50
        STX_ROAM_FAST_SCAN=0
    fi
    STX_RSSI_3=$STX_RSSI_2
    STX_RSSI_2=$STX_RSSI_1
    STX_RSSI_1=$STX_RSSI_0
    STX_RSSI_0=$rssi
    rssi=$((($STX_RSSI_3 + (2 * $STX_RSSI_2) + (2 * $STX_RSSI_1) + (3 * $STX_RSSI_0)) / 8))
    if [ $rssi -gt $(($STX_RSSI + $STX_RSSI_STEP)) ] || [ $rssi -lt $(($STX_RSSI - $STX_RSSI_STEP)) ]; then
        STX_RSSI=$rssi
        logger "STX ($STX_IF) info: rssi $rssi dBm"
    fi
    if [ "$STX_ROAM_OFF" = "0" ]; then
        STX_ROAM_FULL_SCAN=$(($STX_ROAM_FULL_SCAN + 1))
        STX_ROAM_FAST_SCAN=$(($STX_ROAM_FAST_SCAN + 1))
        if [ $STX_ROAM_FULL_SCAN -ge 55 ] && [ $STX_ROAM_FAST_SCAN -ge 5 ]; then
            STX_ROAM_FULL_SCAN=0
            STX_ROAM_FAST_SCAN=0
            logger "STX ($STX_IF) info: start roam full scan (rssi: $rssi dBm)"
            wpa_cli -p $STX_CTRL scan > /dev/null 2>&1
            return
        fi
        if [ $rssi -le -75 ] && [ $STX_ROAM_FAST_SCAN -ge 5 ] && [ $STX_ROAM_FULL_SCAN -ge 10 ]; then
            STX_ROAM_FAST_SCAN=0
        elif [ $rssi -le -65 ] && [ $STX_ROAM_FAST_SCAN -ge 10 ]; then
            STX_ROAM_FAST_SCAN=0
        fi
        if [ $STX_ROAM_FAST_SCAN -eq 0 ]; then
            logger "STX ($STX_IF) info: start roam fast scan (rssi: $rssi dBm)"
            if [ -n "$SSIDStx" ]; then
                wpa_cli -p $STX_CTRL scan $SSIDStx > /dev/null 2>&1
            else
                wpa_cli -p $STX_CTRL scan > /dev/null 2>&1
            fi
            return
        fi
    fi
    stx_phy=$(cat /sys/class/net/$STX_IF/operstate) > /dev/null 2>&1
    if [ "$stx_phy" = "down" ]; then
        ifconfig $STX_IF up
        return
    fi
    if [ "$BRI_OP" != "0" ]; then
        stx_ip=$(ip addr show $STX_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$stx_ip" ]; then
            config_stx
            return
        fi
        stx_gw=$(ip route show dev $STX_IF | grep default | awk '{print $3}')
        if [ -n "$stx_gw" ]; then
            del_default_route $STX_IF
        fi
        return
    fi
    if [ "$ENX_OP" = "1" ] && [ "$ENX_STATE" = "ATTACHED" ]; then
        enx_gw=$(ip route show dev $ENX_IF | grep default | awk '{print $3}')
        if [ -n "$enx_gw" ]; then
            ENX_WAN_GW="$enx_gw"
            del_default_route $ENX_IF
        fi
    fi
    if [ "$USB_OP" = "1" ] && [ "$USB_STATE" = "ATTACHED" ]; then
        usb_gw=$(ip route show dev $USB_IF | grep default | awk '{print $3}')
        if [ -n "$usb_gw" ]; then
            USB_WAN_GW="$usb_gw"
            del_default_route $USB_IF
        fi
    fi
    stx_ip=$(ip addr show $STX_IF | grep 'inet ' | head -n1 | awk '{print $2}')
    if [ -z "$stx_ip" ]; then
        if [ -n "$STX_WAN_IP" ]; then
            ip addr add dev $STX_IF $STX_WAN_IP broadcast $STX_WAN_BRD > /dev/null 2>&1
            STX_WAN_IP=""
            return
        fi
        config_stx
        return
    fi
    if [ "$stx_ip" != "$STX_WAN_IP" ]; then
        STX_DHCP_STARTED=0
        STX_WAN_IP="$stx_ip"
        STX_WAN_BRD=$(ip addr show dev $STX_WAN_IF | grep $STX_WAN_IP | head -n1 | awk '{print $4}')
        STX_WAN_NET=""
        stx_routes=$(ip route show dev $STX_WAN_IF | awk '{print $1}')
        for stx_net in $stx_routes; do
            if [ "$stx_net" = "default" ]; then
                continue
            fi
            STX_WAN_NET=${stx_net}" $STX_WAN_NET"
        done
        dump_wan_stx
    fi
    if [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
        eth_ip=$(ip addr show $ETH_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$eth_ip" ]; then
            return
        fi
    fi
    if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
        sta_ip=$(ip addr show $STA_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$sta_ip" ]; then
            return
        fi
    fi
    stx_gw=$(ip route show dev $STX_WAN_IF | grep default | head -n1 | awk '{print $3}')
    if [ -z "$stx_gw" ]; then
        stx_net=$(ip route show dev $STX_IF | head -n1 | awk '{print $1}')
        if [ -z "$stx_net" ]; then
            if [ -n "$STX_WAN_GW" ] && [ -n "$STX_WAN_NET" ]; then
                for stx_net in $STX_WAN_NET; do
                    ip route add $stx_net dev $STX_IF > /dev/null 2>&1
                done
                ip route add default via $STX_WAN_GW dev $STX_IF > /dev/null 2>&1
                STX_WAN_GW=""
                STX_WAN_NET=""
                return
            fi
        fi
        config_stx
        return
    fi
    if [ "$stx_gw" != "$STX_WAN_GW" ]; then
        STX_DHCP_STARTED=0
        STX_WAN_GW="$stx_gw"
        logger "WAN ($STX_WAN_IF) info: $STX_WAN_IP (gateway: $STX_WAN_GW)"
        STX_PING_PUBLIC=1
        STX_PING_COUNT=3
        STX_WAN_COUNT=15
        add_network_dns
        dump_wan_stx
        if [ "$SON_OP" = "1" ]; then
            check_son "$STX_WAN_IF" "$STX_WAN_GW"
        fi
    fi
    if [ "$ENX_OP" = "1" ] && [ "$ENX_STATE" = "ATTACHED" ]; then
        for enx_route in $(ip route | grep dev.*$ENX_IF | awk '{print $1}'); do
            for enx_route in $STX_WAN_NET; do
                ip route del $enx_route dev $ENX_IF > /dev/null 2>&1
            done
        done
    fi
    if [ "$USB_OP" = "1" ] && [ "$USB_STATE" = "ATTACHED" ]; then
        for usb_route in $(ip route | grep dev.*$USB_IF | awk '{print $1}'); do
            for usb_route in $STX_WAN_NET; do
                ip route del $usb_route dev $USB_IF > /dev/null 2>&1
            done
        done
    fi
    if [ ! -e "$WAN_INFO" ]; then
        dump_wan_stx
    fi
    if [ $STX_WAN_COUNT -gt 0 ]; then
        STX_WAN_COUNT=$(($STX_WAN_COUNT - 1))
        return
    fi
    STX_WAN_COUNT=4
    if [ -n "$STX_WAN_GW" ] && [ "$STX_PING" = "1" ]; then
        ping_stx
        if [ $? -eq 1 ]; then
            logger "WAN ($STX_WAN_IF) info: lost connection (ip: $STX_WAN_IP gw: $STX_WAN_GW)"
            clean_stx
        fi
    fi
}

link_stx()
{
    pid=$(ps -e | grep wpa_supplicant | awk '{print $1}')
    if [ -n "$pid" ]; then
        bssid=$($IWUTILS dev $STX_IF link | grep Connected | awk '{print $3}') > /dev/null 2>&1
        if [ -n "$bssid" ]; then
            bssid_stx "$bssid"
            dump_stx
            STX_STATE="COMPLETED"
            return
        fi
    fi
    if [ $STX_LINK_COUNT -gt 0 ]; then
        STX_LINK_COUNT=$(($STX_LINK_COUNT - 1))
        return
    fi
    stop_stx
    STX_STATE="STARTING"
}

start_stx()
{
    ifconfig $STX_IF 0.0.0.0 up
    if [ "$STX_DBG" = "1" ]; then
        $WPASUPP -i $STX_IF -B -D "nl80211" -P $STX_PID -t -f $STX_LOG -c $STX_CONF > /dev/null 2>&1
    elif [ "$STX_DBG" = "2" ]; then
        $WPASUPP -i $STX_IF -B -D "nl80211" -P $STX_PID -t -f $STX_LOG -d -c $STX_CONF > /dev/null 2>&1
    elif [ "$STX_DBG" = "3" ]; then
        $WPASUPP -i $STX_IF -B -D "nl80211" -P $STX_PID -t -f $STX_LOG -d -K -c $STX_CONF > /dev/null 2>&1
    else
        $WPASUPP -i $STX_IF -B -D "nl80211" -P $STX_PID -t -s -c $STX_CONF > /dev/null 2>&1
    fi
    STX_CHAN=0
    STX_SSID=""
    STX_STATE="STARTED"
    STX_LINK_COUNT=30
}

stop_stx()
{
    kill_all "$WPASUPP"
    if [ -e $STX_CTRL ]; then
        rm -rf $STX_CTRL
    fi
    kill_one "$STX_DHCP_PID"
    if [ -e $STX_DHCP_LEASE ]; then
        rm -f $STX_DHCP_LEASE
    fi
    if [ -n "$STX_MAC" ]; then
        ifconfig $STX_IF down
        del_default_route $STX_IF
        del_route $STX_IF
        del_addr $STX_IF
    fi
}

init_stx()
{
    if [ -z "$STX_IF" ]; then
        return
    fi
    STX_MAC=$(ip addr show dev $STX_IF | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$STX_MAC" ]; then
        logger "Cannot find STX interface $STX_IF"
        STX_OP=0
        STX_IF=""
        return
    fi
    stop_stx
    if [ "$STX_OP" = "1" ]; then
        ssid_stx
        STX_WAN_IF=$STX_IF
        STX_STATE="STARTING"
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
        if [ $ENX_DHCP_COUNT -eq 0 ]; then
            echo "  WAN_DHCP=0"
        else
            echo "  WAN_DHCP=1"
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
        elif [ "$SON_OP" = "1" ]; then
            add_enx_son
        else
            check_lan
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
    if [ "$USB_OP" = "1" ] && [ "$USB_STATE" = "ATTACHED" ]; then
        usb_gw=$(ip route show dev $USB_IF | grep default | awk '{print $3}')
        if [ -n "$usb_gw" ]; then
            USB_WAN_GW="$usb_gw"
            del_default_route $USB_IF
        fi
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
    if [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
        eth_ip=$(ip addr show $ETH_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$eth_ip" ]; then
            return
        fi
    fi
    if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
        sta_ip=$(ip addr show $STA_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$sta_ip" ]; then
            return
        fi
    fi
    if [ "$STX_OP" = "1" ] && [ "$STX_STATE" = "COMPLETED" ]; then
        stx_ip=$(ip addr show $STX_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$stx_ip" ]; then
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
        logger "WAN ($ENX_IF) info: $ENX_WAN_IP (gateway: $ENX_WAN_GW)"
        ENX_PING_PUBLIC=1
        ENX_PING_COUNT=3
        ENX_WAN_COUNT=15
        add_network_dns
        dump_wan_enx
    fi
    if [ "$USB_OP" = "1" ] && [ "$USB_STATE" = "ATTACHED" ]; then
        for usb_route in $(ip route | grep dev.*$USB_IF | awk '{print $1}'); do
            for usb_route in $ENX_WAN_NET; do
                ip route del $usb_route dev $USB_IF > /dev/null 2>&1
            done
        done
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
            logger "WAN ($ENX_IF) info: lost connection (ip: $ENX_WAN_IP gw: $ENX_WAN_GW)"
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
                elif [ "$SON_OP" = "1" ]; then
                    del_enx_son
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
            logger "ENX ($ENX_IF) info: interface disabled"
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
        if [ $USB_DHCP_COUNT -eq 0 ]; then
            echo "  WAN_DHCP=0"
        else
            echo "  WAN_DHCP=1"
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
        elif [ "$SON_OP" = "1" ]; then
            add_usb_son
        else
            check_lan
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
    if [ "$ETH_OP" = "1" ] && [ "$ETH_STATE" = "ATTACHED" ]; then
        eth_ip=$(ip addr show $ETH_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$eth_ip" ]; then
            return
        fi
    fi
    if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
        sta_ip=$(ip addr show $STA_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$sta_ip" ]; then
            return
        fi
    fi
    if [ "$STX_OP" = "1" ] && [ "$STX_STATE" = "COMPLETED" ]; then
        stx_ip=$(ip addr show $STX_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$stx_ip" ]; then
            return
        fi
    fi
    if [ "$ENX_OP" = "1" ] && [ "$ENX_STATE" = "ATTACHED" ]; then
        enx_ip=$(ip addr show $ENX_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -n "$enx_ip" ]; then
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
        logger "WAN ($USB_IF) info: $USB_WAN_IP (gateway: $USB_WAN_GW)"
        USB_PING_PUBLIC=1
        USB_PING_COUNT=3
        USB_WAN_COUNT=15
        add_network_dns
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
            logger "WAN ($USB_IF) info: lost connection (ip: $USB_WAN_IP gw: $USB_WAN_GW)"
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
                elif [ "$SON_OP" = "1" ]; then
                    del_usb_son
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
            logger "USB ($USB_IF) info: interface disabled"
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
        if [ $ETH_DHCP_COUNT -eq 0 ]; then
            echo "  WAN_DHCP=0"
        else
            echo "  WAN_DHCP=1"
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
        elif [ "$SON_OP" = "1" ]; then
            add_eth_son
        else
            check_lan
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
        if [ "$ENX_OP" = "1" ] && [ "$ENX_STATE" = "ATTACHED" ]; then
            enx_gw=$(ip route show dev $ENX_IF | grep default | awk '{print $3}')
            if [ -n "$enx_gw" ]; then
                ENX_WAN_GW="$enx_gw"
                del_default_route $ENX_IF
            fi
        fi
        if [ "$USB_OP" = "1" ] && [ "$USB_STATE" = "ATTACHED" ]; then
            usb_gw=$(ip route show dev $USB_IF | grep default | awk '{print $3}')
            if [ -n "$usb_gw" ]; then
                USB_WAN_GW="$usb_gw"
                del_default_route $USB_IF
            fi
        fi
        if [ "$STX_OP" = "1" ] && [ "$STX_STATE" = "COMPLETED" ]; then
            stx_gw=$(ip route show dev $STX_IF | grep default | awk '{print $3}')
            if [ -n "$stx_gw" ]; then
                STX_WAN_GW="$stx_gw"
                del_default_route $STX_IF
            fi
        fi
        if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ] && [ "$STA_PRI" = "0" ]; then
            sta_gw=$(ip route show dev $STA_IF | grep default | awk '{print $3}')
            if [ -n "$sta_gw" ]; then
                STA_WAN_GW="$sta_gw"
                del_default_route $STA_IF
            fi
        fi
        eth_ip=$(ip addr show $ETH_IF | grep 'inet ' | head -n1 | awk '{print $2}')
        if [ -z "$eth_ip" ]; then
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
        dump_wan_eth
    fi
    if [ "$BRI_OP" = "0" ] && [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ]; then
        if [ "$STA_PRI" = "1" ]; then
            sta_ip=$(ip addr show $STA_IF | grep 'inet ' | head -n1 | awk '{print $2}')
            if [ -n "$sta_ip" ]; then
                return
            fi
        else
            sta_gw=$(ip route show dev $STA_IF | grep default | awk '{print $3}')
            if [ -n "$sta_gw" ]; then
                STA_WAN_GW="$sta_gw"
                del_default_route $STA_IF
                config_eth
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
        logger "WAN ($ETH_WAN_IF) info: $ETH_WAN_IP (gateway: $ETH_WAN_GW)"
        ETH_PING_PUBLIC=1
        ETH_PING_COUNT=3
        ETH_WAN_COUNT=15
        add_network_dns
        dump_wan_eth
    fi
    if [ "$ENX_OP" = "1" ] && [ "$ENX_STATE" = "ATTACHED" ]; then
        for enx_route in $(ip route | grep dev.*$ENX_IF | awk '{print $1}'); do
            for enx_route in $ETH_WAN_NET; do
                ip route del $enx_route dev $ENX_IF > /dev/null 2>&1
            done
        done
    fi
    if [ "$USB_OP" = "1" ] && [ "$USB_STATE" = "ATTACHED" ]; then
        for usb_route in $(ip route | grep dev.*$USB_IF | awk '{print $1}'); do
            for usb_route in $ETH_WAN_NET; do
                ip route del $usb_route dev $USB_IF > /dev/null 2>&1
            done
        done
    fi
    if [ "$STX_OP" = "1" ] && [ "$STX_STATE" = "COMPLETED" ]; then
        for stx_route in $(ip route | grep dev.*$STX_IF | awk '{print $1}'); do
            for stx_route in $ETH_WAN_NET; do
                ip route del $stx_route dev $STX_IF > /dev/null 2>&1
            done
        done
    fi
    if [ "$STA_OP" = "1" ] && [ "$STA_STATE" = "COMPLETED" ] && [ "$STA_PRI" = "0" ]; then
        for sta_route in $(ip route | grep dev.*$STA_IF | awk '{print $1}'); do
            for sta_route in $ETH_WAN_NET; do
                ip route del $sta_route dev $STA_IF > /dev/null 2>&1
            done
        done
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
            logger "WAN ($ETH_WAN_IF) info: lost connection (ip: $ETH_WAN_IP gw: $ETH_WAN_GW)"
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
        if [ "$BRI_OP" = "1" ]; then
            del_eth_bri
        elif [ "$SON_OP" = "1" ]; then
            del_eth_son
        else
            del_eth_lan
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
            mac2=$(echo $WIRE_MAC | cut -d ':' -f2)
            mac3=$(echo $WIRE_MAC | cut -d ':' -f3)
            mac4=$(echo $WIRE_MAC | cut -d ':' -f4)
            mac5=$(echo $WIRE_MAC | cut -d ':' -f5)
            mac6=$(echo $WIRE_MAC | cut -d ':' -f6)
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
        logger "ETH ($ETH_IF) info: interface disabled"
    fi
}

#**********************#
# WAN Bridge Operation #
#**********************#
del_sta_bri()
{
    if [ -n "$BRI_MAC" ] && [ -n "$STA_IF" ]; then
        brif=$(brctl show $BRI_IF | grep $STA_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $BRI_IF $STA_IF
            logger "WAN ($STA_IF) info: interface removed from $BRI_IF"
        fi
    fi
}

add_sta_bri()
{
    brif=$(brctl show $BRI_IF | grep $STA_IF) > /dev/null 2>&1
    if [ -z "$brif" ]; then
        brctl addif $BRI_IF $STA_IF
        logger "WAN ($STA_IF) info: interface added to $BRI_IF"
    fi
}

del_enx_bri()
{
    if [ -n "$BRI_MAC" ] && [ -n "$ENX_IF" ]; then
        enx_if=$(brctl show $BRI_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -n "$enx_if" ]; then
            brctl delif $BRI_IF $ENX_IF
            logger "WAN ($ENX_IF) info: interface removed from $BRI_IF"
        fi
    fi
}

add_enx_bri()
{
    enx_if=$(brctl show $BRI_IF | grep $ENX_IF) > /dev/null 2>&1
    if [ -z "$enx_if" ]; then
        brctl addif $BRI_IF $ENX_IF
        logger "WAN ($ENX_IF) info: interface added to $BRI_IF"
    fi
}

del_usb_bri()
{
    if [ -n "$BRI_MAC" ] && [ -n "$USB_IF" ]; then
        usb_if=$(brctl show $BRI_IF | grep $USB_IF) > /dev/null 2>&1
        if [ -n "$usb_if" ]; then
            brctl delif $BRI_IF $USB_IF
            logger "WAN ($USB_IF) info: interface removed from $BRI_IF"
        fi
    fi
}

add_usb_bri()
{
    usb_if=$(brctl show $BRI_IF | grep $USB_IF) > /dev/null 2>&1
    if [ -z "$usb_if" ]; then
        brctl addif $BRI_IF $USB_IF
        logger "WAN ($USB_IF) info: interface added to $BRI_IF"
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
        mac2=$(echo $WIRE_MAC | cut -d ':' -f2)
        mac3=$(echo $WIRE_MAC | cut -d ':' -f3)
        mac4=$(echo $WIRE_MAC | cut -d ':' -f4)
        mac5=$(echo $WIRE_MAC | cut -d ':' -f5)
        mac6=$(echo $WIRE_MAC | cut -d ':' -f6)
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
    init_stx
    init_wlx
    init_sta
    init_sap
    init_wln
    init_mon
    init_lan
    init_son
}

init_wifi()
{
    if [ -n "$WIFI_PCI" ] && [ "$WLN_IF" = "$WIFI_PCI" -o "$STA_IF" = "$WIFI_PCI" ]; then
        MAC_PCI=$(ip addr show dev $WIFI_PCI | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
        if [ -z "$MAC_PCI" ]; then
            logger "Cannot find Wi-Fi interface $WIFI_PCI"
            return
        fi
        ifconfig $WIFI_PCI up
        sleep 1
    fi
    if [ -n "$WIFI_USB" ] && [ "$WLX_IF" = "$WIFI_USB" -o "$STX_IF" = "$WIFI_USB" ]; then
        MAC_USB=$(ip addr show dev $WIFI_USB | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
        if [ -z "$MAC_USB" ]; then
            logger "Cannot find Wi-Fi USB interface $WIFI_USB"
            return
        fi
        ifconfig $WIFI_USB up
        sleep 1
    fi
}

init_drv()
{
    param=$(ls /sys/module/cfg80211/parameters | grep block_wildcard_scan)
    if [ -n "$param" ]; then
        echo 1 > /sys/module/cfg80211/parameters/block_wildcard_scan
    fi
    param=$(ls /sys/module/cfg80211/parameters | grep bss_scan_filtering)
    if [ -n "$param" ]; then
        echo 1 > /sys/module/cfg80211/parameters/bss_scan_filtering
    fi
    if [ -n "$WIFI_PCI" ] && [ "$WLN_IF" = "$WIFI_PCI" -o "$STA_IF" = "$WIFI_PCI" ]; then
        if [ -n "$ATH_MOD" ]; then
            logger "Probing Wi-Fi module $ATH_MOD"
            modprobe $ATH_MOD > /dev/null 2>&1
        fi
        if [ -n "$IWL_MOD" ]; then
            logger "Probing Wi-Fi module $IWL_MOD"
            modprobe $IWL_MOD > /dev/null 2>&1
        fi
        if [ -n "$BCM_MOD" ]; then
            logger "Probing Wi-Fi module $BCM_MOD"
            modprobe $BCM_MOD > /dev/null 2>&1
        fi
        sleep 1
        if [ -n "$ATH_MOD" -o -n "$IWL_MOD" ]; then
            wiphy=$(iw phy | grep 'Wiphy' | awk '{print $2}') > /dev/null 2>&1
            if [ -z "$wiphy" ]; then
                logger "Cannot find Wiphy interface"
                return
            fi
            $IWUTILS dev $WIFI_PCI del
            sleep 1
            if [ "$PCI_WDS" = "1" ]; then
                logger "Wi-Fi radio device will run 4-address mode"
                $IWUTILS phy $wiphy interface add $WIFI_PCI type managed 4addr on > /dev/null 2>&1
            else
                logger "Wi-Fi radio device will run 3-address mode"
                $IWUTILS phy $wiphy interface add $WIFI_PCI type managed > /dev/null 2>&1
            fi
            sleep 1
        fi
    fi
    if [ -n "$WIFI_USB" ] && [ "$WLX_IF" = "$WIFI_USB" -o "$STX_IF" = "$WIFI_USB" ]; then
        if [ -n "$RTL_MOD" ]; then
            logger "Probing Wi-Fi USB module $RTL_MOD"
            modprobe $RTL_MOD > /dev/null 2>&1
        fi
        sleep 1
    fi
    rfkill unblock wifi
    sleep 5
}

clean_wifi()
{
    pid=$(ps -e | grep NetworkManager | awk '{print $1}')
    if [ -n "$pid" ] && [ $pid -ne $$ ]; then
        if [ "$WIFI_PCI" = "wls2" ]; then
            systemctl stop named.service
        fi
        systemctl stop NetworkManager.service
        systemctl stop systemd-resolved.service
        kill_all "hostapd"
        kill_all "wpa_supplicant"
    fi
    kill_all $WPASUPP
    if [ -n "$HOSTAPD" ]; then
        kill_all $HOSTAPD
    fi
    if [ -n "$DHCPSRV" ]; then
        kill_all "$DHCPSRV"
    fi
    if [ -n "$DHCPCLI" ]; then
        kill_all "$DHCPCLI"
    fi
    if [ -n "$DNSMASQ" ]; then
        kill_all "$DNSMASQ"
    fi
    if [ -e "/var/log/hostapd-$WIFI_PCI.log" ]; then
        rm /var/log/hostapd-$WIFI_PCI.log
    fi
    if [ -e "/var/log/wpa_supplicant-$WIFI_PCI.log" ]; then
        rm /var/log/wpa_supplicant-$WIFI_PCI.log
    fi
    if [ -e "/var/log/hostapd-$WIFI_USB.log" ]; then
        rm /var/log/hostapd-$WIFI_USB.log
    fi
    if [ -e "/var/log/wpa_supplicant-$WIFI_USB.log" ]; then
        rm /var/log/wpa_supplicant-$WIFI_USB.log
    fi
    while [ 1 ]; do
        enx=$(ifconfig | grep enx | head -n1 | awk '{print $1}' | cut -d ':' -f1) > /dev/null 2>&1
        if [ -z "$enx" ]; then
            break
        fi
        ifconfig $enx down
    done
    while [ 1 ]; do
        wlx=$(ifconfig | grep wlx | head -n1 | awk '{print $1}' | cut -d ':' -f1) > /dev/null 2>&1
        if [ -z "$wlx" ]; then
            break
        fi
        ifconfig $wlx down
    done
}

clean_info()
{
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
    if [ -e "$STX_INFO" ]; then
        rm -f $STX_INFO
    fi
    if [ -e "$WLX_INFO" ]; then
        rm -f $WLX_INFO
    fi
    if [ -e "$LAN_INFO" ]; then
        rm -f $LAN_INFO
    fi
    if [ -d "$OPT_DIR" ]; then
        rm -fr $OPT_DIR
    fi
    mkdir -p $OPT_DIR
}

clean_drv()
{
    if [ -n "$ATH_MOD" ]; then
        ath=$(lsmod | grep $ATH_MOD | head -n1 | awk '{print $1}')
        if [ -n "$ath" ]; then
            rmmod $ATH_MOD > /dev/null 2>&1
        fi
    fi
    if [ -n "$IWL_MOD" ]; then
        iwl=$(lsmod | grep $IWL_MOD | head -n1 | awk '{print $1}')
        if [ -n "$iwl" ]; then
            rmmod $IWL_MOD > /dev/null 2>&1
        fi
    fi
    if [ -n "$BCM_MOD" ]; then
        wl=$(lsmod | grep $BCM_MOD | head -n1 | awk '{print $1}')
        if [ -n "$wl" ]; then
            rmmod $BCM_MOD > /dev/null 2>&1
        fi
    fi
    if [ -n "$RTL_MOD" ]; then
        rtl=$(lsmod | grep $RTL_MOD | head -n1 | awk '{print $1}')
        if [ -n "$rtl" ]; then
            rmmod $RTL_MOD > /dev/null 2>&1
        fi
    fi
}

set_opmode()
{
    if [ "$BRI_PHY" = "2" ] && [ -n "$STA_IF" ]; then
        PCI_WDS=1
        BRI_OP=2
        STA_OP=1
        logger "UWIN info: STA Mode --> Bridge PHY"
        if [ -n "$SAP_IF" ]; then
            SAP_OP=1
            SAP_WDS=1
            if [ "$SAP_WAN" = "1" ]; then
                logger "UWIN info: SAP Mode --> Bridge"
            else
                if [ "$LAN_SON" = "1" ]; then
                    SON_OP=1
                else
                    LAN_OP=1
                fi
                logger "UWIN info: SAP Mode --> Server"
            fi
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
            ETH_OP=2
            if [ "$LAN_SON" = "1" ]; then
                SON_OP=1
            else
                LAN_OP=1
            fi
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
            USB_OP=2
            if [ "$LAN_SON" = "1" ]; then
                SON_OP=1
            else
                LAN_OP=1
            fi
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
            ENX_OP=2
            if [ "$LAN_SON" = "1" ]; then
                SON_OP=1
            else
                LAN_OP=1
            fi
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
    if [ "$BRI_OP" != "2" ] && [ -n "$STA_IF" ]; then
        STA_OP=1
        if [ "$STA_MODE" = "1" ]; then
            STA_CONFIG=1
            logger "UWIN info: STA Mode --> Client"
        else
            logger "UWIN info: STA Mode --> Static"
        fi
        if [ -n "$SAP_IF" ]; then
            SAP_OP=1
            if [ "$SAP_WDS" = "1" ]; then
                PCI_WDS=1
            fi
            if [ "$SAP_WAN" = "1" ]; then
                if [ "$BRI_OP" = "1" ]; then
                    logger "UWIN info: SAP Mode --> Bridge"
                else
                    logger "No WAN bridge found for SAP interface"
                    exit 0
                fi
            else
                if [ "$LAN_SON" = "1" ]; then
                    SON_OP=1
                else
                    LAN_OP=1
                fi
                logger "UWIN info: SAP Mode --> Server"
            fi
        fi
    elif [ "$BRI_OP" != "2" ] && [ -n "$WLN_IF" ]; then
        WLN_OP=1
        if [ "$WLN_WDS" = "1" ]; then
            PCI_WDS=1
        fi
        if [ "$WLN_WAN" = "1" ]; then
            if [ "$BRI_OP" = "1" ]; then
                logger "UWIN info: WLN Mode --> Bridge"
            else
                logger "No WAN bridge found for WLN interface"
                exit 0
            fi
        else
            if [ "$LAN_SON" = "1" ]; then
                SON_OP=1
            else
                LAN_OP=1
            fi
            logger "UWIN info: WLN Mode --> Server"
            if [ -n "$VAP_IF" ]; then
                VAP_OP=1
                if [ "$VAP_WAN" = "1" ]; then
                    if [ "$BRI_OP" = "1" ]; then
                        logger "UWIN info: VAP Mode --> Bridge"
                    else
                        logger "No WAN bridge found for VAP interface"
                        exit 0
                    fi
                else
                    LAN_OP=1
                    logger "UWIN info: VAP Mode --> Server"
                fi
            fi
        fi
    fi
    if [ -n "$STX_IF" ]; then
        STX_OP=1
        if [ "$STX_MODE" = "1" ]; then
            STX_CONFIG=1
            logger "UWIN info: STX Mode --> Client"
        else
            logger "UWIN info: STX Mode --> Static"
        fi
    elif [ -n "$WLX_IF" ]; then
        WLX_OP=1
        if [ "$WLX_WAN" = "1" ]; then
            if [ "$BRI_OP" != "0" ]; then
                logger "UWIN info: WLX Mode --> Bridge"
            else
                logger "No WAN bridge found for WLX interface"
                exit 0
            fi
        else
            if [ "$LAN_SON" = "1" ]; then
                SON_OP=1
            else
                LAN_OP=1
            fi
            logger "UWIN info: WLX Mode --> Server"
        fi
    fi
    if [ -n "$MON_IF" ] && [ -n "$WIFI_PCI" ]; then
        if [ -n "$MON_CHAN" ] && [ "$MON_CHAN" != "0" ]; then
            MON_OP=1
            logger "UWIN info: MON Mode --> Active"
        fi
    fi
    if [ "$SON_OP" = "1" ]; then
        if [ "$STA_OP" = "1" -a "$WLX_OP" = "1" ] || [ "$WLN_OP" = "1" -a "$STX_OP" = "1" ]; then
            logger "UWIN info: LAN will be Self Organizing Network (SON)"
        else
            logger "UWIN info: Cannot run SON without dual-channel Wi-Fi connections"
            exit 0
        fi
    fi
    if [ "$BRI_OP" = "0" ] && [ "$ETH_OP" = "1" ] && [ "$STA_OP" = "1" ] && [ "$STA_PRI" = "1" ]; then
        logger "UWIN info: STA Mode Top Priority" 
    fi
    if [ "$PCI_WDS" = "1" ]; then
        logger "UWIN info: Wi-Fi WDS enabled"
    fi
}

init_param()
{
    BRI_OP=0
    ETH_OP=0
    USB_OP=0
    ENX_OP=0
    STA_OP=0
    SAP_OP=0
    WLN_OP=0
    VAP_OP=0
    STX_OP=0
    WLX_OP=0
    MON_OP=0
    LAN_OP=0
    SON_OP=0
    ETH_BR=0
    USB_BR=0
    ENX_BR=0
    PCI_WDS=0
    STX_WDS=0
    WLX_WDS=0
    BRI_CONFIG=0
    ETH_CONFIG=0
    USB_CONFIG=0
    ENX_CONFIG=0
    STA_CONFIG=0
    STX_CONFIG=0
}

clear_conf()
{
    WIRE_ETH=""
    WIFI_PCI=""
    WIFI_USB=""
    BRI_IF=""
    ETH_IF=""
    BRV_IF=""
    USB_IF=""
    ENX_IF=""
    STX_IF=""
    WLX_IF=""
    STA_IF=""
    SAP_IF=""
    WLN_IF=""
    VAP_IF=""
    MON_IF=""
    LAN_IF=""
    SON_IF=""
    ATH_MOD=""
    IWL_MOD=""
    BCM_MOD=""
    RTL_MOD=""
    WPASUPP=""
    HOSTAPD=""
    DHCPSRV=""
    DHCPCLI=""
    DNSMASQ=""
    RESCONF=""
    DNSADDR=""
}

#***********#
# Main Loop #
#***********#
logger "$0 checking..."
kill_all $0

clear_conf
if [ ! -e "/etc/uwin.conf" ]; then
    logger "Cannot find configuration file /etc/uwin.conf"
    exit 0
fi
source "/etc/uwin.conf"
init_param
set_opmode

if [ "$STA_OP" = "1" ] && [ ! -e "$STA_CONF" ]; then
    logger "Cannot find configuration file $STA_CONF"
    exit 0
fi
if [ "$SAP_OP" = "1" ] && [ ! -e "$SAP_CONF11" -o ! -e "$SAP_CONF12" -o ! -e "$SAP_CONF21" -o ! -e "$SAP_CONF22" ]; then
    logger "Cannot find configuration files for $SAP_IF"
    exit 0
fi
if [ "$WLN_OP" = "1" ] && [ ! -e "$WLN_CONF11" -o ! -e "$WLN_CONF12" -o ! -e "$WLN_CONF21" -o ! -e "$WLN_CONF22" ]; then
    logger "Cannot find configuration files for $WLN_IF"
    exit 0
fi
if [ "$VAP_OP" = "1" ] && [ ! -e "$VAP_CONF11" -o ! -e "$VAP_CONF12" -o ! -e "$VAP_CONF21" -o ! -e "$VAP_CONF22" ]; then
    logger "Cannot find configuration files for $VAP_IF"
    exit 0
fi
if [ "$STX_OP" = "1" ] && [ ! -e "$STX_CONF" ]; then
    logger "Cannot find configuration file $STX_CONF"
    exit 0
fi
if [ "$WLX_OP" = "1" ] && [ ! -e "$WLX_CONF1" -o ! -e "$WLX_CONF2" ]; then
    logger "Cannot find configuration files for $WLX_IF"
    exit 0
fi
if [ -n "$WIRE_ETH" ]; then
    WIRE_MAC=$(ip addr show dev $WIRE_ETH | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
fi
if [ -z "$WIRE_MAC" ]; then
    logger "Cannot find primary wired interface $WIRE_ETH"
    exit 0
fi

logger "UWIN network manager version $UWINVER"

clean_drv
clean_info
clean_wifi

init_drv
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
    if [ "$STX_OP" = "1" ]; then
        if [ "$STX_STATE" = "STARTING" ]; then
            start_stx
        elif [ "$STX_STATE" = "STARTED" ]; then
            link_stx
        elif [ "$STX_STATE" = "COMPLETED" ]; then
            check_stx
        fi
    elif [ "$WLX_OP" = "1" ]; then
        if [ "$WLX_STATE" = "STARTING" ]; then
            start_wlx
        elif [ "$WLX_STATE" = "STARTED" ]; then
            link_wlx
        elif [ "$WLX_STATE" = "COMPLETED" ]; then
            check_wlx
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
