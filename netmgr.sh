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
# BTT Bridge Operation #
#**********************#
del_enx_btt()
{
    if [ -n "$BTT_MAC" ] && [ -n "$ENX_IF" ]; then
        brif=$(brctl show $BTT_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $BTT_IF $ENX_IF
            logger "LAN ($ENX_IF) info: interface removed from $BTT_IF"
        fi
    fi
}

add_enx_btt()
{
    if [ -n "$BTT_WAN_IF" ] && [ -n "$BTT_WAN_GW" ]; then
        brif=$(brctl show $BTT_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $BTT_IF $ENX_IF
            logger "LAN ($ENX_IF) info: interface added to $BTT_IF"
        fi
    fi
}

del_usb_btt()
{
    if [ -n "$BTT_MAC" ] && [ -n "$USB_IF" ]; then
        brif=$(brctl show $BTT_IF | grep $USB_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $BTT_IF $USB_IF
            logger "LAN ($USB_IF) info: interface removed from $BTT_IF"
        fi
    fi
}

add_usb_btt()
{
    if [ -n "$BTT_WAN_IF" ] && [ -n "$BTT_WAN_GW" ]; then
        brif=$(brctl show $BTT_IF | grep $USB_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $BTT_IF $USB_IF
            logger "LAN ($USB_IF) info: interface added to $BTT_IF"
        fi
    fi
}

del_eth_btt()
{
    if [ -n "$BTT_MAC" ] && [ -n "$ETH_IF" ]; then
        brif=$(brctl show $BTT_IF | grep $ETH_IF) > /dev/null 2>&1
        if [ -n "$brif" ]; then
            brctl delif $BTT_IF $ETH_IF
            logger "LAN ($ETH_IF) info: interface removed from $BTT_IF"
        fi
    fi
}

add_eth_btt()
{
    if [ -n "$BTT_WAN_IF" ] && [ -n "$BTT_WAN_GW" ]; then
        brif=$(brctl show $BTT_IF | grep $ETH_IF) > /dev/null 2>&1
        if [ -z "$brif" ]; then
            brctl addif $BTT_IF $ETH_IF
            logger "LAN ($ETH_IF) info: interface added to $BTT_IF"
        fi
    fi    
}

dump_lan_btt()
{
    echo -n > $LAN_INFO
    {
        echo "LAN info:"
        echo "  LAN_IF=$BTT_IF"
        echo "  LAN_MAC=$BTT_MAC"
        echo "  LAN_IP=$BTT_IP"
        echo "  LAN_START=$BTT_START"
        echo "  LAN_END=$BTT_END"
        echo "  LAN_GW=$BTT_GW"
    } >> $LAN_INFO
}

dump_phy_btt()
{
    phy1=$1
    phy2=$2
    phy3=$3
    phy4=$4
    echo -n > $PHY_INFO
    {
        echo "PHY info:"
        if [ -n "$phy3" ]; then
            echo "  LAN_CHAN=$phy3"
            echo "  LAN_BAND=$phy4"
            echo "  WAN_RSSI=$phy1"
            echo "  WAN_RATE=$phy2"
        else
            echo "  LAN_CHAN=$phy1"
            echo "  LAN_BAND=$phy2"
        fi
    } >> $PHY_INFO
}

conf_btt()
{
    DNSMASQ_ARGS=${DNSMASQ_ARGS}" $@"
}

start_btt()
{
    ifconfig $BTT_IF 0.0.0.0 up
    old_ip=$(ip addr show $BTT_IF | grep 'inet ' | head -n1 | awk '{print $2}')
    if [ -n "$old_ip" ]; then
        del_addr $BTT_IF
        del_route $BTT_IF
    fi
    ip addr add dev $BTT_IF $btt_ip broadcast $btt_brd
    DNSMASQ_ARGS="-o -f -b -K -D -Q 2007"
    conf_btt "--dhcp-sequential-ip --dhcp-leasefile=$BTT_DHCP_LEASE"
    conf_btt "--clear-on-reload --dhcp-option=6,8.8.8.8,8.8.4.4"
    conf_btt "-i $BTT_IF -F $BTT_IF,$btt_start,$btt_end,3600"
    $DNSMASQ $DNSMASQ_ARGS
}

dnsmasq_btt()
{
    kill_all "$DNSMASQ"
    btt_ip=$BTT_IP
    btt_brd=$BTT_BRD
    btt_gw=$BTT_GW
    btt_start=$BTT_START
    btt_end=$BTT_END
    start_btt
    logger "LAN ($BTT_IF) info: $BTT_IP (gateway: $BTT_GW)"
    dump_lan_btt
}

config_16_btt()
{
    n1=$(echo $BTT_NET | cut -d '.' -f1)
    n2=$(echo $BTT_NET | cut -d '.' -f2)
    n3=$(echo $BTT_NET | cut -d '.' -f3)
    case $btt_node in
    15)
        BTT_IP="$n1.$n2.$n3.241/28"
        BTT_GW="$n1.$n2.$n3.241"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.242"
        BTT_END="$n1.$n2.$n3.254"
        ;;
    14)
        BTT_IP="$n1.$n2.$n3.225/27"
        BTT_GW="$n1.$n2.$n3.225"
        BTT_BRD="$n1.$n2.$n3.239"
        BTT_START="$n1.$n2.$n3.226"
        BTT_END="$n1.$n2.$n3.238"
        ;;
    13)
        BTT_IP="$n1.$n2.$n3.209/28"
        BTT_GW="$n1.$n2.$n3.209"
        BTT_BRD="$n1.$n2.$n3.223"
        BTT_START="$n1.$n2.$n3.210"
        BTT_END="$n1.$n2.$n3.222"
        ;;
    12)
        BTT_IP="$n1.$n2.$n3.193/26"
        BTT_GW="$n1.$n2.$n3.193"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.194"
        BTT_END="$n1.$n2.$n3.206"
        ;;
    11)
        BTT_IP="$n1.$n2.$n3.177/28"
        BTT_GW="$n1.$n2.$n3.177"
        BTT_BRD="$n1.$n2.$n3.191"
        BTT_START="$n1.$n2.$n3.178"
        BTT_END="$n1.$n2.$n3.190"
        ;;
    10)
        BTT_IP="$n1.$n2.$n3.161/27"
        BTT_GW="$n1.$n2.$n3.161"
        BTT_BRD="$n1.$n2.$n3.191"
        BTT_START="$n1.$n2.$n3.162"
        BTT_END="$n1.$n2.$n3.174"
        ;;
    9)
        BTT_IP="$n1.$n2.$n3.145/28"
        BTT_GW="$n1.$n2.$n3.145"
        BTT_BRD="$n1.$n2.$n3.159"
        BTT_START="$n1.$n2.$n3.146"
        BTT_END="$n1.$n2.$n3.158"
        ;;
    8)
        BTT_IP="$n1.$n2.$n3.129/25"
        BTT_GW="$n1.$n2.$n3.129"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.130"
        BTT_END="$n1.$n2.$n3.142"
        ;;
    7)
        BTT_IP="$n1.$n2.$n3.113/28"
        BTT_GW="$n1.$n2.$n3.113"
        BTT_BRD="$n1.$n2.$n3.127"
        BTT_START="$n1.$n2.$n3.114"
        BTT_END="$n1.$n2.$n3.126"
        ;;
    6)
        BTT_IP="$n1.$n2.$n3.97/27"
        BTT_GW="$n1.$n2.$n3.97"
        BTT_BRD="$n1.$n2.$n3.127"
        BTT_START="$n1.$n2.$n3.98"
        BTT_END="$n1.$n2.$n3.110"
        ;;
    5)
        BTT_IP="$n1.$n2.$n3.81/28"
        BTT_GW="$n1.$n2.$n3.81"
        BTT_BRD="$n1.$n2.$n3.95"
        BTT_START="$n1.$n2.$n3.82"
        BTT_END="$n1.$n2.$n3.94"
        ;;
    4)
        BTT_IP="$n1.$n2.$n3.65/26"
        BTT_GW="$n1.$n2.$n3.65"
        BTT_BRD="$n1.$n2.$n3.127"
        BTT_START="$n1.$n2.$n3.66"
        BTT_END="$n1.$n2.$n3.78"
        ;;
    3)
        BTT_IP="$n1.$n2.$n3.49/28"
        BTT_GW="$n1.$n2.$n3.49"
        BTT_BRD="$n1.$n2.$n3.63"
        BTT_START="$n1.$n2.$n3.50"
        BTT_END="$n1.$n2.$n3.62"
        ;;
    2)
        BTT_IP="$n1.$n2.$n3.33/27"
        BTT_GW="$n1.$n2.$n3.33"
        BTT_BRD="$n1.$n2.$n3.63"
        BTT_START="$n1.$n2.$n3.34"
        BTT_END="$n1.$n2.$n3.46"
        ;;
    1)
        BTT_IP="$n1.$n2.$n3.17/28"
        BTT_GW="$n1.$n2.$n3.17"
        BTT_BRD="$n1.$n2.$n3.31"
        BTT_START="$n1.$n2.$n3.18"
        BTT_END="$n1.$n2.$n3.30"
        ;;
    *)
        BTT_IP="$n1.$n2.$n3.1/24"
        BTT_GW="$n1.$n2.$n3.1"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.2"
        BTT_END="$n1.$n2.$n3.14"
        ;;
    esac
}

config_8_btt()
{
    n1=$(echo $BTT_NET | cut -d '.' -f1)
    n2=$(echo $BTT_NET | cut -d '.' -f2)
    n3=$(echo $BTT_NET | cut -d '.' -f3)
    case $btt_node in
    7)
        BTT_IP="$n1.$n2.$n3.225/27"
        BTT_GW="$n1.$n2.$n3.225"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.226"
        BTT_END="$n1.$n2.$n3.254"
        ;;
    6)
        BTT_IP="$n1.$n2.$n3.193/26"
        BTT_GW="$n1.$n2.$n3.193"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.194"
        BTT_END="$n1.$n2.$n3.222"
        ;;
    5)
        BTT_IP="$n1.$n2.$n3.161/27"
        BTT_GW="$n1.$n2.$n3.161"
        BTT_BRD="$n1.$n2.$n3.191"
        BTT_START="$n1.$n2.$n3.162"
        BTT_END="$n1.$n2.$n3.190"
        ;;
    4)
        BTT_IP="$n1.$n2.$n3.129/25"
        BTT_GW="$n1.$n2.$n3.129"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.130"
        BTT_END="$n1.$n2.$n3.158"
        ;;
    3)
        BTT_IP="$n1.$n2.$n3.97/27"
        BTT_GW="$n1.$n2.$n3.97"
        BTT_BRD="$n1.$n2.$n3.127"
        BTT_START="$n1.$n2.$n3.98"
        BTT_END="$n1.$n2.$n3.126"
        ;;
    2)
        BTT_IP="$n1.$n2.$n3.65/26"
        BTT_GW="$n1.$n2.$n3.65"
        BTT_BRD="$n1.$n2.$n3.127"
        BTT_START="$n1.$n2.$n3.66"
        BTT_END="$n1.$n2.$n3.94"
        ;;
    1)
        BTT_IP="$n1.$n2.$n3.33/27"
        BTT_GW="$n1.$n2.$n3.33"
        BTT_BRD="$n1.$n2.$n3.63"
        BTT_START="$n1.$n2.$n3.34"
        BTT_END="$n1.$n2.$n3.62"
        ;;
    *)
        BTT_IP="$n1.$n2.$n3.1/24"
        BTT_GW="$n1.$n2.$n3.1"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.2"
        BTT_END="$n1.$n2.$n3.30"
        ;;
    esac
}

config_4_btt()
{
    n1=$(echo $BTT_NET | cut -d '.' -f1)
    n2=$(echo $BTT_NET | cut -d '.' -f2)
    n3=$(echo $BTT_NET | cut -d '.' -f3)
    case $btt_node in
    3)
        BTT_IP="$n1.$n2.$n3.193/26"
        BTT_GW="$n1.$n2.$n3.193"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.194"
        BTT_END="$n1.$n2.$n3.254"
        ;;
    2)
        BTT_IP="$n1.$n2.$n3.129/25"
        BTT_GW="$n1.$n2.$n3.129"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.130"
        BTT_END="$n1.$n2.$n3.190"
        ;;
    1)
        BTT_IP="$n1.$n2.$n3.65/26"
        BTT_GW="$n1.$n2.$n3.65"
        BTT_BRD="$n1.$n2.$n3.127"
        BTT_START="$n1.$n2.$n3.66"
        BTT_END="$n1.$n2.$n3.126"
        ;;
    *)
        BTT_IP="$n1.$n2.$n3.1/24"
        BTT_GW="$n1.$n2.$n3.1"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.2"
        BTT_END="$n1.$n2.$n3.62"
        ;;
    esac
}

config_2_btt()
{
    n1=$(echo $BTT_NET | cut -d '.' -f1)
    n2=$(echo $BTT_NET | cut -d '.' -f2)
    n3=$(echo $BTT_NET | cut -d '.' -f3)
    case $btt_node in
    1)
        BTT_IP="$n1.$n2.$n3.129/25"
        BTT_GW="$n1.$n2.$n3.129"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.130"
        BTT_END="$n1.$n2.$n3.254"
        ;;
    *)
        BTT_IP="$n1.$n2.$n3.1/24"
        BTT_GW="$n1.$n2.$n3.1"
        BTT_BRD="$n1.$n2.$n3.255"
        BTT_START="$n1.$n2.$n3.2"
        BTT_END="$n1.$n2.$n3.126"
        ;;
    esac
}

check_btt()
{
    btt_if=$(ifconfig | grep $BTT_IF | awk '{print $1}')
    if [ -z "$btt_if" ]; then
        stop_btt
    fi
    if [ ! -e "$BTT_DHCP_LEASE" ]; then
        btt_node=""
        if [ "$BTT_LOCAL" != "$BTT_COUNT" ]; then
            btt_node=$BTT_LOCAL
        elif [ -e "$BTT_INFO" ]; then
            btt_node=$(cat $BTT_INFO | grep 'Node ID:' | awk '{print $3}')
        fi
        if [ -n "$btt_node" ]; then
            case $BTT_COUNT in
            16)
                config_16_btt
                ;;
            8)
                config_8_btt
                ;;
            4)
                config_4_btt
                ;;
            *)
                config_2_btt
                ;;
            esac
            dnsmasq_btt
        fi
    fi
}

stop_btt()
{
    kill_all "$DNSMASQ"
    if [ -e "$BTT_DHCP_LEASE" ]; then
        rm -f $BTT_DHCP_LEASE
    fi
    if [ -n "$BTT_MAC" ]; then
        ifconfig $BTT_IF down 
        del_route $BTT_IF
        del_addr $BTT_IF
        del_eth_btt
        del_enx_btt
        del_usb_btt
    fi
}

init_btt()
{
    BTT_IF="$LAN_IF"
    if [ -z "$BTT_IF" ]; then
        return
    fi
    BTT_MAC=""
    btt_if=$(ifconfig -a | grep $BTT_IF | awk '{print $1}')
    if [ -n "$btt_if" ]; then
        BTT_MAC=$(ip addr show dev $BTT_IF | grep 'link/' | awk '{print $2}')
    fi
    stop_btt
    if [ "$BTT_OP" = "1" ]; then
        mac2=$(echo $ETH_MAC | cut -d ':' -f2)
        mac3=$(echo $ETH_MAC | cut -d ':' -f3)
        mac4=$(echo $ETH_MAC | cut -d ':' -f4)
        mac5=$(echo $ETH_MAC | cut -d ':' -f5)
        mac6=$(echo $ETH_MAC | cut -d ':' -f6)
        mac="ee:$mac2:$mac3:$mac4:$mac5:$mac6"
        if [ "$BTT_MAC" != "$mac" ]; then
            if [ -n "$BTT_MAC" ]; then
                brctl delbr $BTT_IF > /dev/null 2>&1
            fi
            BTT_MAC="$mac"
            brctl addbr $BTT_IF > /dev/null 2>&1
            brctl setfd $BTT_IF 1 > /dev/null 2>&1
            ip link set dev $BTT_IF address $BTT_MAC > /dev/null 2>&1
        fi
        ifconfig $BTT_IF 0.0.0.0 up
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
    lan_net=$(echo $LAN_NET | cut -d '/' -f1)
    echo -n > $LAN_DHCP_CONF
    {
        if [ -n "$DNSADDR" ]; then
            echo "option domain-name-servers 8.8.8.8, $DNSADDR;"
        else
            echo "option domain-name-servers 8.8.8.8, 8.8.4.4;"
        fi
        echo "default-lease-time 28800;"
        echo "max-lease-time 7200;"
        echo "subnet $lan_net netmask $LAN_MASK {"
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
stop_mon()
{
    kill_all "wireshark"
    if [ -n "$MON_IF" ]; then
        ifconfig $MON_IF down
        $IWUTILS dev $MON_IF del
    fi
}

init_mon()
{
    if [ -z "$MON_IF" ]; then
        monif=$(ifconfig -a | grep mon0 | awk '{print $1}')
        if [ -n "$monif" ]; then
            MON_IF=mon0
            stop_mon
        fi
        return
    fi
    monif=$(ifconfig -a | grep $MON_IF | awk '{print $1}')
    if [ -n "$mon_if" ]; then
        stop_mon
    fi
    if [ "$MON_OP" = "1" ]; then
        $IWUTILS dev $WIFI_PCI interface add $MON_IF type monitor > /dev/null 2>&1
        monif=$(ifconfig -a | grep $MON_IF | awk '{print $1}')
        if [ -n "$monif" ]; then
            logger "MON ($MON_IF) info: monitor interface created"
            ifconfig $MON_IF up
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
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" = "0" ] && [ "$WLX_OP" = "0" ]; then
        pid=$(pgrep -f $BTTNODE)
        if [ -n "$pid" ]; then
            kill $pid
        fi
        if [ -e "$PHY_INFO" ]; then
            rm -f $PHY_INFO
        fi
        if [ -e "$BTT_INFO" ]; then
            rm -f $BTT_INFO
        fi
    fi
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
    wlnphy=$(cat /sys/class/net/$WLN_IF/operstate) > /dev/null 2>&1
    if [ "$wlnphy" = "down" ]; then
        ifconfig $WLN_IF up
        return
    fi
    pid=$(ps -ef | grep $WLNCONF | awk '{print $2}')
    fid=$(cat $WLN_PID)
    for pi in $pid; do
        if [ "$pi" = "$fid" ]; then
            break
        fi
    done
    if [ "$pi" != "$fid" ]; then
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
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" = "0" ] && [ "$WLX_OP" = "0" ]; then
        pid=$(pgrep -f $BTTNODE)
        if [ -z "$pid" ]; then
            $BTTNODE -l $WLN_IF -m $BTT_COUNT -n $BTT_LOCAL &
            return
        fi
        check_btt
    fi
    if [ "$LAN_OP" = "1" ]; then
        check_lan
    fi
    if [ "$WLN_TOGGLE_TEST" = "1" ]; then
        WLN_TOGGLE_COUNT=$(($WLN_TOGGLE_COUNT - 1))
        if [ $WLN_TOGGLE_COUNT -eq 0 ]; then
            logger "WLN ($WLN_IF) info: toggle interface down..."
            WLN_TOGGLE_COUNT=$WLN_TOGGLE_OFF
            stop_wln
            WLN_SSID=""
            dump_wln
        fi
    elif [ "$WLN_SWING_TEST" = "1" ]; then
        if [ $WLN_SWING_COUNT -eq $WLN_SWING_DWELL ]; then
            logger "WLN ($WLN_IF) info: Tx power $WLN_SWING_LEVEL mBm"
            $IWUTILS $WLN_IF set txpower fixed $WLN_SWING_LEVEL
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
    pid=$(ps -ef | grep $WLNCONF | awk '{print $2}')
    fid=$(cat $WLN_PID)
    for pi in $pid; do
        if [ "$pi" = "$fid" ]; then
            break
        fi
    done
    if [ "$pi" = "$fid" ]; then
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
            if [ "$WLN_TOGGLE_TEST" = "1" ]; then
                WLN_TOGGLE_COUNT=$WLN_TOGGLE_ON
            elif [ "$WLN_SWING_TEST" = "1" ]; then
                WLN_SWING_COUNT=$WLN_SWING_DWELL
                WLN_SWING_LEVEL=$WLN_SWING_HIGH
                WLN_SWING_CLIMB=0
            elif [ -n "$WLN_POWER_TX" ] && [ "$WLN_POWER_TX" != "0" ]; then
                $IWUTILS $WLN_IF set txpower fixed $WLN_POWER_TX
            else
                $IWUTILS $WLN_IF set txpower auto
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
    if [ "$VAP_OP" = "1" ] && [ "$WLN_WDS" = "1" ]; then
        if [ "$WLN_WAN" = "1" ] && [ "$VAP_WAN" = "1" ]; then
            WLNCONF=$VAP_CONF42
        elif [ "$WLN_WAN" = "1" ]; then
            WLNCONF=$VAP_CONF41
        elif [ "$WLN_WAN" = "0" ] && [ "$VAP_WAN" = "1" ]; then
            WLNCONF=$VAP_CONF32
        else
            WLNCONF=$VAP_CONF31
        fi
    elif [ "$VAP_OP" = "1" ]; then
        if [ "$WLN_WAN" = "1" ] && [ "$VAP_WAN" = "1" ]; then
            WLNCONF=$VAP_CONF22
        elif [ "$WLN_WAN" = "1" ]; then
            WLNCONF=$VAP_CONF21
        elif [ "$WLN_WAN" = "0" ] && [ "$VAP_WAN" = "1" ]; then
            WLNCONF=$VAP_CONF12
        else
            WLNCONF=$VAP_CONF11
        fi
    else
        sed '/bridge=/d' $WLN_CONF > tmpconf
        sed '/wds_sta=/d' tmpconf > $WLN_CONF
        rm -f tmpconf
        if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ]; then
            tmpchan=$STX_CHAN
            if [ $tmpchan -lt 15 ]; then
                sed '/channel=/d' $WLN_CONF > tmpconf
                mv -f tmpconf $WLN_CONF
                tmpchan=$(($tmpchan + 6))
                if [ $tmpchan -gt 11 ]; then
                    tmpchan=$(($tmpchan - 11))
                fi
                echo channel=$tmpchan >> $WLN_CONF
            fi
        fi
        echo "wds_sta=$WLN_WDS" >> $WLN_CONF
        if [ "$WLN_WAN" = "1" ]; then
            echo "bridge=br-wan" >> $WLN_CONF
        else
            echo "bridge=br-lan" >> $WLN_CONF
        fi
        WLNCONF=$WLN_CONF
    fi
    WLN_CHAN=$(cat $WLNCONF | grep 'channel=' | cut -d '=' -f2)
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" = "0" ] && [ "$WLX_OP" = "0" ]; then
        dump_phy_btt $WLN_CHAN $BTT_CHAN_BAND
    fi
    if [ "$WLN_DBG" = "3" ]; then
        $HOSTAPD -B -P $WLN_PID -t -f $WLN_LOG -d -K $WLNCONF > /dev/null 2>&1
    elif [ "$WLN_DBG" = "2" ]; then
        $HOSTAPD -B -P $WLN_PID -t -f $WLN_LOG -d $WLNCONF > /dev/null 2>&1
    elif [ "$WLN_DBG" = "1" ]; then
        $HOSTAPD -B -P $WLN_PID -t -f $WLN_LOG $WLNCONF > /dev/null 2>&1
    else
        $HOSTAPD -B -P $WLN_PID -t $WLNCONF > /dev/null 2>&1
    fi
    WLN_STATE="STARTED"
    WLN_LINK_COUNT=10
    WLN_SWING_COUNT=0
    WLN_TOGGLE_COUNT=0
}

stop_wln()
{
    kill_one "$WLN_PID"
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
        WLN_MAC=$MAC_PCI
        WLN_IF=$WIFI_PCI
        stop_wln
        return
    fi
    WLN_MAC=""
    wlnif=$(ifconfig -a | grep $WLN_IF | awk '{print $1}')
    if [ -n "$wlnif" ]; then
        WLN_MAC=$(ip addr show dev $WLN_IF | grep 'link/' | awk '{print $2}')
    fi
    stop_wln
    if [ -z "$WLN_MAC" ]; then
        logger "Cannot find WLN interface $WLN_IF"
        WLN_OP=0
        WLN_IF=""
        return
    fi
    if [ "$WLN_OP" = "1" ] && [ "$BTT_OP" != "1" -o "$BTT_LOCAL" = "0" ]; then
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
    pid=$(ps -ef | grep $SAP_CONF | awk '{print $2}')
    fid=$(cat $SAP_PID)
    for pi in $pid; do
        if [ "$pi" = "$fid" ]; then
            break
        fi
    done
    if [ "$pi" != "$fid" ]; then
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
        if [ "$SAP_TOGGLE_TEST" = "1" ]; then
            SAP_TOGGLE_COUNT=$SAP_TOGGLE_ON
        elif [ "$SAP_SWING_TEST" = "1" ]; then
            SAP_SWING_COUNT=$SAP_SWING_DWELL
            SAP_SWING_LEVEL=$SAP_SWING_HIGH
            SAP_SWING_CLIMB=0
        elif [ -n "$SAP_POWER_TX" ] && [ "$SAP_POWER_TX" != "0" ]; then
            $IWUTILS $SAP_IF set txpower fixed $SAP_POWER_TX
        else
            $IWUTILS $SAP_IF set txpower auto
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
    if [ "$SAP_TOGGLE_TEST" = "1" ]; then
        SAP_TOGGLE_COUNT=$(($SAP_TOGGLE_COUNT - 1))
        if [ $SAP_TOGGLE_COUNT -eq 0 ]; then
            logger "SAP ($SAP_IF) info: toggle interface down..."
            SAP_TOGGLE_COUNT=$SAP_TOGGLE_OFF
            stop_sap
            SAP_SSID=""
            dump_sap
        fi
    elif [ "$SAP_SWING_TEST" = "1" ]; then
        if [ $SAP_SWING_COUNT -eq $SAP_SWING_DWELL ]; then
            logger "SAP ($SAP_IF) info: Tx power $SAP_SWING_LEVEL mBm"
            $IWUTILS $SAP_IF set txpower fixed $SAP_SWING_LEVEL
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
    sed '/bridge=/d' $SAP_CONF > tmpconf
    sed '/wds_sta=/d' tmpconf > $SAP_CONF
    rm -f tmpconf
    if [ $SAP_CHAN -ne $STA_CHAN ]; then
        sed '/channel=/d' $SAP_CONF > tmpconf
        mv -f tmpconf $SAP_CONF
        echo channel=$STA_CHAN >> $SAP_CONF
        SAP_CHAN=$STA_CHAN
    fi
    echo "wds_sta=$SAP_WDS" >> $SAP_CONF
    if [ "$SAP_WAN" = "1" ]; then
        echo "bridge=br-wan" >> $SAP_CONF
    else
        echo "bridge=br-lan" >> $SAP_CONF
    fi
    if [ "$SAP_DBG" = "3" ]; then
        $HOSTAPD -B -P $SAP_PID -t -f $SAP_LOG -d -K $SAP_CONF > /dev/null 2>&1
    elif [ "$SAP_DBG" = "2" ]; then
        $HOSTAPD -B -P $SAP_PID -t -f $SAP_LOG -d $SAP_CONF > /dev/null 2>&1
    elif [ "$SAP_DBG" = "1" ]; then
        $HOSTAPD -B -P $SAP_PID -t -f $SAP_LOG $SAP_CONF > /dev/null 2>&1
    else
        $HOSTAPD -B -P $SAP_PID -t $SAP_CONF > /dev/null 2>&1
    fi
    SAP_LINK_COUNT=10
    SAP_SWING_COUNT=0
    SAP_TOGGLE_COUNT=0
}

stop_sap()
{
    kill_one "$SAP_PID"
    if [ -e $SAP_CTRL ]; then
        rm -rf $SAP_CTRL
    fi
    if [ -n "$SAP_MAC" ]; then
        ifconfig $SAP_IF down
        $IWUTILS dev $SAP_IF del
    fi
}

init_sap()
{
    if [ -z "$SAP_IF" ]; then
        sapif=$(ifconfig -a | grep sap0 | awk '{print $1}')
        if [ -n "$sapif" ]; then
            SAP_MAC=$(ip addr show dev sap0 | grep 'link/' | awk '{print $2}')
            SAP_IF=sap0
        fi
        stop_sap
        return
    fi
    sapif=$(ifconfig -a | grep $SAP_IF | awk '{print $1}')
    if [ -n "$sapif" ]; then
        SAP_MAC=$(ip addr show dev $SAP_IF | grep 'link/' | awk '{print $2}')
    fi
    stop_sap
    if [ "$SAP_OP" = "1" ] && [ -n "$STA_MAC" ]; then
        mac2=$(echo $STA_MAC | cut -d ':' -f2)
        mac3=$(echo $STA_MAC | cut -d ':' -f3)
        mac4=$(echo $STA_MAC | cut -d ':' -f4)
        mac5=$(echo $STA_MAC | cut -d ':' -f5)
        mac6=$(echo $STA_MAC | cut -d ':' -f6)
        mac="fe:$mac2:$mac3:$mac4:$mac5:$mac6"
        SAP_MAC="$mac"
        $IWUTILS dev $STA_IF interface add $SAP_IF type managed > /dev/null 2>&1
        ip link set dev $SAP_IF address $SAP_MAC
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
            echo "  STA_FREQ=$STA_FREQ"
            echo "  STA_WDS=$PCI_WDS"
        fi
    } >> $STA_INFO
}

clean_sta()
{
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ] && [ -e "$BTT_DHCP_LEASE" ]; then
        stop_btt
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
    STA_WAN_IP=""
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
    STA_CHAN=$($IWUTILS dev $STA_IF info | grep channel | awk '{print $2}') > /dev/null 2>&1
    if [ -n "$STA_CHAN" ]; then
        if [ $STA_CHAN -gt 30 ]; then
            STA_FREQ=$((5000 + ($STA_CHAN * 5)))
        else
            STA_FREQ=$((2407 + ($STA_CHAN * 5)))
        fi
    else
        STA_FREQ=$($IWUTILS dev $STA_IF link | grep freq | awk '{print $2}') > /dev/null 2>&1
        if [ $STA_FREQ -gt 5000 ]; then
            STA_CHAN=$((($STA_FREQ - 5000) / 5))
        else
            STA_CHAN=$((($STA_FREQ - 2407) / 5))
        fi
    fi
    logger "STA ($STA_IF) info: \"$STA_SSID\" (bssid: $STA_BSSID freq: $STA_FREQ)"
    STA_RATE=""
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
    clean_sta
    STA_BSSID=""
    stop_sta
    STA_STATE="STARTING"
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
    pid=$(ps -ef | grep $STA_CONF | awk '{print $2}')
    fid=$(cat $STA_PID)
    for pi in $pid; do
        if [ "$pi" = "$fid" ]; then
            break
        fi
    done
    if [ "$pi" != "$fid" ]; then
        logger "STA ($STA_IF) info: process killed"
        lost_sta
        return
    fi
    staphy=$(cat /sys/class/net/$STA_IF/operstate) > /dev/null 2>&1
    if [ "$staphy" = "down" ]; then
        logger "STA ($STA_IF) info: interface down"
        STA_IFACE_DOWN=$(($STA_IFACE_DOWN + 1))
        if [ $STA_IFACE_DOWN -gt 5 ]; then
            STA_IFACE_DOWN=0
            lost_sta
            return
        fi
        ifconfig $STA_IF up
        return
    fi
    STA_IFACE_DOWN=0
    bssid=$($IWUTILS dev $STA_IF link | grep Connected | awk '{print $3}') > /dev/null 2>&1
    if [ -z "$bssid" ]; then
        logger "STA ($STA_IF) info: BSSID not found"
        lost_sta
        return
    fi
    if [ "$bssid" != "$STA_BSSID" ]; then
        if [ "$STA_ACL" = "0" ] || [ "$STA_ACL" = "1" ] || [ "$BTT_OP" = "1" -a "$BTT_LOCAL" != "0" ]; then
            logger "STA ($STA_IF) info: reconnect forced"
            lost_sta
            return
        fi
        clean_sta
        STA_BSSID="$bssid"
        return
    fi
    rssi=$($IWUTILS dev $STA_IF link | grep 'signal:' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$rssi" ]; then
        logger "STA ($STA_IF) info: RSSI not found"
        lost_sta
        return
    fi
    BTT_PHY_UPDATE=0
    if [ -z "$STA_RSSI" ]; then
        STA_RSSI=$rssi
        STA_RSSI_SHOW=$STX_RSSI
        logger "STA ($STA_IF) info: RSSI $STA_RSSI_SHOW dBm"
        STA_RSSI_2=$STA_RSSI
        STA_RSSI_1=$STA_RSSI
        STA_RSSI_0=$STA_RSSI
        STA_ROAM_FULL_SCAN=50
        STA_ROAM_FAST_SCAN=0
        BTT_PHY_UPDATE=1
        if [ "$SAP_OP" = "1" ]; then
            start_sap
        fi
    fi
    STA_RSSI_3=$STA_RSSI_2
    STA_RSSI_2=$STA_RSSI_1
    STA_RSSI_1=$STA_RSSI_0
    STA_RSSI_0=$rssi
    rssi=$((($STA_RSSI_3 + (2 * $STA_RSSI_2) + (2 * $STA_RSSI_1) + (3 * $STA_RSSI_0)) / 8))
    if [ $rssi -gt $(($STA_RSSI_SHOW + $STA_RSSI_STEP)) ] || [ $rssi -lt $(($STA_RSSI_SHOW - $STA_RSSI_STEP)) ]; then
        STA_RSSI_SHOW=$rssi
        logger "STA ($STA_IF) info: RSSI $STA_RSSI_SHOW dBm"
    fi
    if [ "$rssi" != "$STA_RSSI" ]; then
        if [ $rssi -gt $(($STA_RSSI + 1)) ] || [ $rssi -lt $(($STA_RSSI - 1)) ]; then
            BTT_PHY_UPDATE=1
        fi
        STA_RSSI=$rssi
    fi
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ]; then
        rate=$($IWUTILS dev $STA_IF link | grep 'tx bitrate:' | awk '{print $3}') > /dev/null 2>&1
        if [ "$rate" != "$STA_RATE" ]; then
            BTT_PHY_UPDATE=1
            STA_RATE=$rate
        fi
        if [ "$BTT_PHY_UPDATE" = "1" ]; then
            dump_phy_btt $STA_RSSI $STA_RATE $WLX_CHAN $BTT_CHAN_BAND
            return
        fi
        pid=$(pgrep -f $BTTNODE)
        if [ -z "$pid" ]; then
            $BTTNODE -l $WLX_IF -m $BTT_COUNT -n $BTT_LOCAL -p $STA_BSSID -w $STA_IF &
            if [ "$BTT_LOCAL" = "$BTT_COUNT" ]; then
                BTT_NODE_CHAIN_COUNT=0
                sed '/auto_roam=/d' $STA_CONF > tmpconf
                sed '/acl_policy=/d' tmpconf > $STA_CONF
                sed '/denylist={/,$d' $STA_CONF > tmpconf
                sed '/acceptlist={/,$d' tmpconf > $STA_CONF
                rm -f tmpconf
            fi
            return
        fi
        if [ "$BTT_LOCAL" = "$BTT_COUNT" ] && [ ! -e "$BTT_INFO" ]; then
            BTT_NODE_CHAIN_COUNT=$(($BTT_NODE_CHAIN_COUNT + 1))
            logger "STA ($STA_IF) info: BTT chaining ($STA_BSSID) count $BTT_NODE_CHAIN_COUNT"
            if [ $BTT_NODE_CHAIN_COUNT -gt 20 ]; then
                BTT_NODE_CHAIN_COUNT=0
                {
                    echo "denylist={"
                    echo "  $STA_BSSID"
                    echo "}"
                    echo "acl_policy=0"
                } >> $STA_CONF
                lost_sta
            fi
            return
        fi
        if [ -n "$STA_WAN_GW" ]; then
            if [ "$BTT_LOCAL" = "$BTT_COUNT" ]; then
                sed '/acceptlist={/,$d' $STA_CONF > tmpconf
                mv -f tmpconf $STA_CONF
                {
                    echo "acceptlist={"
                    echo "  $STA_BSSID"
                    echo "}"
                    echo "acl_policy=1"
                } >> $STA_CONF
            fi
            check_btt
        fi
    fi
    if [ "$STA_AUTO_ROAM" = "2" ]; then
        STA_ROAM_FULL_SCAN=$(($STA_ROAM_FULL_SCAN + 1))
        STA_ROAM_FAST_SCAN=$(($STA_ROAM_FAST_SCAN + 1))
        if [ $STA_ROAM_FULL_SCAN -ge 55 ] && [ $STA_ROAM_FAST_SCAN -ge 5 ]; then
            STA_ROAM_FULL_SCAN=0
            STA_ROAM_FAST_SCAN=0
            logger "STA ($STA_IF) info: start roam full scan (RSSI: $STA_RSSI dBm)"
            wpa_cli -p $STA_CTRL scan > /dev/null 2>&1
            return
        fi
        if [ $STA_RSSI -le -75 ] && [ $STA_ROAM_FAST_SCAN -ge 5 ] && [ $STA_ROAM_FULL_SCAN -ge 10 ]; then
            STA_ROAM_FAST_SCAN=0
        elif [ $STA_RSSI -le -65 ] && [ $STA_ROAM_FAST_SCAN -ge 10 ]; then
            STA_ROAM_FAST_SCAN=0
        fi
        if [ $STA_ROAM_FAST_SCAN -eq 0 ]; then
            logger "STA ($STA_IF) info: start roam fast scan (RSSI: $STA_RSSI dBm)"
            if [ -n "$SSIDSta" ]; then
                wpa_cli -p $STA_CTRL scan $SSIDSta > /dev/null 2>&1
            else
                wpa_cli -p $STA_CTRL scan > /dev/null 2>&1
            fi
            return
        fi
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
        pid=$(pgrep -f webalive)
        if [ -n "$pid" ]; then
            kill $pid
        fi
        STA_PING_PUBLIC=1
        STA_PING_COUNT=3
        STA_WAN_COUNT=15
        add_network_dns
        dump_wan_sta
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
    if [ "$BRI_OP" = "2" ] && [ "$BRI_ALIVE" = "1" ]; then
        pid=$(pgrep -f webalive)
        if [ -z "$pid" ]; then
            webalive -s $BRI_ALIVE_IP -m $BRI_MAC &
        fi
        return
    fi
    if [ "$STA_ALIVE" = "1" ]; then
        pid=$(pgrep -f webalive)
        if [ -z "$pid" ]; then
            webalive -s $STA_ALIVE_IP -m $STA_MAC &
        fi
        return
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
    pid=$(ps -ef | grep $STA_CONF | awk '{print $2}')
    fid=$(cat $STA_PID)
    for pi in $pid; do
        if [ "$pi" = "$fid" ]; then
            break
        fi
    done
    if [ "$pi" = "$fid" ]; then
        bssid=$($IWUTILS dev $STA_IF link | grep Connected | awk '{print $3}') > /dev/null 2>&1
        if [ -n "$bssid" ]; then
            bssid_sta "$bssid"
            dump_sta
            if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ] && [ -z "$WLX_STATE" ]; then
                WLX_STATE="STARTING"
            fi
            STA_IFACE_DOWN=0
            STA_STATE="COMPLETED"
            return
        fi
    fi
    if [ $STA_LINK_COUNT -gt 0 ]; then
        STA_LINK_COUNT=$(($STA_LINK_COUNT - 1))
        return
    fi
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ]; then
        sed '/denylist={/,$d' $STA_CONF > tmpconf
        sed '/acceptlist={/,$d' tmpconf > $STA_CONF
        rm -f tmpconf
    fi
    stop_sta
    STA_STATE="STARTING"
}

start_sta()
{
    ifconfig $STA_IF 0.0.0.0 up
    sed '/auto_roam=/d' $STA_CONF > tmpconf
    sed '/acl_policy=/d' tmpconf > $STA_CONF
    rm -f tmpconf
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ]; then
        sta_acl=$(cat $STA_CONF | grep acceptlist)
        if [ -n "$sta_acl" ]; then
            echo "acl_policy=1" >> $STA_CONF
        else
            echo "acl_policy=0" >> $STA_CONF
        fi
        echo "auto_roam=0" >> $STA_CONF
    else
        if [ "$STA_ACL" != "0" ]; then
            sed '/denylist={/,$d' $STA_CONF > tmpconf
            mv -f tmpconf $STA_CONF
        fi
        if [ "$STA_ACL" != "1" ]; then
            sed '/acceptlist={/,$d' $STA_CONF > tmpconf
            mv -f tmpconf $STA_CONF
        fi
        echo "acl_policy=$STA_ACL" >> $STA_CONF
        echo "auto_roam=$STA_AUTO_ROAM" >> $STA_CONF
    fi
    if [ "$BRI_OP" = "2" ]; then
        if [ "$STA_DBG" = "3" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -b $BRI_IF -t -f $STA_LOG -d -K -c $STA_CONF > /dev/null 2>&1
        elif [ "$STA_DBG" = "2" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -b $BRI_IF -t -f $STA_LOG -d -c $STA_CONF > /dev/null 2>&1
        elif [ "$STA_DBG" = "1" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -b $BRI_IF -t -f $STA_LOG -c $STA_CONF > /dev/null 2>&1
        else
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -b $BRI_IF -t -s -c $STA_CONF > /dev/null 2>&1
        fi
    else
        if [ "$STA_DBG" = "3" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -t -f $STA_LOG -d -K -c $STA_CONF > /dev/null 2>&1
        elif [ "$STA_DBG" = "2" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -t -f $STA_LOG -d -c $STA_CONF > /dev/null 2>&1
        elif [ "$STA_DBG" = "1" ]; then
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -t -f $STA_LOG -c $STA_CONF > /dev/null 2>&1
        else
            $WPASUPP -i $STA_IF -B -D "nl80211" -P $STA_PID -t -s -c $STA_CONF > /dev/null 2>&1
        fi
    fi
    STA_CHAN=0
    STA_SSID=""
    STA_STATE="STARTED"
    STA_LINK_COUNT=30
    dump_sta
}

stop_sta()
{
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ]; then
        pid=$(pgrep -f $BTTNODE)
        if [ -n "$pid" ]; then
            kill $pid
        fi
        if [ -e "$PHY_INFO" ]; then
            rm -f $PHY_INFO
        fi
        if [ -e "$BTT_INFO" ]; then
            rm -f $BTT_INFO
        fi
        stop_wlx
        WLX_STATE=""
    fi
    kill_one "$STA_PID"
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
        STA_MAC=$MAC_PCI
        STA_IF=$WIFI_PCI
        stop_sta
        return
    fi
    STA_MAC=""
    staif=$(ifconfig -a | grep $STA_IF | awk '{print $1}')
    if [ -n "$staif" ]; then
        STA_MAC=$(ip addr show dev $STA_IF | grep 'link/' | awk '{print $2}')
    fi
    stop_sta
    if [ -z "$STA_MAC" ]; then
        logger "Cannot find STA interface $STA_IF"
        STA_OP=0
        STA_IF=""
        return
    fi
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
            echo "  WLX_CHAN=$WLX_CHAN$_BOND"
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
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" = "0" ]; then
        pid=$(pgrep -f $BTTNODE)
        if [ -n "$pid" ]; then
            kill $pid
        fi
        if [ -e "$PHY_INFO" ]; then
            rm -f $PHY_INFO
        fi
        if [ -e "$BTT_INFO" ]; then
            rm -f $BTT_INFO
        fi
    fi
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
    wlxphy=$(cat /sys/class/net/$WLX_IF/operstate) > /dev/null 2>&1
    if [ "$wlxphy" = "down" ]; then
        ifconfig $WLX_IF up
        return
    fi
    pid=$(ps -ef | grep $WLX_CONF | awk '{print $2}')
    fid=$(cat $WLX_PID)
    for pi in $pid; do
        if [ "$pi" = "$fid" ]; then
            break
        fi
    done
    if [ "$pi" != "$fid" ]; then
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
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" = "0" ]; then
        pid=$(pgrep -f $BTTNODE)
        if [ -z "$pid" ]; then
            $BTTNODE -l $WLX_IF -m $BTT_COUNT -n $BTT_LOCAL &
            return
        fi
        check_btt
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
    elif [ "$WLX_SWING_TEST" = "1" ]; then
        if [ $WLX_SWING_COUNT -eq $WLX_SWING_DWELL ]; then
            logger "WLX ($WLX_IF) info: Tx power $WLX_SWING_LEVEL mBm"
            $IWUTILS $WLX_IF set txpower fixed $WLX_SWING_LEVEL
        fi
        WLX_SWING_COUNT=$(($WLX_SWING_COUNT - 1))
        if [ $WLX_SWING_COUNT -eq 0 ]; then
            WLX_SWING_COUNT=$WLX_SWING_DWELL
            if [ $WLX_SWING_CLIMB -eq 0 ]; then
                WLX_SWING_LEVEL=$(($WLX_SWING_LEVEL - $WLX_SWING_STEP))
                if [ $WLX_SWING_LEVEL -lt $WLX_SWING_LOW ]; then
                    WLX_SWING_LEVEL=$WLX_SWING_LOW
                    WLX_SWING_CLIMB=1
                fi
            else
                WLX_SWING_LEVEL=$(($WLX_SWING_LEVEL + $WLX_SWING_STEP))
                if [ $WLX_SWING_LEVEL -gt $WLX_SWING_HIGH ]; then
                    WLX_SWING_LEVEL=$WLX_SWING_HIGH
                    WLX_SWING_CLIMB=0
                fi
            fi
        fi
    fi
}

link_wlx()
{
    pid=$(ps -ef | grep $WLX_CONF | awk '{print $2}')
    fid=$(cat $WLX_PID)
    for pi in $pid; do
        if [ "$pi" = "$fid" ]; then
            break
        fi
    done
    if [ "$pi" = "$fid" ]; then
        ssid=$(ssid_wlx $WLX_IF)
        if [ -n "$ssid" ]; then
            logger "WLX ($WLX_IF) info: \"$ssid\" (bssid: $WLX_MAC channel: $WLX_CHAN$_BOND)"
            WLX_STATE="COMPLETED"
            WLX_SSID="$ssid"
            dump_wlx
            if [ "$WLX_TOGGLE_TEST" = "1" ]; then
                WLX_TOGGLE_COUNT=$WLX_TOGGLE_ON
            elif [ "$WLX_SWING_TEST" = "1" ]; then
                WLX_SWING_COUNT=$WLX_SWING_DWELL
                WLX_SWING_LEVEL=$WLX_SWING_HIGH
                WLX_SWING_CLIMB=0
            elif [ -n "$WLX_POWER_TX" ] && [ "$WLX_POWER_TX" != "0" ]; then
                $IWUTILS $WLX_IF set txpower fixed $WLX_POWER_TX
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
    sed '/bridge=/d' $WLX_CONF > tmpconf
    mv -f tmpconf $WLX_CONF
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ]; then
        sed '/channel=/d' $WLX_CONF > tmpconf
        mv -f tmpconf $WLX_CONF
        tmpchan=$STA_CHAN
        if [ $tmpchan -gt 100 ]; then
            tmpchan=$(($tmpchan + 8))
            if [ $tmpchan -gt 161 ]; then
                tmpchan=$(($tmpchan - 16))
            fi
        elif [ $tmpchan -gt 30 ]; then
            tmpchan=$(($tmpchan + 8))
            if [ $tmpchan -gt 48 ]; then
                tmpchan=$(($tmpchan - 16))
            fi
        else
            tmpchan=$(($tmpchan + 6))
            if [ $tmpchan -gt 11 ]; then
                tmpchan=$(($tmpchan - 11))
            fi
        fi
        echo channel=$tmpchan >> $WLX_CONF
    fi
    if [ "$WLX_WAN" = "1" ]; then
        echo "bridge=br-wan" >> $WLX_CONF
    else
        echo "bridge=br-lan" >> $WLX_CONF
    fi
    WLX_CHAN=$(cat $WLX_CONF | grep 'channel=' | cut -d '=' -f2)
    if [ $WLX_CHAN -gt 30 ]; then
        _BOND=""
        bond=$(cat $WLX_CONF | grep 'HT40-')
        if [ -n "$bond" ]; then
            _BOND="-"
            BTT_CHAN_BAND="40-"
        else
            bond=$(cat $WLX_CONF | grep 'HT40+')
            if [ -n "$bond" ]; then
                _BOND="+"
                BTT_CHAN_BAND="40+"
            fi
        fi
    fi
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" = "0" ]; then
        dump_phy_btt $WLX_CHAN $BTT_CHAN_BAND
    fi
    if [ "$WLX_DBG" = "3" ]; then
        $HOSTAPD -B -P $WLX_PID -t -f $WLX_LOG -d -K $WLX_CONF > /dev/null 2>&1
    elif [ "$WLX_DBG" = "2" ]; then
        $HOSTAPD -B -P $WLX_PID -t -f $WLX_LOG -d $WLX_CONF > /dev/null 2>&1
    elif [ "$WLX_DBG" = "1" ]; then
        $HOSTAPD -B -P $WLX_PID -t -f $WLX_LOG $WLX_CONF > /dev/null 2>&1
    else
        $HOSTAPD -B -P $WLX_PID -t $WLX_CONF > /dev/null 2>&1
    fi
    WLX_STATE="STARTED"
    WLX_LINK_COUNT=10
    WLX_SWING_COUNT=0
    WLX_TOGGLE_COUNT=0
}

stop_wlx()
{
    kill_one "$WLX_PID"
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
        WLX_MAC=$MAC_USB
        WLX_IF=$WIFI_USB
        stop_wlx
        return
    fi
    WLX_MAC=""
    wlxif=$(ifconfig -a | grep $WLX_IF | awk '{print $1}')
    if [ -n "$wlxif" ]; then
        WLX_MAC=$(ip addr show dev $WLX_IF | grep 'link/' | awk '{print $2}')
    fi
    stop_wlx
    if [ -z "$WLX_MAC" ]; then
        logger "Cannot find WLX interface $WLX_IF"
        WLX_OP=0
        WLX_IF=""
        return
    fi
    if [ "$WLX_OP" = "1" ] && [ "$BTT_OP" != "1" -o "$BTT_LOCAL" = "0" ]; then
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
            echo "  STX_FREQ=$STX_FREQ"
            echo "  STX_WDS=$STX_WDS"
        fi
    } >> $STX_INFO
}

clean_stx()
{
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ] && [ -e "$BTT_DHCP_LEASE" ]; then
        stop_btt
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
    STX_WAN_IP=""
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
    STX_CHAN=$($IWUTILS dev $STX_IF info | grep channel | awk '{print $2}') > /dev/null 2>&1
    if [ -n "$STX_CHAN" ]; then
        if [ $STX_CHAN -gt 30 ]; then
            STX_FREQ=$((5000 + ($STX_CHAN * 5)))
        else
            STX_FREQ=$((2407 + ($STX_CHAN * 5)))
        fi
    else
        STX_FREQ=$($IWUTILS dev $STX_IF link | grep freq | awk '{print $2}') > /dev/null 2>&1
        if [ $STX_FREQ -gt 5000 ]; then
            STX_CHAN=$((($STX_FREQ - 5000) / 5))
        else
            STX_CHAN=$((($STX_FREQ - 2407) / 5))
        fi
    fi
    logger "STX ($STX_IF) info: \"$STX_SSID\" (bssid: $STX_BSSID freq: $STX_FREQ)"
    STX_RATE=""
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
    clean_stx
    STX_BSSID=""
    stop_stx
    STX_STATE="STARTING"
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
    pid=$(ps -ef | grep $STX_CONF | awk '{print $2}')
    fid=$(cat $STX_PID)
    for pi in $pid; do
        if [ "$pi" = "$fid" ]; then
            break
        fi
    done
    if [ "$pi" != "$fid" ]; then
        logger "STX ($STX_IF) info: process killed"
        lost_stx
        return
    fi
    stxphy=$(cat /sys/class/net/$STX_IF/operstate) > /dev/null 2>&1
    if [ "$stxphy" = "down" ]; then
        logger "STX ($STX_IF) info: interface down"
        STX_IFACE_DOWN=$(($STX_IFACE_DOWN + 1))
        if [ $STX_IFACE_DOWN -gt 5 ]; then
            STX_IFACE_DOWN=0
            lost_stx
            return
        fi
        ifconfig $STX_IF up
        return
    fi
    STX_IFACE_DOWN=0
    bssid=$($IWUTILS dev $STX_IF link | grep Connected | awk '{print $3}') > /dev/null 2>&1
    if [ -z "$bssid" ]; then
        logger "STX ($STX_IF) info: BSSID not found"
        lost_stx
        return
    fi
    if [ "$bssid" != "$STX_BSSID" ]; then
        if [ "$STX_ACL" = "0" ] || [ "$STX_ACL" = "1" ] || [ "$BTT_OP" = "1" -a "$BTT_LOCAL" != "0" ]; then
            logger "STX ($STX_IF) info: reconnect forced"
            lost_stx
            return
        fi
        clean_stx
        STX_BSSID="$bssid"
        return
    fi
    rssi=$($IWUTILS dev $STX_IF link | grep 'signal:' | awk '{print $2}') > /dev/null 2>&1
    if [ -z "$rssi" ]; then
        logger "STX ($STX_IF) info: RSSI not found"
        lost_stx
        return
    fi
    BTT_PHY_UPDATE=0
    if [ -z "$STX_RSSI" ]; then
        STX_RSSI=$rssi
        STX_RSSI_SHOW=$STX_RSSI
        logger "STX ($STX_IF) info: RSSI $STX_RSSI_SHOW dBm"
        STX_RSSI_2=$STX_RSSI
        STX_RSSI_1=$STX_RSSI
        STX_RSSI_0=$STX_RSSI
        STX_ROAM_FULL_SCAN=50
        STX_ROAM_FAST_SCAN=0
        BTT_PHY_UPDATE=1
    fi
    STX_RSSI_3=$STX_RSSI_2
    STX_RSSI_2=$STX_RSSI_1
    STX_RSSI_1=$STX_RSSI_0
    STX_RSSI_0=$rssi
    rssi=$((((2 * $STX_RSSI_3) + (2 * $STX_RSSI_2) + (2 * $STX_RSSI_1) + (2 * $STX_RSSI_0)) / 8))
    if [ $rssi -gt $(($STX_RSSI_SHOW + $STX_RSSI_STEP)) ] || [ $rssi -lt $(($STX_RSSI_SHOW - $STX_RSSI_STEP)) ]; then
        STX_RSSI_SHOW=$rssi
        logger "STX ($STX_IF) info: RSSI $STX_RSSI_SHOW dBm"
    fi
    if [ "$rssi" != "$STX_RSSI" ]; then
        if [ $rssi -gt $(($STX_RSSI + 1)) ] || [ $rssi -lt $(($STX_RSSI - 1)) ]; then
            BTT_PHY_UPDATE=1
        fi
        STX_RSSI=$rssi
    fi
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ] && [ "$STA_OP" = "0" ]; then
        rate=$($IWUTILS dev $STX_IF link | grep 'tx bitrate:' | awk '{print $3}') > /dev/null 2>&1
        if [ "$rate" != "$STX_RATE" ]; then
            BTT_PHY_UPDATE=1
            STX_RATE=$rate
        fi
        if [ "$BTT_PHY_UPDATE" = "1" ]; then
            dump_phy_btt $STX_RSSI $STX_RATE $WLN_CHAN $BTT_CHAN_BAND
            return
        fi
        pid=$(pgrep -f $BTTNODE)
        if [ -z "$pid" ]; then
            $BTTNODE -l $WLN_IF -m $BTT_COUNT -n $BTT_LOCAL -p $STX_BSSID -w $STX_IF &
            if [ "$BTT_LOCAL" = "$BTT_COUNT" ]; then
                BTT_NODE_CHAIN_COUNT=0
                sed '/auto_roam=/d' $STX_CONF > tmpconf
                sed '/acl_policy=/d' tmpconf > $STX_CONF
                sed '/denylist={/,$d' $STX_CONF > tmpconf
                sed '/acceptlist={/,$d' tmpconf > $STX_CONF
                rm -f tmpconf
            fi
            return
        fi
        if [ "$BTT_LOCAL" = "$BTT_COUNT" ] && [ ! -e "$BTT_INFO" ]; then
            BTT_NODE_CHAIN_COUNT=$(($BTT_NODE_CHAIN_COUNT + 1))
            logger "STX ($STX_IF) info: BTT chaining ($STX_BSSID) count $BTT_NODE_CHAIN_COUNT"
            if [ $BTT_NODE_CHAIN_COUNT -gt 20 ]; then
                BTT_NODE_CHAIN_COUNT=0
                {
                    echo "denylist={"
                    echo "  $STX_BSSID"
                    echo "}"
                    echo "acl_policy=0"
                } >> $STX_CONF
                lost_stx
            fi
            return
        fi
        if [ -n "$STX_WAN_GW" ]; then
            if [ "$BTT_LOCAL" = "$BTT_COUNT" ]; then
                sed '/acceptlist={/,$d' $STX_CONF > tmpconf
                mv -f tmpconf $STX_CONF
                {
                    echo "acceptlist={"
                    echo "  $STX_BSSID"
                    echo "}"
                    echo "acl_policy=1"
                } >> $STX_CONF
            fi
            check_btt
        fi
    fi
    if [ "$STX_AUTO_ROAM" = "2" ]; then
        STX_ROAM_FULL_SCAN=$(($STX_ROAM_FULL_SCAN + 1))
        STX_ROAM_FAST_SCAN=$(($STX_ROAM_FAST_SCAN + 1))
        if [ $STX_ROAM_FULL_SCAN -ge 55 ] && [ $STX_ROAM_FAST_SCAN -ge 5 ]; then
            STX_ROAM_FULL_SCAN=0
            STX_ROAM_FAST_SCAN=0
            logger "STX ($STX_IF) info: start roam full scan (RSSI: $STX_RSSI dBm)"
            wpa_cli -p $STX_CTRL scan > /dev/null 2>&1
            return
        fi
        if [ $STX_RSSI -le -75 ] && [ $STX_ROAM_FAST_SCAN -ge 5 ] && [ $STX_ROAM_FULL_SCAN -ge 10 ]; then
            STX_ROAM_FAST_SCAN=0
        elif [ $STX_RSSI -le -65 ] && [ $STX_ROAM_FAST_SCAN -ge 10 ]; then
            STX_ROAM_FAST_SCAN=0
        fi
        if [ $STX_ROAM_FAST_SCAN -eq 0 ]; then
            logger "STX ($STX_IF) info: start roam fast scan (RSSI: $STX_RSSI dBm)"
            if [ -n "$SSIDStx" ]; then
                wpa_cli -p $STX_CTRL scan $SSIDStx > /dev/null 2>&1
            else
                wpa_cli -p $STX_CTRL scan > /dev/null 2>&1
            fi
            return
        fi
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
        pid=$(pgrep -f webalive)
        if [ -n "$pid" ]; then
            kill $pid
        fi
        STX_PING_PUBLIC=1
        STX_PING_COUNT=3
        STX_WAN_COUNT=15
        add_network_dns
        dump_wan_stx
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
    if [ "$STX_ALIVE" = "1" ]; then
        pid=$(pgrep -f webalive)
        if [ -z "$pid" ]; then
            webalive -s $STX_ALIVE_IP -m $STX_MAC &
        fi
        return
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
    pid=$(ps -ef | grep $STX_CONF | awk '{print $2}')
    fid=$(cat $STX_PID)
    for pi in $pid; do
        if [ "$pi" = "$fid" ]; then
            break
        fi
    done
    if [ "$pi" = "$fid" ]; then
        bssid=$($IWUTILS dev $STX_IF link | grep Connected | awk '{print $3}') > /dev/null 2>&1
        if [ -n "$bssid" ]; then
            bssid_stx "$bssid"
            dump_stx
            if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ] && [ -z "$WLN_STATE" ]; then
                WLN_STATE="STARTING"
            fi
            STX_IFACE_DOWN=0
            STX_STATE="COMPLETED"
            return
        fi
    fi
    if [ $STX_LINK_COUNT -gt 0 ]; then
        STX_LINK_COUNT=$(($STX_LINK_COUNT - 1))
        return
    fi
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ] && [ "$STA_OP" = "0" ]; then
        sed '/denylist={/,$d' $STX_CONF > tmpconf
        sed '/acceptlist={/,$d' tmpconf > $STX_CONF
        rm -f tmpconf
    fi
    stop_stx
    STX_STATE="STARTING"
}

start_stx()
{
    ifconfig $STX_IF 0.0.0.0 up
    sed '/auto_roam=/d' $STX_CONF > tmpconf
    sed '/acl_policy=/d' tmpconf > $STX_CONF
    rm -f tmpconf
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ]; then
        stx_acl=$(cat $STX_CONF | grep acceptlist)
        if [ -n "$stx_acl" ]; then
            echo "acl_policy=1" >> $STX_CONF
        else
            echo "acl_policy=0" >> $STX_CONF
        fi
        echo "auto_roam=0" >> $STX_CONF
    else
        if [ "$STX_ACL" != "0" ]; then
            sed '/denylist={/,$d' $STX_CONF > tmpconf
            mv -f tmpconf $STX_CONF
        fi
        if [ "$STX_ACL" != "1" ]; then
            sed '/acceptlist={/,$d' $STX_CONF > tmpconf
            mv -f tmpconf $STX_CONF
        fi
        echo "acl_policy=$STX_ACL" >> $STX_CONF
        echo "auto_roam=$STX_AUTO_ROAM" >> $STX_CONF
    fi
    if [ "$STX_DBG" = "3" ]; then
        $WPASUPP -i $STX_IF -B -D "nl80211" -P $STX_PID -t -f $STX_LOG -d -K -c $STX_CONF > /dev/null 2>&1
    elif [ "$STX_DBG" = "2" ]; then
        $WPASUPP -i $STX_IF -B -D "nl80211" -P $STX_PID -t -f $STX_LOG -d -c $STX_CONF > /dev/null 2>&1
    elif [ "$STX_DBG" = "1" ]; then
        $WPASUPP -i $STX_IF -B -D "nl80211" -P $STX_PID -t -f $STX_LOG -c $STX_CONF > /dev/null 2>&1
    else
        $WPASUPP -i $STX_IF -B -D "nl80211" -P $STX_PID -t -s -c $STX_CONF > /dev/null 2>&1
    fi
    STX_CHAN=0
    STX_SSID=""
    STX_STATE="STARTED"
    STX_LINK_COUNT=30
    dump_stx
}

stop_stx()
{
    if [ "$BTT_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ] && [ "$STA_OP" = "0" ]; then
        pid=$(pgrep -f $BTTNODE)
        if [ -n "$pid" ]; then
            kill $pid
        fi
        if [ -e "$PHY_INFO" ]; then
            rm -f $PHY_INFO
        fi
        if [ -e "$BTT_INFO" ]; then
            rm -f $BTT_INFO
        fi
        stop_wln
        WLN_STATE=""
    fi
    kill_one "$STX_PID"
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
        STX_MAC=$MAC_USB
        STX_IF=$WIFI_USB
        stop_stx
        return
    fi
    STX_MAC=""
    stxif=$(ifconfig -a | grep $STX_IF | awk '{print $1}')
    if [ -n "$stxif" ]; then
        STX_MAC=$(ip addr show dev $STX_IF | grep 'link/' | awk '{print $2}')
    fi
    stop_stx
    if [ -z "$STX_MAC" ]; then
        logger "Cannot find STX interface $STX_IF"
        STX_OP=0
        STX_IF=""
        return
    fi
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
        elif [ "$BTT_OP" = "1" ]; then
            add_enx_btt
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
        pid=$(pgrep -f webalive)
        if [ -n "$pid" ]; then
            kill $pid
        fi
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
    if [ "$ENX_ALIVE" = "1" ]; then
        pid=$(pgrep -f webalive)
        if [ -z "$pid" ]; then
            webalive -s $ENX_ALIVE_IP -m $ENX_MAC &
        fi
        return
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
    enxif=$(ifconfig -a | grep $ENX_IF | awk '{print $1}')
    if [ -z "$enxif" ]; then
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
                elif [ "$BTT_OP" = "1" ]; then
                    del_enx_btt
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
    enxif=$(ifconfig -a | grep $ENX_IF | awk '{print $1}')
    if [ -n "$enxif" ]; then
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
        elif [ "$BTT_OP" = "1" ]; then
            add_usb_btt
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
        pid=$(pgrep -f webalive)
        if [ -n "$pid" ]; then
            kill $pid
        fi
        USB_PING_PUBLIC=1
        USB_PING_COUNT=3
        USB_WAN_COUNT=15
        add_network_dns
        dump_wan_usb
    fi
    if [ ! -e "$WAN_INFO" ]; then
        dump_wan_usb
    fi
    if [ "$USB_ALIVE" = "1" ]; then
        pid=$(pgrep -f webalive)
        if [ -z "$pid" ]; then
            webalive -s $USB_ALIVE_IP -m $USB_MAC &
        fi
        return
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
    usbif=$(ifconfig -a | grep $USB_IF | awk '{print $1}')
    if [ -z "$usbif" ]; then
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
                elif [ "$BTT_OP" = "1" ]; then
                    del_usb_btt
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
    usbif=$(ifconfig -a | grep $USB_IF | awk '{print $1}')
    if [ -n "$usbif" ]; then
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
        elif [ "$BTT_OP" = "1" ]; then
            add_eth_btt
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
        pid=$(pgrep -f webalive)
        if [ -n "$pid" ]; then
            kill $pid
        fi
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
    if [ "$BRI_OP" = "1" ] && [ "$BRI_ALIVE" = "1" ]; then
        pid=$(pgrep -f webalive)
        if [ -z "$pid" ]; then
            webalive -s $BRI_ALIVE_IP -m $BRI_MAC &
        fi
        return
    fi
    if [ "$ETH_ALIVE" = "1" ]; then
        pid=$(pgrep -f webalive)
        if [ -z "$pid" ]; then
            webalive -s $ETH_ALIVE_IP -m $ETH_MAC &
        fi
        return
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
        elif [ "$BTT_OP" = "1" ]; then
            del_eth_btt
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
    ETH_MAC=""
    ethif=$(ifconfig -a | grep $ETH_IF | awk '{print $1}')
    if [ -n "$ethif" ]; then
        ETH_MAC=$(ip addr show dev $ETH_IF | grep 'link/' | awk '{print $2}')
    fi
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
        enxif=$(brctl show $BRI_IF | grep $ENX_IF) > /dev/null 2>&1
        if [ -n "$enxif" ]; then
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
    init_btt
}

init_monitor()
{
    if [ "$MON_PCI_OP" = "1" ]; then
        $IWUTILS dev $WIFI_PCI set type monitor
        ifconfig $WIFI_PCI 0.0.0.0 up
        $IWUTILS dev $WIFI_PCI set channel $MON_PCI_CHAN HT20
        logger "MON ($WIFI_PCI) info: Wi-Fi PCI monitor channel $MON_PCI_CHAN"
    fi
    if [ "$MON_USB_OP" = "1" ]; then
        ifconfig $WIFI_USB 0.0.0.0 up
        iwconfig $WIFI_USB mode monitor
        iwconfig $WIFI_USB channel $MON_USB_CHAN
        logger "MON ($WIFI_USB) info: Wi-Fi USB monitor channel $MON_USB_CHAN"
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
    if [ -n "$WIFI_PCI" ]; then
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
            wiphy=$($IWUTILS phy | grep 'Wiphy' | awk '{print $2}') > /dev/null 2>&1
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
        MAC_PCI=""
        wifipci=$(ifconfig -a | grep $WIFI_PCI | awk '{print $1}')
        if [ -n "$wifipci" ]; then
            MAC_PCI=$(ip addr show dev $WIFI_PCI | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
        fi
        if [ -z "$MAC_PCI" ]; then
            logger "Cannot find Wi-Fi interface $WIFI_PCI"
            return
        fi
    fi
    if [ -n "$WIFI_USB" ]; then
        if [ -n "$RTL_MOD" ]; then
            logger "Probing Wi-Fi USB module $RTL_MOD"
            modprobe $RTL_MOD > /dev/null 2>&1
        fi
        sleep 1
        MAC_USB=""
        wifiusb=$(ifconfig -a | grep $WIFI_USB | awk '{print $1}')
        if [ -n "$wifiusb" ]; then
            MAC_USB=$(ip addr show dev $WIFI_USB | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
        fi
        if [ -z "$MAC_USB" ]; then
            logger "Cannot find Wi-Fi interface $WIFI_USB"
            return
        fi
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
    pid=$(pgrep -f webalive)
    if [ -n "$pid" ]; then
        kill $pid
    fi
    kill_all $WPASUPP
    if [ -n "$HOSTAPD" ]; then
        kill_all $HOSTAPD
    fi
    if [ -n "$BTTNODE" ]; then
        kill_all $BTTNODE
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
    if [ -e "/var/run/hostapd-$WIFI_PCI.pid" ]; then
        rm /var/run/hostapd-$WIFI_PCI.pid
    fi
    if [ -e "/var/run/wpa_supplicant-$WIFI_PCI.pid" ]; then
        rm /var/run/wpa_supplicant-$WIFI_PCI.pid
    fi
    if [ -e "/var/log/hostapd-$WIFI_USB.log" ]; then
        rm /var/log/hostapd-$WIFI_USB.log
    fi
    if [ -e "/var/log/wpa_supplicant-$WIFI_USB.log" ]; then
        rm /var/log/wpa_supplicant-$WIFI_USB.log
    fi
    if [ -e "/var/run/hostapd-$WIFI_USB.pid" ]; then
        rm /var/run/hostapd-$WIFI_USB.pid
    fi
    if [ -e "/var/run/wpa_supplicant-$WIFI_USB.pid" ]; then
        rm /var/run/wpa_supplicant-$WIFI_USB.pid
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
    if [ -e "$LAN_INFO" ]; then
        rm -f $LAN_INFO
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
    if [ -e "$PHY_INFO" ]; then
        rm -f $PHY_INFO
    fi
    if [ -e "$BTT_INFO" ]; then
        rm -f $BTT_INFO
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

check_conf()
{
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
    if [ "$VAP_OP" = "1" ] && [ "$WLN_WDS" = "1" ]; then
        if [ "$WLN_WAN" = "1" ] && [ "$VAP_WAN" = "1" ] && [ ! -e "$VAP_CONF42" ]; then
            logger "Cannot find configuration file $VAP_CONF42"
            exit 0
        elif [ "$WLN_WAN" = "1" ] && [ ! -e "$VAP_CONF41" ]; then
            logger "Cannot find configuration file $VAP_CONF41"
            exit 0
        elif [ "$WLN_WAN" = "0" ] && [ "$VAP_WAN" = "1" ] && [ ! -e "$VAP_CONF32" ]; then
            logger "Cannot find configuration file $VAP_CONF32"
            exit 0
        elif [ ! -e "$VAP_CONF31" ]; then
            logger "Cannot find configuration file $VAP_CONF31"
            exit 0
        fi
    fi
    if [ "$VAP_OP" = "1" ] && [ "$WLN_WDS" = "0" ]; then
        if [ "$WLN_WAN" = "1" ] && [ "$VAP_WAN" = "1" ] && [ ! -e "$VAP_CONF22" ]; then
            logger "Cannot find configuration file $VAP_CONF22"
            exit 0
        elif [ "$WLN_WAN" = "1" ] && [ ! -e "$VAP_CONF21" ]; then
            logger "Cannot find configuration file $VAP_CONF21"
            exit 0
        elif [ "$WLN_WAN" = "0" ] && [ "$VAP_WAN" = "1" ] && [ ! -e "$VAP_CONF12" ]; then
            logger "Cannot find configuration file $VAP_CONF12"
            exit 0
        elif [ ! -e "$VAP_CONF11" ]; then
            logger "Cannot find configuration file $VAP_CONF11"
            exit 0
        fi
    fi
    if [ "$STX_OP" = "1" ] && [ ! -e "$STX_CONF" ]; then
        logger "Cannot find configuration file $STX_CONF"
        exit 0
    fi
    if [ "$WLX_OP" = "1" ] && [ ! -e "$WLX_CONF" ]; then
        logger "Cannot find configuration file $WLX_CONF"
        exit 0
    fi
    if [ -n "$WIRE_ETH" ]; then
        WIRE_MAC=$(ip addr show dev $WIRE_ETH | grep 'link/' | awk '{print $2}') > /dev/null 2>&1
    fi
    if [ -z "$WIRE_MAC" ]; then
        logger "Cannot find primary wired interface $WIRE_ETH"
        exit 0
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
                LAN_OP=1
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
            LAN_OP=1
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
            LAN_OP=1
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
            LAN_OP=1
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
                LAN_OP=1
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
            LAN_OP=1
            logger "UWIN info: WLN Mode --> Server"
        fi
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
            LAN_OP=1
            logger "UWIN info: WLX Mode --> Server"
        fi
    fi
    if [ "$BTT_COUNT" = "2" -o "$BTT_COUNT" = "4" -o "$BTT_COUNT" = "8" -o "$BTT_COUNT" = "16" ]; then
        if [ "$LAN_OP" = "1" ] && [ "$BTT_LOCAL" = "0" ] && [ "$WLX_OP" = "1" -o "$WLN_OP" = "1" ]; then
            LAN_OP=0
            BTT_OP=1
        else
            if [ "$LAN_OP" = "1" ] && [ "$BTT_LOCAL" != "0" ] && [ $BTT_LOCAL -le $BTT_COUNT ]; then
                if [ "$STA_OP" = "1" -a "$WLX_OP" = "1" ] || [ "$WLN_OP" = "1" -a "$STX_OP" = "1" ]; then
                    LAN_OP=0
                    BTT_OP=1
                fi
            fi
        fi
        if [ "$BTT_OP" = "1" ]; then
            BTT_CHAN_BAND="20"
            logger "UWIN info: BTT ($BTT_COUNT,$BTT_LOCAL) node chaining enabled"
        else
            logger "UWIN info: Cannot run BTT ($BTT_COUNT,$BTT_LOCAL) node chaining"
            exit 0
        fi
    fi
    if [ "$BRI_OP" = "0" ] && [ "$ETH_OP" = "1" ] && [ "$STA_OP" = "1" ] && [ "$STA_PRI" = "1" ]; then
        logger "UWIN info: STA Mode Top Priority" 
    fi
    if [ "$PCI_WDS" = "1" ]; then
        logger "UWIN info: Wi-Fi WDS enabled"
    fi
    if [ -n "$MON_IF" ] && [ -n "$WIFI_PCI" ] && [ -n "$STA_IF" -o -n "$WLN_IF" ]; then
        MON_OP=1
        logger "UWIN info: Wi-Fi monitor interface enabled"
    fi
    if [ "$MON_PCI" = "1" ] && [ -n "$WIFI_PCI" ] && [ -z "$STA_IF" -a -z "$WLN_IF" ]; then
        MON_PCI_OP=1
        logger "UWIN info: Wi-Fi PCI monitor enabled"
    fi
    if [ "$MON_USB" = "1" ] && [ -n "$WIFI_USB" ] && [ -z "$STX_IF" -a -z "$WLX_IF" ]; then
        MON_USB_OP=1
        logger "UWIN info: Wi-Fi USB monitor enabled"
    fi
    check_conf
}

clear_vars()
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
    BTT_OP=0
    ETH_BR=0
    USB_BR=0
    ENX_BR=0
    PCI_WDS=0
    SAP_WDS=0
    SAP_WAN=0
    WLN_WDS=0
    WLN_WAN=0
    VAP_WAN=0
    STX_WDS=0
    WLX_WDS=0
    WLX_WAN=0
    MON_PCI_OP=0
    MON_USB_OP=0
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
    BTT_IF=""
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
logger "\"$0\" checking..."

kill_all $0

clear_conf
clear_vars

if [ ! -e "/etc/uwin.conf" ]; then
    logger "Cannot find configuration file /etc/uwin.conf"
    exit 0
fi
source "/etc/uwin.conf"
set_opmode

logger "UWIN network manager version $UWINVER"

clean_drv
clean_info
clean_wifi

init_drv
init_iface
init_monitor

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
