```bash title="iptables rule - OCF Resource Agent"
#!/bin/sh
# Borrowed from chriscowley
# https://gist.github.com/chriscowley/bdd466a09b13ca676af2
#
#       OCF Resource Agent compliant resource script.
#
# Copyright (c) 2009 IN-telegence GmbH & Co. KG, Dominik Klein
#                    All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it would be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# Further, this software is distributed without any warranty that it is
# free of the rightful claim of any third person regarding infringement
# or the like.  Any license provided herein, whether implied or
# otherwise, applies only to this software file.  Patent licenses, if
# any, provided herein do not apply to combinations of this program with
# other software, or any other product whatsoever.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.

# OCF instance parameters
#       OCF_RESKEY_chain
#       OCF_RESKEY_source
#       OCF_RESKEY_protocol
#       OCF_RESKEY_ports
#       OCF_RESKEY_action
#
# This RA adds a rule to an iptables firewall
# Monitoring is done through checking the output of iptables -L

# Initialization:
: ${OCF_FUNCTIONS_DIR=${OCF_ROOT}/lib/heartbeat}
. ${OCF_FUNCTIONS_DIR}/ocf-shellfuncs

iptables_rule_status() {
    if  [ $(/sbin/iptables -nL | grep  ${OCF_RESKEY_source} | grep ${OCF_RESKEY_protocol} | grep  ${OCF_RESKEY_ports} | grep ${OCF_RESKEY_action}  | wc -l) -eq 1 ]
    then
        return $OCF_RUNNING
    else
        return $OCF_NOT_RUNNING
    fi
}

iptables_rule_start() {
	if ! iptables_status
	then
        cmd="/sbin/iptables -A ${OCF_RESKEY_chain} -s ${OCF_RESKEY_source} -p ${OCF_RESKEY_protocol} --dport ${OCF_RESKEY_ports} -j ${OCF_RESKEY_action}"
        ocf_log debug "Adding rule -s ${OCF_RESKEY_source} -p ${OCF_RESKEY_protocol} --dport ${OCF_RESKEY_ports} -j ${OCF_RESKEY_action} to ${OCF_RESKEY_chain} chain"
        eval ${cmd}
        if iptables_rule_status
        then
            ocf_log debug "Rule: -s ${OCF_RESKEY_source} -p ${OCF_RESKEY_protocol} --dport ${OCF_RESKEY_ports} -j ${OCF_RESKEY_action} added to  ${OCF_RESKEY_chain} successfully"
            return $OCF_SUCCESS
        else
            ocf_log err "Could not add rule"
            return $OCF_ERR_GENERIC
        fi
    else
		# If already running, consider start successful
		ocf_log debug "Rule already exists"
        return $OCF_SUCCESS
    fi
}

iptables_rule_stop() {
    if [ -n "$OCF_RESKEY_stop_timeout" ]
    then
            stop_timeout=$OCF_RESKEY_stop_timeout
    elif [ -n "$OCF_RESKEY_CRM_meta_timeout" ]; then
            # Allow 2/3 of the action timeout for the orderly shutdown
            # (The origin unit is ms, hence the conversion)
            stop_timeout=$((OCF_RESKEY_CRM_meta_timeout/1500))
    else
            stop_timeout=10
    fi
	if iptables_rule_status
	then
        cmd="/sbin/iptables -D ${OCF_RESKEY_chain} -s ${OCF_RESKEY_source} -p ${OCF_RESKEY_protocol} --dport ${OCF_RESKEY_ports} -j ${OCF_RESKEY_action}"
        eval ${cmd}
        i=0
        while [ $i -lt ${stop_timeout}]
        do
            if ! iptables_rule_status
            then
                return ${OCF_SUCCESS}
            fi
            sleep 1
            i=$((i+1))
        done
        ocf_log warn "Could not remove rule"
        return $OCF_ERR_GENERIC
    else
        # Rule not in table
        return $OCF_SUCCESS
    fi
}

iptables_rule_monitor() {
	iptables_rule_status
	ret=$?
	if [ $ret -eq $OCF_SUCCESS ]
	then
		return $ret
	fi
}

# FIXME: Attributes special meaning to the resource id
if [ -z ${OCF_RESKEY_chain} ]
then
    chain="$OCF_RESKEY_chain"
else
    chain="INPUT"
fi
if [ -z "${OCF_RESKEY_source}"]
then
    source="$OCF_RESKEY_source"
else
    source="0.0.0.0"
fi
if [ -z ${OCF_RESKEY_protocol} ]
then
    protocol="$OCF_RESKEY_protocol"
else
    protocol="tcp"
fi
if [ -z ${OCF_RESKEY_action} ]
then
    action="$OCF_RESKEY_action"
else
    action="ACCEPT"
fi
ports="$OCF_RESKEY_ports"

function valid_ip() {
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}
iptables_rule_validate() {
    if [ `/sbin/iptables -L | grep 'Chain' | grep ${chain}` -nq 1 ]
    then
        ocf_log err "Chain ${chain} does not exist in iptables"
        exit $OCF_ERR_INSTALLED
    fi
    if [ ! valid_ip ${source} ]
    then
        ocf_log err "${source} is not a valid IP address"
        exit $OCF_ERR_INSTALLED
    fi
    if [ ${protocol} != 'tcp' || ${protocol} != 'udp']
    then
        ocf_log err "${protocol} is not a valid protocol"
        exit $OCF_ERR_INSTALLED
    fi
    if [ ${ports} != [0-9*] || ${ports} != [0-9*]:[0-9]* ]
    then
        ocf_log err "${ports} is not a valid port range"
        exit $OCF_ERR_INSTALLED
    fi
    if [ ${action} != "ACCEPT" || ${action} != "REJECT" || ${action} != "DROP" || ${action} != "LOG"]
    then
        ocf_log err "${action} is not a valid action"
        exit $OCF_ERR_INSTALLED
    fi
	return $OCF_SUCCESS
}

anything_meta() {
cat <<END
<?xml version="1.0"?>
<!DOCTYPE resource-agent SYSTEM "ra-api-1.dtd">
<resource-agent name="iptables_rule">
<version>1.0</version>
<longdesc lang="en">
This is an OCF RA to add an Iptables rule
</longdesc>
<shortdesc lang="en">Adds an Iptables rule</shortdesc>
<parameters>
<parameter name="chain" required="0">
<longdesc lang="en">
The firewall chain to add the rule to
</longdesc>
<shortdesc lang="en">Firewall chain to add the rule to</shortdesc>
<content type="string" default=""/>
</parameter>
<parameter name="source" required="0">
<longdesc lang="en">
Source address for traffic. Defaults to 0.0.0.0 (anywhere)
</longdesc>
<shortdesc lang="en">Source address</shortdesc>
<content type="string" />
</parameter>
<parameter name="protocol" required="0">
<longdesc lang="en">
Protocol, defaults to "tcp"
</longdesc>
<shortdesc lang="en">protocol</shortdesc>
<content type="string" default="tcp"/>
</parameter>
<parameter name="ports" required="1">
<longdesc lang="en">
Ports to process. Can be either a port (80), or a range (6000:6033)
</longdesc>
<shortdesc lang="en">ports to process</shortdesc>
</parameter>
<parameter name="action" >
<longdesc lang="en">
What to do with the traffic. Can be one of ACCEPT, REJECT, DROP or LOG. Default to ACCEPT
</longdesc>
<shortdesc lang="en">What to do with the traffic</shortdesc>
</parameter>
</parameters>
<actions>
<action name="start"   timeout="20s" />
<action name="stop"    timeout="20s" />
<action name="monitor" depth="0"  timeout="20s" interval="10" />
<action name="meta-data"  timeout="5" />
<action name="validate-all"  timeout="5" />
</actions>
</resource-agent>
END
exit 0
}

case "$1" in
	meta-data|metadata|meta_data)
	iptables_rule_meta	
	;;
	start)
		iptables_rule_start
	;;
	stop)
		iptables_rule_stop
	;;
	monitor)
		iptables_rule_monitor
	;;
	validate-all)
		iptables_rule_validate
	;;
	*)
		ocf_log err "$0 was called with unsupported arguments: $*"
		exit $OCF_ERR_UNIMPLEMENTED
	;;
esac
```