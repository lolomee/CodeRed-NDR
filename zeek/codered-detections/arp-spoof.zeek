##! CodeRed NDR — Layer-2 detection: ARP spoofing / MITM and rogue DHCP servers.
##!
##! ARP spoofing: tracks the IP->MAC binding learned from ARP replies and raises
##! a notice when an IP is suddenly claimed by a *different* MAC (classic ARP
##! cache poisoning used for man-in-the-middle / credential interception).
##!
##! Rogue DHCP: notices when a host other than an authorized server answers DHCP
##! (a rogue DHCP server can redirect gateway/DNS for MITM).
##!
##! Low overhead: one table lookup per ARP reply; DHCP is already parsed by Zeek.
##! Tunables below are operator-adjustable to silence benign churn (VRRP/HSRP
##! virtual gateways, DHCP failover pairs, etc.).

module CodeRed;

export {
	redef enum Notice::Type += {
		## An IP address was seen binding to a new MAC (possible ARP spoofing / MITM).
		ARP_Spoofing,
		## A host other than an authorized server answered DHCP (possible rogue DHCP).
		Rogue_DHCP_Server,
	};

	## IPs whose MAC is allowed to change without alerting (e.g. VRRP/HSRP
	## virtual gateway IPs, or hosts behind a load balancer).
	const arp_spoof_ignore: set[addr] = {} &redef;

	## Authorized DHCP server IPs. If empty, the first server observed is
	## learned automatically and any *additional* distinct server alerts.
	const authorized_dhcp_servers: set[addr] = {} &redef;
}

# Learned IP -> MAC bindings from ARP replies (bounded by hosts on the segment).
global arp_bindings: table[addr] of string;

# DHCP servers observed answering (for the auto-learn heuristic).
global seen_dhcp_servers: set[addr];

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
	if ( SPA in arp_spoof_ignore )
		return;
	# Ignore null / broadcast sender hardware addresses.
	if ( SHA == "00:00:00:00:00:00" || SHA == "ff:ff:ff:ff:ff:ff" || SHA == "" )
		return;

	if ( SPA !in arp_bindings )
		{
		arp_bindings[SPA] = SHA;
		return;
		}

	if ( arp_bindings[SPA] != SHA )
		{
		local old_mac = arp_bindings[SPA];
		NOTICE([$note=ARP_Spoofing,
		        $msg=fmt("ARP binding change for %s: %s -> %s (possible ARP spoofing / MITM)",
		                 SPA, old_mac, SHA),
		        $src=SPA,
		        $sub=fmt("old_mac=%s new_mac=%s", old_mac, SHA),
		        $identifier=fmt("arp-%s-%s", SPA, SHA),
		        $suppress_for=1hr]);
		arp_bindings[SPA] = SHA;
		}
	}

# Zeek raises dhcp_message for each DHCP packet; the server-sent message types
# (OFFER=2, ACK=5) identify a host acting as a DHCP server.
event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
	{
	# Server replies come from the server (is_orig = F on the response side).
	if ( msg$m_type != 2 && msg$m_type != 5 )   # OFFER or ACK only
		return;

	local server = c$id$orig_h;
	# In DHCP, the server is the responder; pick the non-client endpoint.
	if ( is_orig )
		server = c$id$orig_h;
	else
		server = c$id$resp_h;

	if ( server in authorized_dhcp_servers )
		return;

	# Auto-learn mode: if no authorized list is configured, accept the first
	# server seen and only alert on any additional distinct server.
	if ( |authorized_dhcp_servers| == 0 && |seen_dhcp_servers| == 0 )
		{
		add seen_dhcp_servers[server];
		return;
		}
	if ( server in seen_dhcp_servers )
		return;

	add seen_dhcp_servers[server];
	NOTICE([$note=Rogue_DHCP_Server,
	        $msg=fmt("DHCP server activity from unapproved host %s (possible rogue DHCP)", server),
	        $src=server,
	        $identifier=fmt("rogue-dhcp-%s", server),
	        $suppress_for=1day]);
	}
