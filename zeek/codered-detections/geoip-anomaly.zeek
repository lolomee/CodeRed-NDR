##! CodeRed NDR — GeoIP destination anomaly.
##! Raises a notice when an internal host connects OUT to a destination in a
##! configured high-risk country, using the bundled MaxMind GeoLite2 DB.
##!
##! INERT BY DEFAULT: high_risk_countries is empty, so this does NOTHING (and
##! costs nothing — it returns before any GeoIP lookup) until you set it. Which
##! countries are "high risk" is a per-network policy call, so enable it by
##! redef-ing the set in local.zeek, e.g.:
##!     redef CodeRed::high_risk_countries += { "KP", "RU", "IR", "BY" };
##! Notices are de-duplicated per (host, country) and suppressed for 1 day.

module CodeRed;

export {
	redef enum Notice::Type += {
		## An internal host connected to a destination in a high-risk country.
		GeoIP_HighRisk_Destination,
	};

	## ISO 3166-1 alpha-2 country codes treated as high-risk for THIS network.
	## Empty by default (inert). Populate in local.zeek to enable.
	const high_risk_countries: set[string] = {} &redef;

	## Internal networks (for the outbound direction test). Self-contained so it
	## does not depend on Site::local_nets, which is unset on this sensor.
	## Defaults to RFC1918; narrow to your monitored subnet if you prefer.
	const geo_internal_nets: set[subnet] = {
		10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
	} &redef;
}

event connection_state_remove(c: connection)
	{
	# Inert until configured — no GeoIP lookups, no notices when list is empty.
	if ( |high_risk_countries| == 0 )
		return;

	# Outbound only: internal originator, external responder.
	if ( c$id$orig_h !in geo_internal_nets )
		return;
	if ( c$id$resp_h in geo_internal_nets )
		return;

	local loc = lookup_location(c$id$resp_h);
	if ( ! loc?$country_code )
		return;
	if ( loc$country_code !in high_risk_countries )
		return;

	NOTICE([$note=GeoIP_HighRisk_Destination,
	        $msg=fmt("Internal host %s connected to %s in high-risk country %s",
	                 c$id$orig_h, c$id$resp_h, loc$country_code),
	        $conn=c,
	        $src=c$id$orig_h,
	        $dst=c$id$resp_h,
	        $identifier=fmt("geo-%s-%s", c$id$orig_h, loc$country_code),
	        $suppress_for=1day]);
	}
