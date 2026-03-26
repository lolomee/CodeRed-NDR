##! CodeRed NDR — OT / ICS Anomaly Detection
##! Detects threats in Operational Technology and Industrial Control System networks:
##! unauthorized Modbus commands, DNP3 anomalies, engineering station abuse,
##! and IT-to-OT lateral movement (the most dangerous OT threat vector).
##!
##! Zeek ships with Modbus and DNP3 protocol analyzers. This script
##! layers behavioral detection on top of those parsers.
##!
##! MITRE ATT&CK for ICS:
##!   T0803 — Block Command Message
##!   T0855 — Unauthorized Command Message
##!   T0836 — Modify Parameter
##!   T0846 — Remote System Discovery (OT reconnaissance)
##!   T0886 — Remote Services
##!   T0840 — Network Connection Enumeration
##!   T0862 — Supply Chain Compromise

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when Modbus write commands are sent from unexpected sources.
        OT_Modbus_Unauthorized_Write,

        ## Raised when Modbus function codes associated with attacks are seen.
        OT_Modbus_Dangerous_FC,

        ## Raised when DNP3 unsolicited responses or unusual traffic patterns appear.
        OT_DNP3_Anomaly,

        ## Raised when IT hosts communicate directly with OT/SCADA devices.
        OT_IT_to_OT_Lateral,

        ## Raised on port scans or enumeration of OT protocol ports.
        OT_Reconnaissance,

        ## Raised when engineering workstation behavior is seen from unexpected hosts.
        OT_Engineering_Station_Abuse,
    };

    ## OT/SCADA protocol ports — traffic on these from unexpected sources is flagged.
    const ot_ports: set[port] = {
        502/tcp,    # Modbus TCP
        20000/tcp,  # DNP3
        20000/udp,  # DNP3 UDP
        44818/tcp,  # EtherNet/IP (Allen-Bradley)
        44818/udp,  # EtherNet/IP
        2404/tcp,   # IEC 60870-5-104
        102/tcp,    # IEC 61850 / S7comm (Siemens)
        4840/tcp,   # OPC UA
        9600/tcp,   # OMRON FINS
        1962/tcp,   # PCWorx (Phoenix Contact)
        789/tcp,    # Red Lion Controls
        20547/tcp,  # ProConOs
        1089/tcp,   # FF HSE (Foundation Fieldbus)
        7700/tcp,   # BACnet/IP
        47808/udp,  # BACnet UDP
    } &redef;

    ## Modbus function codes that should NEVER appear in normal operations.
    ## These are used by attackers to write to coils, force outputs, restart PLCs.
    const modbus_dangerous_fcs: set[count] = {
        5,   # Write Single Coil — force output ON/OFF
        6,   # Write Single Register — modify parameter
        8,   # Diagnostics — force restart / clear counters
        15,  # Write Multiple Coils — mass output manipulation
        16,  # Write Multiple Registers — mass parameter write
        23,  # Read/Write Multiple Registers
        43,  # Encapsulated Interface Transport — rarely legitimate
        90,  # Vendor-specific — often abused in Industroyer/Crash Override
        125, # Vendor-specific (Schneider-specific FC used in Triton/TRISIS)
    } &redef;

    ## Known engineering workstation IPs — only these should send write commands.
    ## Configure via redef in local.zeek:
    ##   redef CodeRed::ot_engineering_stations += { 10.100.1.10, 10.100.1.11 };
    const ot_engineering_stations: set[addr] = {} &redef;

    ## Known OT device subnets — used to detect IT-to-OT lateral movement.
    ## Configure via redef in local.zeek:
    ##   redef CodeRed::ot_subnets += { 192.168.100.0/24 };
    const ot_subnets: set[subnet] = {} &redef;

    ## IT network subnets — sources of OT protocol traffic from here are flagged.
    const it_subnets: set[subnet] = {} &redef;

    ## Number of unique OT protocol destinations from a single source
    ## in the window to flag as OT reconnaissance.
    const ot_recon_threshold: double = 5.0 &redef;

    ## Time window for OT recon detection.
    const ot_recon_window: interval = 3 min &redef;

    ## Suppress interval for OT alerts.
    const ot_suppress_interval: interval = 15 min &redef;
}

# ─── SumStats: OT port reconnaissance ────────────────────────────────────

event zeek_init()
    {
    local r = SumStats::Reducer($stream="codered.ot.recon_targets", $apply=set(SumStats::UNIQUE));
    SumStats::create([
        $name="codered.ot.reconnaissance",
        $epoch=ot_recon_window,
        $reducers=set(r),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.ot.recon_targets"]$unique + 0.0; },
        $threshold=ot_recon_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.ot.recon_targets"]$unique;
            local msg = fmt("OT/ICS reconnaissance: %s probed %d unique OT devices in %s [MITRE ATT&CK ICS: T0846]",
                            key$host, n, ot_recon_window);
            NOTICE([$note=OT_Reconnaissance,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("unique_ot_targets=%d", n),
                    $identifier=cat(key$host, "ot_recon"),
                    $suppress_for=ot_suppress_interval]);
            }
    ]);
    }

# ─── Modbus: dangerous function code detection ────────────────────────────

event modbus_read_coils_request(c: connection, headers: ModbusHeaders,
                                 start_address: count, quantity: count) { }

event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders,
                                        address: count, value: bool)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Flag if source is not a known engineering station
    if ( |ot_engineering_stations| > 0 && src !in ot_engineering_stations )
        {
        local msg = fmt("Unauthorized Modbus coil write: %s -> %s (address=%d value=%s) — not from known eng. station [MITRE ATT&CK ICS: T0855]",
                        src, dst, address, value);
        NOTICE([$note=OT_Modbus_Unauthorized_Write,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("fc=5 address=%d value=%s", address, value),
                $identifier=cat(src, dst, "modbus_coil_write"),
                $suppress_for=ot_suppress_interval]);
        }
    }

event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders,
                                               start_address: count,
                                               registers: ModbusRegisters)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    local suspicious = F;

    # Unauthorized source writing registers
    if ( |ot_engineering_stations| > 0 && src !in ot_engineering_stations )
        suspicious = T;

    # Very large register writes are always suspicious (mass parameter modification)
    if ( |registers| > 50 )
        suspicious = T;

    if ( ! suspicious )
        return;

    local msg = fmt("Suspicious Modbus register write: %s -> %s (start_addr=%d, count=%d registers) [MITRE ATT&CK ICS: T0836]",
                    src, dst, start_address, |registers|);
    NOTICE([$note=OT_Modbus_Dangerous_FC,
            $conn=c,
            $src=src,
            $dst=dst,
            $msg=msg,
            $sub=fmt("fc=16 start=%d count=%d", start_address, |registers|),
            $identifier=cat(src, dst, "modbus_mass_write"),
            $suppress_for=ot_suppress_interval]);
    }

# ─── DNP3 anomalies ───────────────────────────────────────────────────────

event dnp3_application_request_header(c: connection, is_orig: bool,
                                       application: count, fc: count)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # DNP3 function codes:
    # 3 = Direct Operate (dangerous — direct control without select-before-operate)
    # 4 = Direct Operate No ACK (fire and forget — attacker evasion)
    # 13 = Cold Restart (crash the RTU)
    # 14 = Warm Restart
    # 30 = Enable Unsolicited (can flood controller with responses)
    # 131 = Authenticate Error (indicative of auth bypass attempts)
    local dangerous_dnp3_fcs: set[count] = { 3, 4, 13, 14, 130, 131 };

    if ( fc !in dangerous_dnp3_fcs )
        return;

    local fc_names: table[count] of string = {
        [3]   = "Direct Operate",
        [4]   = "Direct Operate No ACK",
        [13]  = "Cold Restart",
        [14]  = "Warm Restart",
        [130] = "Authentication Challenge",
        [131] = "Authentication Error",
    };

    local fc_name = fc in fc_names ? fc_names[fc] : fmt("FC-%d", fc);

    # Unauthorized source check
    if ( |ot_engineering_stations| > 0 && src !in ot_engineering_stations )
        {
        local msg = fmt("Unauthorized DNP3 command: %s -> %s (%s, fc=%d) — not from known eng. station [MITRE ATT&CK ICS: T0855]",
                        src, dst, fc_name, fc);
        NOTICE([$note=OT_DNP3_Anomaly,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("fc=%d fc_name=%s", fc, fc_name),
                $identifier=cat(src, dst, fmt("dnp3_fc%d", fc)),
                $suppress_for=ot_suppress_interval]);
        }
    }

# ─── IT-to-OT lateral movement ───────────────────────────────────────────

event connection_established(c: connection)
    {
    if ( c$id$resp_p !in ot_ports )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Track for reconnaissance detection
    SumStats::observe("codered.ot.recon_targets",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=cat(dst)));

    # IT-to-OT: source is in IT subnet, dest is in OT subnet
    if ( |it_subnets| > 0 && |ot_subnets| > 0 )
        {
        local src_is_it = F;
        local dst_is_ot = F;

        for ( it_net in it_subnets )
            if ( src in it_net ) { src_is_it = T; break; }
        for ( ot_net in ot_subnets )
            if ( dst in ot_net ) { dst_is_ot = T; break; }

        if ( src_is_it && dst_is_ot )
            {
            local msg = fmt("IT-to-OT lateral movement: %s (IT) -> %s (OT) on port %s [MITRE ATT&CK ICS: T0886, T0840]",
                            src, dst, c$id$resp_p);
            NOTICE([$note=OT_IT_to_OT_Lateral,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=msg,
                    $sub=fmt("port=%s", c$id$resp_p),
                    $identifier=cat(src, dst, "it_to_ot"),
                    $suppress_for=ot_suppress_interval]);
            return;
            }
        }

    # Engineering station abuse: OT protocol from non-eng-station
    if ( |ot_engineering_stations| > 0 && src !in ot_engineering_stations )
        {
        local abuse_msg = fmt("OT protocol from non-engineering host: %s -> %s (port=%s) [MITRE ATT&CK ICS: T0855]",
                               src, dst, c$id$resp_p);
        NOTICE([$note=OT_Engineering_Station_Abuse,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=abuse_msg,
                $sub=fmt("port=%s", c$id$resp_p),
                $identifier=cat(src, dst, cat(c$id$resp_p)),
                $suppress_for=ot_suppress_interval]);
        }
    }
