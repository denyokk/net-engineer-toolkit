import { useState } from "react";

// ─── Theme ────────────────────────────────────────────────────────────────────
const T = {
  bg:       "#eef0f4",
  surface:  "#ffffff",
  surface2: "#f5f6f9",
  surface3: "#eef0f4",
  border:   "#dde1e7",
  border2:  "#c8cdd6",
  accent:   "#1a6fce",
  accentBg: "#e8f0fc",
  accentLt: "#cdddf8",
  text:     "#1c2333",
  textSub:  "#52606d",
  textMuted:"#8a95a3",
  codeBg:   "#f4f6f9",
  green:    "#0d7a4e",
  greenBg:  "#edf7f2",
  red:      "#c0392b",
  redBg:    "#fdf1f0",
  orange:   "#b45309",
  purple:   "#6b4fbb",
  mono:     "'JetBrains Mono','Fira Mono',monospace",
  sans:     "Inter,system-ui,sans-serif",
};

// ─── Subnet helpers ───────────────────────────────────────────────────────────
const ipToInt = ip => ip.split(".").reduce((a,o)=>(a<<8)+parseInt(o,10),0)>>>0;
const intToIp = n  => [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join(".");
const cidrToMask = c => c===0?0:(0xffffffff<<(32-c))>>>0;

function calcSubnet(ipStr, cidr) {
  const ip=ipToInt(ipStr), mask=cidrToMask(cidr);
  const net=(ip&mask)>>>0, bc=(net|(~mask>>>0))>>>0;
  const fh=cidr<31?net+1:net, lh=cidr<31?bc-1:bc;
  const hc=cidr>=31?Math.pow(2,32-cidr):Math.max(0,bc-net-1);
  const wc=(~mask)>>>0;
  const ipp=ipToInt;
  const cls=ip>=ipp("224.0.0.0")?"D/E (Multicast)":
    ip>=ipp("192.168.0.0")&&ip<=ipp("192.168.255.255")?"C · Private (RFC1918)":
    ip>=ipp("172.16.0.0") &&ip<=ipp("172.31.255.255") ?"B · Private (RFC1918)":
    ip>=ipp("10.0.0.0")   &&ip<=ipp("10.255.255.255")  ?"A · Private (RFC1918)":
    cidr<8?"A · Public":cidr<16?"B · Public":"C · Public";
  return {network:intToIp(net),broadcast:intToIp(bc),mask:intToIp(mask),
    wildcard:intToIp(wc),firstHost:intToIp(fh),lastHost:intToIp(lh),
    hostCount:hc,cidr,
    binaryMask:intToIp(mask).split(".").map(o=>parseInt(o).toString(2).padStart(8,"0")).join("."),
    ipClass:cls};
}

// ─── Syntax highlight (light theme) ──────────────────────────────────────────
function HL({line}) {
  if(!line) return <span>&nbsp;</span>;
  if(line.startsWith("!")|| line.startsWith("#"))
    return <span style={{color:T.textMuted,fontStyle:"italic"}}>{line}</span>;
  if(/^(interface|router|zone|zone-pair|policy-map|class-map|crypto map|line vty|spanning-tree mode|vlan|username|ip dhcp pool)\b/.test(line))
    return <span style={{color:T.accent,fontWeight:600}}>{line}</span>;
  if(/^(no |ip |ntp |clock |set |add |\/ip|\/interface|\/routing|permit|deny|shutdown|description|switchport|channel-group|lacp|spanning-tree|crypto|hostname|enable|service)\b/.test(line))
    return <span style={{color:T.purple}}>{line}</span>;
  const parts=line.split(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  if(parts.length>1) return <span>{parts.map((p,i)=>
    /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(p)
      ?<span key={i} style={{color:T.orange}}>{p}</span>
      :<span key={i}>{p}</span>)}</span>;
  return <span style={{color:T.text}}>{line}</span>;
}

// ─── ACL services ─────────────────────────────────────────────────────────────
const ACL_SERVICES = [
  {id:"dns",   label:"DNS",    port:"53",  proto:"udp",  desc:"Domain Name System",       def:true },
  {id:"http",  label:"HTTP",   port:"80",  proto:"tcp",  desc:"Web (unencrypted)",         def:true },
  {id:"https", label:"HTTPS",  port:"443", proto:"tcp",  desc:"Web (encrypted)",           def:true },
  {id:"ntp",   label:"NTP",    port:"123", proto:"udp",  desc:"Time synchronization",      def:true },
  {id:"icmp",  label:"ICMP",   port:null,  proto:"icmp", desc:"Ping / diagnostics",        def:true },
  {id:"smtp",  label:"SMTP",   port:"25",  proto:"tcp",  desc:"Email sending",             def:false},
  {id:"imap",  label:"IMAP",   port:"143", proto:"tcp",  desc:"Email retrieval",           def:false},
  {id:"ssh",   label:"SSH",    port:"22",  proto:"tcp",  desc:"Secure remote access",      def:false},
  {id:"rdp",   label:"RDP",    port:"3389",proto:"tcp",  desc:"Remote Desktop",            def:false},
  {id:"ftp",   label:"FTP",    port:"21",  proto:"tcp",  desc:"File Transfer Protocol",    def:false},
  {id:"telnet",label:"Telnet", port:"23",  proto:"tcp",  desc:"Unencrypted remote access", def:false},
  {id:"snmp",  label:"SNMP",   port:"161", proto:"udp",  desc:"Network management",        def:false},
  {id:"ldap",  label:"LDAP",   port:"389", proto:"tcp",  desc:"Directory services",        def:false},
  {id:"smb",   label:"SMB",    port:"445", proto:"tcp",  desc:"Windows file sharing",      def:false},
  {id:"tftp",  label:"TFTP",   port:"69",  proto:"udp",  desc:"Trivial File Transfer",     def:false},
];

// ─── TEMPLATES ────────────────────────────────────────────────────────────────
const VENDORS = {
  cisco_ios: {
    label:"Cisco IOS", icon:"🔵",
    groups:[
      {
        label:"Базові налаштування",
        templates:{
          initial:{
            label:"Initial Setup",
            fields:[
              {id:"hostname",  label:"Hostname",           ph:"SW-CORE-01"       },
              {id:"domain",    label:"Domain Name",        ph:"corp.local"       },
              {id:"enable_sec",label:"Enable Secret",      ph:"Str0ng-Passw0rd"  },
              {id:"username",  label:"Admin Username",     ph:"admin"            },
              {id:"password",  label:"Admin Password",     ph:"Str0ng-Passw0rd"  },
              {id:"vty_lines", label:"VTY Lines (e.g. 0 4)",ph:"0 4"            },
              {id:"banner",    label:"MOTD Banner",        ph:"Authorized access only!" },
            ],
            generate: f => `! ─── Initial Device Configuration ───
hostname ${f.hostname||"DEVICE"}
!
service password-encryption
no ip domain-lookup
!
ip domain-name ${f.domain||"corp.local"}
!
enable secret ${f.enable_sec||"[ENABLE-SECRET]"}
!
username ${f.username||"admin"} privilege 15 secret ${f.password||"[PASSWORD]"}
!
banner motd ^
  ${f.banner||"Authorized access only!"}
^
!
! ─── SSH v2 ───
crypto key generate rsa modulus 2048
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
line vty ${f.vty_lines||"0 4"}
 login local
 transport input ssh
 exec-timeout 10 0
!
line con 0
 login local
 exec-timeout 5 0
!
! ─── Basic hardening ───
no cdp run
ip tcp intercept list 100`,
          },
          ssh:{
            label:"SSH Hardening",
            fields:[
              {id:"hostname",  label:"Hostname",          ph:"SW-CORE-01"       },
              {id:"domain",    label:"Domain Name",       ph:"corp.local"       },
              {id:"username",  label:"Admin Username",    ph:"admin"            },
              {id:"vty_start", label:"VTY start",         ph:"0"                },
              {id:"vty_end",   label:"VTY end",           ph:"4"                },
            ],
            generate: f => `! ─── SSH v2 Hardening ───
hostname ${f.hostname||"ROUTER"}
ip domain-name ${f.domain||"corp.local"}
!
crypto key generate rsa modulus 2048
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
username ${f.username||"admin"} privilege 15 secret 0 [STRONG-PASSWORD]
!
line vty ${f.vty_start||"0"} ${f.vty_end||"4"}
 login local
 transport input ssh
 exec-timeout 10 0`,
          },
          ntp:{
            label:"NTP",
            fields:[
              {id:"ntp_server",label:"NTP Server IP",     ph:"216.239.35.0"     },
              {id:"timezone",  label:"Timezone",          ph:"EET"              },
              {id:"offset",    label:"UTC Offset",        ph:"2"                },
              {id:"source_if", label:"Source Interface",  ph:"Loopback0"        },
            ],
            generate: f => `! ─── NTP Configuration ───
clock timezone ${f.timezone||"EET"} ${f.offset||"2"}
!
ntp server ${f.ntp_server||"x.x.x.x"}
ntp source ${f.source_if||"Loopback0"}
ntp update-calendar`,
          },
        },
      },
      {
        label:"L2 – Switching",
        templates:{
          vlan:{
            label:"VLAN",
            fields:[
              {id:"vlan_id",   label:"VLAN ID",           ph:"10"               },
              {id:"vlan_name", label:"VLAN Name",          ph:"MANAGEMENT"       },
              {id:"interface", label:"Access Interface",   ph:"GigabitEthernet0/1"},
              {id:"ip",        label:"SVI IP Address",     ph:"192.168.10.1"     },
              {id:"mask",      label:"Subnet Mask",        ph:"255.255.255.0"    },
              {id:"description",label:"Description",       ph:"Management VLAN"  },
            ],
            generate: f => `! ─── VLAN ${f.vlan_id||"?"} ───
vlan ${f.vlan_id||"?"}
 name ${f.vlan_name||"?"}
!
interface Vlan${f.vlan_id||"?"}
 description ${f.description||"VLAN Interface"}
 ip address ${f.ip||"x.x.x.x"} ${f.mask||"255.255.255.0"}
 no shutdown
!
interface ${f.interface||"GigabitEthernet0/1"}
 description ${f.description||"Access port"}
 switchport mode access
 switchport access vlan ${f.vlan_id||"?"}
 spanning-tree portfast
 no shutdown`,
          },
          stp:{
            label:"STP / RSTP",
            fields:[
              {id:"mode",      label:"STP Mode",           ph:"rapid-pvst"       },
              {id:"vlan_range",label:"VLAN Range",          ph:"1-100"            },
              {id:"priority",  label:"Bridge Priority",    ph:"4096"             },
              {id:"portfast_if",label:"PortFast Interface",ph:"GigabitEthernet0/1"},
              {id:"guard_if",  label:"BPDU Guard Interface",ph:"GigabitEthernet0/2"},
            ],
            generate: f => `! ─── STP Configuration ───
spanning-tree mode ${f.mode||"rapid-pvst"}
!
spanning-tree vlan ${f.vlan_range||"1-100"} priority ${f.priority||"4096"}
!
interface ${f.portfast_if||"GigabitEthernet0/1"}
 spanning-tree portfast
!
interface ${f.guard_if||"GigabitEthernet0/2"}
 spanning-tree portfast
 spanning-tree bpduguard enable
!
spanning-tree portfast bpduguard default`,
          },
          port_channel:{
            label:"Port-Channel (LACP)",
            fields:[
              {id:"po_num",    label:"Port-Channel Number",ph:"1"                },
              {id:"if1",       label:"Interface 1",        ph:"GigabitEthernet0/1"},
              {id:"if2",       label:"Interface 2",        ph:"GigabitEthernet0/2"},
              {id:"mode",      label:"LACP Mode (active/passive)",ph:"active"    },
              {id:"trunk_vlans",label:"Allowed VLANs",     ph:"10,20,30"         },
              {id:"native_vlan",label:"Native VLAN",       ph:"99"               },
              {id:"description",label:"Description",       ph:"Uplink to SW-DIST"},
            ],
            generate: f => `! ─── Port-Channel ${f.po_num||"1"} (LACP) ───
!
interface ${f.if1||"GigabitEthernet0/1"}
 description ${f.description||"LAG member"}
 switchport mode trunk
 switchport trunk native vlan ${f.native_vlan||"99"}
 switchport trunk allowed vlan ${f.trunk_vlans||"10,20,30"}
 channel-group ${f.po_num||"1"} mode ${f.mode||"active"}
 no shutdown
!
interface ${f.if2||"GigabitEthernet0/2"}
 description ${f.description||"LAG member"}
 switchport mode trunk
 switchport trunk native vlan ${f.native_vlan||"99"}
 switchport trunk allowed vlan ${f.trunk_vlans||"10,20,30"}
 channel-group ${f.po_num||"1"} mode ${f.mode||"active"}
 no shutdown
!
interface Port-channel${f.po_num||"1"}
 description ${f.description||"Aggregated Uplink"}
 switchport mode trunk
 switchport trunk native vlan ${f.native_vlan||"99"}
 switchport trunk allowed vlan ${f.trunk_vlans||"10,20,30"}
 no shutdown`,
          },
        },
      },
      {
        label:"L3 – Routing",
        templates:{
          ospf:{
            label:"OSPF",
            fields:[
              {id:"process_id",label:"Process ID",         ph:"1"                },
              {id:"router_id", label:"Router ID",          ph:"1.1.1.1"          },
              {id:"network",   label:"Network",            ph:"192.168.1.0"      },
              {id:"wildcard",  label:"Wildcard Mask",      ph:"0.0.0.255"        },
              {id:"area",      label:"Area",               ph:"0"                },
              {id:"passive_if",label:"Passive Interface",  ph:"GigabitEthernet0/2"},
            ],
            generate: f => `! ─── OSPF Process ${f.process_id||"1"} ───
router ospf ${f.process_id||"1"}
 router-id ${f.router_id||"x.x.x.x"}
 network ${f.network||"x.x.x.x"} ${f.wildcard||"0.0.0.x"} area ${f.area||"0"}
 passive-interface ${f.passive_if||"GigabitEthernet0/2"}
 auto-cost reference-bandwidth 10000`,
          },
          bgp:{
            label:"BGP",
            fields:[
              {id:"local_as",  label:"Local AS",           ph:"65001"            },
              {id:"router_id", label:"Router ID",          ph:"1.1.1.1"          },
              {id:"neighbor_ip",label:"Neighbor IP",       ph:"10.0.0.2"         },
              {id:"remote_as", label:"Remote AS",          ph:"65002"            },
              {id:"network",   label:"Advertise Network",  ph:"192.168.1.0"      },
              {id:"mask",      label:"Network Mask",       ph:"255.255.255.0"    },
              {id:"pass",      label:"MD5 Password",       ph:"BGP-SECRET"       },
            ],
            generate: f => `! ─── BGP AS ${f.local_as||"?"} ───
router bgp ${f.local_as||"?"}
 bgp router-id ${f.router_id||"x.x.x.x"}
 bgp log-neighbor-changes
 !
 neighbor ${f.neighbor_ip||"x.x.x.x"} remote-as ${f.remote_as||"?"}
 neighbor ${f.neighbor_ip||"x.x.x.x"} password ${f.pass||"[PASSWORD]"}
 neighbor ${f.neighbor_ip||"x.x.x.x"} soft-reconfiguration inbound
 !
 address-family ipv4
  neighbor ${f.neighbor_ip||"x.x.x.x"} activate
  network ${f.network||"x.x.x.x"} mask ${f.mask||"255.255.255.0"}
  no auto-summary
 exit-address-family`,
          },
          nat_pat:{
            label:"NAT / PAT",
            fields:[
              {id:"inside_if", label:"Inside Interface",   ph:"GigabitEthernet0/0"},
              {id:"outside_if",label:"Outside Interface",  ph:"GigabitEthernet0/1"},
              {id:"acl_num",   label:"ACL Number",         ph:"10"               },
              {id:"network",   label:"Inside Network",     ph:"192.168.1.0"      },
              {id:"wildcard",  label:"Wildcard Mask",      ph:"0.0.0.255"        },
            ],
            generate: f => `! ─── NAT/PAT Overload ───
access-list ${f.acl_num||"10"} permit ${f.network||"x.x.x.x"} ${f.wildcard||"0.0.0.255"}
!
interface ${f.inside_if||"GigabitEthernet0/0"}
 ip nat inside
!
interface ${f.outside_if||"GigabitEthernet0/1"}
 ip nat outside
!
ip nat inside source list ${f.acl_num||"10"} interface ${f.outside_if||"GigabitEthernet0/1"} overload`,
          },
          dhcp:{
            label:"DHCP Server",
            fields:[
              {id:"pool_name", label:"Pool Name",          ph:"LAN-POOL"         },
              {id:"network",   label:"Network",            ph:"192.168.1.0"      },
              {id:"mask",      label:"Subnet Mask",        ph:"255.255.255.0"    },
              {id:"gateway",   label:"Default Gateway IP", ph:"192.168.1.1"      },
              {id:"dns1",      label:"DNS Server 1",       ph:"8.8.8.8"          },
              {id:"dns2",      label:"DNS Server 2",       ph:"8.8.4.4"          },
              {id:"lease_days",label:"Lease (days)",       ph:"7"                },
              {id:"excl_end",  label:"Exclude up to (last reserved IP)",ph:"192.168.1.20"},
            ],
            generate: f => {
              const gw = f.gateway||"192.168.1.1";
              const excl = f.excl_end||gw;
              const net = f.network||"192.168.1.0";
              const parts = net.split(".");
              const netBase = parts.slice(0,3).join(".")+".1";
              return `! ─── DHCP Server: ${f.pool_name||"LAN-POOL"} ───
!
! Exclude gateway + reserved addresses
ip dhcp excluded-address ${netBase} ${excl}
!
ip dhcp pool ${f.pool_name||"LAN-POOL"}
 network ${net} ${f.mask||"255.255.255.0"}
 default-router ${gw}
 dns-server ${f.dns1||"8.8.8.8"} ${f.dns2||"8.8.4.4"}
 lease ${f.lease_days||"7"}
!
! Optional: DHCP snooping (recommended on access switches)
! ip dhcp snooping
! ip dhcp snooping vlan 1-100`;
            },
          },
        },
      },
      {
        label:"Security",
        templates:{
          acl:{
            label:"Extended ACL",
            fields:[
              {id:"acl_name",  label:"ACL Name",           ph:"CORP-IN"          },
              {id:"src_net",   label:"Source Network",     ph:"192.168.1.0"      },
              {id:"src_wild",  label:"Source Wildcard",    ph:"0.0.0.255"        },
              {id:"dst_net",   label:"Destination",        ph:"any"              },
              {id:"interface", label:"Apply to Interface", ph:"GigabitEthernet0/1"},
              {id:"direction", label:"Direction (in/out)", ph:"in"               },
            ],
            generate: f => `! ─── Extended ACL: ${f.acl_name||"CORP-IN"} ───
ip access-list extended ${f.acl_name||"CORP-IN"}
 permit tcp ${f.src_net||"x.x.x.x"} ${f.src_wild||"0.0.0.255"} ${f.dst_net||"any"} established
 permit tcp ${f.src_net||"x.x.x.x"} ${f.src_wild||"0.0.0.255"} ${f.dst_net||"any"} eq 443
 permit tcp ${f.src_net||"x.x.x.x"} ${f.src_wild||"0.0.0.255"} ${f.dst_net||"any"} eq 80
 permit udp ${f.src_net||"x.x.x.x"} ${f.src_wild||"0.0.0.255"} ${f.dst_net||"any"} eq 53
 deny   ip  ${f.src_net||"x.x.x.x"} ${f.src_wild||"0.0.0.255"} any log
!
interface ${f.interface||"GigabitEthernet0/1"}
 ip access-group ${f.acl_name||"CORP-IN"} ${f.direction||"in"}`,
          },
          ipsec:{
            label:"IPsec VPN",
            fields:[
              {id:"peer_ip",   label:"Peer IP",            ph:"203.0.113.1"      },
              {id:"local_net", label:"Local Network",      ph:"192.168.1.0"      },
              {id:"local_wild",label:"Local Wildcard",     ph:"0.0.0.255"        },
              {id:"remote_net",label:"Remote Network",     ph:"10.10.10.0"       },
              {id:"remote_wild",label:"Remote Wildcard",   ph:"0.0.0.255"        },
              {id:"psk",       label:"Pre-Shared Key",     ph:"STRONG-PSK-KEY"   },
              {id:"transform", label:"Transform Set Name", ph:"VPN-TRANSFORM"    },
              {id:"map_name",  label:"Crypto Map Name",    ph:"VPN-MAP"          },
              {id:"outside_if",label:"Outside Interface",  ph:"GigabitEthernet0/0"},
            ],
            generate: f => `! ─── IPsec Site-to-Site VPN ───
crypto isakmp policy 10
 encr aes 256
 hash sha256
 authentication pre-share
 group 14
 lifetime 86400
!
crypto isakmp key ${f.psk||"[PSK]"} address ${f.peer_ip||"x.x.x.x"}
!
crypto ipsec transform-set ${f.transform||"VPN-TRANSFORM"} esp-aes 256 esp-sha256-hmac
 mode tunnel
!
ip access-list extended VPN-TRAFFIC
 permit ip ${f.local_net||"x.x.x.x"} ${f.local_wild||"0.0.0.255"} ${f.remote_net||"x.x.x.x"} ${f.remote_wild||"0.0.0.255"}
!
crypto map ${f.map_name||"VPN-MAP"} 10 ipsec-isakmp
 set peer ${f.peer_ip||"x.x.x.x"}
 set transform-set ${f.transform||"VPN-TRANSFORM"}
 set pfs group14
 match address VPN-TRAFFIC
!
interface ${f.outside_if||"GigabitEthernet0/0"}
 crypto map ${f.map_name||"VPN-MAP"}`,
          },
          bgp_filter:{
            label:"BGP Prefix-List + Route-Map",
            fields:[
              {id:"pl_in_name", label:"Prefix-List IN Name",    ph:"PL-FROM-ISP"      },
              {id:"pl_out_name",label:"Prefix-List OUT Name",   ph:"PL-TO-ISP"        },
              {id:"permit_net", label:"Permit Network (IN)",    ph:"10.0.0.0/8"       },
              {id:"advertise",  label:"Advertise Network (OUT)",ph:"192.168.1.0/24"   },
              {id:"neighbor_ip",label:"Neighbor IP",            ph:"10.0.0.2"         },
              {id:"rm_in",      label:"Route-Map IN Name",      ph:"RM-FROM-ISP"      },
              {id:"rm_out",     label:"Route-Map OUT Name",     ph:"RM-TO-ISP"        },
              {id:"local_pref", label:"Local Preference",       ph:"200"              },
            ],
            generate: f => `! ─── BGP Prefix-List + Route-Map ───
!
! ── Prefix-Lists ──
ip prefix-list ${f.pl_in_name||"PL-FROM-ISP"} seq 10 permit ${f.permit_net||"10.0.0.0/8"} le 32
ip prefix-list ${f.pl_in_name||"PL-FROM-ISP"} seq 999 deny 0.0.0.0/0 le 32
!
ip prefix-list ${f.pl_out_name||"PL-TO-ISP"} seq 10 permit ${f.advertise||"192.168.1.0/24"}
ip prefix-list ${f.pl_out_name||"PL-TO-ISP"} seq 999 deny 0.0.0.0/0 le 32
!
! ── Route-Maps ──
route-map ${f.rm_in||"RM-FROM-ISP"} permit 10
 match ip address prefix-list ${f.pl_in_name||"PL-FROM-ISP"}
 set local-preference ${f.local_pref||"200"}
!
route-map ${f.rm_out||"RM-TO-ISP"} permit 10
 match ip address prefix-list ${f.pl_out_name||"PL-TO-ISP"}
!
! ── Apply to neighbor ──
router bgp [LOCAL-AS]
 neighbor ${f.neighbor_ip||"x.x.x.x"} route-map ${f.rm_in||"RM-FROM-ISP"} in
 neighbor ${f.neighbor_ip||"x.x.x.x"} route-map ${f.rm_out||"RM-TO-ISP"} out
 neighbor ${f.neighbor_ip||"x.x.x.x"} prefix-list ${f.pl_in_name||"PL-FROM-ISP"} in
 neighbor ${f.neighbor_ip||"x.x.x.x"} prefix-list ${f.pl_out_name||"PL-TO-ISP"} out`,
          },
          zpf:{
            label:"Zone-Based Firewall",
            fields:[
              {id:"inside_if", label:"Inside Interface",   ph:"GigabitEthernet0/1"},
              {id:"outside_if",label:"Outside Interface",  ph:"GigabitEthernet0/0"},
              {id:"dmz_if",    label:"DMZ Interface",      ph:"GigabitEthernet0/2"},
            ],
            generate: f => `! ─── Zone-Based Policy Firewall ───
zone security INSIDE
zone security OUTSIDE
zone security DMZ
!
class-map type inspect match-any INSIDE-TRAFFIC
 match protocol http
 match protocol https
 match protocol dns
 match protocol icmp
!
class-map type inspect match-any DMZ-TRAFFIC
 match protocol http
 match protocol https
!
policy-map type inspect INSIDE-TO-OUTSIDE
 class type inspect INSIDE-TRAFFIC
  inspect
 class class-default
  drop log
!
policy-map type inspect INSIDE-TO-DMZ
 class type inspect DMZ-TRAFFIC
  inspect
 class class-default
  drop
!
zone-pair security IN-TO-OUT source INSIDE destination OUTSIDE
 service-policy type inspect INSIDE-TO-OUTSIDE
!
zone-pair security IN-TO-DMZ source INSIDE destination DMZ
 service-policy type inspect INSIDE-TO-DMZ
!
interface ${f.inside_if||"GigabitEthernet0/1"}
 zone-member security INSIDE
!
interface ${f.outside_if||"GigabitEthernet0/0"}
 zone-member security OUTSIDE
!
interface ${f.dmz_if||"GigabitEthernet0/2"}
 zone-member security DMZ`,
          },
        },
      },
    ],
  },

  mikrotik: {
    label:"MikroTik", icon:"🔴",
    groups:[
      {
        label:"Базові налаштування",
        templates:{
          initial:{
            label:"Initial Setup",
            fields:[
              {id:"hostname",  label:"Hostname (Identity)", ph:"MK-ROUTER-01"    },
              {id:"username",  label:"Admin Username",     ph:"admin"            },
              {id:"password",  label:"Admin Password",     ph:"Str0ng-Passw0rd"  },
              {id:"ntp_server",label:"NTP Server",         ph:"216.239.35.0"     },
              {id:"timezone",  label:"Timezone",           ph:"Europe/Kiev"      },
            ],
            generate: f => `/system identity
set name="${f.hostname||"MK-ROUTER"}"

! ─── User management ───
/user
set admin password="${f.password||"[PASSWORD]"}"
add name=${f.username||"admin"} password="${f.password||"[PASSWORD]"}" group=full

! ─── Disable unused services ───
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set api disabled=yes
set api-ssl disabled=yes
set ssh port=22 disabled=no
set winbox port=8291 disabled=no

! ─── NTP ───
/system ntp client
set enabled=yes primary-ntp=${f.ntp_server||"216.239.35.0"}

/system clock
set time-zone-name=${f.timezone||"Europe/Kiev"}

! ─── Strong crypto for SSH ───
/ip ssh
set strong-crypto=yes`,
          },
          ntp:{
            label:"NTP",
            fields:[
              {id:"ntp_server",label:"NTP Server",         ph:"216.239.35.0"     },
              {id:"timezone",  label:"Timezone",           ph:"Europe/Kiev"      },
            ],
            generate: f => `/system ntp client
set enabled=yes primary-ntp=${f.ntp_server||"216.239.35.0"}

/system clock
set time-zone-name=${f.timezone||"Europe/Kiev"}`,
          },
        },
      },
      {
        label:"L2 – Switching",
        templates:{
          vlan:{
            label:"VLAN",
            fields:[
              {id:"vlan_id",   label:"VLAN ID",            ph:"10"               },
              {id:"vlan_name", label:"VLAN Name",           ph:"management"       },
              {id:"interface", label:"Parent Interface",    ph:"ether1"           },
              {id:"ip",        label:"IP Address",          ph:"192.168.10.1"     },
              {id:"prefix",    label:"Prefix Length",       ph:"24"               },
            ],
            generate: f => `/interface vlan
add name=vlan${f.vlan_id||"?"} vlan-id=${f.vlan_id||"?"} interface=${f.interface||"ether1"} comment="${f.vlan_name||"VLAN"}"

/ip address
add address=${f.ip||"x.x.x.x"}/${f.prefix||"24"} interface=vlan${f.vlan_id||"?"} comment="${f.vlan_name||"VLAN"} GW"`,
          },
          port_channel:{
            label:"LACP Bonding",
            fields:[
              {id:"bond_name", label:"Bond Name",           ph:"bond1"            },
              {id:"if1",       label:"Interface 1",         ph:"ether1"           },
              {id:"if2",       label:"Interface 2",         ph:"ether2"           },
              {id:"mode",      label:"Mode (802.3ad/balance-rr)",ph:"802.3ad"     },
              {id:"ip",        label:"IP Address/Prefix",   ph:"192.168.1.1/24"   },
              {id:"comment",   label:"Comment",             ph:"Uplink bond"      },
            ],
            generate: f => `/interface bonding
add name=${f.bond_name||"bond1"} slaves=${f.if1||"ether1"},${f.if2||"ether2"} \\
  mode=${f.mode||"802.3ad"} lacp-rate=fast comment="${f.comment||"LACP Bond"}"

/ip address
add address=${f.ip||"192.168.1.1/24"} interface=${f.bond_name||"bond1"}`,
          },
        },
      },
      {
        label:"L3 – Routing",
        templates:{
          static_route:{
            label:"Static Route",
            fields:[
              {id:"dst",       label:"Destination",         ph:"10.0.0.0/8"       },
              {id:"gateway",   label:"Gateway IP",          ph:"192.168.1.1"      },
              {id:"distance",  label:"Distance",            ph:"1"                },
              {id:"comment",   label:"Comment",             ph:"To HQ"            },
            ],
            generate: f => `/ip route
add dst-address=${f.dst||"0.0.0.0/0"} gateway=${f.gateway||"x.x.x.x"} distance=${f.distance||"1"} comment="${f.comment||"Static route"}"`,
          },
          bgp:{
            label:"BGP",
            fields:[
              {id:"local_as",  label:"Local AS",            ph:"65001"            },
              {id:"router_id", label:"Router ID",           ph:"1.1.1.1"          },
              {id:"peer_ip",   label:"Peer IP",             ph:"10.0.0.2"         },
              {id:"peer_as",   label:"Peer AS",             ph:"65002"            },
              {id:"network",   label:"Advertise Prefix",    ph:"192.168.1.0/24"   },
            ],
            generate: f => `/routing bgp instance
set default as=${f.local_as||"?"} router-id=${f.router_id||"x.x.x.x"}

/routing bgp peer
add remote-address=${f.peer_ip||"x.x.x.x"} remote-as=${f.peer_as||"?"} \\
  name=PEER-${f.peer_as||"?"} ttl=default

/routing bgp network
add network=${f.network||"x.x.x.x/24"} synchronize=no`,
          },
          nat:{
            label:"NAT Masquerade",
            fields:[
              {id:"out_if",    label:"WAN Interface",       ph:"ether1"           },
              {id:"src_network",label:"Source Network",     ph:"192.168.1.0/24"   },
              {id:"comment",   label:"Comment",             ph:"LAN-to-WAN"       },
            ],
            generate: f => `/ip firewall nat
add chain=srcnat out-interface=${f.out_if||"ether1"} src-address=${f.src_network||"192.168.1.0/24"} \\
  action=masquerade comment="${f.comment||"LAN-to-WAN"}"`,
          },
          dhcp:{
            label:"DHCP Server",
            fields:[
              {id:"pool_name", label:"Pool Name",           ph:"LAN-POOL"         },
              {id:"interface", label:"Interface",           ph:"bridge1"          },
              {id:"network",   label:"Network",             ph:"192.168.1.0/24"   },
              {id:"gateway",   label:"Gateway IP",          ph:"192.168.1.1"      },
              {id:"dns",       label:"DNS Servers",         ph:"8.8.8.8,8.8.4.4"  },
              {id:"lease",     label:"Lease Time",          ph:"7d"               },
              {id:"range_from",label:"Pool Range From",     ph:"192.168.1.50"     },
              {id:"range_to",  label:"Pool Range To",       ph:"192.168.1.200"    },
            ],
            generate: f => `/ip pool
add name=${f.pool_name||"LAN-POOL"} ranges=${f.range_from||"192.168.1.50"}-${f.range_to||"192.168.1.200"}

/ip dhcp-server
add name=dhcp-${f.interface||"bridge1"} interface=${f.interface||"bridge1"} \\
  address-pool=${f.pool_name||"LAN-POOL"} disabled=no lease-time=${f.lease||"7d"}

/ip dhcp-server network
add address=${f.network||"192.168.1.0/24"} gateway=${f.gateway||"192.168.1.1"} \\
  dns-server=${f.dns||"8.8.8.8,8.8.4.4"} comment="LAN DHCP Network"`,
          },
        },
      },
      {
        label:"Security",
        templates:{
          ipsec:{
            label:"IPsec VPN",
            fields:[
              {id:"peer_ip",   label:"Peer IP",             ph:"203.0.113.1"      },
              {id:"psk",       label:"Pre-Shared Key",      ph:"STRONG-PSK"       },
              {id:"local_net", label:"Local Network",       ph:"192.168.1.0/24"   },
              {id:"remote_net",label:"Remote Network",      ph:"10.10.10.0/24"    },
            ],
            generate: f => `/ip ipsec proposal
set [ find default=yes ] enc-algorithms=aes-256-cbc auth-algorithms=sha256

/ip ipsec peer
add address=${f.peer_ip||"x.x.x.x"}/32 auth-method=pre-shared-key \\
  secret="${f.psk||"[PSK]"}" enc-algorithm=aes-256 hash-algorithm=sha256 \\
  dh-group=modp2048 name=PEER-${f.peer_ip||"site2"}

/ip ipsec policy
add src-address=${f.local_net||"192.168.1.0/24"} dst-address=${f.remote_net||"10.10.10.0/24"} \\
  tunnel=yes action=encrypt peer=PEER-${f.peer_ip||"site2"} proposal=default`,
          },
          firewall:{
            label:"Firewall Rules",
            fields:[
              {id:"wan_if",    label:"WAN Interface",       ph:"ether1"           },
              {id:"lan_net",   label:"LAN Network",         ph:"192.168.1.0/24"   },
            ],
            generate: f => `/ip firewall filter
add chain=input connection-state=established,related action=accept comment="Allow established"
add chain=forward connection-state=established,related action=accept
add chain=input connection-state=invalid action=drop comment="Drop invalid"
add chain=forward connection-state=invalid action=drop
add chain=forward in-interface=!${f.wan_if||"ether1"} out-interface=${f.wan_if||"ether1"} \\
  src-address=${f.lan_net||"192.168.1.0/24"} action=accept comment="LAN to WAN"
add chain=input in-interface=${f.wan_if||"ether1"} action=drop comment="Drop WAN"`,
          },
        },
      },
    ],
  },

  ubiquiti: {
    label:"Ubiquiti EdgeOS", icon:"🟠",
    groups:[
      {
        label:"Базові налаштування",
        templates:{
          initial:{
            label:"Initial Setup",
            fields:[
              {id:"hostname",  label:"Hostname",            ph:"ER-CORE-01"       },
              {id:"username",  label:"Admin Username",      ph:"admin"            },
              {id:"password",  label:"Admin Password",      ph:"Str0ng-Passw0rd"  },
              {id:"timezone",  label:"Timezone",            ph:"Europe/Kiev"      },
              {id:"ntp_server",label:"NTP Server",          ph:"216.239.35.0"     },
              {id:"dns1",      label:"DNS Server 1",        ph:"8.8.8.8"          },
              {id:"dns2",      label:"DNS Server 2",        ph:"8.8.4.4"          },
            ],
            generate: f => `set system host-name '${f.hostname||"ER-CORE-01"}'
set system time-zone '${f.timezone||"Europe/Kiev"}'
!
set system ntp server ${f.ntp_server||"216.239.35.0"}
!
set system name-server ${f.dns1||"8.8.8.8"}
set system name-server ${f.dns2||"8.8.4.4"}
!
! ─── SSH only, disable telnet ───
set service ssh port 22
delete service telnet
!
! ─── GUI over HTTPS only ───
set service gui https-port 443
set service gui http-redirect enable
!
! ─── Admin user ───
set system login user ${f.username||"admin"} authentication plaintext-password '${f.password||"[PASSWORD]"}'
set system login user ${f.username||"admin"} level admin`,
          },
          ntp:{
            label:"NTP",
            fields:[
              {id:"ntp_server",label:"NTP Server",          ph:"216.239.35.0"     },
              {id:"timezone",  label:"Timezone",            ph:"Europe/Kiev"      },
            ],
            generate: f => `set system ntp server ${f.ntp_server||"216.239.35.0"}
set system time-zone '${f.timezone||"Europe/Kiev"}'`,
          },
        },
      },
      {
        label:"L2 – Switching",
        templates:{
          vlan:{
            label:"VLAN Interface",
            fields:[
              {id:"parent_if", label:"Parent Interface",    ph:"eth0"             },
              {id:"vlan_id",   label:"VLAN ID",             ph:"10"               },
              {id:"ip",        label:"IP/Prefix",           ph:"192.168.10.1/24"  },
              {id:"description",label:"Description",        ph:"Management"       },
            ],
            generate: f => `set interfaces ethernet ${f.parent_if||"eth0"} vif ${f.vlan_id||"?"} address '${f.ip||"x.x.x.x/24"}'
set interfaces ethernet ${f.parent_if||"eth0"} vif ${f.vlan_id||"?"} description '${f.description||"VLAN"}'`,
          },
          port_channel:{
            label:"LACP Bonding",
            fields:[
              {id:"bond_name", label:"Bond Interface Name",  ph:"bond0"            },
              {id:"if1",       label:"Interface 1",          ph:"eth1"             },
              {id:"if2",       label:"Interface 2",          ph:"eth2"             },
              {id:"ip",        label:"IP/Prefix",            ph:"192.168.1.1/24"   },
              {id:"description",label:"Description",         ph:"Uplink bond"      },
            ],
            generate: f => `set interfaces bonding ${f.bond_name||"bond0"} mode '802.3ad'
set interfaces bonding ${f.bond_name||"bond0"} lacp-rate 'fast'
set interfaces bonding ${f.bond_name||"bond0"} member interface '${f.if1||"eth1"}'
set interfaces bonding ${f.bond_name||"bond0"} member interface '${f.if2||"eth2"}'
set interfaces bonding ${f.bond_name||"bond0"} address '${f.ip||"192.168.1.1/24"}'
set interfaces bonding ${f.bond_name||"bond0"} description '${f.description||"LACP Bond"}'`,
          },
        },
      },
      {
        label:"L3 – Routing",
        templates:{
          static_route:{
            label:"Static Route",
            fields:[
              {id:"dst",       label:"Destination",         ph:"10.0.0.0/8"       },
              {id:"next_hop",  label:"Next Hop",            ph:"192.168.1.1"      },
              {id:"description",label:"Description",        ph:"To HQ"            },
            ],
            generate: f => `set protocols static route ${f.dst||"0.0.0.0/0"} next-hop ${f.next_hop||"x.x.x.x"}
set protocols static route ${f.dst||"0.0.0.0/0"} description '${f.description||"Static route"}'`,
          },
          bgp:{
            label:"BGP",
            fields:[
              {id:"local_as",  label:"Local AS",            ph:"65001"            },
              {id:"neighbor_ip",label:"Neighbor IP",        ph:"10.0.0.2"         },
              {id:"remote_as", label:"Remote AS",           ph:"65002"            },
              {id:"network",   label:"Advertise Network",   ph:"192.168.1.0/24"   },
            ],
            generate: f => `set protocols bgp ${f.local_as||"?"} neighbor ${f.neighbor_ip||"x.x.x.x"} remote-as '${f.remote_as||"?"}'
set protocols bgp ${f.local_as||"?"} neighbor ${f.neighbor_ip||"x.x.x.x"} soft-reconfiguration inbound
set protocols bgp ${f.local_as||"?"} network ${f.network||"192.168.1.0/24"}`,
          },
          ospf:{
            label:"OSPF",
            fields:[
              {id:"router_id", label:"Router ID",           ph:"1.1.1.1"          },
              {id:"network",   label:"Network/Prefix",      ph:"192.168.1.0/24"   },
              {id:"area",      label:"Area",                ph:"0.0.0.0"          },
            ],
            generate: f => `set protocols ospf parameters router-id '${f.router_id||"1.1.1.1"}'
set protocols ospf area ${f.area||"0.0.0.0"} network '${f.network||"192.168.1.0/24"}'
set protocols ospf auto-cost reference-bandwidth '10000'`,
          },
          nat:{
            label:"NAT Masquerade",
            fields:[
              {id:"out_if",    label:"Outbound Interface",  ph:"eth0"             },
              {id:"src_net",   label:"Source Network",      ph:"192.168.1.0/24"   },
              {id:"rule_num",  label:"Rule Number",         ph:"5010"             },
            ],
            generate: f => `set service nat rule ${f.rule_num||"5010"} outbound-interface '${f.out_if||"eth0"}'
set service nat rule ${f.rule_num||"5010"} source address '${f.src_net||"192.168.1.0/24"}'
set service nat rule ${f.rule_num||"5010"} type masquerade
set service nat rule ${f.rule_num||"5010"} description 'LAN Masquerade'`,
          },
          dhcp:{
            label:"DHCP Server",
            fields:[
              {id:"pool_name", label:"Pool Name",           ph:"LAN-POOL"         },
              {id:"subnet",    label:"Subnet",              ph:"192.168.1.0/24"   },
              {id:"gateway",   label:"Default Gateway",     ph:"192.168.1.1"      },
              {id:"dns1",      label:"DNS Server 1",        ph:"8.8.8.8"          },
              {id:"dns2",      label:"DNS Server 2",        ph:"8.8.4.4"          },
              {id:"range_from",label:"Range From",          ph:"192.168.1.50"     },
              {id:"range_to",  label:"Range To",            ph:"192.168.1.200"    },
              {id:"lease",     label:"Lease (seconds)",     ph:"86400"            },
            ],
            generate: f => `set service dhcp-server shared-network-name '${f.pool_name||"LAN-POOL"}' subnet ${f.subnet||"192.168.1.0/24"} default-router '${f.gateway||"192.168.1.1"}'
set service dhcp-server shared-network-name '${f.pool_name||"LAN-POOL"}' subnet ${f.subnet||"192.168.1.0/24"} dns-server '${f.dns1||"8.8.8.8"}'
set service dhcp-server shared-network-name '${f.pool_name||"LAN-POOL"}' subnet ${f.subnet||"192.168.1.0/24"} dns-server '${f.dns2||"8.8.4.4"}'
set service dhcp-server shared-network-name '${f.pool_name||"LAN-POOL"}' subnet ${f.subnet||"192.168.1.0/24"} start '${f.range_from||"192.168.1.50"}' stop '${f.range_to||"192.168.1.200"}'
set service dhcp-server shared-network-name '${f.pool_name||"LAN-POOL"}' subnet ${f.subnet||"192.168.1.0/24"} lease '${f.lease||"86400"}'`,
          },
        },
      },
      {
        label:"Security",
        templates:{
          ipsec:{
            label:"IPsec VPN",
            fields:[
              {id:"peer_ip",   label:"Peer IP",             ph:"203.0.113.1"      },
              {id:"psk",       label:"Pre-Shared Key",      ph:"STRONG-PSK"       },
              {id:"local_net", label:"Local Network",       ph:"192.168.1.0/24"   },
              {id:"remote_net",label:"Remote Network",      ph:"10.10.10.0/24"    },
              {id:"outside_if",label:"Outside Interface",   ph:"eth0"             },
            ],
            generate: f => `! ─── IKE Group ───
set vpn ipsec ike-group IKE-GROUP proposal 1 encryption aes256
set vpn ipsec ike-group IKE-GROUP proposal 1 hash sha256
set vpn ipsec ike-group IKE-GROUP proposal 1 dh-group 14
set vpn ipsec ike-group IKE-GROUP lifetime 86400
!
! ─── ESP Group ───
set vpn ipsec esp-group ESP-GROUP proposal 1 encryption aes256
set vpn ipsec esp-group ESP-GROUP proposal 1 hash sha256
set vpn ipsec esp-group ESP-GROUP pfs dh-group14
set vpn ipsec esp-group ESP-GROUP lifetime 3600
!
! ─── Site-to-Site ───
set vpn ipsec site-to-site peer ${f.peer_ip||"x.x.x.x"} authentication mode pre-shared-secret
set vpn ipsec site-to-site peer ${f.peer_ip||"x.x.x.x"} authentication pre-shared-secret '${f.psk||"[PSK]"}'
set vpn ipsec site-to-site peer ${f.peer_ip||"x.x.x.x"} ike-group IKE-GROUP
set vpn ipsec site-to-site peer ${f.peer_ip||"x.x.x.x"} local-address ${f.outside_if||"eth0"}
set vpn ipsec site-to-site peer ${f.peer_ip||"x.x.x.x"} tunnel 1 esp-group ESP-GROUP
set vpn ipsec site-to-site peer ${f.peer_ip||"x.x.x.x"} tunnel 1 local prefix ${f.local_net||"192.168.1.0/24"}
set vpn ipsec site-to-site peer ${f.peer_ip||"x.x.x.x"} tunnel 1 remote prefix ${f.remote_net||"10.10.10.0/24"}`,
          },
          firewall:{
            label:"Firewall Rules",
            fields:[
              {id:"ruleset_name",label:"Ruleset Name",      ph:"WAN-IN"           },
              {id:"wan_if",    label:"WAN Interface",       ph:"eth0"             },
              {id:"direction", label:"Direction (in/out/local)",ph:"in"           },
            ],
            generate: f => `set firewall name ${f.ruleset_name||"WAN-IN"} default-action drop
set firewall name ${f.ruleset_name||"WAN-IN"} description 'WAN inbound traffic'
!
set firewall name ${f.ruleset_name||"WAN-IN"} rule 10 action accept
set firewall name ${f.ruleset_name||"WAN-IN"} rule 10 state established enable
set firewall name ${f.ruleset_name||"WAN-IN"} rule 10 state related enable
set firewall name ${f.ruleset_name||"WAN-IN"} rule 10 description 'Allow established/related'
!
set firewall name ${f.ruleset_name||"WAN-IN"} rule 20 action drop
set firewall name ${f.ruleset_name||"WAN-IN"} rule 20 state invalid enable
set firewall name ${f.ruleset_name||"WAN-IN"} rule 20 description 'Drop invalid'
!
set interfaces ethernet ${f.wan_if||"eth0"} firewall ${f.direction||"in"} name '${f.ruleset_name||"WAN-IN"}'`,
          },
        },
      },
    ],
  },
};

// ─── ACL Wizard ───────────────────────────────────────────────────────────────
function ACLWizard() {
  const init = () => { const s={}; ACL_SERVICES.forEach(v=>{s[v.id]=v.def?"permit":"deny";}); return s; };
  const [services,  setServices]  = useState(init);
  const [aclType,   setAclType]   = useState("extended"); // "standard" | "extended"
  const [aclName,   setAclName]   = useState("CORP-POLICY");
  const [srcNet,    setSrcNet]    = useState("192.168.1.0");
  const [srcWild,   setSrcWild]   = useState("0.0.0.255");
  const [srcAny,    setSrcAny]    = useState(false);
  const [dstNet,    setDstNet]    = useState("10.0.0.0");
  const [dstWild,   setDstWild]   = useState("0.255.255.255");
  const [dstAny,    setDstAny]    = useState(true);
  const [iface,     setIface]     = useState("GigabitEthernet0/1");
  const [dir,       setDir]       = useState("in");
  const [copied,    setCopied]    = useState(false);

  const toggle = id => setServices(p=>({...p,[id]:p[id]==="permit"?"deny":"permit"}));

  // Standard ACL: номери 1–99 та 1300–1999; Extended: 100–199 та 2000–2699
  const aclTypeInfo = {
    standard: { label:"Standard ACL", range:"(1–99, 1300–1999)", note:"Фільтрує тільки за source IP. Без port/protocol." },
    extended: { label:"Extended ACL", range:"(100–199, 2000–2699)", note:"Фільтрує за src/dst IP, протоколом та портом." },
  };

  const srcStr = srcAny ? "any" : `${srcNet||"x.x.x.x"} ${srcWild||"0.0.0.255"}`;
  const dstStr = dstAny ? "any" : `${dstNet||"x.x.x.x"} ${dstWild||"0.0.0.255"}`;

  const generateACL = () => {
    const lines = [];
    if (aclType === "standard") {
      lines.push(`! ─── Standard ACL: ${aclName} ─── ${aclTypeInfo.standard.range}`);
      lines.push(`! Увага: Standard ACL фільтрує ТІЛЬКИ за source IP`);
      lines.push(`ip access-list standard ${aclName}`);
      ACL_SERVICES.filter(s=>services[s.id]==="permit").forEach(s=>{
        lines.push(` permit ${srcStr}  ! ${s.label}`);
      });
      lines.push(` deny   ${srcStr} log`);
      lines.push(` deny   any log`);
      lines.push(`!`);
      lines.push(`interface ${iface||"GigabitEthernet0/1"}`);
      lines.push(` ip access-group ${aclName} ${dir}`);
    } else {
      const permits = ACL_SERVICES.filter(s=>services[s.id]==="permit");
      const denies  = ACL_SERVICES.filter(s=>services[s.id]==="deny");
      lines.push(`! ─── Extended ACL: ${aclName} ─── ${aclTypeInfo.extended.range}`);
      lines.push(`ip access-list extended ${aclName}`);
      lines.push(` permit tcp ${srcStr} ${dstStr} established  ! Return traffic`);
      lines.push(` !`);
      if(permits.length){
        lines.push(` ! ── PERMITTED ──`);
        permits.forEach(s=>{
          if(s.proto==="icmp") lines.push(` permit icmp ${srcStr} ${dstStr}  ! ${s.label}`);
          else lines.push(` permit ${s.proto} ${srcStr} ${dstStr} eq ${s.port}  ! ${s.label} :${s.port}`);
        });
        lines.push(` !`);
      }
      if(denies.length){
        lines.push(` ! ── DENIED ──`);
        denies.forEach(s=>{
          if(s.proto==="icmp") lines.push(` deny   icmp ${srcStr} ${dstStr} log  ! ${s.label}`);
          else lines.push(` deny   ${s.proto} ${srcStr} ${dstStr} eq ${s.port} log  ! ${s.label} :${s.port}`);
        });
        lines.push(` !`);
      }
      lines.push(` deny   ip ${srcStr} ${dstStr} log  ! Implicit deny all`);
      lines.push(`!`);
      lines.push(`interface ${iface||"GigabitEthernet0/1"}`);
      lines.push(` ip access-group ${aclName} ${dir}`);
    }
    return lines.join("\n");
  };

  const config=generateACL();
  const copy=()=>{navigator.clipboard.writeText(config);setCopied(true);setTimeout(()=>setCopied(false),2000);};

  const inpStyle={width:"100%",boxSizing:"border-box",background:T.surface2,border:`1px solid ${T.border}`,borderRadius:6,padding:"7px 10px",color:T.text,fontFamily:T.mono,fontSize:12,outline:"none"};
  const selStyle={...inpStyle,cursor:"pointer"};

  // Helper: "any" checkbox + net/wildcard inputs
  const NetRow=({label,net,setNet,wild,setWild,isAny,setIsAny})=>(
    <div style={{display:"flex",flexDirection:"column",gap:4}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
        <label style={{color:T.textMuted,fontSize:10,letterSpacing:1,fontFamily:T.mono}}>{label}</label>
        <label style={{display:"flex",alignItems:"center",gap:5,cursor:"pointer",userSelect:"none"}}>
          <div onClick={()=>setIsAny(p=>!p)}
            style={{width:28,height:15,borderRadius:8,background:isAny?T.accent:T.border2,display:"flex",alignItems:"center",padding:"0 2px",transition:"background 0.2s",flexShrink:0}}>
            <div style={{width:11,height:11,borderRadius:"50%",background:"white",transform:isAny?"translateX(13px)":"translateX(0)",transition:"transform 0.2s"}}/>
          </div>
          <span style={{fontFamily:T.mono,fontSize:10,color:isAny?T.accent:T.textMuted}}>any</span>
        </label>
      </div>
      {!isAny&&(
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
          <input value={net} onChange={e=>setNet(e.target.value)} placeholder="192.168.1.0" style={inpStyle}/>
          <input value={wild} onChange={e=>setWild(e.target.value)} placeholder="0.0.0.255" style={inpStyle}/>
        </div>
      )}
      {isAny&&<div style={{padding:"7px 10px",background:T.accentBg,borderRadius:6,fontFamily:T.mono,fontSize:12,color:T.accent}}>any</div>}
    </div>
  );

  return (
    <div style={{display:"flex",flexDirection:"column",gap:14}}>
      {/* Top settings panel */}
      <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:10,padding:18}}>
        <div style={{color:T.textSub,fontFamily:T.mono,fontSize:10,letterSpacing:2,marginBottom:14}}>ACL WIZARD — CISCO IOS</div>

        {/* ACL Type selector */}
        <div style={{marginBottom:14}}>
          <div style={{color:T.textMuted,fontSize:10,letterSpacing:1,fontFamily:T.mono,marginBottom:8}}>TИП ACL</div>
          <div style={{display:"flex",gap:8}}>
            {Object.entries(aclTypeInfo).map(([key,info])=>(
              <div key={key} onClick={()=>setAclType(key)}
                style={{flex:1,padding:"10px 14px",borderRadius:8,cursor:"pointer",border:`1.5px solid ${aclType===key?T.accent:T.border}`,
                  background:aclType===key?T.accentBg:T.surface2,transition:"all 0.15s"}}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                  <div style={{width:14,height:14,borderRadius:"50%",border:`2px solid ${aclType===key?T.accent:T.border2}`,
                    background:aclType===key?T.accent:"transparent",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
                    {aclType===key&&<div style={{width:5,height:5,borderRadius:"50%",background:"white"}}/>}
                  </div>
                  <span style={{fontFamily:T.mono,fontSize:11,fontWeight:700,color:aclType===key?T.accent:T.text}}>{info.label}</span>
                  <span style={{fontFamily:T.mono,fontSize:9,color:T.textMuted}}>{info.range}</span>
                </div>
                <div style={{fontSize:10,color:T.textMuted,paddingLeft:22}}>{info.note}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Fields row */}
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:12,alignItems:"start"}}>
          <div>
            <label style={{display:"block",color:T.textMuted,fontSize:10,letterSpacing:1,fontFamily:T.mono,marginBottom:4}}>ACL NAME</label>
            <input value={aclName} onChange={e=>setAclName(e.target.value)} placeholder="CORP-POLICY" style={inpStyle}/>
          </div>
          <NetRow label="SOURCE" net={srcNet} setNet={setSrcNet} wild={srcWild} setWild={setSrcWild} isAny={srcAny} setIsAny={setSrcAny}/>
          {aclType==="extended"&&(
            <NetRow label="DESTINATION" net={dstNet} setNet={setDstNet} wild={dstWild} setWild={setDstWild} isAny={dstAny} setIsAny={setDstAny}/>
          )}
          <div>
            <label style={{display:"block",color:T.textMuted,fontSize:10,letterSpacing:1,fontFamily:T.mono,marginBottom:4}}>INTERFACE</label>
            <input value={iface} onChange={e=>setIface(e.target.value)} placeholder="GigabitEthernet0/1" style={inpStyle}/>
            <div style={{marginTop:6}}>
              <label style={{display:"block",color:T.textMuted,fontSize:10,letterSpacing:1,fontFamily:T.mono,marginBottom:4}}>DIRECTION</label>
              <select value={dir} onChange={e=>setDir(e.target.value)} style={selStyle}>
                <option value="in">in — фільтр вхідного трафіку</option>
                <option value="out">out — фільтр вихідного трафіку</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Services + Output */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
        <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:10,padding:14}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
            <div style={{color:T.textSub,fontSize:10,letterSpacing:1.5,fontFamily:T.mono}}>СЕРВІСИ — PERMIT / DENY</div>
            {aclType==="standard"&&(
              <div style={{background:"#fff8e1",border:"1px solid #f5d76e",borderRadius:5,padding:"2px 8px",fontSize:9,fontFamily:T.mono,color:"#7a6000"}}>
                Standard: тільки src IP
              </div>
            )}
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:5}}>
            {ACL_SERVICES.map(svc=>{
              const ok=services[svc.id]==="permit";
              const disabled=aclType==="standard"&&svc.proto!=="tcp"&&svc.proto!=="icmp";
              return (
                <div key={svc.id} onClick={()=>!disabled&&toggle(svc.id)}
                  style={{display:"flex",alignItems:"center",gap:10,padding:"6px 10px",borderRadius:7,
                    cursor:disabled?"default":"pointer",opacity:disabled?0.4:1,
                    background:ok?T.greenBg:T.redBg,border:`1px solid ${ok?"#9dd6b8":"#f5b8b3"}`,transition:"all 0.15s"}}>
                  <div style={{width:30,height:16,borderRadius:8,background:ok?T.green:"#d9534f",display:"flex",alignItems:"center",padding:"0 2px",flexShrink:0,transition:"background 0.2s"}}>
                    <div style={{width:12,height:12,borderRadius:"50%",background:"white",transform:ok?"translateX(14px)":"translateX(0)",transition:"transform 0.2s"}}/>
                  </div>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:"flex",gap:6,alignItems:"baseline"}}>
                      <span style={{fontFamily:T.mono,fontSize:11,fontWeight:600,color:T.text}}>{svc.label}</span>
                      {svc.port&&<span style={{fontFamily:T.mono,fontSize:9,color:T.textMuted}}>:{svc.port}/{svc.proto}</span>}
                    </div>
                    <div style={{fontSize:9,color:T.textMuted}}>{svc.desc}</div>
                  </div>
                  <span style={{fontFamily:T.mono,fontSize:9,fontWeight:700,color:ok?T.green:"#c0392b",width:38,textAlign:"right",flexShrink:0}}>
                    {ok?"PERMIT":"DENY"}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        <div style={{background:T.codeBg,border:`1px solid ${T.border}`,borderRadius:10,overflow:"hidden",display:"flex",flexDirection:"column"}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"9px 14px",borderBottom:`1px solid ${T.border}`,background:T.surface}}>
            <span style={{fontFamily:T.mono,fontSize:10,color:T.textMuted}}>
              {aclType==="extended"?"Extended":"Standard"} ACL · {aclName} · {dir}
            </span>
            <button onClick={copy} style={{background:copied?T.greenBg:"transparent",border:`1px solid ${copied?T.green:T.border}`,color:copied?T.green:T.textSub,borderRadius:5,padding:"3px 10px",fontFamily:T.mono,fontSize:10,cursor:"pointer"}}>
              {copied?"COPIED ✓":"COPY"}
            </button>
          </div>
          <div style={{padding:14,fontFamily:T.mono,fontSize:11,lineHeight:1.8,overflowY:"auto",flex:1}}>
            {config.split("\n").map((line,i)=><div key={i} style={{minHeight:"1.5em"}}><HL line={line}/></div>)}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Subnet Calculator ────────────────────────────────────────────────────────
function SubnetCalculator() {
  const [ip,setIp]=useState("192.168.1.0");
  const [cidr,setCidr]=useState(24);
  const [result,setResult]=useState(null);
  const [error,setError]=useState("");
  const [splitCount,setSplitCount]=useState(4);
  const [showSplit,setShowSplit]=useState(false);

  const validate=s=>/^(\d{1,3}\.){3}\d{1,3}$/.test(s)&&s.split(".").every(o=>parseInt(o)<=255);
  const calc=()=>{
    if(!validate(ip)){setError("Невірний формат IP-адреси");setResult(null);return;}
    setError("");setResult(calcSubnet(ip,parseInt(cidr)));setShowSplit(false);
  };
  const subnets=result&&showSplit?(()=>{
    const nc=parseInt(cidr)+Math.ceil(Math.log2(splitCount));
    if(nc>30)return[];
    const size=Math.pow(2,32-nc),base=ipToInt(result.network);
    return Array.from({length:Math.min(splitCount,Math.pow(2,nc-parseInt(cidr)))},(_,i)=>calcSubnet(intToIp((base+i*size)>>>0),nc));
  })():[];

  const inp={width:"100%",boxSizing:"border-box",background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,padding:"9px 12px",color:T.text,fontFamily:T.mono,fontSize:13,outline:"none"};
  return (
    <div style={{display:"flex",flexDirection:"column",gap:18}}>
      <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:10,padding:20}}>
        <div style={{color:T.textSub,fontFamily:T.mono,fontSize:10,marginBottom:14,letterSpacing:2}}>SUBNET CALCULATOR</div>
        <div style={{display:"flex",gap:10,flexWrap:"wrap",alignItems:"flex-end"}}>
          <div style={{flex:"1 1 180px"}}>
            <label style={{display:"block",color:T.textMuted,fontSize:10,marginBottom:5,fontFamily:T.mono,letterSpacing:1}}>IP ADDRESS</label>
            <input value={ip} onChange={e=>setIp(e.target.value)} onKeyDown={e=>e.key==="Enter"&&calc()} placeholder="192.168.1.0" style={inp}/>
          </div>
          <div style={{flex:"0 0 100px"}}>
            <label style={{display:"block",color:T.textMuted,fontSize:10,marginBottom:5,fontFamily:T.mono,letterSpacing:1}}>CIDR</label>
            <div style={{display:"flex",alignItems:"center",gap:5}}>
              <span style={{color:T.accent,fontFamily:T.mono,fontSize:18,fontWeight:700}}>/</span>
              <input type="number" min={1} max={32} value={cidr} onChange={e=>setCidr(e.target.value)} onKeyDown={e=>e.key==="Enter"&&calc()} style={{...inp,flex:1}}/>
            </div>
          </div>
          <button onClick={calc} style={{flex:"0 0 auto",background:T.accent,color:"white",border:"none",borderRadius:6,padding:"10px 20px",fontFamily:T.mono,fontWeight:700,fontSize:12,cursor:"pointer",letterSpacing:1}}>CALCULATE</button>
        </div>
        {error&&<div style={{color:T.red,fontFamily:T.mono,fontSize:12,marginTop:8}}>{error}</div>}
      </div>
      {result&&(<>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(185px,1fr))",gap:10}}>
          {[{l:"Network Address",v:result.network,ac:true},{l:"Broadcast",v:result.broadcast},{l:"Subnet Mask",v:result.mask},{l:"Wildcard Mask",v:result.wildcard},{l:"First Host",v:result.firstHost},{l:"Last Host",v:result.lastHost},{l:"Total Hosts",v:result.hostCount.toLocaleString()},{l:"IP Class",v:result.ipClass}].map(({l,v,ac})=>(
            <div key={l} style={{background:ac?T.accentBg:T.surface,border:`1px solid ${ac?T.accentLt:T.border}`,borderRadius:8,padding:"12px 14px"}}>
              <div style={{color:T.textMuted,fontSize:10,letterSpacing:1.5,fontFamily:T.mono,marginBottom:4}}>{l.toUpperCase()}</div>
              <div style={{color:ac?T.accent:T.text,fontFamily:T.mono,fontSize:13,fontWeight:ac?700:400}}>{v}</div>
            </div>
          ))}
        </div>
        <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:8,padding:"12px 16px"}}>
          <div style={{color:T.textMuted,fontSize:10,letterSpacing:1.5,fontFamily:T.mono,marginBottom:7}}>BINARY MASK</div>
          <div style={{fontFamily:T.mono,fontSize:12,letterSpacing:1.5}}>
            {result.binaryMask.split(".").map((oct,i)=>(
              <span key={i}>{i>0&&<span style={{color:T.border2}}>.</span>}
                {oct.split("").map((b,j)=><span key={j} style={{color:b==="1"?T.accent:T.textMuted}}>{b}</span>)}
              </span>
            ))}
          </div>
        </div>
        <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:8,padding:"12px 16px"}}>
          <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
            <span style={{color:T.textMuted,fontSize:10,fontFamily:T.mono}}>РОЗБИТИ НА</span>
            <select value={splitCount} onChange={e=>{setSplitCount(Number(e.target.value));setShowSplit(false);}}
              style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:6,padding:"5px 8px",color:T.text,fontFamily:T.mono,fontSize:12}}>
              {[2,4,8,16].map(n=><option key={n} value={n}>{n} підмереж</option>)}
            </select>
            <button onClick={()=>setShowSplit(true)} style={{background:T.accentBg,border:`1px solid ${T.accentLt}`,color:T.accent,borderRadius:6,padding:"5px 14px",fontFamily:T.mono,fontSize:11,cursor:"pointer",fontWeight:600}}>SPLIT</button>
          </div>
          {showSplit&&subnets.length>0&&(
            <div style={{marginTop:10,display:"flex",flexDirection:"column",gap:5}}>
              {subnets.map((s,i)=>(
                <div key={i} style={{display:"flex",gap:12,alignItems:"center",padding:"6px 10px",background:T.surface2,borderRadius:6}}>
                  <span style={{color:T.accent,fontFamily:T.mono,fontSize:10,minWidth:22}}>#{i+1}</span>
                  <span style={{color:T.text,fontFamily:T.mono,fontSize:12}}>{s.network}/{s.cidr}</span>
                  <span style={{color:T.textSub,fontFamily:T.mono,fontSize:11}}>{s.firstHost} – {s.lastHost}</span>
                  <span style={{color:T.textMuted,fontFamily:T.mono,fontSize:10,marginLeft:"auto"}}>{s.hostCount} hosts</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </>)}
    </div>
  );
}

// ─── Config Builder (sidebar) ─────────────────────────────────────────────────
function ConfigBuilder() {
  const [vendorKey,  setVendorKey]  = useState("cisco_ios");
  const [groupIdx,   setGroupIdx]   = useState(0);
  const [templateKey,setTemplateKey]= useState("initial");
  const [fields,     setFields]     = useState({});
  const [copied,     setCopied]     = useState(false);
  const [expanded,   setExpanded]   = useState({0:true});

  const vendor   = VENDORS[vendorKey];
  let   template = null;
  vendor.groups.forEach(g=>{if(g.templates[templateKey]) template=g.templates[templateKey];});

  const selectTemplate=(gIdx,tKey)=>{setGroupIdx(gIdx);setTemplateKey(tKey);setFields({});setCopied(false);};
  const toggleGroup=(i)=>setExpanded(p=>({...p,[i]:!p[i]}));

  const changeVendor=(vk)=>{
    setVendorKey(vk);
    const firstTk=Object.keys(VENDORS[vk].groups[0].templates)[0];
    setGroupIdx(0);setTemplateKey(firstTk);setFields({});setCopied(false);
    setExpanded({0:true});
  };

  const config=template?template.generate(fields):"";
  const copy=()=>{navigator.clipboard.writeText(config);setCopied(true);setTimeout(()=>setCopied(false),2000);};

  return (
    <div style={{display:"flex",gap:0,minHeight:520,border:`1px solid ${T.border}`,borderRadius:12,overflow:"hidden"}}>
      {/* Sidebar */}
      <div style={{width:220,flexShrink:0,background:T.surface2,borderRight:`1px solid ${T.border}`,display:"flex",flexDirection:"column"}}>
        {/* Vendor tabs */}
        <div style={{display:"flex",borderBottom:`1px solid ${T.border}`}}>
          {Object.entries(VENDORS).map(([key,v])=>(
            <button key={key} onClick={()=>changeVendor(key)}
              style={{flex:1,padding:"10px 4px",background:vendorKey===key?T.surface:"transparent",border:"none",
                borderBottom:vendorKey===key?`2px solid ${T.accent}`:"2px solid transparent",
                cursor:"pointer",fontFamily:T.mono,fontSize:10,color:vendorKey===key?T.accent:T.textMuted,
                fontWeight:vendorKey===key?700:400,lineHeight:1.3,textAlign:"center"}}>
              <div style={{fontSize:14}}>{v.icon}</div>
              <div style={{fontSize:9,marginTop:2}}>{v.label.split(" ")[0]}</div>
            </button>
          ))}
        </div>
        {/* Groups + templates */}
        <div style={{overflowY:"auto",flex:1,padding:"6px 0"}}>
          {vendor.groups.map((g,gi)=>(
            <div key={gi}>
              <div onClick={()=>toggleGroup(gi)}
                style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"8px 14px",cursor:"pointer",userSelect:"none"}}>
                <span style={{fontFamily:T.mono,fontSize:10,fontWeight:700,color:T.textSub,letterSpacing:0.5}}>{g.label.toUpperCase()}</span>
                <span style={{color:T.textMuted,fontSize:11,transform:expanded[gi]?"rotate(90deg)":"rotate(0deg)",transition:"transform 0.2s",display:"inline-block"}}>▶</span>
              </div>
              {expanded[gi]&&Object.entries(g.templates).map(([tk,t])=>{
                const active=templateKey===tk;
                return (
                  <div key={tk} onClick={()=>selectTemplate(gi,tk)}
                    style={{padding:"7px 16px 7px 20px",cursor:"pointer",
                      background:active?T.accentBg:"transparent",
                      borderLeft:active?`3px solid ${T.accent}`:"3px solid transparent",
                      color:active?T.accent:T.textSub,fontFamily:T.sans,fontSize:12,
                      fontWeight:active?600:400,transition:"all 0.15s"}}>
                    {t.label}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Main area */}
      <div style={{flex:1,display:"flex",flexDirection:"column",minWidth:0}}>
        {/* Template header */}
        <div style={{padding:"14px 18px",borderBottom:`1px solid ${T.border}`,background:T.surface,display:"flex",alignItems:"center",gap:10}}>
          <span style={{fontSize:16}}>{vendor.icon}</span>
          <div>
            <div style={{fontFamily:T.sans,fontSize:13,fontWeight:600,color:T.text}}>{template?.label||"Оберіть шаблон"}</div>
            <div style={{fontFamily:T.mono,fontSize:10,color:T.textMuted}}>{vendor.label}</div>
          </div>
        </div>

        <div style={{flex:1,display:"grid",gridTemplateColumns:"1fr 1fr",overflow:"hidden"}}>
          {/* Fields */}
          <div style={{padding:16,overflowY:"auto",borderRight:`1px solid ${T.border}`,display:"flex",flexDirection:"column",gap:11}}>
            <div style={{color:T.textSub,fontFamily:T.mono,fontSize:10,letterSpacing:1.5}}>ПАРАМЕТРИ</div>
            {template?.fields.map(f=>(
              <div key={f.id}>
                <label style={{display:"block",color:T.textMuted,fontSize:10,letterSpacing:0.8,fontFamily:T.mono,marginBottom:4}}>{f.label.toUpperCase()}</label>
                <input type={f.type||"text"} value={fields[f.id]||""} placeholder={f.ph}
                  onChange={e=>setFields(p=>({...p,[f.id]:e.target.value}))}
                  style={{width:"100%",boxSizing:"border-box",background:T.surface2,border:`1px solid ${T.border}`,borderRadius:6,padding:"8px 10px",color:T.text,fontFamily:T.mono,fontSize:12,outline:"none"}}/>
              </div>
            ))}
            {template&&<button onClick={()=>setFields({})} style={{marginTop:4,background:"transparent",border:`1px solid ${T.border}`,color:T.textMuted,borderRadius:6,padding:"6px 0",fontFamily:T.mono,fontSize:10,cursor:"pointer"}}>CLEAR</button>}
          </div>

          {/* Output */}
          <div style={{display:"flex",flexDirection:"column",overflow:"hidden"}}>
            <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"9px 14px",borderBottom:`1px solid ${T.border}`,background:T.surface,flexShrink:0}}>
              <div style={{display:"flex",gap:5}}>
                {["#f85149","#e3b341","#3fb950"].map(c=><div key={c} style={{width:9,height:9,borderRadius:"50%",background:c,opacity:0.6}}/>)}
              </div>
              <button onClick={copy} style={{background:copied?T.greenBg:"transparent",border:`1px solid ${copied?T.green:T.border}`,color:copied?T.green:T.textSub,borderRadius:5,padding:"3px 10px",fontFamily:T.mono,fontSize:10,cursor:"pointer"}}>
                {copied?"COPIED ✓":"COPY"}
              </button>
            </div>
            <div style={{padding:14,fontFamily:T.mono,fontSize:11.5,lineHeight:1.8,overflowY:"auto",flex:1,background:T.codeBg}}>
              {config.split("\n").map((line,i)=><div key={i} style={{minHeight:"1.6em"}}><HL line={line}/></div>)}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Subnetty AI Assistant ────────────────────────────────────────────────────
const SUBNETTY_SYSTEM = `You are Subnetty — a friendly, expert AI assistant for network engineers. 
You specialize in: Cisco IOS, MikroTik RouterOS, Ubiquiti EdgeOS, VLANs, OSPF, BGP, IPsec VPNs, 
NAT/PAT, ACLs, STP/RSTP, LACP/Port-Channel, DHCP, NTP, SSH hardening, Zone-Based Firewalls, 
subnetting, IP addressing, network design, and cybersecurity fundamentals relevant to network engineers.

When asked to generate configs: always output clean, production-ready CLI configuration with comments.
When explaining concepts: be concise but thorough. Use examples with real IP addresses when helpful.
Format code blocks with proper indentation. 
If someone asks about subnetting math — show the calculation step by step.
Respond in the same language the user writes in (Ukrainian or English).
Keep responses focused and practical — this is a tool used by working engineers.`;

const QUICK_PROMPTS = [
  { label:"Що таке OSPF DR/BDR?",       text:"Поясни коротко що таке OSPF DR та BDR вибори і навіщо вони потрібні." },
  { label:"BGP iBGP vs eBGP",            text:"В чому різниця між iBGP та eBGP? Коли використовувати кожен?" },
  { label:"Як працює STP?",              text:"Поясни як працює Spanning Tree Protocol і чому він потрібен." },
  { label:"IPsec фази IKE",              text:"Поясни фази IKE в IPsec VPN: що відбувається в Phase 1 та Phase 2?" },
  { label:"VLAN vs підмережа",           text:"В чому різниця між VLAN та IP-підмережею? Коли вони збігаються?" },
  { label:"Розрахувати /26",             text:"Порахуй підмережу 192.168.10.0/26: маска, wildcard, broadcast, кількість хостів." },
  { label:"ACL Standard vs Extended",   text:"Поясни різницю між Standard ACL та Extended ACL на Cisco IOS з прикладами." },
  { label:"Що таке ZPF?",               text:"Що таке Zone-Based Policy Firewall і чим він кращий за класичний ACL?" },
];

function Subnetty() {
  const [messages,  setMessages]  = useState([]);
  const [input,     setInput]     = useState("");
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState("");
  const bottomRef = { current: null };

  const scrollToBottom = () => {
    setTimeout(() => {
      const el = document.getElementById("subnetty-bottom");
      if (el) el.scrollIntoView({ behavior: "smooth" });
    }, 50);
  };

  const sendMessage = async (text) => {
    const userText = (text || input).trim();
    if (!userText || loading) return;
    setInput("");
    setError("");

    const newMessages = [...messages, { role: "user", content: userText }];
    setMessages(newMessages);
    setLoading(true);
    scrollToBottom();

    try {
      // Використовуємо /api/chat proxy (Vercel serverless) щоб не світити API-ключ
      const endpoint = typeof window !== "undefined" && window.location.hostname === "localhost"
        ? "https://api.anthropic.com/v1/messages"
        : "/api/chat";

      const headers = { "Content-Type": "application/json" };

      const response = await fetch(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify({
          model: "claude-sonnet-4-6",
          max_tokens: 1000,
          system: SUBNETTY_SYSTEM,
          messages: newMessages.map(m => ({ role: m.role, content: m.content })),
        }),
      });
      const data = await response.json();
      if (data.error) throw new Error(data.error.message);
      const reply = data.content?.find(b => b.type === "text")?.text || "";
      setMessages(prev => [...prev, { role: "assistant", content: reply }]);
    } catch (e) {
      setError("Помилка з'єднання з API: " + e.message);
    } finally {
      setLoading(false);
      scrollToBottom();
    }
  };

  const handleKey = e => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  };

  // Simple markdown-ish renderer: fenced code blocks + bold
  const renderContent = (text) => {
    const parts = text.split(/(```[\s\S]*?```)/g);
    return parts.map((part, i) => {
      if (part.startsWith("```")) {
        const lines = part.replace(/^```[^\n]*\n?/, "").replace(/```$/, "");
        return (
          <div key={i} style={{margin:"10px 0",borderRadius:8,overflow:"hidden",border:`1px solid ${T.border}`}}>
            <div style={{background:"#e8eaf0",padding:"5px 12px",fontSize:9,fontFamily:T.mono,color:T.textMuted,letterSpacing:1}}>CONFIG</div>
            <div style={{background:T.codeBg,padding:"12px 14px",fontFamily:T.mono,fontSize:11.5,lineHeight:1.8,overflowX:"auto"}}>
              {lines.split("\n").map((line,j)=>(
                <div key={j} style={{minHeight:"1.5em"}}><HL line={line}/></div>
              ))}
            </div>
          </div>
        );
      }
      // bold **text**
      const boldParts = part.split(/(\*\*[^*]+\*\*)/g);
      return (
        <span key={i}>
          {boldParts.map((bp,j) =>
            bp.startsWith("**") && bp.endsWith("**")
              ? <strong key={j} style={{color:T.text}}>{bp.slice(2,-2)}</strong>
              : <span key={j}>{bp}</span>
          )}
        </span>
      );
    });
  };

  return (
    <div style={{display:"flex",flexDirection:"column",height:"calc(100vh - 130px)",minHeight:500}}>
      {/* Header card */}
      <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:12,padding:"16px 20px",marginBottom:14,display:"flex",alignItems:"center",gap:16}}>
        <div style={{width:44,height:44,borderRadius:12,background:T.accentBg,border:`1px solid ${T.accentLt}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:22,flexShrink:0}}>
          🤖
        </div>
        <div>
          <div style={{fontFamily:T.mono,fontSize:14,fontWeight:700,color:T.accent,letterSpacing:1}}>Subnetty</div>
          <div style={{fontSize:12,color:T.textSub,marginTop:2}}>AI-асистент мережевого інженера · Cisco · MikroTik · Ubiquiti · Subnetting</div>
        </div>
        {messages.length > 0 && (
          <button onClick={()=>setMessages([])}
            style={{marginLeft:"auto",background:"transparent",border:`1px solid ${T.border}`,color:T.textMuted,borderRadius:6,padding:"6px 12px",fontFamily:T.mono,fontSize:10,cursor:"pointer"}}>
            CLEAR CHAT
          </button>
        )}
      </div>

      {/* Quick prompts — only when no messages */}
      {messages.length === 0 && (
        <div style={{marginBottom:14}}>
          <div style={{color:T.textMuted,fontFamily:T.mono,fontSize:10,letterSpacing:1.5,marginBottom:10}}>ШВИДКІ ПИТАННЯ</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))",gap:8}}>
            {QUICK_PROMPTS.map((q,i)=>(
              <div key={i} onClick={()=>sendMessage(q.text)}
                style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:8,padding:"10px 14px",cursor:"pointer",
                  fontSize:12,color:T.textSub,fontFamily:T.sans,lineHeight:1.4,transition:"all 0.15s",
                  borderLeft:`3px solid ${T.accentLt}`}}
                onMouseEnter={e=>e.currentTarget.style.borderLeftColor=T.accent}
                onMouseLeave={e=>e.currentTarget.style.borderLeftColor=T.accentLt}>
                {q.label}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Chat area */}
      <div style={{flex:1,overflowY:"auto",display:"flex",flexDirection:"column",gap:12,paddingRight:4}}>
        {messages.map((msg, i) => (
          <div key={i} style={{display:"flex",gap:12,alignItems:"flex-start",flexDirection:msg.role==="user"?"row-reverse":"row"}}>
            {/* Avatar */}
            <div style={{width:32,height:32,borderRadius:8,flexShrink:0,display:"flex",alignItems:"center",justifyContent:"center",fontSize:15,
              background:msg.role==="user"?T.accentBg:"#f0f4f0",border:`1px solid ${msg.role==="user"?T.accentLt:"#c8d8c8"}`}}>
              {msg.role==="user"?"👤":"🤖"}
            </div>
            {/* Bubble */}
            <div style={{maxWidth:"80%",background:msg.role==="user"?T.accentBg:T.surface,
              border:`1px solid ${msg.role==="user"?T.accentLt:T.border}`,borderRadius:10,
              padding:"12px 16px",fontSize:13,lineHeight:1.7,color:T.text}}>
              {msg.role==="assistant"
                ? <div style={{fontFamily:T.sans}}>{renderContent(msg.content)}</div>
                : <div style={{fontFamily:T.sans,color:T.accent,fontWeight:500}}>{msg.content}</div>
              }
            </div>
          </div>
        ))}

        {/* Loading */}
        {loading && (
          <div style={{display:"flex",gap:12,alignItems:"flex-start"}}>
            <div style={{width:32,height:32,borderRadius:8,flexShrink:0,display:"flex",alignItems:"center",justifyContent:"center",fontSize:15,background:"#f0f4f0",border:`1px solid #c8d8c8`}}>🤖</div>
            <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:10,padding:"12px 16px",display:"flex",gap:6,alignItems:"center"}}>
              {[0,1,2].map(j=>(
                <div key={j} style={{width:7,height:7,borderRadius:"50%",background:T.accent,
                  animation:"bounce 1.2s infinite",animationDelay:`${j*0.2}s`,opacity:0.7}}/>
              ))}
              <style>{`@keyframes bounce{0%,80%,100%{transform:scale(0.7);}40%{transform:scale(1.1);}}`}</style>
            </div>
          </div>
        )}

        {error && (
          <div style={{background:T.redBg,border:`1px solid #f5b8b3`,borderRadius:8,padding:"10px 14px",fontSize:12,color:T.red,fontFamily:T.mono}}>
            ⚠ {error}
          </div>
        )}

        <div id="subnetty-bottom"/>
      </div>

      {/* Input area */}
      <div style={{marginTop:14,background:T.surface,border:`1px solid ${T.border}`,borderRadius:10,padding:12,display:"flex",gap:10,alignItems:"flex-end"}}>
        <textarea
          value={input}
          onChange={e=>setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Запитай Subnetty про мережі, конфіги, протоколи... (Enter — надіслати, Shift+Enter — новий рядок)"
          rows={2}
          style={{flex:1,background:"transparent",border:"none",outline:"none",resize:"none",fontFamily:T.sans,fontSize:13,color:T.text,lineHeight:1.6,padding:0}}
        />
        <button onClick={()=>sendMessage()}
          disabled={!input.trim()||loading}
          style={{flexShrink:0,background:input.trim()&&!loading?T.accent:"#c8cdd6",color:"white",border:"none",borderRadius:8,
            padding:"10px 18px",fontFamily:T.mono,fontSize:12,fontWeight:700,cursor:input.trim()&&!loading?"pointer":"default",
            letterSpacing:0.5,transition:"background 0.2s"}}>
          {loading?"...":"SEND"}
        </button>
      </div>
    </div>
  );
}

// ─── App ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [tab,setTab]=useState("config");

  const TABS=[
    {key:"config",  label:"⌨ Config Builder"},
    {key:"acl",     label:"🛡 ACL Wizard"},
    {key:"subnet",  label:"⬡ Subnet Calculator"},
    {key:"subnetty",label:"🤖 Subnetty AI"},
  ];

  return (
    <div style={{minHeight:"100vh",background:T.bg,color:T.text,fontFamily:T.sans,paddingBottom:0}}>
      {/* Header */}
      <div style={{background:T.surface,borderBottom:`1px solid ${T.border}`,padding:"14px 28px",display:"flex",alignItems:"center",gap:12}}>
        <div style={{width:8,height:8,borderRadius:"50%",background:T.accent,boxShadow:`0 0 8px ${T.accentLt}`}}/>
        <div>
          <div style={{fontFamily:T.mono,fontSize:13,color:T.accent,fontWeight:700,letterSpacing:2}}>NET ENGINEER TOOLKIT</div>
          <div style={{color:T.textMuted,fontSize:10,fontFamily:T.mono,marginTop:1}}>v4.0 · Cisco IOS · MikroTik · Ubiquiti EdgeOS · Subnetty AI</div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{background:T.surface,borderBottom:`1px solid ${T.border}`,padding:"0 28px",display:"flex",gap:0}}>
        {TABS.map(t=>(
          <button key={t.key} onClick={()=>setTab(t.key)}
            style={{background:"none",border:"none",cursor:"pointer",padding:"13px 18px",
              color:tab===t.key?T.accent:T.textSub,fontFamily:T.mono,fontSize:11,letterSpacing:0.8,
              borderBottom:`2px solid ${tab===t.key?T.accent:"transparent"}`,fontWeight:tab===t.key?600:400}}>
            {t.label}
          </button>
        ))}
      </div>

      <div style={{padding:"22px 28px"}}>
        {tab==="config"   &&<ConfigBuilder/>}
        {tab==="acl"      &&<ACLWizard/>}
        {tab==="subnet"   &&<SubnetCalculator/>}
        {tab==="subnetty" &&<Subnetty/>}
      </div>
    </div>
  );
}
