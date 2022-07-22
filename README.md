# palo-alto-firewall-logs-threat-hunt-using-bytes.

index=pan src_zone!=OUTSIDE dest_zone=OUTSIDE | search NOT src_ip IN ("10.*") | search NOT action IN ("blocked","failure","dropped") 
| search src_ip!="10.0.0.0/25" AND dest_ip!="10.0.0.0/25"
| stats dc(bytes) as num_bytes by src_ip
