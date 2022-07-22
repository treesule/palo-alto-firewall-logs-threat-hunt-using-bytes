# palo-alto-firewall-logs-threat-hunt-using-bytes.

index=pan src_zone!=OUTSIDE dest_zone=OUTSIDE | search NOT src_ip IN ("10.*") | search NOT action IN ("blocked","failure","dropped") 
| search src_ip!="10.0.0.0/25" AND dest_ip!="10.0.0.0/25"
| stats dc(bytes) as num_bytes by src_ip



index=pan src_zone!=OUTSIDE dest_zone=OUTSIDE | search src_ip IN ("172.*") | search NOT action IN ("blocked","failure","dropped")  | search src_ip!="10.128.117.0/25" AND dest_ip!="10.128.117.0/25"  user!=unknown | stats  dc(bytes) as num_bytes by src_ip, user | sort -num_bytes | where num_bytes > 2
