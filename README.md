# palo-alto-firewall-logs-threat-hunt-using-bytes.

index=pan dest_zone=OUTSIDE src_zone!=OUTSIDE AND src_ip IN ("172.*")
| streamstats sum(duration) AS total_duration BY src_ip
| table src_ip dest_ip total_duration | sort -total_duration


index=pan dest_zone=OUTSIDE src_zone!=OUTSIDE 
| streamstats current=f last(_time) as next_time by dest 
| eval gap = next_time - _time
| stats count, avg(gap) as avg_gap, var(gap) as var_gap by dest src
| search avg_gap<50 count>500
| sort avg_gap

index=pan src_zone!=OUTSIDE dest_zone=OUTSIDE | search NOT src_ip IN ("10.*") | search NOT action IN ("blocked","failure","dropped") 
| search src_ip!="10.0.0.0/25" AND dest_ip!="10.0.0.0/25"
| stats dc(bytes) as num_bytes by src_ip



index=pan src_zone!=OUTSIDE dest_zone=OUTSIDE | search src_ip IN ("172.*") | search NOT action IN ("blocked","failure","dropped")  | search src_ip!="10.128.117.0/25" AND dest_ip!="10.128.117.0/25"  user!=unknown | stats  dc(bytes) as num_bytes by src_ip, user | sort -num_bytes | where num_bytes > 2
