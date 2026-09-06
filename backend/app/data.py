"""Minimal compatibility data for the new backend."""
PCAPS = [
    {"id":"apt29_dns_tunneling","name":"APT29 DNS/DoH Tunneling","totalPkts":50000},
    {"id":"mirai_c2","name":"Mirai Botnet C2 Beacon","totalPkts":50000},
    {"id":"syn_flood_ddos","name":"SYN Flood DDoS","totalPkts":50000},
    {"id":"quic_exfil","name":"Covert QUIC Exfiltration","totalPkts":50000},
]
BASE_DASHBOARD_STATS = {"flowsPerSec":0,"threatsDetected":0,"aiConfidence":0.0,"latency":0.0}
ALERTS = []
