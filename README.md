# PacketAnalyser

A Python-based network traffic analysis tool that captures live packets or reads PCAP files, enriches source IPs with threat intelligence (AbuseIPDB, GeoIP), calculates dynamic risk scores, and stores structured results in a normalized SQLite database. Perfect for learning network security monitoring, threat hunting, and database design.

---

## Features

- **Live or offline capture** – Sniff traffic from a network interface or analyze a previously saved capture (read mode coming soon – see TODO).
- **IP reputation checking** – Query AbuseIPDB API for malicious activity reports (free tier).
- **Geographic risk** – Flag IPs from user-defined high-risk countries using a free GeoIP API.
- **Port scanning detection** – Alert on connection attempts to commonly targeted ports (e.g., 22, 445, 3389).
- **Volume-based anomaly detection** – Flag IPs that exceed a configurable packet count threshold.
- **Safelist support** – Skip analysis for trusted IPs (e.g., internal monitoring, known good hosts).
- **Normalized database schema** – Three related tables: `ip_observations`, `suspicious_flags`, `raw_packet_summary`.
- **Risk score accumulation** – Each suspicious activity adds to a running risk total for the IP.
- **Configurable via YAML** – No hardcoded values; adjust thresholds, API keys, ports, and file paths easily.

---

## Project Structure

```
PacketAnalyser/
├── MonitorTool.py                  # Main script (capture, analysis, DB)
├── config.yaml              # Configuration file
├── safelist.txt             # Optional: one IP per line to ignore
├── countries.txt            # Optional: high-risk country names (one per line)
├── PacketAnalyzer.db        # SQLite database (auto-created)
└── README.md
```

---

## Setup & Installation

### 1. Clone & Dependencies

```bash
git clone https://github.com/oflandernorth/PacketAnalyser.git
cd PacketAnalyser
pip install scapy requests pyyaml ipaddress
```

> **Note**: `scapy` may require administrator/root privileges to capture live traffic.

### 2. Obtain API Keys (Optional)

- **AbuseIPDB** – Sign up at [AbuseIPDB](https://www.abuseipdb.com/) for a free API key.
- (GeoIP uses a free API from hackertarget.com – no key required.)

### 3. Configure `config.yaml`

```yaml
paths:
  safelist: "safelist.txt"          # leave empty to disable
  countries: "countries.txt"        # leave empty to disable
  database: "PacketAnalyzer.db"

data:
  abuseipdb: "your_abuseipdb_key"   # leave empty to disable API checks
  abuseipdb_threshold: 5            # min reports to flag as suspicious
  network_interface: "Wi-Fi"         # change to your interface ("Wi-Fi" on windows / "en0" on macOS)
  count_threshold: 10               # number of packets from same IP to trigger alert
  suspicious_ports: [22, 23, 445, 3389] # common ports for attacks (SSH, Telnet, SMB, RDP)
```

### 4. Prepare Optional Lists

- **safelist.txt** – one IP per line. Packets from these IPs are completely ignored.
- **countries.txt** – one country name per line (exactly as returned by the GeoIP API).  
  Example: `China`, `Russia`, `North Korea`.

---

## Usage

Preferably Run the script using a venv with the required modules:

```bash
python MonitorTool.py
```

Then choose:

- `live` – capture live traffic from your network interface.
- `read` – analyze a PCAP file (not yet implemented – see TODO).

For **live capture**, you'll be asked:

- `time` – capture for a given number of seconds.
- `amount` – capture a fixed number of packets.

The analysis runs in real-time, printing alerts and storing data in the SQLite database.

---

## Database Schema

The tool uses a normalized SQLite database with three tables:

### `ip_observations`
| Column     | Type    | Description                                 |
|------------|---------|---------------------------------------------|
| ID         | INTEGER | PRIMARY KEY (derived from IP using `ipaddress`) |
| IP         | TEXT    | Source IP address (string)                  |
| FSEEN      | TEXT    | First seen timestamp                        |
| LSEEN      | TEXT    | Last seen timestamp                         |
| RISK       | INTEGER | Accumulated risk score (higher = more suspicious) |

### `suspicious_flags`
| Column          | Type    | Description                                |
|-----------------|---------|--------------------------------------------|
| ID              | INTEGER | PRIMARY KEY AUTOINCREMENT                 |
| OBSERVATION_ID  | INTEGER | Foreign key to `ip_observations(ID)`      |
| FLAG_REASON     | TEXT    | Why it was flagged (e.g., "From China")    |
| SOURCE          | TEXT    | Source of flag (GeoIP, AbuseIPDB, etc.)   |

### `raw_packet_summary`
| Column          | Type    | Description                                |
|-----------------|---------|--------------------------------------------|
| ID              | INTEGER | PRIMARY KEY AUTOINCREMENT                 |
| OBSERVATION_ID  | INTEGER | Foreign key to `ip_observations(ID)`      |
| PROTOCOL        | TEXT    | Protocol number (6=TCP, 17=UDP)           |
| SRC_PORT        | INTEGER | Source port (if TCP/UDP)                  |
| DST_PORT        | INTEGER | Destination port (if TCP/UDP)             |
| PACKET_SIZE     | INTEGER | Size of packet payload in bytes           |

---

## Risk Scoring Logic

Each time a packet is analyzed, the following checks add to the IP’s `RISK` score:

| Condition                                      | Risk Added |
|------------------------------------------------|------------|
| IP from high-risk country (GeoIP)              | +5         |
| IP has > `abuseipdb_threshold` reports         | +10        |
| IP exceeds `count_threshold` packets in session| +5         |
| Destination port is in `suspicious_ports`      | +20        |

The final risk score is stored in `ip_observations.RISK` and can be queried for prioritization.

---

## Example Output

```
Starting live capture
Packet from 185.130.5.253 is from an unsafe country: Russia
Packet from 185.130.5.253 has been reported 12 times in the last 90 days
Packet from 185.130.5.253 is targeting a common attack port: 445
```

Database query example:

```sql
SELECT IP, RISK FROM ip_observations ORDER BY RISK DESC LIMIT 10;
```

---

## TODO / Future Enhancements

The following features are planned based on the project scope review. Contributions welcome!

### High Priority

- [x] **Implement `read_cap()` function** – allow analysis of existing PCAP files (using `scapy`’s `rdpcap`).
- [ ] **Time-series reporting** – add queries to show "Top 10 most suspicious IPs" and "IPs that changed risk level."
- [ ] **Human-readable report** – after capture, print a summary to console and optionally export to CSV/JSON.
- [x] **Improve risk scoring** – make weights configurable in `config.yaml` (e.g., `risk_weights: {geoip: 5, abuseipdb: 10, port_scan: 20, volume: 5}`).

### Medium Priority

- [ ] **Add other threat intel sources**
- [ ] **Command-line arguments** – allow `--interface`, `--timeout`, `--pcap` instead of interactive prompts.
- [ ] **Add stored procedure or view** – e.g., `active_suspicious_ips(last_hours=1)`.
- [ ] **Asynchronous API queries** – prevent packet processing from blocking on slow HTTP requests.

### Low Priority / Stretch Goals / Might Never Happen

- [ ] **Basic web dashboard** (Flask + Chart.js) to visualize risk trends.
- [ ] **Docker support** – containerize with all dependencies.
- [ ] **Unit tests** – for risk calculation and database insertion logic.

---

## Troubleshooting

| Problem                                      | Solution                                                                 |
|----------------------------------------------|--------------------------------------------------------------------------|
| `Permission denied` when capturing           | Run with `sudo` (Linux/macOS) or as Administrator (Windows).             |
| AbuseIPDB returns 401                        | Check your API key in `config.yaml` – ensure it’s not empty or revoked. |
| GeoIP returns "Unknown" for all IPs          | The hackertarget API may be rate-limited. Try again later or use a fallback. |
| `safelist` / `countries` not working         | Make sure the file paths are correct and each entry is on a new line.    |
| Database `ON CONFLICT` syntax error          | SQLite version must be ≥ 3.24.0. Upgrade if needed (or use `INSERT OR REPLACE`). |
| `scapy` not capturing on Wi-Fi interface (macOS) | Use `ifaces` to list interfaces; try `en0` or use a wired connection. |

---

## Contributing

Pull requests are welcome! Please follow the existing code style and add docstrings for new functions. For major changes, open an issue first to discuss.

---

## License

MIT – free to use, modify, and distribute.

---

## Acknowledgments

- Built with [Scapy](https://scapy.net/)
- Threat intel: [AbuseIPDB](https://www.abuseipdb.com/)
- GeoIP: [HackerTarget](https://hackertarget.com/ip-geolocation-api/)
- Inspired by SOC analyst workflows and the need for simple, transparent threat detection.

---

**Happy analyzing!**
