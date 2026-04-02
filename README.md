# SSH Brute Force Detection in Splunk - Project Checklist

## Phase 1: Data Collection & Ingestion
- [ ] **Identify log sources**
  - [ ] Linux syslog (auth.log / secure)
  - [ ] Windows Event Logs (if monitoring RDP/SSH gateway)
  - [ ] SSH server logs (OpenSSH, SSHD)
  - [ ] Firewall/IDS logs (Suricata, Snort if applicable)

- [ ] **Set up Splunk forwarders/inputs**
  - [ ] Install Universal Forwarder on SSH server(s) or configure HTTP Event Collector (HEC)
  - [ ] Configure inputs.conf to monitor syslog paths:
    - [ ] `/var/log/auth.log` (Debian/Ubuntu)
    - [ ] `/var/log/secure` (RedHat/CentOS)
    - [ ] Custom SSH server logs if applicable
  - [ ] Set source type as `syslog` or create custom source type `ssh:syslog`
  - [ ] Assign index (e.g., `main` or create dedicated `security` index)
  - [ ] Enable log forwarding to Splunk

- [ ] **Validate data ingestion**
  - [ ] Check Splunk web for incoming data
  - [ ] Run: `index=main source="/var/log/auth.log" | stats count`
  - [ ] Confirm timestamps are correct
  - [ ] Check for any parsing issues

---

## Phase 2: Understanding SSH Attack Patterns
- [ ] **Study SSH authentication failure patterns**
  - [ ] Failed login attempts: "Invalid user" / "Authentication failure"
  - [ ] Multiple failures from same source IP
  - [ ] Multiple users attempted from same source
  - [ ] Password spray vs. credential stuffing patterns
  - [ ] Rapid-fire attempts (velocity)

- [ ] **Common SSH log markers to detect**
  - [ ] `Failed password for [user]`
  - [ ] `Invalid user [user]`
  - [ ] `Connection closed by authenticating user [user]`
  - [ ] `Disconnected from [IP]`
  - [ ] `Too many authentication failures`

- [ ] **Define threshold for "brute force"**
  - [ ] N failed attempts in X minutes per source IP
  - [ ] N failed users from same IP in X minutes
  - [ ] N failed attempts per user account in X minutes
  - [ ] Document your chosen thresholds (e.g., 5 failures in 10 min = brute force)

---

## Phase 3: Data Parsing & Field Extraction
- [ ] **Parse SSH logs to extract key fields**
  - [ ] `src_ip` (attacker IP)
  - [ ] `user` (target username)
  - [ ] `status` (success/failure)
  - [ ] `action` (authentication attempt, disconnection, etc.)
  - [ ] `timestamp`

- [ ] **Create custom field extractions**
  - [ ] Use Splunk UI: Settings > Fields > Field Extractions
  - [ ] Or configure props.conf/transforms.conf:
    ```
    [ssh:syslog]
    TRANSFORMS-extract = ssh_extract_fields
    ```
  - [ ] Test regex patterns on sample logs
  - [ ] Validate field extraction quality (Settings > Fields > Validation)

- [ ] **Alternative: Use Splunk App for Unix/Linux**
  - [ ] Install if not already present
  - [ ] Verify it provides `user`, `src_ip`, and status fields
  - [ ] Check if additional fields are auto-extracted

---

## Phase 4: Create Detection Searches
- [ ] **Basic failed login search**
  ```
  index=main source="/var/log/auth.log" "Failed password"
  | stats count by src_ip, user
  | where count > 3
  ```

- [ ] **Invalid user detection**
  ```
  index=main source="/var/log/auth.log" "Invalid user"
  | stats count by src_ip
  | where count > 5
  ```

- [ ] **Brute force by source IP (time-windowed)**
  ```
  index=main source="/var/log/auth.log" "Failed password"
  | bucket _time span=10m
  | stats count by src_ip, _time
  | where count > 5
  ```

- [ ] **Multiple users from single IP**
  ```
  index=main source="/var/log/auth.log" "Failed password"
  | stats dc(user) as unique_users by src_ip
  | where unique_users > 5
  ```

- [ ] **Successful login after many failures** (potential compromise)
  ```
  index=main source="/var/log/auth.log"
  | stats count(eval(match(raw, "Failed password"))) as failures, 
          count(eval(match(raw, "Accepted password"))) as success by src_ip, user
  | where failures > 5 AND success > 0
  ```

- [ ] **Test each search**
  - [ ] Run in Search & Reporting app
  - [ ] Verify results match expectations
  - [ ] Check for false positives
  - [ ] Adjust time ranges and thresholds as needed

---

## Phase 5: Create Alerts
- [ ] **Convert searches to alerts**
  - [ ] Save each search
  - [ ] Click "Alert" (or use "Create Alert" if in search results)
  - [ ] Set alert trigger condition:
    - [ ] Schedule (e.g., every 5 minutes, every hour)
    - [ ] Trigger threshold (e.g., number of results > 0)

- [ ] **Configure alert actions**
  - [ ] Email notification
  - [ ] Log event to index
  - [ ] Webhook/integration (optional: Discord, Slack, SOAR)
  - [ ] Include relevant fields in alert output
  - [ ] Set alert severity (High, Medium, Low)

- [ ] **Alert naming & tagging**
  - [ ] Name: `SSH - Brute Force Detected from [src_ip]`
  - [ ] Tag: `detection`, `ssh`, `brute_force`, `authentication`
  - [ ] Add description/runbook link

- [ ] **Set alert retention**
  - [ ] Decide how long to keep alert records
  - [ ] Configure in index settings

---

## Phase 6: Create Dashboards & Visualizations
- [ ] **Create main SSH security dashboard**
  - [ ] **Panel: Top source IPs with failed logins**
    ```
    index=main source="/var/log/auth.log" "Failed password"
    | stats count by src_ip | sort - count | head 10
    ```
  - [ ] Visualization: Bar chart or table

- [ ] **Panel: Failed attempts timeline**
  - [ ] Search: `index=main source="/var/log/auth.log" "Failed password" | timechart count by src_ip`
  - [ ] Visualization: Line chart or column chart

- [ ] **Panel: Target users under attack**
  - [ ] Search: `index=main source="/var/log/auth.log" "Failed password" | stats count by user | sort - count | head 10`
  - [ ] Visualization: Table or bar chart

- [ ] **Panel: Current alerts/incidents**
  - [ ] Display latest triggered brute force alerts
  - [ ] Include src_ip, failure count, time

- [ ] **Panel: Geographic heatmap** (bonus)
  - [ ] Enrich src_ip with GeoIP data
  - [ ] Display attack sources on world map

- [ ] **Add filters to dashboard**
  - [ ] Time range picker
  - [ ] Source IP filter
  - [ ] Username filter

---

## Phase 7: Threat Enrichment & Response
- [ ] **IP enrichment**
  - [ ] Add GeoIP lookup (Settings > Lookups > GeoIP)
  - [ ] Add reputation data (IP blocklist, threat feed)
  - [ ] Check if src_ip is internal or external

- [ ] **User enrichment**
  - [ ] Lookup admin accounts vs. regular users
  - [ ] Flag attempts on critical accounts (root, admin)
  - [ ] Identify service accounts vs. human users

- [ ] **Create playbook/runbook for SOC analyst**
  - [ ] When brute force alert fires:
    - [ ] Check if IP is known/expected (VPN, admin)
    - [ ] Review successful logins from that IP
    - [ ] Check for lateral movement post-compromise
    - [ ] Block IP in firewall if malicious
    - [ ] Reset password if compromise suspected
  - [ ] Document each step

- [ ] **Integrate with incident response** (optional)
  - [ ] Create automatic ticket in ticketing system
  - [ ] Send to SOAR for auto-remediation (IP blocking, etc.)

---

## Phase 8: Testing & Validation
- [ ] **Generate test brute force attempts**
  - [ ] SSH from test machine: `for i in {1..10}; do ssh invalid_user@target_ip; done`
  - [ ] Use tool: `hydra`, `medusa`, or custom script
  - [ ] **IMPORTANT**: Only test on your own lab/authorized systems
  - [ ] Capture logs from multiple angles

- [ ] **Verify detection triggers**
  - [ ] Confirm searches return results
  - [ ] Check alerts are fired
  - [ ] Verify alert notifications are sent
  - [ ] Check dashboard updates in real-time

- [ ] **Test false positive scenarios**
  - [ ] User fails password 2-3 times (should NOT alert)
  - [ ] Automated tool with wrong password (verify threshold sensitivity)
  - [ ] Locked account attempts (expected behavior)
  - [ ] Adjust thresholds if needed

- [ ] **Performance testing**
  - [ ] Run searches over large time window (30 days)
  - [ ] Check search speed/performance
  - [ ] Optimize searches if too slow (use summary indexing if needed)

---

## Phase 9: Documentation
- [ ] **Create project documentation**
  - [ ] Overview: What problem does this solve?
  - [ ] Architecture: Data flow from SSH server → Splunk
  - [ ] Detection logic: How attacks are identified
  - [ ] Alerts: What triggers, thresholds, actions
  - [ ] Dashboard guide: How to interpret visualizations
  - [ ] Playbook: SOC analyst workflow

- [ ] **Document all searches**
  - [ ] Search query
  - [ ] What it detects
  - [ ] Expected results
  - [ ] Threshold/tuning parameters

- [ ] **Create knowledge base article** (optional)
  - [ ] SSH brute force attack overview
  - [ ] Detection methodology
  - [ ] Real-world examples

---

## Phase 10: Optimization & Continuous Improvement
- [ ] **Monitor alert quality**
  - [ ] Track true positives vs. false positives
  - [ ] Adjust thresholds based on 2-3 weeks of data
  - [ ] Reduce alert fatigue

- [ ] **Add advanced detections** (stretch goals)
  - [ ] Detect lateral movement post-compromise
  - [ ] Correlate failed attempts with successful logins
  - [ ] Detect distributed brute force (same user, different IPs)
  - [ ] Machine learning: Anomaly detection for unusual login patterns

- [ ] **Scale & operationalize**
  - [ ] Add more SSH servers to monitoring
  - [ ] Integrate with Windows RDP detection
  - [ ] Add other authentication sources (LDAP, VPN)
  - [ ] Create SLA: Detection time < 5 minutes

---

## Phase 11: Deliverables (For Portfolio/Reporting)
- [ ] **Screenshots/evidence**
  - [ ] Sample alert notification
  - [ ] Dashboard overview
  - [ ] Detection search results
  - [ ] Alert configuration

- [ ] **Writeup/blog post** (optional)
  - [ ] How to detect SSH brute force in Splunk
  - [ ] Lessons learned
  - [ ] Challenges & solutions

- [ ] **Video demo** (optional)
  - [ ] Live brute force simulation
  - [ ] Alert triggering
  - [ ] Dashboard analysis

---

## Quick Reference: Key Splunk Commands
```
# Search failed logins
index=main source="/var/log/auth.log" "Failed password"

# Extract fields
| rex field=raw "Failed password for (?<user>\w+)"

# Time bucketing
| bucket _time span=5m

# Statistics
| stats count by src_ip
| stats dc(user) as unique_users by src_ip

# Filtering results
| where count > 5

# Sorting
| sort - count

# Limiting results
| head 20
```

---

## Estimated Timeline
- **Phase 1-2**: 1-2 hours (setup + research)
- **Phase 3-4**: 2-3 hours (parsing + searches)
- **Phase 5-6**: 2-3 hours (alerts + dashboards)
- **Phase 7-8**: 2-3 hours (enrichment + testing)
- **Phase 9-11**: 1-2 hours (documentation + polish)

**Total**: ~10-14 hours for a complete, production-ready detection system

---

## Next Steps
1. Start with Phase 1: Get SSH logs into Splunk
2. Do Phase 2: Understand what you're detecting
3. Move through phases sequentially
4. Test heavily in Phase 8
5. Document everything in Phase 9
