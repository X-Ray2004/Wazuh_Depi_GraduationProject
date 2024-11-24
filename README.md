We implemented Wazuh as our primary SIEM solution and configured it to connect to hosts via SSH, bypassing the need for a local agent. This setup allows Wazuh to perform threat detection and take actions through the host's Windows Defender, log events, and trigger alerts. 

We achieved this by integrating the `ossec_agent.conf` file and defining custom rules within the `ossec_rules.xml` file on the Wazuh server. However, in scenarios where Windows Defender faced evasion issues—whether due to an attack or technical malfunction—we extended Wazuh's capabilities by integrating it with VirusTotal using their Public API. 

This integration not only allowed us to query VirusTotal's hashes database but also enabled Wazuh to detect malicious files, suspend their operations, and clean them effectively, ensuring robust endpoint protection.
