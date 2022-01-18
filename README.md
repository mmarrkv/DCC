# D-Cloud-Collector files

Content:
1. DCC-HSM firmware - ./forensicrclone/SEcubeDevBoard (patched version for re-inject attack hardening)
2. DCC_HSM host files - ./forensicrclone/SEcubeHost
3. DCC-HSM client app (representing the DCC admin and DCC-compatible cloud forensics tools) - ./hsmenc
4. DCC-HSM audit part of the DCC admin tool - ./hsmenc_audit
5. Dataset traffic generation code - ./dataset/traffic_generator (including python httplib2 and requests patches to switch off TLS1.3 certificate validation for ease of experimentation)
6. Experimentation scripts and binaries - ./experiment_runs


