// Canned demo verdicts for the three example URLs in the PRD.
// These render INSTANTLY so the demo experience is reliable;
// any other URL goes through the live Claude verdict path.

window.SIFT_DEMOS = {
  "https://securelist.com/tr/lotus-wiper/119472/": {
    verdict: "SHIP",
    source: "securelist.com",
    title: "LOTUS WIPER: A new destructive malware family targeting Turkish infrastructure",
    publishedAt: "Apr 18, 2026",
    readTime: "11 min read",
    reasoning: "Kaspersky GReAT walks through a brand-new wiper with a documented kill chain, named TTPs, and IOCs you can hash. This is not a recap — it is primary research with enough specificity to write a detection in an afternoon. Skip the tea, ship the rule.",
    confidence: 0.92,
    tags: ["primary-research", "named-malware", "fresh-IOCs"],
    ttp: {
      name: "Indicator Removal: File Deletion via Raw Disk Write",
      mitre: "T1485 / T1561.002",
      summary: "LOTUS opens \\\\.\\PhysicalDrive0 and overwrites the MBR + first 512KB of every attached volume with a hardcoded pattern, then schedules a reboot via shutdown.exe /r /t 0."
    },
    sigma: `title: LOTUS Wiper — Raw Disk Write to PhysicalDrive
id: 8a4f2c1e-9b7d-4f3a-a1c2-3d5e6f7a8b9c
status: experimental
description: Detects the LOTUS wiper opening a raw handle to \\\\.\\PhysicalDrive* and issuing high-volume sequential writes within 60s of process start. Combine with the scheduled reboot for high-confidence.
author: Sift / Detection Dispatch
date: 2026/04/22
references:
  - https://securelist.com/tr/lotus-wiper/119472/
logsource:
  product: windows
  category: process_creation
detection:
  selection_proc:
    Image|endswith: '\\\\lotus.exe'
  selection_handle:
    EventID: 4663
    ObjectName|startswith: '\\\\Device\\\\Harddisk'
    AccessMask: '0x40000000'   # GENERIC_WRITE
  selection_reboot:
    Image|endswith: '\\\\shutdown.exe'
    CommandLine|contains|all: ['/r', '/t', '0']
  condition: selection_proc and selection_handle and selection_reboot | within 60s
falsepositives:
  - Disk imaging tools run by IT (dd, Clonezilla)
  - Veeam / Acronis recovery agents during restore
level: high
tags:
  - attack.impact
  - attack.t1485
  - attack.t1561.002`,
    telemetry: [
      {
        source: "Windows Sysmon",
        events: ["Event ID 1 (Process Create)", "Event ID 11 (FileCreate)"],
        fields: ["Image", "CommandLine", "OriginalFileName", "Hashes"],
        config: "Sysmon config must include rule for raw disk handles. Default SwiftOnSecurity config does NOT capture \\\\.\\PhysicalDrive opens — you need a custom RawAccessRead rule."
      },
      {
        source: "Windows Security Auditing",
        events: ["Event ID 4663 (Object Access)"],
        fields: ["ObjectName", "AccessMask", "ProcessName"],
        config: "Object Access auditing must be enabled on Removable Storage and Other Object Access Events. Off by default."
      }
    ],
    notes: [
      "Expected volume: ~0 events/day on a healthy fleet. If you see this firing, do not page — answer the page.",
      "Disk imaging by Veeam/Acronis is the only meaningful FP source. Allowlist by parent process and signed-binary check.",
      "Correlate with EventID 1074 (system shutdown) within 5 minutes to upgrade severity."
    ]
  },

  "https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/": {
    verdict: "SHIP",
    source: "thedfirreport.com",
    title: "BISSA Scanner Exposed: AI-Assisted Mass Exploitation and Credential Harvesting",
    publishedAt: "Apr 22, 2026",
    readTime: "27 min read",
    reasoning: "Full DFIR Report on a campaign that chains a public scanner, an LLM-fronted exploit selector, and a credential dumper. Initial access through TTPs through exfil with timestamps. The Sigma rules write themselves — and DFIR Report basically did, in their appendix.",
    confidence: 0.97,
    tags: ["full-intrusion", "named-tooling", "appendix-with-rules"],
    ttp: {
      name: "Valid Accounts: Domain Accounts via Harvested Credentials",
      mitre: "T1078.002 / T1110.004",
      summary: "After the BISSA scanner identifies a vulnerable edge device, an LLM-fronted module selects an exploit, drops a Mimikatz variant (renamed m.exe), and uses harvested NTLM hashes for lateral movement via PsExec within 14 minutes of initial access."
    },
    sigma: `title: BISSA — Renamed Mimikatz + PsExec Lateral Within 15min of Edge CVE Hit
id: 4c7e9f1a-2b3d-4e5f-8a1b-9c0d2e3f4a5b
status: experimental
description: Sequence detection — public-facing service exploit followed by credential dumper execution and SMB lateral movement to >2 hosts under the same parent within 15 minutes.
author: Sift / Detection Dispatch
date: 2026/04/24
references:
  - https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/
logsource:
  product: windows
  category: process_creation
detection:
  exploit_landing:
    ParentImage|endswith:
      - '\\\\w3wp.exe'
      - '\\\\httpd.exe'
      - '\\\\nginx.exe'
    Image|endswith:
      - '\\\\cmd.exe'
      - '\\\\powershell.exe'
  creddump:
    Image|endswith: '\\\\m.exe'
    OriginalFileName: 'mimikatz.exe'
  lateral:
    Image|endswith: '\\\\PsExec.exe'
    CommandLine|contains: '\\\\\\\\'
  condition: exploit_landing followed_by creddump followed_by lateral | within 15m
falsepositives:
  - Sanctioned red team engagements (announced in advance; allowlist source IP)
  - IT using PsExec from a jump box (allowlist by source host)
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.lateral_movement
  - attack.t1021.002`,
    telemetry: [
      {
        source: "EDR Process Telemetry",
        events: ["Process Create", "Image Load", "Network Connect"],
        fields: ["process.name", "process.parent.name", "process.command_line", "process.hash.sha256"],
        config: "Most EDRs cover this out of the box. Validate that command_line is captured fully — Defender truncates at 4096 chars."
      },
      {
        source: "Windows Security",
        events: ["4624 Type 3 (Network logon)", "4688 (Process Creation)"],
        fields: ["TargetUserName", "IpAddress", "LogonType", "ProcessName"],
        config: "Audit Process Creation must be enabled with command-line capture (Group Policy: 'Include command line in process creation events')."
      },
      {
        source: "Edge Web Server Access Logs",
        events: ["Request log"],
        fields: ["url.path", "http.response.status_code", "user_agent"],
        config: "Needed for the exploit_landing anchor. Must be ingested with no more than 5min latency."
      }
    ],
    notes: [
      "The 15-minute window is from the DFIR Report's median dwell time. Tune wider for slower environments.",
      "If you can't get web server logs, drop the exploit_landing branch and accept the higher FP rate from creddump+lateral alone.",
      "DFIR Report's appendix includes IOCs — hash-block them at the EDR layer; this rule is the safety net."
    ]
  },

  "https://www.huntress.com/blog/nightmare-eclipse-intrusion": {
    verdict: "SKIM",
    source: "huntress.com",
    title: "Inside the 'Nightmare Eclipse' Intrusion: A 72-Hour Breakdown",
    publishedAt: "Apr 19, 2026",
    readTime: "9 min read",
    reasoning: "Solid storytelling, real intrusion, but the technical specifics are thin — vendor blog optimized for the marketing funnel rather than the detection engineer. You'll learn the shape of the attack in three minutes; you will not get a Sigma rule out of it. Read it on the train, don't block your sprint for it.",
    confidence: 0.78,
    tags: ["vendor-blog", "narrative-heavy", "low-IOC-density"],
    skimSummary: [
      "Initial access via a phishing lure impersonating a Docusign envelope (no novel TTP — same lure pattern as the past 18 months).",
      "Persistence via a scheduled task masquerading as a Chrome updater. Detection already covered by existing Sigma rule `proc_creation_win_schtasks_chrome_updater_masquerade.yml`.",
      "Lateral movement was manual RDP — no tooling, no automation, no detection opportunity beyond what you already have on 4624 Type 10."
    ],
    skimVerdict: "Three minutes of skim. No new detection content. Forward to leadership if they like a good story; do not put it on the eng backlog."
  }
};

// Translation demos — keyed by `${url}::${platform}`
window.SIFT_TRANSLATIONS = {
  "https://securelist.com/tr/lotus-wiper/119472/::splunk": {
    query: `index=windows (sourcetype=WinEventLog:Sysmon OR sourcetype=WinEventLog:Security)
| eval is_lotus=if(match(Image,"\\\\\\\\lotus\\\\.exe$"),1,0)
| eval is_rawdisk=if(EventID=4663 AND match(ObjectName,"^\\\\\\\\Device\\\\\\\\Harddisk") AND AccessMask="0x40000000",1,0)
| eval is_reboot=if(match(Image,"\\\\\\\\shutdown\\\\.exe$") AND match(CommandLine,"/r") AND match(CommandLine,"/t\\\\s+0"),1,0)
| stats max(is_lotus) as lotus, max(is_rawdisk) as rawdisk, max(is_reboot) as reboot,
        min(_time) as first_seen, max(_time) as last_seen by host
| where lotus=1 AND rawdisk=1 AND reboot=1 AND (last_seen - first_seen) < 60
| eval window_seconds=last_seen-first_seen
| table host, first_seen, last_seen, window_seconds`,
    sources: [
      { sigma: "windows / process_creation", platform: "index=windows sourcetype=WinEventLog:Sysmon EventCode=1" },
      { sigma: "Event ID 4663", platform: "sourcetype=WinEventLog:Security EventCode=4663" }
    ],
    fieldMaps: [
      { sigma: "Image", platform: "Image (Sysmon) — ensure CIM normalization is OFF or use process.executable" },
      { sigma: "AccessMask", platform: "AccessMask — Splunk parses as string, keep '0x40000000' literal" }
    ],
    notes: [
      "The `within 60s` Sigma operator becomes a stats + range filter in SPL. Tune the 60 if you have slow disks.",
      "If you use the CIM Process datamodel, swap the first stanza for `tstats` — ~40x faster on big indexes.",
      "Recommended schedule: real-time (continuous) or 1-minute interval. Volume is near zero so cost is negligible."
    ]
  },
  "https://securelist.com/tr/lotus-wiper/119472/::sentinel": {
    query: `let exploit_window = 60s;
let proc = DeviceProcessEvents
  | where FileName =~ "lotus.exe"
  | project lotus_time=TimeGenerated, DeviceId, lotus_pid=ProcessId;
let raw_disk = DeviceFileEvents
  | where FolderPath startswith @"\\\\Device\\\\Harddisk"
  | where ActionType == "FileCreated" or ActionType == "FileModified"
  | project disk_time=TimeGenerated, DeviceId;
let reboot = DeviceProcessEvents
  | where FileName =~ "shutdown.exe"
  | where ProcessCommandLine has "/r" and ProcessCommandLine matches regex @"/t\\\\s+0"
  | project reboot_time=TimeGenerated, DeviceId;
proc
| join kind=inner raw_disk on DeviceId
| where disk_time between (lotus_time .. (lotus_time + exploit_window))
| join kind=inner reboot on DeviceId
| where reboot_time between (lotus_time .. (lotus_time + exploit_window))
| project DeviceId, lotus_time, disk_time, reboot_time, lotus_pid`,
    sources: [
      { sigma: "windows / process_creation", platform: "DeviceProcessEvents (Defender for Endpoint)" },
      { sigma: "Event ID 4663", platform: "DeviceFileEvents — note: Defender does not surface raw \\\\.\\PhysicalDrive writes natively. You need MDE Advanced Hunting + the M365 connector." }
    ],
    fieldMaps: [
      { sigma: "Image", platform: "FileName (just basename — Sentinel splits path)" },
      { sigma: "CommandLine", platform: "ProcessCommandLine" },
      { sigma: "AccessMask", platform: "Not surfaced. Use ActionType + FolderPath instead." }
    ],
    notes: [
      "MDE does not natively log \\\\.\\PhysicalDrive opens. This rule degrades to file-modify on the device path, which has lower fidelity.",
      "If you have Sysmon forwarded into Sentinel via AMA, swap DeviceFileEvents for Event | where Source == 'Microsoft-Windows-Sysmon' for the higher-fidelity version.",
      "Schedule as a NRT rule (1-min). Output to Microsoft.SecurityInsights/Incidents directly."
    ]
  },
  "https://securelist.com/tr/lotus-wiper/119472/::scanner": {
    query: `%ingest.source_type: "windows_sysmon" OR %ingest.source_type: "windows_security"
| project _time, host, EventID, Image, CommandLine, ObjectName, AccessMask
| join (
    where Image:endsWith("\\\\lotus.exe")
    | project lotus_time = _time, host, lotus_pid = ProcessId
  ) on host
  with (
    where EventID == 4663
      and ObjectName:startsWith("\\\\Device\\\\Harddisk")
      and AccessMask == "0x40000000"
    | project rawdisk_time = _time, host
  )
  with (
    where Image:endsWith("\\\\shutdown.exe")
      and CommandLine:contains("/r")
      and CommandLine:matches("/t\\\\s+0")
    | project reboot_time = _time, host
  )
  within 60s
| project host, lotus_time, rawdisk_time, reboot_time, lotus_pid
| sort _time desc`,
    sources: [
      { sigma: "windows / process_creation", platform: "%ingest.source_type: \"windows_sysmon\"" },
      { sigma: "Event ID 4663", platform: "%ingest.source_type: \"windows_security\" + EventID == 4663" }
    ],
    fieldMaps: [
      { sigma: "Image", platform: "Image (preserved from Sysmon)" },
      { sigma: "AccessMask", platform: "AccessMask (string literal, no parsing)" }
    ],
    notes: [
      "Scanner's `within 60s` join handles the time-window correlation natively — no stats hack required.",
      "Recommended: schedule as a continuous detection. Index-time skip cost on this query is roughly 1/1000 of the full scan because the Image filter is highly selective.",
      "If your Sysmon and Security logs land in separate datasets, replace the source_type filter with %dataset: in:(\"sysmon_prod\", \"winsec_prod\")."
    ]
  },

  "https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/::splunk": {
    query: `index=windows sourcetype=WinEventLog:Sysmon EventCode=1
| eval stage=case(
    match(ParentImage,"(w3wp|httpd|nginx)\\\\.exe$") AND match(Image,"(cmd|powershell)\\\\.exe$"), "exploit",
    match(Image,"\\\\\\\\m\\\\.exe$") AND OriginalFileName="mimikatz.exe", "creddump",
    match(Image,"\\\\\\\\PsExec\\\\.exe$") AND match(CommandLine,"\\\\\\\\\\\\\\\\"), "lateral",
    1=1, null())
| where isnotnull(stage)
| transaction host maxspan=15m startswith=eval(stage="exploit") endswith=eval(stage="lateral")
| where mvcount(mvfilter(stage="creddump"))>=1 AND mvcount(mvfilter(stage="lateral"))>=1
| table _time, host, duration, eventcount, stage`,
    sources: [
      { sigma: "windows / process_creation", platform: "index=windows sourcetype=WinEventLog:Sysmon EventCode=1" },
      { sigma: "edge web server logs", platform: "index=web sourcetype=access_combined (optional anchor)" }
    ],
    fieldMaps: [
      { sigma: "ParentImage", platform: "ParentImage" },
      { sigma: "OriginalFileName", platform: "OriginalFileName (Sysmon Image Load enrichment, EventCode 7)" }
    ],
    notes: [
      "transaction is expensive. If volume is high, swap for streamstats with a session window keyed on host.",
      "OriginalFileName requires Sysmon ImageLoaded events (EID 7) — check your SwiftOnSecurity config has them enabled.",
      "Schedule: 5-min interval, 15-min lookback. Don't run real-time — transaction RT is rough on the indexer."
    ]
  },
  "https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/::sentinel": {
    query: `let lookback = 15m;
let exploit = DeviceProcessEvents
  | where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe")
  | where FileName in~ ("cmd.exe","powershell.exe")
  | project exploit_time=TimeGenerated, DeviceId;
let creddump = DeviceProcessEvents
  | where FileName =~ "m.exe"
  | where ProcessVersionInfoOriginalFileName =~ "mimikatz.exe"
  | project creddump_time=TimeGenerated, DeviceId;
let lateral = DeviceProcessEvents
  | where FileName =~ "PsExec.exe"
  | where ProcessCommandLine matches regex @"\\\\\\\\\\\\\\\\\\\\S+"
  | project lateral_time=TimeGenerated, DeviceId;
exploit
| join kind=inner creddump on DeviceId
| where creddump_time between (exploit_time .. (exploit_time + lookback))
| join kind=inner lateral on DeviceId
| where lateral_time between (creddump_time .. (creddump_time + lookback))
| project DeviceId, exploit_time, creddump_time, lateral_time, total_window=lateral_time-exploit_time`,
    sources: [
      { sigma: "windows / process_creation", platform: "DeviceProcessEvents (Defender for Endpoint via M365 connector)" }
    ],
    fieldMaps: [
      { sigma: "ParentImage", platform: "InitiatingProcessFileName (basename only)" },
      { sigma: "OriginalFileName", platform: "ProcessVersionInfoOriginalFileName" }
    ],
    notes: [
      "Sentinel's join can be expensive on 15m windows; consider splitting into a saved analytic that materializes the exploit step into a Watchlist first.",
      "ProcessVersionInfoOriginalFileName is sparsely populated — fallback to FileSize + FileVersion combo if you see misses.",
      "Output as Incident with severity=High and tactics: [\"InitialAccess\",\"CredentialAccess\",\"LateralMovement\"]."
    ]
  },
  "https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/::scanner": {
    query: `%ingest.source_type: "windows_sysmon"
| where EventID == 1
| join (
    where ParentImage:matches("(w3wp|httpd|nginx)\\\\.exe$")
      and Image:matches("(cmd|powershell)\\\\.exe$")
    | project exploit_time = _time, host
  ) on host
  with (
    where Image:endsWith("\\\\m.exe")
      and OriginalFileName == "mimikatz.exe"
    | project creddump_time = _time, host
  )
  with (
    where Image:endsWith("\\\\PsExec.exe")
      and CommandLine:matches("\\\\\\\\\\\\\\\\")
    | project lateral_time = _time, host
  )
  within 15m
| project host, exploit_time, creddump_time, lateral_time,
          dwell_seconds = (lateral_time - exploit_time) / 1s
| sort dwell_seconds asc`,
    sources: [
      { sigma: "windows / process_creation", platform: "%ingest.source_type: \"windows_sysmon\"" }
    ],
    fieldMaps: [
      { sigma: "ParentImage", platform: "ParentImage (full path preserved)" }
    ],
    notes: [
      "Scanner's index-time skipping makes the multi-stage join cheap even at 15m windows. Run on continuous schedule.",
      "If you have web server logs in a separate dataset, prepend a sub-query to anchor on a 4xx→200 transition before the exploit stage for fewer FPs.",
      "Output via webhook to your case management — payload includes dwell_seconds so triagers can prioritize the fastest intrusions."
    ]
  }
};
