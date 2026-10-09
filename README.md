# Day 68 — Enterprise Incident Simulation

## Overview

This project simulates an enterprise SOC investigation involving potentially suspicious PowerShell activity and encoded-command indicators. The investigation uses Splunk to examine available telemetry, establish event-volume baselines, correlate indicators across five-minute windows, validate raw events, and document the findings.

The objective is to determine whether the available evidence supports the hypothesis of an endpoint security incident. The investigation follows an evidence-based approach: a matching string is an investigative lead, not proof of malicious execution.

## Objectives

- Establish the investigation scope and available telemetry.
- Identify relevant hosts and sourcetypes.
- Analyze event volumes across five-minute intervals.
- Investigate PowerShell-related and encoded-command indicators.
- Correlate multiple indicators within common time windows.
- Validate raw events and their sources.
- Construct an investigation timeline.
- Distinguish confirmed observations from unverified hypotheses.
- Document investigation limitations and response recommendations.

## Lab Environment

| Component | Details |
|---|---|
| SIEM | Splunk |
| Primary index | `_internal` |
| Host | `DESKTOP-9MMM37V` |
| Operating system | Windows 11 Pro |
| Correlation interval | Five minutes |
| Investigation type | Enterprise incident simulation |
| Primary focus | Event correlation and evidence validation |

## Incident Scenario

A simulated SOC alert reports potentially suspicious PowerShell activity on a Windows endpoint. The analyst investigates strings such as `powershell.exe` and `-EncodedCommand`, examines the corresponding sources and sourcetypes, and correlates observations within common time windows.

The investigation does not assume that the alert represents a genuine compromise. Every result must be validated against the underlying event and the telemetry source that produced it.

## Investigation Workflow

1. Establish the investigation scope.
2. Identify available hosts and sourcetypes.
3. Establish an event-volume baseline.
4. Investigate PowerShell-related indicators.
5. Examine encoded-command matches.
6. Validate raw events and source context.
7. Correlate indicators across five-minute windows.
8. Build an investigation timeline.
9. Assess findings and telemetry limitations.
10. Document the final assessment and response recommendations.

## Key Findings

- `DESKTOP-9MMM37V` appeared in the captured searches against `_internal`.
- Available sourcetypes included `splunkd`, `splunkd_ui_access`, `splunkd_access`, and KV Store-related logs.
- The five-minute baseline showed 4,661 events at 09:50 and 3,177 events at 10:05 on October 8, 2026.
- The captured Last 24 hours search for `powershell.exe` returned four events under `splunkd`.
- The captured Last 24 hours search for `-EncodedCommand` returned 12 events, with displayed matches under `splunkd_ui_access`.
- The supporting-indicator search for `Invoke-Expression`, `IEX`, `DownloadString`, `FromBase64String`, and `WebClient` returned zero events in the captured search.
- PowerShell-related strings were observed, but the results did not establish actual malicious PowerShell execution.
- The available telemetry was insufficient to confirm endpoint compromise.

## Investigation Limitations

The investigation used Splunk `_internal` operational telemetry rather than dedicated Windows Security or Sysmon endpoint telemetry. Searches for PowerShell-related strings can match operational records or search requests instead of actual endpoint process execution.

Correlation within a common time window does not prove that the events belong to the same attack. Independent endpoint process events, command lines, parent-child relationships, authentication records, and other relevant evidence would be needed for stronger validation.

## Conclusion

This exercise demonstrates how a SOC analyst can investigate a simulated alert, correlate available indicators, validate raw events, and document evidence limitations. The observed results support further investigation but do not establish a confirmed endpoint compromise. The assessment remains limited to the telemetry available in the lab.

## Skills Demonstrated

- Splunk Search Processing Language (SPL)
- SIEM investigation
- Event-volume analysis
- Time-based correlation
- Raw-event validation
- Evidence-based incident assessment
- Investigation documentation
- Telemetry-gap identification
