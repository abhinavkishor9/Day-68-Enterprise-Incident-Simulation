# Day-68-Enterprise-Incident-Simulation
## Overview
An Enterprise Incident Simulation is a controlled exercise that reproduces how a SOC analyst would investigate a suspected security incident in a real enterprise environment. Instead of investigating one isolated alert, the analyst follows the incident across multiple stages: alert → triage → evidence collection → correlation → timeline → validation → incident assessment → response recommendation → reporting.

The important skill is not simply finding suspicious strings. The analyst must determine whether different observations actually belong to the same activity and whether the available evidence is strong enough to support the incident hypothesis. For example, a search for -EncodedCommand may return a result, but the analyst must inspect the raw event and determine whether it represents actual PowerShell execution or merely a Splunk search containing that string. This reinforces the SOC principle: correlation creates an investigative lead; evidence validation determines what can actually be concluded.

This project simulates an enterprise SOC investigation involving potentially suspicious PowerShell activity and encoded-command indicators. The investigation uses Splunk to examine available telemetry, establish event-volume baselines, correlate indicators across five-minute windows, validate raw events, and document the findings.

The objective is to determine whether the available evidence supports the hypothesis of an endpoint security incident. The investigation follows an evidence-based approach: a matching string is an investigative lead, not proof of malicious execution.

## Lab Objectives

- Investigate a simulated enterprise security alert involving potentially suspicious PowerShell activity.
- Establish the investigation scope and identify the hosts, sourcetypes, and telemetry available in Splunk.
- Analyze event volumes across five-minute intervals to identify periods requiring further investigation.
- Examine PowerShell-related strings and encoded-command indicators to understand their context and source.
- Validate suspicious matches by inspecting raw events, timestamps, source files, and sourcetypes.
- Correlate multiple indicators within common time windows while distinguishing temporal overlap from a confirmed attack relationship.
- Investigate supporting indicators and document searches that return no results.
- Construct a chronological investigation timeline based on observed evidence.
- Classify findings as confirmed, plausible, unconfirmed, or not observed, according to the available evidence.
- Identify telemetry gaps that prevent confirmation of endpoint process execution or compromise.
- Develop appropriate incident response recommendations without claiming actions that were not performed.
- Produce a structured investigation report that documents the methodology, findings, limitations, and final evidence-based assessment.
  
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

## Lab Scenario

An organization is conducting an enterprise incident simulation to evaluate how a SOC analyst investigates potentially suspicious command-line activity using Splunk. During the exercise, several searches identify references to PowerShell, `-EncodedCommand`, and common system-discovery commands. These indicators may appear in legitimate administrative activity, security investigations, application logs, or attacker behavior, so their presence alone does not establish that a compromise occurred.

The investigation is performed using the available Splunk `_internal` index, which primarily contains Splunk platform and operational telemetry rather than dedicated Windows endpoint security events. The analyst must therefore determine what the available logs actually demonstrate and whether the suspicious strings originate from endpoint activity or from Splunk's own interface and internal processes.

### Investigation Tasks

- Establish a baseline of event volume by host, sourcetype, and five-minute time intervals to identify periods of elevated activity.
- Search for PowerShell-related strings, encoded-command indicators, and common discovery commands, then examine the associated raw events.
- Compare timestamps and sourcetypes to determine whether multiple indicators occur within the same investigation window.
- Investigate the source and context of matches, paying particular attention to Splunk UI access logs and other internal operational records.
- Document searches that produce no results and distinguish the absence of matching records from proof that an activity did not occur.
- Build a chronological timeline and assess each finding according to the strength and limitations of its supporting evidence.

### Expected Outcome

The analyst must produce a concise, evidence-based assessment that separates confirmed observations from plausible explanations and unresolved questions. The report should explain whether the available telemetry supports a suspicious-activity finding, identify the limitations of relying on `_internal` logs for endpoint investigation, and recommend additional evidence—such as Windows Security events, Sysmon process-creation events, or endpoint detection telemetry—needed to validate possible PowerShell execution.

The objective is not to force a malicious verdict, but to demonstrate a disciplined SOC investigation in which indicators are validated, correlations are treated cautiously, and conclusions remain proportional to the available evidence.

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

