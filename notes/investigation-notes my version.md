# Investigation Notes

## 1. Establish the Host Baseline

### SPL Query

```spl
index=_internal
| stats count by host
| sort - count
```

### Observation

The captured Last 24 hours search returned 22,687 events for `DESKTOP-9MMM37V`.

### Interpretation

The host appeared in the available Splunk operational telemetry. This establishes host context but does not demonstrate that the returned events originated from Windows endpoint security monitoring.

## 2. Identify Available Sourcetypes

### SPL Query

```spl
index=_internal
| stats count by sourcetype
| sort - count
```

### Selected Results

| Sourcetype | Events |
|---|---:|
| `splunkd` | 12,094 |
| `node:sidecar:kvstore_pdl:stdout` | 3,838 |
| `node:sidecar:postgres:stdout` | 1,859 |
| `splunkd_access` | 1,272 |
| `splunkd_ui_access` | 965 |
| `node:supervisor` | 916 |

These values came from the captured Last 24 hours search.

### Interpretation

The available dataset primarily represented Splunk application, access, and supporting-service activity. These sourcetypes did not independently establish Windows process execution or malicious endpoint behavior.

## 3. Establish a Five-Minute Event Baseline

### SPL Query

```spl
index=_internal
| bin _time span=5m
| stats count AS event_count by _time host
| sort _time
```

### Selected Results

| Time on October 8, 2026 | Host | Events |
|---|---|---:|
| 09:50 | `DESKTOP-9MMM37V` | 4,661 |
| 09:55 | `DESKTOP-9MMM37V` | 681 |
| 10:00 | `DESKTOP-9MMM37V` | 515 |
| 10:05 | `DESKTOP-9MMM37V` | 3,177 |
| 10:10 | `DESKTOP-9MMM37V` | 2,170 |
| 10:15 | `DESKTOP-9MMM37V` | 1,996 |

### Interpretation

Event volume varied substantially across the observed intervals. The periods at 09:50 and 10:05 had higher event counts than the neighboring intervals.

High volume is an investigative signal, not proof of an attack. Splunk operational activity can produce event spikes, so the source and composition of each interval must be examined before assigning security significance.

## 4. Investigate PowerShell-Related Indicators

### SPL Query

```spl
index=_internal "powershell.exe"
| stats count by sourcetype
| sort - count
| head 20
```

### Observation

The captured Last 24 hours search returned four events under the `splunkd` sourcetype.

### Interpretation

The search established that the string `powershell.exe` appeared in the matched operational data. It did not establish that a Windows process-creation event recorded PowerShell execution.

Inspect the raw events to determine why the string appeared and whether it represented relevant endpoint activity.

## 5. Investigate Encoded-Command Indicators

### SPL Query

```spl
index=_internal "-EncodedCommand"
| stats count by _time host sourcetype
| sort _time
| head 10
```

### Observation

The captured Last 24 hours search returned 12 events. The displayed results included `splunkd_ui_access` records on October 8 and October 9, 2026.

### Interpretation

The `splunkd_ui_access` sourcetype represents Splunk UI access telemetry. An encoded-command string in this source may occur in a search or UI request rather than document PowerShell execution on Windows.

The event source and raw content must be validated before treating the match as evidence of an endpoint attack.

## 6. Investigate Supporting PowerShell Indicators

### SPL Query

```spl
index=_internal
("Invoke-Expression" OR "IEX" OR "DownloadString" OR "FromBase64String" OR "WebClient")
| stats count by sourcetype
| sort - count
```

### Observation

The captured search returned zero events.

### Interpretation

The searched strings were not found in the available data under that query and time scope. This does not prove that the associated behaviors never occurred. It records only the result of the search against the selected telemetry.

## 7. Search for Discovery-Related Strings

### SPL Query

```spl
index=_internal
("whoami" OR "hostname" OR "ipconfig" OR "Get-Process")
| stats count by sourcetype
| sort - count
```

### Observation

The captured search returned 21,428 events. The largest counts included KV Store PDL output and supervisor logs.

### Interpretation

The results show that the searched strings occurred in operational records. They do not independently establish that the corresponding commands were executed on the endpoint.

Raw-event inspection and an appropriate endpoint process data source would be required to verify execution.

## 8. Correlate Indicators Across Five-Minute Windows

### SPL Query

```spl
index=_internal
| bin _time span=5m
| eval has_search=if(match(_raw,"(?i)search"),1,0)
| eval has_powershell=if(match(_raw,"(?i)powershell\.exe"),1,0)
| eval has_encoded=if(match(_raw,"(?i)-EncodedCommand"),1,0)
| stats count AS total_events
    sum(has_search) AS search_events
    sum(has_powershell) AS powershell_events
    sum(has_encoded) AS encoded_events
    values(sourcetype) AS sourcetypes
    by _time host
| where search_events > 0
| table _time host total_events search_events powershell_events encoded_events sourcetypes
| sort _time
```

### Purpose

This query groups events by host and five-minute interval, then counts records containing each selected string.

### Interpretation

The query identifies intervals that merit closer inspection. However, the counts represent matching events, not necessarily distinct searches, process executions, or malicious actions. A single event can contain multiple strings.

A common time window establishes temporal overlap only. It does not prove that the events belong to the same attack.

## 9. Evidence Assessment

| Finding | Assessment |
|---|---|
| `DESKTOP-9MMM37V` present in `_internal` | Confirmed |
| Multiple Splunk operational sourcetypes present | Confirmed |
| Event-volume variation across five-minute intervals | Confirmed |
| `powershell.exe` string found in `splunkd` records | Confirmed |
| `-EncodedCommand` string found in `splunkd_ui_access` records | Confirmed |
| Supporting-indicator search returned zero events | Confirmed for the captured query and scope |
| Actual Windows PowerShell process execution | Not established |
| Malicious encoded PowerShell execution | Not established |
| Endpoint compromise | Not established |

