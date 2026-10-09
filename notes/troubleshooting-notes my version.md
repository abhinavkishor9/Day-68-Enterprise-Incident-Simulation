# Troubleshooting Notes

## 1. The Investigation Uses `_internal` Telemetry

### Observation

The investigation returned operational sourcetypes such as:

- `splunkd`
- `splunkd_ui_access`
- `splunkd_access`
- `node:sidecar:kvstore_pdl:stdout`
- `node:sidecar:postgres:stdout`
- `node:supervisor`

### Explanation

The `_internal` index records Splunk's own operational activity. It is not a substitute for Windows Security events, Sysmon events, or endpoint detection telemetry.

### Recommended Action

Check which indexes are available before running endpoint detection searches.

```spl
| eventcount summarize=false index=*
| table index
```

Inspect sourcetypes in an index that actually contains endpoint data.

```spl
index=<endpoint_index>
| stats count by sourcetype
| sort - count
```

Replace `<endpoint_index>` with an existing index. Do not assume that an index or event source exists simply because a detection query expects it.

## 2. PowerShell Search Returns Operational Events

### Observation

The captured Last 24 hours search for `powershell.exe` returned four events under `splunkd`.

### Explanation

The string may occur in operational messages, request content, search expressions, or other application records.

### Recommended Action

Inspect the matching raw events.

```spl
index=_internal "powershell.exe"
| table _time host source sourcetype _raw
| sort _time
```

Determine whether an event represents a Windows process record or a string inside Splunk operational telemetry.

A string match alone is not evidence of process execution.

## 3. Encoded-Command Matches Appear in UI Access Logs

### Observation

The captured Last 24 hours search for `-EncodedCommand` returned 12 events, with displayed results under `splunkd_ui_access`.

### Explanation

A Splunk UI request can contain a search expression that includes `-EncodedCommand`. The request can therefore match the indicator without documenting actual PowerShell execution.

### Recommended Action

Inspect the event source and raw content.

```spl
index=_internal "-EncodedCommand"
| table _time host source sourcetype _raw
| sort _time
```

Validate the source before deciding whether the match is relevant to endpoint security.

## 4. Supporting-Indicator Search Returns Zero Results

### Observation

The search for `Invoke-Expression`, `IEX`, `DownloadString`, `FromBase64String`, and `WebClient` returned zero events.

### Explanation

The strings were not found in the available data under that query and time scope. This result does not prove that the associated behavior never occurred.

### Recommended Action

1. Confirm the selected time range.
2. Confirm that the intended index contains relevant telemetry.
3. Check the raw event format and field extraction.
4. Search the appropriate endpoint source if available.
5. Document the zero-result outcome without inventing supporting evidence.

## 5. Event Counts Differ Between Screenshots

### Observation

The captured searches reported different event totals, including 22,687, 23,069, 23,458, and 24,500.

### Explanation

The searches used different time ranges and were executed at different times. New operational events could also arrive between searches.

### Recommended Action

For comparisons, use the same index, time range, and query logic. Record the search time and scope when saving screenshots.

Do not compare All time and Last 24 hours counts as though they represent the same dataset.

## 6. High Event Volume Is Not Automatically Malicious

### Observation

The five-minute baseline showed 4,661 events at 09:50 and 3,177 events at 10:05 on October 8, 2026.

### Explanation

High event volume can result from normal Splunk operations, service activity, searches, or other workload changes.

### Recommended Action

Break down the interval by sourcetype.

```spl
index=_internal
| bin _time span=5m
| stats count by _time sourcetype
| sort - count
```

Inspect the dominant sourcetypes and raw events before assigning security significance.

## 7. Correlation Produces Multiple Indicator Counts

### Observation

The correlation query calculates counts for search, PowerShell, and encoded-command strings within five-minute intervals.

### Explanation

These counts represent events containing selected strings. They do not necessarily represent distinct actions or a single attack chain. One event can contribute to more than one indicator count.

### Recommended Action

Validate the raw events in the highest-interest interval. Check the source, timestamp, host, and context for each indicator before deciding whether the records are related.

## 8. Endpoint Compromise Cannot Be Confirmed

### Observation

The available evidence primarily comes from Splunk operational logs rather than independent endpoint process and security events.

### Explanation

The current data does not establish actual PowerShell process creation, malicious command execution, persistence, or endpoint compromise.

### Recommended Action

Collect appropriate endpoint telemetry, such as Windows process-creation events, Sysmon process events, relevant authentication logs, and endpoint detection records.

Revisit the incident hypothesis only when additional evidence is available.

