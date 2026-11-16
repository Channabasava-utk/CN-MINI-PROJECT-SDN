# Monitoring and Visualization Dashboard

This module provides a browser-based dashboard for viewing SDN authentication and controller log analysis.

## Files
- `dashboard.html` — dashboard interface.
- `data/analysis_report.json` — generated analysis data used by the dashboard.

## Generate the report
From the repository root:

```bash
python3 team/Chandravadan/analysis/analyze_logs.py

```

## View the dashboard

From the repository root, start a local web server:

```bash
python3 -m http.server 8088
