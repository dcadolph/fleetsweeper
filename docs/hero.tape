# VHS recording script for the README hero animation.
#
# Re-render with:
#   vhs docs/hero.tape
#
# This script assumes:
#   - The fleetsweeper binary is on $PATH (or use ./fleetsweeper).
#   - A headless browser is not required: VHS captures a terminal session.
#
# What it shows: launching the demo server, then a short scripted curl tour
# of the JSON API so the GIF doubles as proof the API is real, not just a UI.
# If you want a browser-driven hero showing the globe and dashboard, record
# that separately with QuickTime or OBS and drop the resulting GIF into
# docs/hero.gif. This tape is the lightweight fallback that anyone with the
# binary can re-render in seconds.

Output docs/hero.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set Padding 18

Type "fleetsweeper serve --demo --addr :8080 &" Sleep 500ms Enter
Sleep 2s
Type "clear" Enter
Sleep 200ms

Type "# 26-cluster synthetic fleet across four continents." Enter
Sleep 800ms
Type "curl -s localhost:8080/api/geo | jq '.points | length'" Enter
Sleep 1500ms

Type "# Findings come ranked with kubectl remediation attached." Enter
Sleep 800ms
Type "curl -s localhost:8080/api/scans/demo-scan-0001/report | jq '.findings[0] | {severity, title, cluster, kubectl: .remediation.command}'" Enter
Sleep 2500ms

Type "# Top fleet score on the dashboard at http://localhost:8080" Enter
Sleep 800ms
Type "curl -s localhost:8080/api/scans/demo-scan-0001/report | jq '.fleet_score'" Enter
Sleep 2s

Type "kill %1 2>/dev/null" Enter
Sleep 500ms
