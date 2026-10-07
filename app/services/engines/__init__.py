"""Security engine package."""
"""Per-finding AI enrichment: explanation, impact, remediation.

Separate from ai_service.analyze_findings (free-text chat across many
findings). This module adds structured, validated fields to a single
Vulnerability. It is additive only -- it never changes severity, confidence,
or any detection result, and failures here never affect the scan itself.
"""
