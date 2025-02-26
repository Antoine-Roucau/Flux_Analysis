# Flux Analysis

## Overview
A comprehensive cybersecurity vulnerability monitoring and analysis tool that tracks ANSSI (French National Cybersecurity Agency) security bulletins, extracts CVE information, and provides analytical visualizations.

## Features
- Automated monitoring of ANSSI security alerts and advisories via RSS feeds
- CVE identification and extraction from bulletins
- Enrichment with MITRE CVE database information (CVSS scores, CWE types, affected products)
- Email notifications for new security bulletins
- Detailed visualization dashboard for vulnerability analysis

## Components
1. **Code_Alertes_Avis_ANSSI_MAJ_alertemail.py** - Core script for fetching and processing ANSSI bulletins
2. **schem.py** - Data visualization module with multiple chart generation functions
3. **alerte_avis.csv** - Dataset containing processed security bulletin information
4. **flux.ipynb** - Interactive presentation of analytical findings
5. **flux_final.html** (not included) - Generated vulnerability analysis report

## Visualizations
The tool generates various visualizations including:
- Severity distribution of vulnerabilities
- CWE type distribution
- EPSS score distribution
- Vendor analysis
- Correlation between CVSS and EPSS scores
- Temporal evolution of vulnerabilities
- Version analysis

## Notes
- Initial run will create a new dataset; subsequent runs will update the existing dataset
- Email notifications require a valid Gmail account for receiving alerts