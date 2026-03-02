#!/usr/bin/env python3
# mostly vibe-coded with cursor
"""
Enrich CSV vulnerability scan data with Red Hat VEX (Vulnerability Exploitability eXchange) information.

This script reads a CSV file containing vulnerability scan results and enriches it with
VEX data from Red Hat's security repository to help identify false-positives.
Also fetches RHSA advisory data for RHSA-prefixed vulnerabilities.
"""

import csv
import json
import sys
import re
import argparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from typing import Dict, Optional, List, Any
import time

# Base URL templates for Red Hat security data (year will be inserted dynamically)
VEX_BASE_URL_TEMPLATE = "https://security.access.redhat.com/data/csaf/v2/vex/{year}"
ADVISORY_BASE_URL_TEMPLATE = "https://security.access.redhat.com/data/csaf/v2/advisories/{year}"

# Cache to avoid fetching the same file multiple times (CVE and RHSA use same cache)
REDHAT_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}

# Rate limiting: small delay between requests to be respectful
REQUEST_DELAY = 0.1


def extract_year_from_id(identifier: str) -> Optional[str]:
    """
    Extract year from CVE or RHSA identifier.

    Args:
        identifier: CVE identifier (e.g., "CVE-2022-29458") or RHSA identifier (e.g., "RHSA-2025:16414")

    Returns:
        Year as string (e.g., "2022" or "2025") or None if not found
    """
    # Try CVE format: CVE-YYYY-NNNNN
    cve_match = re.search(r'CVE-(\d{4})', identifier, re.IGNORECASE)
    if cve_match:
        return cve_match.group(1)

    # Try RHSA format: RHSA-YYYY:NNNNN
    rhsa_match = re.search(r'RHSA-(\d{4}):', identifier, re.IGNORECASE)
    if rhsa_match:
        return rhsa_match.group(1)

    return None


def fetch_redhat_file(identifier: str, base_url_template: str) -> Optional[Dict[str, Any]]:
    """
    Unified function to fetch VEX or advisory files from Red Hat's repository.

    Args:
        identifier: CVE or RHSA identifier (e.g., "CVE-2022-29458" or "RHSA-2025:16414")
        base_url_template: URL template with {year} placeholder

    Returns:
        Parsed JSON document or None if not found
    """
    # Check cache first
    if identifier in REDHAT_CACHE:
        return REDHAT_CACHE[identifier]

    # Extract year from identifier
    year = extract_year_from_id(identifier)
    if not year:
        REDHAT_CACHE[identifier] = None
        return None

    # Generate filename - detect type from identifier
    if identifier.upper().startswith('CVE-'):
        # Format: CVE-YYYY-NNNNN -> cve-YYYY-NNNNN.json
        filename = f"{identifier.lower()}.json"
    elif identifier.upper().startswith('RHSA-'):
        # Format: RHSA-YYYY:NNNNN -> rhsa-YYYY_NNNNN.json
        rhsa_match = re.match(r'RHSA-\d{4}:(\d+)', identifier, re.IGNORECASE)
        if not rhsa_match:
            REDHAT_CACHE[identifier] = None
            return None
        filename = f"rhsa-{year}_{rhsa_match.group(1)}.json"
    else:
        REDHAT_CACHE[identifier] = None
        return None

    # Build URL and fetch
    base_url = base_url_template.format(year=year)
    url = f"{base_url}/{filename}"

    try:
        request = Request(url)
        request.add_header('User-Agent', 'Mozilla/5.0 (compatible; VEX-Enricher/1.0)')
        with urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            REDHAT_CACHE[identifier] = data
            time.sleep(REQUEST_DELAY)
            return data
    except (HTTPError, URLError, json.JSONDecodeError, ValueError, TimeoutError):
        pass

    REDHAT_CACHE[identifier] = None
    return None


def extract_vex_info(vex_data: Optional[Dict[str, Any]], cve_id: str,
                     product_name: str = "", os_version: str = "") -> Dict[str, str]:
    """
    Extract relevant VEX information from a VEX document.

    Args:
        vex_data: Parsed VEX JSON document
        cve_id: CVE identifier
        product_name: Product name from CSV (optional, for matching)
        os_version: OS version from CSV (optional, for matching)

    Returns:
        Dictionary with VEX information fields
    """
    if not vex_data:
        return {
            'RedHat_Severity': '',
            'RedHat_Justification': '',
            'RedHat_Details': ''
        }

    result = {
        'RedHat_Severity': '',
        'RedHat_Justification': '',
        'RedHat_Details': ''
    }

    try:
        # CSAF/VEX format structure - check document type
        document = vex_data.get('document', {})
        document_type = document.get('category', '')
        if document_type not in ['vex', 'csaf_vex']:
            # Not a VEX document, but try to parse anyway
            pass

        # Get severity from document aggregate_severity (Red Hat classification)
        aggregate_severity = document.get('aggregate_severity', {})
        if aggregate_severity:
            severity_text = aggregate_severity.get('text', '')
            if severity_text:
                result['RedHat_Severity'] = severity_text

        # Get vulnerabilities array
        vulnerabilities = vex_data.get('vulnerabilities', [])

        for vuln in vulnerabilities:
            # Check if this vulnerability matches our CVE
            # CVE can be a string or list in CSAF format
            cve_ids = vuln.get('cve', '')
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            elif not isinstance(cve_ids, list):
                cve_ids = []

            # Normalize and check
            if cve_id.upper() not in [c.upper() for c in cve_ids if c]:
                continue

            # Get notes/descriptions
            notes = vuln.get('notes', [])
            descriptions = []
            justifications = []

            for note in notes:
                if not isinstance(note, dict):
                    continue
                note_text = note.get('text', '')
                note_category = note.get('category', '')

                if note_category == 'description':
                    descriptions.append(note_text)
                elif note_category in ['other', 'summary']:
                    text_lower = note_text.lower()
                    if 'justification' in text_lower or 'not affected' in text_lower:
                        justifications.append(note_text)
                    else:
                        descriptions.append(note_text)

            if descriptions:
                result['RedHat_Details'] = ' | '.join(descriptions[:3])  # Limit to first 3
            if justifications:
                result['RedHat_Justification'] = ' | '.join(justifications[:2])  # Limit to first 2

            # Check for explicit justifications in the vulnerability object
            if 'justification' in vuln:
                justification = vuln['justification']
                if isinstance(justification, str):
                    result['RedHat_Justification'] = justification
                elif isinstance(justification, dict):
                    result['RedHat_Justification'] = str(justification)

            # Extract severity from CVSS scores (if not already set from document level)
            if not result['RedHat_Severity']:
                scores = vuln.get('scores', [])
                for score in scores:
                    if isinstance(score, dict):
                        cvss_v3 = score.get('cvss_v3', {})
                        if cvss_v3:
                            # Try both camelCase and snake_case for baseSeverity
                            base_severity = cvss_v3.get('baseSeverity', '') or cvss_v3.get('base_severity', '')
                            if base_severity:
                                result['RedHat_Severity'] = base_severity
                                break

            # If we found a match, break
            break

    except (KeyError, TypeError, AttributeError) as e:
        # If parsing fails, return empty result
        pass

    return result


def extract_advisory_info(advisory_data: Optional[Dict[str, Any]], rhsa_id: str) -> Dict[str, str]:
    """
    Extract relevant information from an advisory document.

    Args:
        advisory_data: Parsed advisory JSON document
        rhsa_id: RHSA identifier

    Returns:
        Dictionary with advisory information fields including severity
    """
    if not advisory_data:
        return {
            'RedHat_Severity': '',
            'RedHat_Summary': '',
            'RedHat_Details': '',
            'RedHat_CVEs': '',
            'RedHat_Justification': ''
        }

    result = {
        'RedHat_Severity': '',
        'RedHat_Summary': '',
        'RedHat_Details': '',
        'RedHat_CVEs': '',
        'RedHat_Justification': ''
    }

    try:
        # CSAF advisory format structure
        document = advisory_data.get('document', {})

        # Get severity from document tracking
        tracking = document.get('tracking', {})
        severity = tracking.get('severity', '')
        if severity:
            result['RedHat_Severity'] = severity

        # Get title/summary
        title = document.get('title', '')
        if title:
            result['RedHat_Summary'] = title

        # Get vulnerabilities and their CVEs
        vulnerabilities = advisory_data.get('vulnerabilities', [])
        cve_list = []
        descriptions = []

        for vuln in vulnerabilities:
            # Extract CVE IDs
            cve_ids = vuln.get('cve', '')
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            elif not isinstance(cve_ids, list):
                cve_ids = []

            for cve in cve_ids:
                if cve and cve not in cve_list:
                    cve_list.append(cve)

            # Get severity from vulnerability scores
            scores = vuln.get('scores', [])
            for score in scores:
                if isinstance(score, dict):
                    cvss_v3 = score.get('cvss_v3', {})
                    if cvss_v3:
                        base_severity = cvss_v3.get('base_severity', '')
                        if base_severity and not result['RedHat_Severity']:
                            result['RedHat_Severity'] = base_severity

            # Get notes/descriptions
            notes = vuln.get('notes', [])
            for note in notes:
                if isinstance(note, dict):
                    note_text = note.get('text', '')
                    if note_text and note_text not in descriptions:
                        descriptions.append(note_text)

        if cve_list:
            result['RedHat_CVEs'] = ', '.join(cve_list[:10])  # Limit to first 10
        if descriptions:
            result['RedHat_Details'] = ' | '.join(descriptions[:3])  # Limit to first 3

        # Alternative: get severity from product tree relationships
        if not result['RedHat_Severity']:
            product_tree = advisory_data.get('product_tree', {})
            relationships = product_tree.get('relationships', [])
            for rel in relationships:
                if isinstance(rel, dict) and 'severity' in rel:
                    result['RedHat_Severity'] = rel.get('severity', '')
                    break

    except (KeyError, TypeError, AttributeError) as e:
        # If parsing fails, return empty result
        pass

    return result


def extract_product_ids_from_branches(branches: List[Dict[str, Any]], product_ids: List[str]) -> None:
    """
    Recursively extract product IDs from nested branch structure.

    Args:
        branches: List of branch dictionaries from product_tree
        product_ids: List to accumulate product IDs
    """
    for branch in branches:
        # Check if this branch has a product
        product = branch.get('product')
        if product:
            prod_id = product.get('product_id', '')
            if prod_id:
                product_ids.append(prod_id)

        # Recursively check nested branches
        nested_branches = branch.get('branches', [])
        if nested_branches:
            extract_product_ids_from_branches(nested_branches, product_ids)


def check_product_affected_status(vex_data: Optional[Dict[str, Any]],
                                  advisory_data: Optional[Dict[str, Any]],
                                  product_id: Optional[str]) -> Dict[str, str]:
    """
    Check if a specified product is affected based on VEX/CSAF data.

    Args:
        vex_data: Parsed VEX JSON document
        advisory_data: Parsed advisory JSON document
        product_id: Red Hat product identifier to check

    Returns:
        Dictionary with product status information
    """
    result = {
        'RedHat_Product_ID': product_id or '',
        'RedHat_Product_Affected': ''
    }

    if not product_id:
        return result

    # Normalize product_id for comparison (case-insensitive)
    product_id_lower = product_id.lower()

    # Check VEX data first
    if vex_data:
        try:
            vulnerabilities = vex_data.get('vulnerabilities', [])

            # Check product status in vulnerabilities directly
            # Product IDs in product_status arrays match exactly with the provided product_id
            # Note: VEX uses "known_affected" and "known_not_affected" (not "affected" and "not_affected")
            for vuln in vulnerabilities:
                product_status = vuln.get('product_status', {})

                # Check known_not_affected (false positive indicator) - highest priority
                known_not_affected = product_status.get('known_not_affected', [])
                for prod in known_not_affected:
                    if product_id_lower == prod.lower():
                        result['RedHat_Product_Affected'] = 'known_not_affected'
                        return result

                # Check fixed
                fixed = product_status.get('fixed', [])
                for prod in fixed:
                    if product_id_lower == prod.lower():
                        result['RedHat_Product_Affected'] = 'fixed'
                        return result

                # Check known_affected
                known_affected = product_status.get('known_affected', [])
                for prod in known_affected:
                    if product_id_lower == prod.lower():
                        result['RedHat_Product_Affected'] = 'known_affected'
                        return result

                # Check under_investigation (if present)
                under_investigation = product_status.get('under_investigation', [])
                for prod in under_investigation:
                    if product_id_lower == prod.lower():
                        result['RedHat_Product_Affected'] = 'under_investigation'
                        return result
        except (KeyError, TypeError, AttributeError) as e:
            # If parsing fails, continue to advisory check
            pass

    # Check advisory data
    if advisory_data:
        try:
            product_tree = advisory_data.get('product_tree', {})

            # Try both products array and branches structure
            products = product_tree.get('products', [])
            if products:
                for product in products:
                    prod_id = product.get('product_id', '')
                    if product_id_lower == prod_id.lower():
                        if not result['RedHat_Product_Affected']:
                            result['RedHat_Product_Affected'] = 'known_affected'
                        return result

            # Check branches structure
            branches = product_tree.get('branches', [])
            if branches:
                all_product_ids = []
                extract_product_ids_from_branches(branches, all_product_ids)
                for prod_id in all_product_ids:
                    if product_id_lower == prod_id.lower():
                        if not result['RedHat_Product_Affected']:
                            result['RedHat_Product_Affected'] = 'known_affected'
                        return result
        except (KeyError, TypeError, AttributeError):
            pass

    # No match found
    if product_id:
        result['RedHat_Product_Affected'] = 'not_found_in_vex_csaf'
    return result


def extract_rhsa_id(vulnerability_name: str) -> Optional[str]:
    """
    Extract RHSA ID from vulnerability name field.

    Args:
        vulnerability_name: Value from "Vulnerability Name" column

    Returns:
        RHSA ID if found, None otherwise
    """
    if not vulnerability_name:
        return None

    # Look for RHSA-YYYY:NNNNN pattern
    rhsa_match = re.search(r'RHSA-\d{4}:\d+', vulnerability_name, re.IGNORECASE)
    if rhsa_match:
        return rhsa_match.group(0).upper()

    return None


def extract_cve_id(vulnerability_name: str) -> Optional[str]:
    """
    Extract CVE ID from vulnerability name field.

    Args:
        vulnerability_name: Value from "Vulnerability Name" column

    Returns:
        CVE ID if found, None otherwise
    """
    if not vulnerability_name:
        return None

    # Look for CVE-YYYY-NNNNN pattern
    cve_match = re.search(r'CVE-\d{4}-\d{4,}', vulnerability_name, re.IGNORECASE)
    if cve_match:
        return cve_match.group(0).upper()

    return None


def should_exclude_severity(severity: str, exclude_low_medium: bool) -> bool:
    """
    Check if a severity should be excluded based on filter settings.

    Args:
        severity: Severity string (low, medium, high, critical, etc.)
        exclude_low_medium: Whether to exclude low and medium severity

    Returns:
        True if should be excluded, False otherwise
    """
    if not exclude_low_medium:
        return False

    severity_lower = severity.lower().strip()
    return severity_lower in ['low', 'medium']


def enrich_csv(input_file: str, output_file: str, exclude_low_medium: bool = False, product_id: Optional[str] = None):
    """
    Read CSV, enrich with VEX and advisory data, and write to output file.

    Args:
        input_file: Path to input CSV file
        output_file: Path to output CSV file
        exclude_low_medium: If True, exclude rows with low or medium severity
        product_id: Optional Red Hat product ID to check against VEX/CSAF data
    """
    rows = []
    cve_column = None
    severity_column = None
    processed_cves = set()
    processed_rhsas = set()
    total_rows = 0
    excluded_rows = 0
    enriched_cve_count = 0
    enriched_rhsa_count = 0

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            fieldnames = list(reader.fieldnames)

            # Add unified enrichment columns (ordered: Severity first, then Justification)
            redhat_columns = [
                'RedHat_Severity',
                'RedHat_Justification',
                'RedHat_Details',
                'RedHat_Summary',
                'RedHat_CVEs',
                'RedHat_Source_Link',
                'RedHat_VEX_CSAF_Link',
                'RedHat_Product_ID',
                'RedHat_Product_Affected'
            ]
            for col in redhat_columns:
                if col not in fieldnames:
                    fieldnames.append(col)

            # Find the vulnerability name column
            for col in reader.fieldnames:
                if 'vulnerability' in col.lower() and 'name' in col.lower():
                    cve_column = col
                    break

            if not cve_column:
                # Try alternative column names
                for col in reader.fieldnames:
                    if 'cve' in col.lower():
                        cve_column = col
                        break

            if not cve_column:
                print("Warning: Could not find CVE/Vulnerability column. Trying 'Vulnerability Name'", file=sys.stderr)
                cve_column = 'Vulnerability Name'

            # Find the severity column
            for col in reader.fieldnames:
                if col.lower() == 'severity':
                    severity_column = col
                    break

            for row in reader:
                total_rows += 1

                # Check if we should exclude this row based on severity
                if exclude_low_medium and severity_column:
                    severity = row.get(severity_column, '')
                    if should_exclude_severity(severity, exclude_low_medium):
                        excluded_rows += 1
                        continue

                vulnerability_name = row.get(cve_column, '')
                cve_id = extract_cve_id(vulnerability_name)
                rhsa_id = extract_rhsa_id(vulnerability_name)

                # Initialize unified Red Hat data structure
                redhat_info = {
                    'RedHat_Severity': '',
                    'RedHat_Justification': '',
                    'RedHat_Details': '',
                    'RedHat_Summary': '',
                    'RedHat_CVEs': '',
                    'RedHat_Source_Link': '',
                    'RedHat_VEX_CSAF_Link': '',
                    'RedHat_Product_ID': product_id or '',
                    'RedHat_Product_Affected': ''
                }

                # Variables to store fetched data for guesstimation
                vex_data = None
                advisory_data = None

                # Process CVE (VEX data)
                if cve_id:
                    # Only fetch VEX data once per unique CVE
                    if cve_id not in processed_cves:
                        vex_data = fetch_redhat_file(cve_id, VEX_BASE_URL_TEMPLATE)
                        processed_cves.add(cve_id)

                        if vex_data:
                            enriched_cve_count += 1
                    else:
                        # Use cached data
                        vex_data = REDHAT_CACHE.get(cve_id)

                    # Extract VEX information
                    product_name = row.get('Resource', '')
                    os_version = row.get('OS Version', '')
                    vex_info = extract_vex_info(vex_data, cve_id, product_name, os_version)

                    # Merge VEX data into unified structure (VEX takes precedence for status/justification)
                    for key, value in vex_info.items():
                        if value:  # Only use non-empty values
                            redhat_info[key] = value

                    # Set source link for CVE
                    redhat_info['RedHat_Source_Link'] = f"https://access.redhat.com/security/cve/{cve_id.lower()}"

                    # Set VEX JSON link for CVE
                    year = extract_year_from_id(cve_id)
                    if year:
                        cve_lower = cve_id.lower()
                        if not cve_lower.startswith('cve-'):
                            cve_lower = f"cve-{cve_lower}"
                        redhat_info['RedHat_VEX_CSAF_Link'] = f"https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve_lower}.json"

                # Process RHSA (Advisory data)
                if rhsa_id:
                    # Only fetch advisory data once per unique RHSA
                    if rhsa_id not in processed_rhsas:
                        advisory_data = fetch_redhat_file(rhsa_id, ADVISORY_BASE_URL_TEMPLATE)
                        processed_rhsas.add(rhsa_id)

                        if advisory_data:
                            enriched_rhsa_count += 1
                    else:
                        # Use cached data
                        advisory_data = REDHAT_CACHE.get(rhsa_id)

                    # Extract advisory information
                    advisory_info = extract_advisory_info(advisory_data, rhsa_id)

                    # Merge advisory data into unified structure
                    # Advisory data fills in gaps or adds additional info
                    for key, value in advisory_info.items():
                        if value:  # Only use non-empty values
                            # For severity, prefer the more specific one
                            if key == 'RedHat_Severity' and redhat_info.get('RedHat_Severity'):
                                # Keep existing if both have values
                                continue
                            redhat_info[key] = value

                    # Set source link for RHSA (keep colon for errata URL)
                    # Format: RHSA-2025:16414 -> keep as RHSA-2025:16414 for errata URL
                    redhat_info['RedHat_Source_Link'] = f"https://access.redhat.com/errata/{rhsa_id}"

                    # Set CSAF JSON link for RHSA (replace colon with underscore for filename)
                    # Format: RHSA-2025:16414 -> rhsa-2025_16414.json
                    year = extract_year_from_id(rhsa_id)
                    if year:
                        # Extract number from RHSA ID
                        rhsa_match = re.match(r'RHSA-\d{4}:(\d+)', rhsa_id, re.IGNORECASE)
                        if rhsa_match:
                            number = rhsa_match.group(1)
                            filename = f"rhsa-{year}_{number}.json"
                            redhat_info['RedHat_VEX_CSAF_Link'] = f"https://security.access.redhat.com/data/csaf/v2/advisories/{year}/{filename}"

                # Check if specified product is affected in VEX/CSAF data
                if product_id:
                    # Use the fetched data for this row
                    product_status_info = check_product_affected_status(
                        vex_data,
                        advisory_data,
                        product_id
                    )

                    # Add product status info to redhat_info
                    redhat_info.update(product_status_info)

                # Add unified Red Hat columns to row
                for key, value in redhat_info.items():
                    row[key] = value

                rows.append(row)

        # Write enriched CSV
        with open(output_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        print(f"Processed {total_rows} rows")
        if exclude_low_medium:
            print(f"Excluded {excluded_rows} rows with low/medium severity")
        print(f"Found {len(processed_cves)} unique CVEs")
        print(f"Enriched {enriched_cve_count} CVEs with VEX data")
        if enriched_cve_count < len(processed_cves):
            print(f"Note: {len(processed_cves) - enriched_cve_count} CVEs had no VEX data available")
        print(f"Found {len(processed_rhsas)} unique RHSAs")
        print(f"Enriched {enriched_rhsa_count} RHSAs with advisory data")
        if enriched_rhsa_count < len(processed_rhsas):
            print(f"Note: {len(processed_rhsas) - enriched_rhsa_count} RHSAs had no advisory data available")
        print(f"Output written to: {output_file}")

    except FileNotFoundError:
        print(f"Error: Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error processing CSV: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Enrich CSV vulnerability scan data with Red Hat VEX and advisory information.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.csv output.csv
  %(prog)s input.csv output.csv --exclude-low-medium
  %(prog)s input.csv output.csv --exclude-low-medium --product-id "red_hat_openshift_container_platform_4:openshift4/ose-kube-rbac-proxy-rhel9"

The script adds the following unified Red Hat columns:
  RedHat_Severity, RedHat_Justification, RedHat_Details, RedHat_Summary,
  RedHat_CVEs, RedHat_Source_Link, RedHat_VEX_CSAF_Link, RedHat_Product_ID,
  RedHat_Product_Affected

Note: If --product-id is specified, the script will check VEX/CSAF data to
  determine if that specific product is affected by each vulnerability.
        """
    )
    parser.add_argument('input_file', help='Input CSV file')
    parser.add_argument('output_file', help='Output CSV file')
    parser.add_argument(
        '--exclude-low-medium',
        action='store_true',
        help='Exclude rows with low or medium severity from output'
    )
    parser.add_argument(
        '--product-id',
        type=str,
        default=None,
        help='Red Hat product ID to check against VEX/CSAF data (e.g., "red_hat_openshift_container_platform_4:openshift4/ose-kube-rbac-proxy-rhel9")'
    )

    args = parser.parse_args()

    enrich_csv(args.input_file, args.output_file, args.exclude_low_medium, args.product_id)


if __name__ == '__main__':
    main()
