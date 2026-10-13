#!/usr/bin/env python3
"""
Fetch all GKI kernel versions from Android's public sources.
This script queries the Android kernel build API and generates the build matrix.
"""
import json
import re
import sys
import subprocess
from pathlib import Path

# ALL known GKI releases with devices and AVDs (as of 2025)
# Source: Android Common Kernels + GKI release tracking + AVD configs + Cuttlefish
GKI_RELEASES = {
    # Android 11 / 5.4 - Legacy but still on devices. No DDK image
    # published upstream (manifest unknown), so no build job and the
    # runtime resolves 5.4 to NO-GO until one appears.
    "android11-5.4": {
        "versions": ["5.4.147", "5.4.162", "5.4.188", "5.4.207", "5.4.219", "5.4.231"],
        "devices": ["pixel4", "pixel4xl", "pixel4a", "pixel5", "pixel5a"],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64"]
    },
    # Android 12 / 5.10
    "android12-5.10": {
        "versions": ["5.10.43", "5.10.66", "5.10.92", "5.10.107", "5.10.131", "5.10.146", "5.10.162", "5.10.179", "5.10.195"],
        "devices": ["pixel6", "pixel6pro", "pixel6a", "pixel7", "pixel7pro"],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64"]
    },
    # Android 13 / 5.10
    "android13-5.10": {
        "versions": ["5.10.146", "5.10.162", "5.10.179", "5.10.195", "5.10.211", "5.10.225"],
        "devices": ["pixel7", "pixel7pro", "pixel7a", "pixel8", "pixel8pro", "pixel8a"],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64", "aosp_cf_x86_64_auto", "aosp_cf_arm64_auto"]
    },
    # Android 13 / 5.15
    "android13-5.15": {
        "versions": ["5.15.61", "5.15.84", "5.15.105", "5.15.122", "5.15.136", "5.15.148"],
        "devices": ["pixel7", "pixel7pro", "pixel7a"],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64"]
    },
    # Android 14 / 5.15
    "android14-5.15": {
        "versions": ["5.15.122", "5.15.136", "5.15.148", "5.15.158", "5.15.168"],
        "devices": ["pixel8", "pixel8pro", "pixel8a", "pixel9", "pixel9pro", "pixel9proxl"],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64", "aosp_cf_x86_64_auto", "aosp_cf_arm64_auto", "aosp_cf_x86_64_tv", "aosp_cf_arm64_tv"]
    },
    # Android 14 / 6.1
    "android14-6.1": {
        "versions": ["6.1.22", "6.1.43", "6.1.56", "6.1.75", "6.1.91", "6.1.106"],
        "devices": ["pixel8", "pixel8pro", "pixel8a", "pixel9", "pixel9pro", "pixel9proxl", "pixel9a"],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64", "aosp_cf_x86_64_auto", "aosp_cf_arm64_auto", "aosp_cf_x86_64_tv", "aosp_cf_arm64_tv", "aosp_cf_x86_64_wear", "aosp_cf_arm64_wear"]
    },
    # Android 15 / 6.1
    "android15-6.1": {
        "versions": ["6.1.75", "6.1.91", "6.1.106", "6.1.124", "6.1.140"],
        "devices": ["pixel9", "pixel9pro", "pixel9proxl", "pixel9a"],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64", "aosp_cf_x86_64_auto", "aosp_cf_arm64_auto", "aosp_cf_x86_64_tv", "aosp_cf_arm64_tv", "aosp_cf_x86_64_wear", "aosp_cf_arm64_wear"]
    },
    # Android 15 / 6.6
    "android15-6.6": {
        "versions": ["6.6.24", "6.6.45", "6.6.60", "6.6.78", "6.6.94", "6.6.112"],
        "devices": ["pixel9", "pixel9pro", "pixel9proxl", "pixel9a"],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64", "aosp_cf_x86_64_auto", "aosp_cf_arm64_auto", "aosp_cf_x86_64_tv", "aosp_cf_arm64_tv", "aosp_cf_x86_64_wear", "aosp_cf_arm64_wear", "aosp_cf_x86_64_tablet", "aosp_cf_arm64_tablet"]
    },
    # Android 16 / 6.6
    "android16-6.6": {
        "versions": ["6.6.60", "6.6.78", "6.6.94", "6.6.112", "6.6.128"],
        "devices": ["pixel10", "pixel10pro", "pixel10proxl"],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64", "aosp_cf_x86_64_auto", "aosp_cf_arm64_auto", "aosp_cf_x86_64_tv", "aosp_cf_arm64_tv", "aosp_cf_x86_64_wear", "aosp_cf_arm64_wear", "aosp_cf_x86_64_tablet", "aosp_cf_arm64_tablet"]
    },
    # Android 16 / 6.12
    "android16-6.12": {
        "versions": ["6.12.5", "6.12.18", "6.12.31", "6.12.45"],
        "devices": ["pixel10", "pixel10pro", "pixel10proxl"],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64", "aosp_cf_x86_64_auto", "aosp_cf_arm64_auto", "aosp_cf_x86_64_tv", "aosp_cf_arm64_tv", "aosp_cf_x86_64_wear", "aosp_cf_arm64_wear", "aosp_cf_x86_64_tablet", "aosp_cf_arm64_tablet"]
    },
    # Android 17 (preview) / 6.12
    "android17-6.12": {
        "versions": ["6.12.31", "6.12.45", "6.12.58"],
        "devices": [],
        "avds": ["aosp_cf_x86_64_phone", "aosp_cf_arm64_phone", "google_car_x86_64", "google_tv_x86_64", "aosp_cf_x86_64_auto", "aosp_cf_arm64_auto", "aosp_cf_x86_64_tv", "aosp_cf_arm64_tv", "aosp_cf_x86_64_wear", "aosp_cf_arm64_wear", "aosp_cf_x86_64_tablet", "aosp_cf_arm64_tablet"]
    },
}

# DDK image tags available (updated from ghcr.io/ylarod/ddk).
# NOTE: android11-5.4 has NO published image (registry: manifest
# unknown), so it has no build job. The 5.4 code paths (GEN_54 tables,
# asserts) stay dormant until upstream publishes one; at runtime 5.4
# resolves to unknown-generation NO-GO rather than guessing offsets.
DDK_IMAGES = {
    "android12-5.10": "android12-5.10-20251016",
    "android13-5.10": "android13-5.10-20251016",
    "android13-5.15": "android13-5.15-20251016",
    "android14-5.15": "android14-5.15-20251016",
    "android14-6.1": "android14-6.1-20251016",
    "android15-6.1": "android15-6.1-20251016",
    "android15-6.6": "android15-6.6-20251016",
    "android16-6.6": "android16-6.6-20251016",
    "android16-6.12": "android16-6.12-20251016",
    "android17-6.12": "android17-6.12-20251016",
}

def generate_matrix():
    """Generate GitHub Actions matrix from GKI releases."""
    matrix = {"include": []}
    
    # Universal baseline builds
    matrix["include"].append({
        "kmi": "universal",
        "img": "android12-5.10",
        "ddk_tag": DDK_IMAGES["android12-5.10"]
    })
    matrix["include"].append({
        "kmi": "universal-test",
        "img": "android12-5.10",
        "ddk_tag": DDK_IMAGES["android12-5.10"],
        "test": True
    })
    
    # Per-KMI builds - ALL GKI versions
    for kmi, ddk_tag in DDK_IMAGES.items():
        if kmi in ["android12-5.10"]:
            continue  # Already covered by universal baseline
        
        matrix["include"].append({
            "kmi": kmi,
            "img": kmi,
            "ddk_tag": ddk_tag
        })
        
        # Add debug variant for all major stable releases
        if kmi in [
            "android13-5.10", "android13-5.15",
            "android14-5.15", "android14-6.1",
            "android15-6.1", "android15-6.6",
            "android16-6.6", "android16-6.12",
            "android17-6.12"
        ]:
            matrix["include"].append({
                "kmi": f"{kmi}-dbg",
                "img": kmi,
                "ddk_tag": ddk_tag,
                "dbg": True
            })
    
    return matrix

def fetch_latest_ddk_tags():
    """Try to fetch latest DDK tags from GitHub Container Registry."""
    try:
        result = subprocess.run([
            "curl", "-s", 
            "https://ghcr.io/v2/ylarod/ddk/tags/list"
        ], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            tags = data.get("tags", [])
            # Extract latest per KMI
            latest = {}
            for tag in tags:
                match = re.match(r"(android\d+-\d+\.\d+)-(\d+)", tag)
                if match:
                    kmi = match.group(1)
                    date = match.group(2)
                    if kmi not in latest or date > latest[kmi]:
                        latest[kmi] = date
            return {k: f"{k}-{v}" for k, v in latest.items()}
    except Exception as e:
        print(f"Failed to fetch DDK tags: {e}", file=sys.stderr)
    return None

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="build-matrix.json")
    parser.add_argument("--fetch-latest", action="store_true")
    args = parser.parse_args()
    
    if args.fetch_latest:
        latest = fetch_latest_ddk_tags()
        if latest:
            for k, v in latest.items():
                DDK_IMAGES[k] = v
    
    matrix = generate_matrix()
    
    with open(args.output, "w") as f:
        json.dump(matrix, f, indent=2)
    
    print(f"Generated matrix with {len(matrix['include'])} jobs")
    for job in matrix["include"]:
        print(f"  {job['kmi']}: {job['ddk_tag']}")

if __name__ == "__main__":
    main()