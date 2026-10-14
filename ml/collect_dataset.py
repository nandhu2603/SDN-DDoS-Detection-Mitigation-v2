"""
Dataset Collection and Synthetic Lab Flow Generator.

Collects labeled flow statistics from either:
  1. A running live Ryu SDN Controller / Mininet lab via polling
  2. Realistic synthetic flow generation matching Mininet SDN traffic patterns
     (Normal web/DNS/ping vs SYN flood, UDP flood, ICMP flood)

Outputs:
  - ml/dataset/flow_dataset.csv
"""

import argparse
import os
import random
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd
import yaml

from controller.feature_extractor import FeatureExtractor
from traffic.traffic_generator import (
    simulate_normal_traffic_window,
    simulate_attack_traffic_window,
)


def load_config(config_path: str = "config.yaml") -> dict:
    """Load system configuration from YAML."""
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


def generate_synthetic_dataset(
    output_path: str = "ml/dataset/flow_dataset.csv",
    num_normal_samples: int = 1500,
    num_attack_samples: int = 1500,
    random_seed: int = 42,
) -> pd.DataFrame:
    """
    Generate a balanced, realistic labeled SDN traffic dataset with diverse
    attack vectors (SYN flood, UDP flood, ICMP flood, IP spoofing) and normal flows.
    """
    random.seed(random_seed)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    extractor = FeatureExtractor(default_interval=3.0)
    dataset_records = []

    print(f"[INFO] Generating {num_normal_samples} normal traffic samples...")
    # 1. Normal Traffic Samples
    for i in range(num_normal_samples):
        extractor.reset()
        flows = simulate_normal_traffic_window(window_duration=3.0)
        # Small variations in duration / jitter
        elapsed = random.uniform(2.8, 3.2)
        features = extractor.extract_features(flows, elapsed_time=elapsed)
        features["label"] = 0  # 0: Normal
        features["attack_type"] = "normal"
        dataset_records.append(features)

    print(f"[INFO] Generating {num_attack_samples} attack traffic samples...")
    attack_types = ["syn", "udp", "icmp"]
    samples_per_type = num_attack_samples // len(attack_types)

    # 2. Attack Traffic Samples
    for atk in attack_types:
        for i in range(samples_per_type):
            extractor.reset()
            # 50% chance of random source spoofing vs fixed botnet
            spoof = random.random() > 0.5
            intensity = random.uniform(0.8, 2.5)
            victim = random.choice(["10.0.0.4", "10.0.0.5"])
            flows = simulate_attack_traffic_window(
                attack_type=atk,
                victim_ip=victim,
                spoof_ips=spoof,
                window_duration=3.0,
                intensity=intensity,
            )
            elapsed = random.uniform(2.8, 3.2)
            features = extractor.extract_features(flows, elapsed_time=elapsed)
            features["label"] = 1  # 1: Attack
            features["attack_type"] = atk
            dataset_records.append(features)

    df = pd.DataFrame(dataset_records)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)

    df.to_csv(output_path, index=False)
    print(f"[SUCCESS] Dataset saved to {output_path} (Total samples: {len(df)})")
    print(f"[INFO] Class distribution:\n{df['label'].value_counts(normalize=True).to_dict()}")
    print(f"[INFO] Attack breakdown:\n{df['attack_type'].value_counts().to_dict()}")
    return df


def collect_from_live_controller(
    controller_url: str = "http://127.0.0.1:5000/api/status",
    output_path: str = "ml/dataset/live_flow_dataset.csv",
    samples: int = 100,
    interval: float = 3.0,
    label: int = 0,
    attack_type: str = "normal",
):
    """Poll live controller REST endpoint and log features into dataset CSV."""
    import requests

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    records = []
    print(f"[INFO] Polling live controller {controller_url} for {samples} samples (label={label})...")
    
    for i in range(samples):
        try:
            resp = requests.get(controller_url, timeout=interval)
            if resp.status_code == 200:
                data = resp.json().get("latest_features", {})
                if data:
                    data["label"] = label
                    data["attack_type"] = attack_type
                    records.append(data)
                    print(f"[{i+1}/{samples}] Logged: pps={data.get('packet_rate')} entropy={data.get('src_ip_entropy')}")
        except Exception as e:
            print(f"[WARN] Failed to poll controller: {e}")
        time.sleep(interval)

    if records:
        df = pd.DataFrame(records)
        mode = "a" if os.path.exists(output_path) else "w"
        header = not os.path.exists(output_path)
        df.to_csv(output_path, mode=mode, header=header, index=False)
        print(f"[SUCCESS] Appended {len(df)} samples to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SDN Dataset Collector")
    parser.add_argument("--generate", action="store_true", default=True, help="Generate synthetic dataset")
    parser.add_argument("--samples", type=int, default=3000, help="Total samples (default: 3000)")
    parser.add_argument("--live", action="store_true", help="Collect from live controller")
    parser.add_argument("--output", default="ml/dataset/flow_dataset.csv", help="Output CSV path")
    args = parser.parse_args()

    config = load_config()
    out_file = args.output or config.get("ml", {}).get("dataset_path", "ml/dataset/flow_dataset.csv")

    if args.live:
        collect_from_live_controller(output_path=out_file)
    else:
        num_normal = args.samples // 2
        num_attack = args.samples - num_normal
        generate_synthetic_dataset(output_path=out_file, num_normal_samples=num_normal, num_attack_samples=num_attack)
