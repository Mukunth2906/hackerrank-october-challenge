import os
import sys
import json
import pandas as pd

sys.stdout.reconfigure(encoding='utf-8')

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_DIR = os.path.join(REPO_ROOT, "dataset")

def evaluate_samples():
    print("=" * 60)
    print("Running Sample Benchmark Evaluation")
    print("=" * 60)
    
    sample_out_path = os.path.join(DATASET_DIR, "sample_output.csv")
    if not os.path.exists(sample_out_path):
        print(f"Error: {sample_out_path} not found.")
        return

    sample_out = pd.read_csv(sample_out_path)
    print(f"Loaded {len(sample_out)} sample reference rows.")
    print("Status distribution in reference:")
    print(sample_out['deletion_status'].value_counts())
    print("=" * 60)

if __name__ == "__main__":
    evaluate_samples()
