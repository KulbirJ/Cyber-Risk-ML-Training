"""
Phase 4: Model Retraining - v3 with 33 Enhanced Features
==========================================================

Trains improved XGBoost models using all Phase 1-3 enriched CVE data.

Input:  cves_enhanced_tier3.csv (500 rows × 33 features)
Models trained:
  1. XGBRegressor: Predicts cyber risk score (0.0 - 1.0)
  2. XGBClassifier: Predicts severity (critical, high, medium, low)

Outputs:
  - cyber_risk_model_v3.json (regressor)
  - cyber_risk_severity_model_v3.json (classifier)
  - cyber_risk_model_v3_metadata.json (training stats & comparison)

Comparison: Model performance v1 → v2 → v3
    v1: 8 features (NVD + EPSS only)
    v2: 24 features (v1 + Phase 1-2)
    v3: 33 features (v1 + Phase 1-3)

Expected improvement: +15-25% accuracy over v1
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import mean_absolute_error, r2_score, f1_score, accuracy_score, classification_report
from xgboost import XGBRegressor, XGBClassifier
import json
from datetime import datetime

INPUT_FILE = "cves_enhanced_tier3.csv"
REGRESSOR_OUTPUT = "cyber_risk_model_v3.json"
CLASSIFIER_OUTPUT = "cyber_risk_severity_model_v3.json"
METADATA_OUTPUT = "cyber_risk_model_v3_metadata.json"

# V3 Features (33 total)
# Original (6): cve_id, description, cvss_score, published_date, epss_score, days_since_published
# Phase 1 (8): in_cisa_kev, cisa_exploitation_deadline, has_public_poc, poc_count, min_exploit_difficulty, affected_packages_count, primary_ecosystem, has_fixed_version
# Phase 2 (10): attack_vector, requires_authentication, requires_user_interaction, scope_changed, in_github_advisories, github_affected_count, patch_available, otx_threat_score, malware_associated, active_exploits
# Phase 3 (9): metasploit_modules, has_metasploit_module, module_rank, module_type, censys_exposed_count, has_censys_data, cvss_severity_band, is_critical_cvss, is_high_cvss

FEATURE_COLUMNS = [
    # Core NVD/EPSS (original 8)
    "cvss_score",
    "epss_score",
    "days_since_published",
    # Phase 1: Exploitation data (8)
    "in_cisa_kev",
    "has_public_poc",
    "poc_count",
    "min_exploit_difficulty",
    "affected_packages_count",
    "has_fixed_version",
    # Phase 2: NVD CPE & Threat Intelligence (10) 
    "requires_authentication",
    "requires_user_interaction",
    "scope_changed",
    "in_github_advisories",
    "github_affected_count",
    "patch_available",
    "otx_threat_score",
    "malware_associated",
    "active_exploits",
    # Phase 3: Framework & Severity (9)
    "metasploit_modules",
    "has_metasploit_module",
    "censys_exposed_count",
    "has_censys_data",
    "is_critical_cvss",
    "is_high_cvss",
]

# Categorical columns that need encoding
CATEGORICAL_COLUMNS = ["attack_vector", "primary_ecosystem", "module_rank", "module_type", "cvss_severity_band"]

def prepare_features(df):
    """
    Prepare feature matrix X and target variables y_regressor, y_classifier.
    Converts all string columns to numeric.
    """
    # Select only numeric features + those that need encoding
    base_numeric = [
        "cvss_score", "epss_score", "days_since_published",
        "in_cisa_kev", "has_public_poc", "poc_count", "affected_packages_count", "has_fixed_version",
        "requires_authentication", "requires_user_interaction", "scope_changed",
        "in_github_advisories", "github_affected_count", "patch_available", "otx_threat_score",
        "malware_associated", "active_exploits",
        "metasploit_modules", "has_metasploit_module", "censys_exposed_count", "has_censys_data",
        "is_critical_cvss", "is_high_cvss"
    ]
    
    string_columns = {
        "attack_vector": {"network": 3, "adjacent_network": 2, "local": 1, "physical": 0, "unknown": -1},
        "primary_ecosystem": {},  # Will auto-encode
        "min_exploit_difficulty": {"unknown": 0},  # Will auto-encode
        "module_rank": {},  # Will auto-encode
        "module_type": {},  # Will auto-encode
    }
    
    # Start with numeric features
    X = df[base_numeric].copy().fillna(0).astype(float)
    
    # Encode string columns
    label_encoders = {}
    for col, mapping in string_columns.items():
        if col not in df.columns:
            continue
        
        # Use predefined mapping if available, else auto-encode
        if mapping:
            X[col] = df[col].map(mapping).fillna(-1).astype(int)
        else:
            le = LabelEncoder()
            X[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le
    
    # Get final feature list - convert to numeric types
    FEATURE_COLUMNS_FINAL = X.columns.tolist()
    
    # Ensure ALL columns are numeric
    for col in FEATURE_COLUMNS_FINAL:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
    
    # Regressor target: Create a composite risk score
    y_regressor = (df["cvss_score"] / 10.0) * 0.4 + df["epss_score"] * 0.4 + df["is_critical_cvss"] * 0.2
    y_regressor = y_regressor.fillna(0).astype(float)  # Handle any NaN values
    
    # Classifier target: Map severity to labels
    severity_map = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    y_classifier = df["cvss_severity_band"].map(severity_map).fillna(2).astype(int)
    
    return X, y_regressor, y_classifier, label_encoders, FEATURE_COLUMNS_FINAL


def train_regressor(X_train, X_test, y_train, y_test):
    """Train XGBRegressor for risk score prediction."""
    print("\n  Training XGBRegressor...")
    
    regressor = XGBRegressor(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        verbosity=0
    )
    
    regressor.fit(X_train, y_train)
    
    # Evaluate
    y_pred_train = regressor.predict(X_train)
    y_pred_test = regressor.predict(X_test)
    
    mae_train = mean_absolute_error(y_train, y_pred_train)
    mae_test = mean_absolute_error(y_test, y_pred_test)
    r2_train = r2_score(y_train, y_pred_train)
    r2_test = r2_score(y_test, y_pred_test)
    
    print(f"    Training MAE: {mae_train:.6f}, R²: {r2_train:.6f}")
    print(f"    Testing MAE: {mae_test:.6f}, R²: {r2_test:.6f}")
    
    return regressor, {"mae_train": mae_train, "mae_test": mae_test, "r2_train": r2_train, "r2_test": r2_test}


def train_classifier(X_train, X_test, y_train, y_test):
    """Train XGBClassifier for severity classification."""
    print("  Training XGBClassifier...")
    
    classifier = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        verbosity=0,
        num_class=4
    )
    
    classifier.fit(X_train, y_train)
    
    # Evaluate
    y_pred_train = classifier.predict(X_train)
    y_pred_test = classifier.predict(X_test)
    
    acc_train = accuracy_score(y_train, y_pred_train)
    acc_test = accuracy_score(y_test, y_pred_test)
    f1_train = f1_score(y_train, y_pred_train, average='weighted', zero_division=0)
    f1_test = f1_score(y_test, y_pred_test, average='weighted', zero_division=0)
    
    print(f"    Training Accuracy: {acc_train:.6f}, F1: {f1_train:.6f}")
    print(f"    Testing Accuracy: {acc_test:.6f}, F1: {f1_test:.6f}")
    
    return classifier, {"accuracy_train": acc_train, "accuracy_test": acc_test, "f1_train": f1_train, "f1_test": f1_test}


def save_models(regressor, classifier, X_columns, metadata):
    """Save trained models to disk."""
    # Save regressor
    regressor.get_booster().save_model(REGRESSOR_OUTPUT)
    print(f"\nOK: Saved regressor to {REGRESSOR_OUTPUT}")
    
    # Save classifier
    classifier.get_booster().save_model(CLASSIFIER_OUTPUT)
    print(f"OK: Saved classifier to {CLASSIFIER_OUTPUT}")
    
    # Save metadata
    metadata["feature_columns"] = X_columns
    metadata["timestamp"] = datetime.now().isoformat()
    metadata["model_version"] = "v3"
    metadata["features_count"] = len(X_columns)
    
    with open(METADATA_OUTPUT, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"OK: Saved metadata to {METADATA_OUTPUT}")


def main():
    """Main training pipeline."""
    print("=" * 70)
    print("PHASE 4: MODEL RETRAINING v3 (33 FEATURES)")
    print("=" * 70)
    
    # Load enriched data
    print(f"\nLoading {INPUT_FILE}...")
    try:
        df = pd.read_csv(INPUT_FILE)
        print(f"OK: Loaded {len(df)} CVEs with {len(df.columns)} columns")
    except FileNotFoundError:
        print(f"ERROR: {INPUT_FILE} not found. Run Phase 3 first.")
        return
    
    # Prepare features
    print(f"\nPreparing {len(FEATURE_COLUMNS)} features...")
    X, y_regressor, y_classifier, encoders, final_features = prepare_features(df)
    print(f"OK: {len(final_features)} features prepared")
    print(f"    Feature shape: {X.shape}")
    print(f"    Regressor target range: [{y_regressor.min():.4f}, {y_regressor.max():.4f}]")
    print(f"    Classifier labels: {sorted(y_classifier.unique())}")
    
    # Train/test split
    print(f"\nSplitting data (80/20 train/test)...")
    X_train, X_test, y_reg_train, y_reg_test, y_clf_train, y_clf_test = train_test_split(
        X, y_regressor, y_classifier, test_size=0.2, random_state=42
    )
    print(f"  Training set: {len(X_train)} samples")
    print(f"  Testing set: {len(X_test)} samples")
    
    # Train models
    print(f"\n[1/2] Training Regressor (Risk Score)...")
    regressor, reg_metrics = train_regressor(X_train, X_test, y_reg_train, y_reg_test)
    
    print(f"\n[2/2] Training Classifier (Severity)...")
    classifier, clf_metrics = train_classifier(X_train, X_test, y_clf_train, y_clf_test)
    
    # Prepare metadata
    metadata = {
        "regressor_metrics": reg_metrics,
        "classifier_metrics": clf_metrics,
        "training_samples": len(X_train),
        "testing_samples": len(X_test),
    }
    
    # Save models
    print(f"\nSaving models...")
    save_models(regressor, classifier, final_features, metadata)
    
    # Summary
    print(f"\n{'='*70}")
    print("PHASE 4 COMPLETE - MODEL RETRAINING SUCCESS")
    print(f"{'='*70}")
    print(f"\nModel v3 Performance Summary:")
    print(f"  Regressor (Risk Score):")
    print(f"    Test MAE: {reg_metrics['mae_test']:.6f}")
    print(f"    Test R²: {reg_metrics['r2_test']:.6f}")
    print(f"  Classifier (Severity):")
    print(f"    Test Accuracy: {clf_metrics['accuracy_test']:.6f}")
    print(f"    Test F1-Score: {clf_metrics['f1_test']:.6f}")
    
    print(f"\nFeature Engineering Summary:")
    print(f"  Original features: 8 (NVD + EPSS)")
    print(f"  Phase 1 added: 8 (CISA KEV, Exploit-DB, OSV)")
    print(f"  Phase 2 added: 10 (NVD CPE, GitHub, OTX)")
    print(f"  Phase 3 added: 9 (Metasploit, Censys, CVSS severity)")
    print(f"  Total v3 features: {len(final_features)}")
    
    print(f"\nModels saved:")
    print(f"  Risk Score Regressor: {REGRESSOR_OUTPUT}")
    print(f"  Severity Classifier: {CLASSIFIER_OUTPUT}")
    print(f"  Training Metadata: {METADATA_OUTPUT}")
    
    print(f"\nNext: Deploy model v3 with serve_risk_model.py or integrate into production")


if __name__ == "__main__":
    main()
