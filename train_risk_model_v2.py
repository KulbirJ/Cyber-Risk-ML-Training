# train_risk_model_v2.py
"""
Enhanced training script with new features:
- text_length_of_description: character count of CVE description
- has_ransomware_keyword: binary feature (1 if description mentions ransomware)
- days_since_published_category: categorical (new=0-30 days, old=31+ days)
- attack_trend_score: simulated/fake trend score

Trains both Regression and Classification models.
Compares performance with the original model (v1).
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error, r2_score, f1_score, classification_report, confusion_matrix
from xgboost import XGBRegressor, XGBClassifier
import json
import warnings
warnings.filterwarnings('ignore')

# ── Step 1: Load data ────────────────────────────────────────────────────────

print("=" * 80)
print("LOADING DATA WITH FEATURE ENGINEERING")
print("=" * 80)

df = pd.read_csv("cves_clean_enriched.csv")
print(f"Loaded {len(df)} CVE records")

# Create attack_count placeholder (like in v1 training)
np.random.seed(42)
df["attack_count"] = np.random.randint(0, 6, size=len(df))

# ── Step 2: Add new features ─────────────────────────────────────────────────

print("\n" + "=" * 80)
print("ENGINEERING NEW FEATURES")
print("=" * 80)

# --- Feature 1: Text length of description ---
# Longer descriptions could indicate more detailed vulnerability info
df["text_length_of_description"] = df["description"].fillna("").str.len()

print(f"✓ text_length_of_description")
print(f"  Min: {df['text_length_of_description'].min()}")
print(f"  Max: {df['text_length_of_description'].max()}")
print(f"  Mean: {df['text_length_of_description'].mean():.1f}")

# --- Feature 2: Has ransomware keyword ---
# Ransomware is a real threat; mention of it might indicate higher risk
ransomware_keywords = ["ransomware", "encrypt", "lockbit", "conti", "alphv", "blackcat"]
df["has_ransomware_keyword"] = (
    df["description"]
    .fillna("")
    .str.lower()
    .apply(lambda x: 1 if any(keyword in x for keyword in ransomware_keywords) else 0)
)

ransomware_count = df["has_ransomware_keyword"].sum()
print(f"\n✓ has_ransomware_keyword")
print(f"  CVEs mentioning ransomware: {ransomware_count} ({100*ransomware_count/len(df):.1f}%)")

# --- Feature 3: Days since published category ---
# Categorize CVEs as "new" (0-30 days) or "old" (31+ days)
# Newer CVEs may have different risk patterns
df["days_since_published_category"] = (
    df["days_since_published"]
    .apply(lambda x: 0 if x <= 30 else 1)  # 0=new, 1=old
)

new_count = (df["days_since_published_category"] == 0).sum()
old_count = (df["days_since_published_category"] == 1).sum()
print(f"\n✓ days_since_published_category")
print(f"  New (0-30 days):   {new_count} CVEs ({100*new_count/len(df):.1f}%)")
print(f"  Old (31+ days):    {old_count} CVEs ({100*old_count/len(df):.1f}%)")

# --- Feature 4: Attack trend score (fake for now) ---
# In production, this would come from exploit databases, threat intel, etc.
# For now, generate a fake trend score based on:
#   - Higher EPSS → higher trend
#   - Newer CVEs → higher trend (more recent threats)
np.random.seed(42)
df["attack_trend_score"] = (
    df["epss_score"] * 0.5 +  # EPSS contributes 50%
    (1 - df["days_since_published"] / df["days_since_published"].max()) * 0.3 +  # Recency 30%
    np.random.uniform(0, 1, len(df)) * 0.2  # Random noise 20%
)

print(f"\n✓ attack_trend_score (simulated)")
print(f"  Min: {df['attack_trend_score'].min():.4f}")
print(f"  Max: {df['attack_trend_score'].max():.4f}")
print(f"  Mean: {df['attack_trend_score'].mean():.4f}")

# ── Step 3: Create target variable ───────────────────────────────────────────

df["epss_score"] = df["epss_score"].fillna(0)
df["risk_score"] = df["cvss_score"] * 1.5 + df["epss_score"] * 50

# ── Step 4: Create severity labels ──────────────────────────────────────────

def assign_severity(row):
    cvss = row["cvss_score"]
    epss = row["epss_score"]
    if epss > 0.7 or cvss >= 9.0:
        return 3
    elif cvss >= 7.0 and (epss > 0.2 or cvss >= 8.5):
        return 2
    elif cvss >= 5.0 and (epss > 0.05 or cvss >= 6.5):
        return 1
    else:
        return 0

df["severity_label"] = df.apply(assign_severity, axis=1)

# ── Step 5: Prepare features (OLD vs NEW) ───────────────────────────────────

print("\n" + "=" * 80)
print("FEATURE COMPARISON")
print("=" * 80)

# OLD features (from v1)
features_old = ["cvss_score", "epss_score", "days_since_published", "attack_count"]

# NEW features (v2) - includes all old + new engineered features
features_new = features_old + [
    "text_length_of_description",
    "has_ransomware_keyword",
    "days_since_published_category",
    "attack_trend_score"
]

print(f"\n📊 OLD Features (v1):  {features_old}")
print(f"📊 NEW Features (v2):  {features_new}")

# ── Step 6: Prepare data and handle missing values ──────────────────────────

X_old = df[features_old].copy()
X_new = df[features_new].copy()
y = df["risk_score"]

# Remove rows with missing target
valid_idx = ~y.isna()
X_old = X_old[valid_idx]
X_new = X_new[valid_idx]
y = y[valid_idx]

# Fill missing values
X_old = X_old.fillna(X_old.mean())
X_new = X_new.fillna(X_new.mean())

print(f"\nDataset shape after cleaning: {X_old.shape}")

# ── Step 7: Split data ──────────────────────────────────────────────────────

X_train_old, X_test_old, y_train, y_test = train_test_split(
    X_old, y, test_size=0.2, random_state=42
)

X_train_new, X_test_new, _, _ = train_test_split(
    X_new, y, test_size=0.2, random_state=42  # Same split
)

y_clf = df.loc[valid_idx, "severity_label"]
X_train_clf_old, X_test_clf_old, y_train_clf, y_test_clf = train_test_split(
    X_old, y_clf, test_size=0.2, random_state=42, stratify=y_clf
)

X_train_clf_new, X_test_clf_new, _, _ = train_test_split(
    X_new, y_clf, test_size=0.2, random_state=42, stratify=y_clf
)

# ── Step 8: Train models on OLD features ────────────────────────────────────

print("\n" + "=" * 80)
print("TRAINING MODEL V1 (OLD FEATURES)")
print("=" * 80)

model_old = XGBRegressor(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42, verbosity=0)
model_old.fit(X_train_old, y_train)

y_pred_old = model_old.predict(X_test_old)
mae_old = mean_absolute_error(y_test, y_pred_old)
r2_old = r2_score(y_test, y_pred_old)

print(f"✓ Model V1 trained")
print(f"  MAE:  {mae_old:.6f}")
print(f"  R²:   {r2_old:.6f}")

# ── Step 9: Train models on NEW features ────────────────────────────────────

print("\n" + "=" * 80)
print("TRAINING MODEL V2 (NEW FEATURES)")
print("=" * 80)

model_new = XGBRegressor(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42, verbosity=0)
model_new.fit(X_train_new, y_train)

y_pred_new = model_new.predict(X_test_new)
mae_new = mean_absolute_error(y_test, y_pred_new)
r2_new = r2_score(y_test, y_pred_new)

print(f"✓ Model V2 trained")
print(f"  MAE:  {mae_new:.6f}")
print(f"  R²:   {r2_new:.6f}")

# ── Step 10: Compare results ────────────────────────────────────────────────

print("\n" + "=" * 80)
print("REGRESSION MODEL COMPARISON (Risk Score)")
print("=" * 80)

mae_improvement = mae_old - mae_new
mae_pct_change = (mae_improvement / mae_old) * 100

r2_improvement = r2_new - r2_old
r2_pct_change = (r2_improvement / r2_old) * 100

print(f"""
╔════════════════════════════════════╗
║         MODEL COMPARISON           ║
╠════════════════════════════════════╣
║ Metric         │  V1 (Old)  │  V2 (New)
╟────────────────────────────────────╢
║ MAE            │  {mae_old:.6f}  │  {mae_new:.6f}
║ R² Score       │  {r2_old:.6f}  │  {r2_new:.6f}
╠════════════════════════════════════╣
║ MAE Change:    {mae_improvement:+.6f}  ({mae_pct_change:+.2f}%)
║ R² Change:     {r2_improvement:+.6f}  ({r2_pct_change:+.2f}%)
╚════════════════════════════════════╝
""")

if mae_new < mae_old:
    print(f"✅ NEW FEATURES IMPROVED MAE by {abs(mae_pct_change):.2f}%")
else:
    print(f"⚠️  NEW FEATURES DEGRADED MAE by {abs(mae_pct_change):.2f}%")

# ── Step 11: Feature importance analysis ────────────────────────────────────

print("\n" + "=" * 80)
print("FEATURE IMPORTANCE ANALYSIS")
print("=" * 80)

# Get feature importance for both models
importance_old = model_old.get_booster().get_score(importance_type='weight')
importance_new = model_new.get_booster().get_score(importance_type='weight')

# Convert to DataFrames for easier viewing
imp_old_df = pd.DataFrame(list(importance_old.items()), columns=["Feature", "Importance"]).sort_values("Importance", ascending=False)
imp_new_df = pd.DataFrame(list(importance_new.items()), columns=["Feature", "Importance"]).sort_values("Importance", ascending=False)

print("\nV1 Feature Importance (OLD):")
print(imp_old_df.to_string(index=False))

print("\n\nV2 Feature Importance (NEW):")
print(imp_new_df.to_string(index=False))

# Calculate importance contributions of new features
new_features_importance = imp_new_df[imp_new_df["Feature"].isin([
    "text_length_of_description",
    "has_ransomware_keyword",
    "days_since_published_category",
    "attack_trend_score"
])]["Importance"].sum()

total_importance_v2 = imp_new_df["Importance"].sum()
new_features_pct = (new_features_importance / total_importance_v2) * 100

print(f"\n\nNew Features Contribution: {new_features_pct:.1f}% of total importance")

# ── Step 12: Train and evaluate classification models ─────────────────────────

print("\n" + "=" * 80)
print("CLASSIFICATION MODEL COMPARISON (Severity)")
print("=" * 80)

# Train classifiers
clf_old = XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42, num_class=4, objective="multi:softprob", verbosity=0)
clf_old.fit(X_train_clf_old, y_train_clf)
y_pred_clf_old = clf_old.predict(X_test_clf_old)
f1_old = f1_score(y_test_clf, y_pred_clf_old, average="weighted")

clf_new = XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42, num_class=4, objective="multi:softprob", verbosity=0)
clf_new.fit(X_train_clf_new, y_train_clf)
y_pred_clf_new = clf_new.predict(X_test_clf_new)
f1_new = f1_score(y_test_clf, y_pred_clf_new, average="weighted")

print(f"""
Classification (Severity) F1 Scores:
  V1 (Old): {f1_old:.6f}
  V2 (New): {f1_new:.6f}
  Change:   {f1_new - f1_old:+.6f}
""")

# ── Step 13: Save v2 models ────────────────────────────────────────────────

print("\n" + "=" * 80)
print("SAVING MODELS")
print("=" * 80)

model_new.get_booster().save_model("cyber_risk_model_v2.json")
clf_new.get_booster().save_model("cyber_risk_severity_model_v2.json")

metadata_v2 = {
    "model_type": "XGBRegressor",
    "version": "v2",
    "training_date": pd.Timestamp.now().isoformat(),
    "features": features_new,
    "metrics": {
        "MAE": float(mae_new),
        "R2": float(r2_new),
        "MAE_vs_v1": float(mae_improvement),
        "MAE_improvement_pct": float(mae_pct_change)
    }
}

with open("cyber_risk_model_v2_metadata.json", "w") as f:
    json.dump(metadata_v2, f, indent=2)

print(f"✓ Model V2 saved to: cyber_risk_model_v2.json")
print(f"✓ Metadata saved to: cyber_risk_model_v2_metadata.json")

# ── Step 14: Summary ────────────────────────────────────────────────────────

print("\n" + "=" * 80)
print("TRAINING COMPLETE - SUMMARY")
print("=" * 80)

print(f"""
📊 REGRESSION MODEL (Risk Score Prediction)
   Version 1 (Old Features):  MAE = {mae_old:.6f}, R² = {r2_old:.6f}
   Version 2 (New Features):  MAE = {mae_new:.6f}, R² = {r2_new:.6f}
   
   Improvement: {mae_improvement:+.6f} MAE ({mae_pct_change:+.2f}%)

💾 NEW FEATURES ADDED:
   1. text_length_of_description  – Length of CVE description
   2. has_ransomware_keyword      – Binary indicator (0/1)
   3. days_since_published_category – Categorical (new=0, old=1)
   4. attack_trend_score          – Simulated threat trend (0-1)

🎯 NEW FEATURES CONTRIBUTION: {new_features_pct:.1f}% of model importance

📦 FILES SAVED:
   • cyber_risk_model_v2.json
   • cyber_risk_model_v2_metadata.json
   • cyber_risk_severity_model_v2.json

Next Steps:
   ✓ Compare model predictions on specific CVEs
   ✓ Tune hyperparameters further
   ✓ Add more real-world features (e.g., from NVD API, GitHub, etc.)
   ✓ Validate on new unseen CVEs
   ✓ Deploy v2 to production if improvements are significant
""")

print("=" * 80)
