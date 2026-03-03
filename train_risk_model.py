# train_risk_model.py
"""
Complete machine learning pipeline to predict CVE risk scores.

This script demonstrates:
1. Loading and preparing data
2. Creating a target variable
3. Splitting into training and test sets
4. Training an XGBoost regressor
5. Evaluating model performance
6. Saving the trained model

Detailed comments explain each step for beginners.
"""

# ── Step 0: Import required libraries ─────────────────────────────────────────

import pandas as pd                          # Data manipulation and analysis
import numpy as np                           # Numerical operations
from sklearn.model_selection import train_test_split  # Split data into train/test
from sklearn.metrics import mean_absolute_error, r2_score  # Performance metrics
from sklearn.metrics import confusion_matrix, f1_score, classification_report  # Classification metrics
from xgboost import XGBRegressor, XGBClassifier  # XGBoost models
import json                                  # Save/load JSON format files

# ── Step 1: Load the CSV file ─────────────────────────────────────────────────
# Read cves_clean_enriched.csv into a pandas DataFrame (a table in memory)

print("=" * 80)
print("LOADING DATA")
print("=" * 80)

df = pd.read_csv("cves_clean_enriched.csv")

print(f"Loaded DataFrame with shape: {df.shape[0]} rows × {df.shape[1]} columns")
print(f"Columns: {', '.join(df.columns.tolist())}")
print(f"\nFirst 3 rows:")
print(df.head(3))

# ── Step 2: Create a placeholder for attack_count (you can replace this later) ─

# For now, generate random attack counts (0-5) to simulate real data
# Later you can load these from an actual data source
np.random.seed(42)  # Use a fixed seed so results are reproducible
df["attack_count"] = np.random.randint(0, 6, size=len(df))

print(f"\n✓ Added placeholder 'attack_count' column")

# ── Step 3: Create the target variable (risk_score) ───────────────────────────
# 
# In a real ML pipeline, this would be:
#   - Historical data of actual risk scores
#   - Expert-labeled severity ratings
#   - Number of known exploits in the wild
#
# For now, use a formula to simulate what risk might look like:
#   risk_score = cvss_score * 1.5 + epss_score * 50
#
# Interpretation:
#   - CVSS (CVSS score 0-10) weighted at 1.5x
#   - EPSS (exploit probability 0-1) weighted at 50x
#   - Total result typically in range 0-65

print("\n" + "=" * 80)
print("CREATING TARGET VARIABLE (risk_score)")
print("=" * 80)

# Before calculating risk_score, fill any missing EPSS scores with 0
# (conservative assumption: no known exploit probability = 0)
df["epss_score"] = df["epss_score"].fillna(0)

# Formula: weight CVSS by 1.5 and EPSS by 50
df["risk_score"] = df["cvss_score"] * 1.5 + df["epss_score"] * 50

print(f"risk_score created using formula: cvss_score * 1.5 + epss_score * 50")
print(f"  Min risk_score: {df['risk_score'].min():.2f}")
print(f"  Max risk_score: {df['risk_score'].max():.2f}")
print(f"  Mean risk_score: {df['risk_score'].mean():.2f}")
print(f"  Std dev: {df['risk_score'].std():.2f}")

# ── Step 4: Select features (predictors) ──────────────────────────────────────
#
# Features = columns we use to make predictions
# Target = column we're trying to predict (risk_score)
#
# We'll use numeric columns that have predictive power:
#   - cvss_score: base vulnerability severity (0-10)
#   - epss_score: probability of being exploited (0-1)
#   - days_since_published: age of the CVE
#   - attack_count: number of known exploits

print("\n" + "=" * 80)
print("SELECTING FEATURES")
print("=" * 80)

# Create X (features) by selecting columns
# We exclude: cve_id (just a name), description (text, not numeric), risk_score (our target)
X = df[["cvss_score", "epss_score", "days_since_published", "attack_count"]]

# Create y (target) by selecting the column we want to predict
y = df["risk_score"]

print(f"Features (X) shape: {X.shape}")
print(f"  Columns: {', '.join(X.columns.tolist())}")
print(f"Target (y) shape: {y.shape}")
print(f"  Any missing values in X? {X.isna().sum().sum()}")
print(f"  Any missing values in y? {y.isna().sum()}")

# ── Step 5: Handle missing values in features ────────────────────────────────
#
# If any feature or target has NaN, we need to handle it:
#   - Option 1: Drop rows with NaN
#   - Option 2: Fill with mean/median
#
# Here we:
#   1. Drop rows where the target (risk_score) is missing
#   2. Fill features with the mean (average value for that column)

print("\nHandling missing values...")

# Remove rows where target is NaN
missing_target = y.isna().sum()
if missing_target > 0:
    print(f"  Dropping {missing_target} rows with NaN in risk_score...")
    valid_idx = ~y.isna()
    X = X[valid_idx]
    y = y[valid_idx]

# Fill missing values in features with column mean
missing_in_features = X.isna().sum().sum()
if missing_in_features > 0:
    print(f"  Filling {missing_in_features} missing values in features with column mean...")
    X = X.fillna(X.mean())

print(f"  Final dataset shape: {X.shape[0]} rows × {X.shape[1]} columns")

# ── Step 6: Split data into training and test sets ─────────────────────────────
#
# Why split?
#   - Train set: used to teach the model
#   - Test set: used to evaluate if the model generalizes to new data
#
# test_size=0.2 means 20% goes to test, 80% to training
# random_state=42 ensures reproducibility (same split every run)

print("\n" + "=" * 80)
print("SPLITTING DATA")
print("=" * 80)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,      # 20% for testing, 80% for training
    random_state=42     # Reproducible split
)

print(f"Training set size: {X_train.shape[0]} samples (80%)")
print(f"Test set size:     {X_test.shape[0]} samples (20%)")

# ── Step 7: Create and configure the XGBoost model ───────────────────────────
#
# XGBoost = eXtreme Gradient Boosting
#   - Powerful ensemble method
#   - Builds many decision trees sequentially
#   - Each tree corrects errors from previous trees
#
# Parameters:
#   - n_estimators: number of trees to build (more = potentially better but slower)
#   - learning_rate: how much each tree contributes (lower = more conservative)
#   - max_depth: how deep each tree can be (prevents overfitting)
#   - random_state: seed for reproducibility
#   - verbosity: 0 = quiet, 1 = show some progress

print("\n" + "=" * 80)
print("CREATING XGBOOST MODEL")
print("=" * 80)

model = XGBRegressor(
    n_estimators=100,       # Build 100 decision trees
    learning_rate=0.1,      # Each tree contributes 10% of its prediction
    max_depth=6,            # Trees can be at most 6 levels deep
    random_state=42,        # Reproducible training
    verbosity=0             # Suppress training messages
)

print("XGBRegressor created with:")
print(f"  n_estimators: 100")
print(f"  learning_rate: 0.1")
print(f"  max_depth: 6")

# ── Step 8: Train the model ──────────────────────────────────────────────────
#
# During training:
#   - Model learns patterns from X_train that predict y_train
#   - XGBoost builds trees that split features to minimize prediction error
#   - This typically takes seconds to minutes depending on data size

print("\n" + "=" * 80)
print("TRAINING MODEL")
print("=" * 80)

model.fit(X_train, y_train)

print("✓ Model training complete")

# ── Step 9: Make predictions on the test set ────────────────────────────────
#
# Now that the model is trained, use it to predict risk_score
# for CVEs it's never seen before (the test set)

y_pred = model.predict(X_test)

print(f"✓ Predictions made for {len(y_pred)} test samples")

# ── Step 10: Evaluate model performance ──────────────────────────────────────
#
# Two common regression metrics:
#
# 1. MAE (Mean Absolute Error)
#    - Average distance between prediction and actual
#    - Lower is better
#    - Same units as target (risk_score)
#
# 2. R² Score (Coefficient of Determination)
#    - Percentage of variance explained by the model
#    - 1.0 = perfect predictions
#    - 0.0 = model is as good as predicting the mean
#    - < 0.0 = model is worse than just guessing the mean

print("\n" + "=" * 80)
print("MODEL PERFORMANCE METRICS")
print("=" * 80)

mae = mean_absolute_error(y_test, y_pred)          # Calculate MAE
r2 = r2_score(y_test, y_pred)                      # Calculate R²

print(f"Mean Absolute Error (MAE):  {mae:.4f}")
print(f"  → On average, predictions are off by {mae:.2f} risk points")
print(f"\nR² Score:                   {r2:.4f}")
print(f"  → Model explains {100 * r2:.1f}% of variance in test set")

# ── Step 11: Show feature importance ────────────────────────────────────────
#
# Which features does the model rely on most?
# XGBoost calculates "importance" = how many times a feature is used for splitting

print("\n" + "=" * 80)
print("FEATURE IMPORTANCE")
print("=" * 80)

importance = model.get_booster().get_score(importance_type='weight')
feature_importance_df = pd.DataFrame(
    list(importance.items()),
    columns=["Feature", "Importance"]
).sort_values("Importance", ascending=False)

print(feature_importance_df.to_string(index=False))

# ── Step 12: Save the trained model ────────────────────────────────────────
#
# Saving allows us to:
#   - Reuse the model without retraining
#   - Deploy to production
#   - Share with teammates
#
# XGBoost models are saved in JSON format by default
# This preserves all tree structure and parameters

print("\n" + "=" * 80)
print("SAVING MODEL")
print("=" * 80)

model_path = "cyber_risk_model_v1.json"
model.get_booster().save_model(model_path)

print(f"✓ Model saved to: {model_path}")

# Also save metadata (metrics and feature names) as JSON for reference
metadata = {
    "model_type": "XGBRegressor",
    "training_date": pd.Timestamp.now().isoformat(),
    "test_size": 0.2,
    "train_samples": len(X_train),
    "test_samples": len(X_test),
    "features": X.columns.tolist(),
    "metrics": {
        "MAE": float(mae),
        "R2": float(r2)
    }
}

with open("cyber_risk_model_v1_metadata.json", "w") as f:
    json.dump(metadata, f, indent=2)

print(f"✓ Metadata saved to: cyber_risk_model_v1_metadata.json")

# ── ════════════════════════════════════════════════════════════════════════ ──
# ── PART 2: SEVERITY CLASSIFICATION (XGBClassifier) ──────────────────────── ──
# ── ════════════════════════════════════════════════════════════════════════ ──

print("\n" + "=" * 80)
print("SEVERITY CLASSIFICATION MODEL")
print("=" * 80)

# ── Step 14: Create severity labels (Low/Medium/High/Critical) ──────────────
#
# Real-world severity = based on CVSS + EPSS + CISA Known Exploited Vulnerabilities (KEV)
# Since we don't have real KEV data, we simulate with rules:
#   - CRITICAL: EPSS > 0.7 OR CVSS >= 9.0  (high likelihood of exploitation or extreme severity)
#   - HIGH:     CVSS >= 7.0 AND (EPSS > 0.2 OR CVSS >= 8.5)
#   - MEDIUM:   CVSS >= 5.0 AND (EPSS > 0.05 OR CVSS >= 6.5)
#   - LOW:      Everything else

print("\nCreating severity labels based on CVSS and EPSS...")

def assign_severity(row):
    """
    Assigns a severity label (0=Low, 1=Medium, 2=High, 3=Critical)
    based on CVSS score and EPSS score.
    """
    cvss = row["cvss_score"]
    epss = row["epss_score"]
    
    # Priority order: check critical first, then high, then medium
    if epss > 0.7 or cvss >= 9.0:
        return 3  # Critical
    elif cvss >= 7.0 and (epss > 0.2 or cvss >= 8.5):
        return 2  # High
    elif cvss >= 5.0 and (epss > 0.05 or cvss >= 6.5):
        return 1  # Medium
    else:
        return 0  # Low

# Apply the severity function to each row
df["severity_label"] = df.apply(assign_severity, axis=1)

# Create a mapping for human-readable labels
severity_names = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
df["severity_name"] = df["severity_label"].map(severity_names)

# Show label distribution
print("\nSeverity Label Distribution:")
label_counts = df["severity_label"].value_counts().sort_index()
for label_id, count in label_counts.items():
    pct = 100 * count / len(df)
    print(f"  {severity_names[label_id]:10s}: {count:3d} CVEs ({pct:5.1f}%)")

# ── Step 15: Prepare features and target for classification ─────────────────

print("\n" + "=" * 80)
print("PREPARING CLASSIFICATION DATA")
print("=" * 80)

# Use the same features as before, but now split all clean data
X_clf = df[["cvss_score", "epss_score", "days_since_published", "attack_count"]]
y_clf = df["severity_label"]

# No need to fill missing values again (already done)
print(f"Classification features shape: {X_clf.shape}")
print(f"Classification target shape:   {y_clf.shape}")

# ── Step 16: Split data for classification ────────────────────────────────

X_train_clf, X_test_clf, y_train_clf, y_test_clf = train_test_split(
    X_clf,
    y_clf,
    test_size=0.2,
    random_state=42,
    stratify=y_clf  # Important: keep class distribution proportional
)

print(f"\nTraining set size: {len(X_train_clf)} samples")
print(f"Test set size:     {len(X_test_clf)} samples")

# ── Step 17: Create and train XGBClassifier ──────────────────────────────

print("\n" + "=" * 80)
print("TRAINING XGBCLASSIFIER")
print("=" * 80)

# XGBClassifier for multi-class classification (4 classes: Low, Medium, High, Critical)
clf_model = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=6,
    random_state=42,
    num_class=4,          # 4 severity classes (0, 1, 2, 3)
    objective="multi:softprob",  # multi-class probability objective
    verbosity=0
)

print("XGBClassifier created with 4 classes: Low, Medium, High, Critical")

# Train the classifier
clf_model.fit(X_train_clf, y_train_clf)
print("✓ Classification model training complete")

# ── Step 18: Make predictions and evaluate ────────────────────────────────

y_pred_clf = clf_model.predict(X_test_clf)

# Calculate classification metrics
f1_weighted = f1_score(y_test_clf, y_pred_clf, average="weighted")
f1_macro = f1_score(y_test_clf, y_pred_clf, average="macro")

print("\n" + "=" * 80)
print("CLASSIFICATION METRICS")
print("=" * 80)

print(f"F1 Score (weighted): {f1_weighted:.4f}")
print(f"  → Accounts for class imbalance; better for skewed datasets")
print(f"F1 Score (macro):    {f1_macro:.4f}")
print(f"  → Average F1 across all classes, treating each equally")

# ── Step 19: Display confusion matrix ────────────────────────────────────

cm = confusion_matrix(y_test_clf, y_pred_clf)

print("\nConfusion Matrix:")
print("(rows=actual, cols=predicted)\n")

# Create a formatted confusion matrix with labels
severity_labels_short = ["L", "M", "H", "C"]  # Low, Medium, High, Critical
print("       Predicted")
print("     " + "   ".join(severity_labels_short))

for i, row in enumerate(cm):
    print(f"{severity_names[i][0]}  {row}")

# ── Step 20: Detailed classification report ──────────────────────────────

print("\n" + "=" * 80)
print("DETAILED CLASSIFICATION REPORT")
print("=" * 80)

report = classification_report(
    y_test_clf,
    y_pred_clf,
    target_names=[severity_names[i] for i in range(4)],
    digits=4
)

print(report)

# Interpret the report:
#   - Precision: Of the predicted [class], how many were correct?
#   - Recall: Of the actual [class], how many did we find?
#   - F1-Score: Harmonic mean of precision and recall
#   - Support: Number of actual samples in each class

# ── Step 21: Save the classification model ─────────────────────────────

clf_model_path = "cyber_risk_severity_model_v1.json"
clf_model.get_booster().save_model(clf_model_path)

print("\n" + "=" * 80)
print("SAVING CLASSIFICATION MODEL")
print("=" * 80)

print(f"✓ Classifier saved to: {clf_model_path}")

# Save metadata for the classifier
clf_metadata = {
    "model_type": "XGBClassifier",
    "training_date": pd.Timestamp.now().isoformat(),
    "test_size": 0.2,
    "train_samples": len(X_train_clf),
    "test_samples": len(X_test_clf),
    "num_classes": 4,
    "classes": ["Low", "Medium", "High", "Critical"],
    "features": X_clf.columns.tolist(),
    "metrics": {
        "F1_weighted": float(f1_weighted),
        "F1_macro": float(f1_macro)
    },
    "class_distribution": label_counts.to_dict()
}

with open("cyber_risk_severity_model_v1_metadata.json", "w") as f:
    json.dump(clf_metadata, f, indent=2)

print(f"✓ Metadata saved to: cyber_risk_severity_model_v1_metadata.json")

# ── Step 22: Feature importance for the classifier ──────────────────────


print("\n" + "=" * 80)
print("FEATURE IMPORTANCE (Classification)")
print("=" * 80)

clf_importance = clf_model.get_booster().get_score(importance_type='weight')
clf_importance_df = pd.DataFrame(
    list(clf_importance.items()),
    columns=["Feature", "Importance"]
).sort_values("Importance", ascending=False)

print(clf_importance_df.to_string(index=False))

# ── Step 13: Final summary ──────────────────────────────────────────────────

print(f"""
📊 Dataset Summary:
   Total samples: {len(df)}
   Train samples (Regression): {len(X_train)} (80%)
   Test samples (Regression):  {len(X_test)} (20%)

📈 Regression Model (Risk Score Prediction):
   MAE:  {mae:.4f} risk points
   R²:   {r2:.4f}

📊 Classification Model (Severity Prediction):
   Classes: Low, Medium, High, Critical
   F1 Score (weighted): {f1_weighted:.4f}
   F1 Score (macro):    {f1_macro:.4f}

💾 Files Saved:
   === Regression Models ===
   1. {model_path}                      (risk score model)
   2. cyber_risk_model_v1_metadata.json (regression metadata)
   
   === Classification Models ===
   3. {clf_model_path}                    (severity classifier)
   4. cyber_risk_severity_model_v1_metadata.json (classifier metadata)

Next Steps:
   - Combine both models for risk scoring + severity classification
   - Add more features (vendor responses, patch availability, exploit databases)
   - Validate on real-world CVE data
   - Deploy to production for automated risk assessment
   - Monitor model performance over time and retrain regularly
""")

print("=" * 80)
