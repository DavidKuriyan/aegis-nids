import pandas as pd
import numpy as np
import os
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler
import config

def clean_and_load_data(filepath=None):
    """
    Loads and cleans dataset. Strips whitespaces from columns, removes NaNs/Infs,
    and returns features and labels.
    """
    if filepath is None:
        filepath = config.DATASET_PATH
        
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found at {filepath}. Please generate or download it first.")
        
    print(f"Loading dataset from: {filepath}...")
    df = pd.read_csv(filepath)
    
    # 1. Clean Column Names (strip whitespaces, which are common in CICIDS2017)
    df.columns = df.columns.str.strip()
    
    # 2. Select configured features + Label
    required_cols = list(config.FEATURES)
    if "Label" in df.columns:
        required_cols.append("Label")
    elif "label" in df.columns:
        df.rename(columns={"label": "Label"}, inplace=True)
        required_cols.append("Label")
    else:
        raise ValueError("Dataset does not contain a 'Label' column.")
        
    # Check for missing features
    missing_cols = [c for c in required_cols if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns in dataset: {missing_cols}")
        
    df = df[required_cols]
    
    # 3. Clean Infinite and NaN values (highly prevalent in flow speed calculations)
    print("Cleaning infinite and missing values...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    initial_len = len(df)
    df.dropna(inplace=True)
    dropped_count = initial_len - len(df)
    if dropped_count > 0:
        print(f"Dropped {dropped_count} rows containing NaNs or Infinite values.")
        
    # Separate features and labels
    X = df[config.FEATURES].copy()
    y = df["Label"].copy()
    
    return X, y

def preprocess_pipeline(X, y, fit_preprocessors=True):
    """
    Fits and applies LabelEncoder and StandardScaler. Saves them for use in real-time prediction.
    """
    # 1. Encode Target Labels
    label_encoder_path = config.LABEL_ENCODER_PATH
    if fit_preprocessors:
        print("Fitting Label Encoder...")
        le = LabelEncoder()
        y_encoded = le.fit_transform(y)
        # Save LabelEncoder
        os.makedirs(config.MODEL_DIR, exist_ok=True)
        joblib.dump(le, label_encoder_path)
        print(f"Label Encoder saved to {label_encoder_path}")
    else:
        if not os.path.exists(label_encoder_path):
            raise FileNotFoundError(f"Label Encoder not found at {label_encoder_path}. Cannot preprocess.")
        le = joblib.load(label_encoder_path)
        y_encoded = le.transform(y)
        
    # 2. Feature Scaling
    scaler_path = config.SCALER_PATH
    if fit_preprocessors:
        print("Fitting Feature Scaler...")
        scaler = StandardScaler()
        X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=config.FEATURES)
        # Save Scaler
        joblib.dump(scaler, scaler_path)
        print(f"Scaler saved to {scaler_path}")
    else:
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Scaler not found at {scaler_path}. Cannot preprocess.")
        scaler = joblib.load(scaler_path)
        X_scaled = pd.DataFrame(scaler.transform(X), columns=config.FEATURES)
        
    return X_scaled, y_encoded, le, scaler

if __name__ == "__main__":
    # Test script locally
    try:
        if not os.path.exists(config.DATASET_PATH):
            # Generate simulated dataset if it doesn't exist
            from dataset.simulate_dataset import generate_mock_dataset
            generate_mock_dataset()
            
        X, y = clean_and_load_data()
        X_scaled, y_encoded, le, scaler = preprocess_pipeline(X, y)
        print("Preprocessing test passed!")
        print(f"Features shape: {X_scaled.shape}")
        print(f"Classes: {le.classes_}")
    except Exception as e:
        print(f"Error during preprocessing pipeline: {e}")
