import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import config
from preprocess import clean_and_load_data, preprocess_pipeline

def train_ids_model():
    """
    Orchestrates the NIDS machine learning pipeline:
    1. Loads / creates dataset
    2. Cleans and preprocesses features
    3. Splits data into training & testing sets
    4. Trains a Random Forest Classifier
    5. Evaluates model performance
    6. Saves the trained model to disk
    """
    print("=== STARTING NIDS ML MODEL TRAINING PIPELINE ===")
    
    # Check if dataset exists, if not generate simulated dataset
    if not os.path.exists(config.DATASET_PATH):
        print("Dataset not found. Launching simulator to generate training dataset...")
        from dataset.simulate_dataset import generate_mock_dataset
        generate_mock_dataset()
        
    try:
        # Load and clean dataset
        X, y = clean_and_load_data()
        
        # Preprocess features & targets
        X_scaled, y_encoded, le, scaler = preprocess_pipeline(X, y, fit_preprocessors=True)
        
        # Perform Train-Test Split (80% train, 20% test)
        print("Splitting dataset into train and test sets...")
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Initialize and Train Random Forest Classifier
        # Use class_weight='balanced' to handle typical network threat imbalance
        print("Training Random Forest Classifier (this may take a few seconds)...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=18,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1  # Use all CPU cores for training
        )
        
        rf_model.fit(X_train, y_train)
        print("Model training complete!")
        
        # Save the model
        model_path = config.MODEL_PATH
        joblib.dump(rf_model, model_path)
        print(f"Model successfully saved to {model_path}")
        
        # Evaluate model
        print("\n=== MODEL EVALUATION METRICS ===")
        y_pred = rf_model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Overall Accuracy: {accuracy * 100:.4f}%")
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=le.classes_))
        
        print("Confusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        cm_df = pd.DataFrame(cm, index=le.classes_, columns=le.classes_)
        print(cm_df)
        
        # Feature Importance Analysis
        print("\n=== FEATURE IMPORTANCE ANALYSIS ===")
        importances = rf_model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print("Feature rankings:")
        for f in range(X_train.shape[1]):
            print(f"{f + 1}. {config.FEATURES[indices[f]]:<30} : {importances[indices[f]]:.6f}")
            
        print("=== NIDS TRAINING PIPELINE COMPLETE ===")
        return True
        
    except Exception as e:
        print(f"Error during NIDS model training: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    train_ids_model()
