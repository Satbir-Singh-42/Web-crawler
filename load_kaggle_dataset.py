import kagglehub
import pandas as pd
import os

def load_phishing_dataset():
    """Load phishing dataset from Kaggle"""
    print("Downloading phishing dataset from Kaggle...")
    
    try:
        path = kagglehub.dataset_download("taruntiwarihp/phishing-site-urls")
        print(f"Dataset downloaded to: {path}")
        
        csv_files = [f for f in os.listdir(path) if f.endswith('.csv')]
        print(f"Found CSV files: {csv_files}")
        
        if not csv_files:
            print("No CSV files found in the dataset")
            return None
        
        csv_path = os.path.join(path, csv_files[0])
        print(f"Loading: {csv_path}")
        
        df = pd.read_csv(csv_path)
        
        print(f"\nDataset loaded successfully!")
        print(f"Total records: {len(df)}")
        print(f"Columns: {df.columns.tolist()}")
        print("\nFirst 5 records:")
        print(df.head())
        
        print("\nDataset info:")
        print(df.info())
        
        print("\nLabel distribution:")
        if 'Label' in df.columns:
            print(df['Label'].value_counts())
        
        df.to_csv('kaggle_phishing_dataset.csv', index=False)
        print("\nDataset saved to: kaggle_phishing_dataset.csv")
        
        return df
        
    except Exception as e:
        print(f"Error loading dataset: {e}")
        print("\nNote: You may need to authenticate with Kaggle.")
        print("Set up Kaggle API credentials:")
        print("1. Go to https://www.kaggle.com/account")
        print("2. Create an API token (downloads kaggle.json)")
        print("3. Set KAGGLE_USERNAME and KAGGLE_KEY environment variables")
        return None

if __name__ == "__main__":
    df = load_phishing_dataset()
