import sys
from pathlib import Path
# Ensure parent directory is in path for imports
sys.path.insert(0, str(Path(__file__).parent))

import os
import argparse
import pandas as pd
import torch
from torch.utils.data import DataLoader, TensorDataset, random_split
from transformers import DistilBertTokenizer
from torch.optim import AdamW
from sklearn.preprocessing import LabelEncoder
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from data_preprocessor import DataPreprocessor
from models.severity_classifier.model import SeverityClassifier, ID_TO_LABEL, LABEL_TO_ID

def train_severity_classifier(api_key: Optional[str], query: str, epochs: int, batch_size: int, learning_rate: float, output_dir: Path):
    """
    Trains and fine-tunes the SeverityClassifier model.
    """
    logger.info("Starting severity classifier training...")

    # 1. Load and preprocess data
    preprocessor = DataPreprocessor(api_key=api_key)
    
    # Fetch a large amount of CVE data for training.
    # Adjust limit as needed, but be mindful of NVD API rate limits.
    logger.info(f"Fetching CVE data for query: '{query}' for training...")
    processed_data = preprocessor.process(query=query, limit=5000) # Fetch more data for training
    df = processed_data.get("dataframe")

    if df is None or df.empty:
        logger.error("No data fetched for training. Exiting.")
        return

    logger.info(f"Successfully fetched and preprocessed {len(df)} CVEs for training.")

    # 2. Prepare data for model
    # Use the 'severity_class' determined by the preprocessor
    texts = df['cleaned_description'].tolist()
    labels_str = df['severity_class'].tolist()

    # Encode labels to integers
    label_encoder = LabelEncoder()
    # Ensure all possible labels are known to the encoder, even if not present in current batch
    all_possible_labels = list(LABEL_TO_ID.keys())
    label_encoder.fit(all_possible_labels)
    labels = label_encoder.transform(labels_str)

    # Tokenize texts
    tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
    encodings = tokenizer(texts, truncation=True, padding=True, max_length=256, return_tensors='pt')

    # Create dataset and DataLoader
    dataset = TensorDataset(encodings['input_ids'], encodings['attention_mask'], torch.tensor(labels))
    
    # Split dataset into training and validation
    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = random_split(dataset, [train_size, val_size])

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size)

    # 3. Initialize model, optimizer, and loss function
    num_classes = len(all_possible_labels)
    model = SeverityClassifier(num_classes=num_classes)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    optimizer = AdamW(model.parameters(), lr=learning_rate)
    criterion = torch.nn.CrossEntropyLoss()

    # 4. Training loop
    best_val_loss = float('inf')
    output_dir.mkdir(parents=True, exist_ok=True)
    model_save_path = output_dir / "best_model.pt"

    for epoch in range(epochs):
        model.train()
        total_loss = 0
        for batch in train_loader:
            input_ids, attention_mask, labels = [b.to(device) for b in batch]
            
            optimizer.zero_grad()
            logits = model(input_ids, attention_mask)
            loss = criterion(logits, labels)
            total_loss += loss.item()
            loss.backward()
            optimizer.step()
        
        avg_train_loss = total_loss / len(train_loader)
        logger.info(f"Epoch {epoch+1}/{epochs} - Training Loss: {avg_train_loss:.4f}")

        # Validation
        model.eval()
        val_loss = 0
        correct_predictions = 0
        total_predictions = 0
        with torch.no_grad():
            for batch in val_loader:
                input_ids, attention_mask, labels = [b.to(device) for b in batch]
                logits = model(input_ids, attention_mask)
                loss = criterion(logits, labels)
                val_loss += loss.item()

                predictions = torch.argmax(logits, dim=1)
                correct_predictions += (predictions == labels).sum().item()
                total_predictions += labels.size(0)
        
        avg_val_loss = val_loss / len(val_loader)
        accuracy = correct_predictions / total_predictions
        logger.info(f"Epoch {epoch+1}/{epochs} - Validation Loss: {avg_val_loss:.4f} - Accuracy: {accuracy:.4f}")

        # Save best model
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'loss': best_val_loss,
                'label_encoder_classes': label_encoder.classes_.tolist()
            }, model_save_path)
            logger.info(f"Best model saved to {model_save_path}")

    logger.info("Severity classifier training finished.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train and fine-tune the CVE Severity Classifier.")
    parser.add_argument("--api_key", type=str, default=os.environ.get("NVD_API_KEY"),
                        help="NVD API key (optional, can be set via NVD_API_KEY env var)")
    parser.add_argument("--query", type=str, default="software",
                        help="Keyword query for fetching CVE data from NVD.")
    parser.add_argument("--epochs", type=int, default=3,
                        help="Number of training epochs.")
    parser.add_argument("--batch_size", type=int, default=16,
                        help="Batch size for training.")
    parser.add_argument("--learning_rate", type=float, default=2e-5,
                        help="Learning rate for the optimizer.")
    parser.add_argument("--output_dir", type=Path, default=Path(__file__).parent / "models" / "severity_classifier",
                        help="Directory to save the trained model.")
    
    args = parser.parse_args()

    train_severity_classifier(
        api_key=args.api_key,
        query=args.query,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        output_dir=args.output_dir
    )
