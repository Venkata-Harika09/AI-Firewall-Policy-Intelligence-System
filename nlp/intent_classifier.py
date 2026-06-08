"""
Task 3: Intent Classification Model
AI Firewall - Milestone 1
Dataset : unified_firewall_dataset.csv (199 rules)
Models  : Logistic Regression + SVM (Linear)
Output  : allow / deny
"""

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.pipeline import Pipeline


class IntentClassifier:

    def __init__(self):

        # Logistic Regression pipeline
        self.lr_pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=800
            )),
            ('clf', LogisticRegression(
                max_iter=1000,
                random_state=42,
                class_weight='balanced'
            ))
        ])

        # Linear SVM pipeline
        self.svm_pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=800
            )),
            ('clf', SVC(
                kernel='linear',
                probability=True,
                random_state=42,
                class_weight='balanced'
            ))
        ])

        self.best_model = None
        self.best_model_name = None
        self.is_trained = False

    def train(self, dataset_path: str):

        df = pd.read_csv(dataset_path)

        X = df['policy_text']
        y = df['intent']        # fixed: unified_firewall_dataset.csv uses 'intent'

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )

        # Train both models
        self.lr_pipeline.fit(X_train, y_train)
        self.svm_pipeline.fit(X_train, y_train)

        self.is_trained = True

        # Evaluate
        lr_preds  = self.lr_pipeline.predict(X_test)
        svm_preds = self.svm_pipeline.predict(X_test)

        lr_acc  = accuracy_score(y_test, lr_preds)
        svm_acc = accuracy_score(y_test, svm_preds)

        lr_cv  = cross_val_score(self.lr_pipeline,  X, y, cv=5, scoring='accuracy')
        svm_cv = cross_val_score(self.svm_pipeline, X, y, cv=5, scoring='accuracy')

        # Select best model
        if svm_acc >= lr_acc:
            self.best_model      = self.svm_pipeline
            self.best_model_name = "SVM"
        else:
            self.best_model      = self.lr_pipeline
            self.best_model_name = "Logistic Regression"

        print("\n" + "=" * 60)
        print("INTENT CLASSIFIER - TRAINING RESULTS")
        print("=" * 60)
        print(f"Dataset Size       : {len(df)}")
        print(f"Allow Rules        : {(y == 'allow').sum()}")
        print(f"Deny Rules         : {(y == 'deny').sum()}")
        print("-" * 60)
        print(f"Logistic Accuracy  : {lr_acc*100:.2f}%")
        print(f"Logistic CV (5)    : {lr_cv.mean()*100:.2f}% +/- {lr_cv.std()*100:.2f}%")
        print(f"SVM Accuracy       : {svm_acc*100:.2f}%")
        print(f"SVM CV (5)         : {svm_cv.mean()*100:.2f}% +/- {svm_cv.std()*100:.2f}%")
        print("-" * 60)
        print(f"Best Model         : {self.best_model_name}")
        print("=" * 60)

        print("\nClassification Report (Best Model):")
        best_preds = self.best_model.predict(X_test)
        print(classification_report(y_test, best_preds))

        # return metrics so run_milestone1.py can use them
        return {
            "dataset_size" : len(df),
            "lr_accuracy"  : round(lr_acc,  4),
            "svm_accuracy" : round(svm_acc, 4),
            "lr_cv_mean"   : round(lr_cv.mean(),  4),
            "svm_cv_mean"  : round(svm_cv.mean(), 4),
            "best_model"   : self.best_model_name
        }

    def predict(self, text: str):

        if not self.is_trained:
            raise Exception("Model not trained. Call train() first.")

        prediction    = self.best_model.predict([text])[0]
        probabilities = self.best_model.predict_proba([text])[0]

        confidence = {
            label: round(float(prob), 4)
            for label, prob in zip(self.best_model.classes_, probabilities)
        }

        return {
            "text"       : text,
            "prediction" : prediction,
            "confidence" : confidence,
            "model_used" : self.best_model_name
        }

    def predict_batch(self, texts: list) -> list:
        return [self.predict(t) for t in texts]


# ── Quick test when run directly ─────────────────────────────────────────────
if __name__ == "__main__":
    import os

    dataset_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "data", "unified_firewall_dataset.csv"
    )

    classifier = IntentClassifier()
    classifier.train(dataset_path)

    test_policies = [
        "Allow HTTPS traffic from internal network to web server on port 443",
        "Block all SSH connections from public internet on port 22",
        "Deny MongoDB access from external zone on port 27017",
        "Permit DNS queries from trusted subnet to resolver on port 53",
        "Drop all traffic from known malicious IP 198.51.100.25",
        "Allow RDP from VPN subnet 172.16.0.0 on port 3389",
        "Block all incoming traffic from external network",
        "Allow database sync on port 5432 during off-peak hours",
    ]

    print("\nLIVE PREDICTION TESTS")
    print("-" * 65)
    print(f"  {'Prediction':<8}  {'allow':>6} {'deny':>6}   Policy Text")
    print("-" * 65)

    for text in test_policies:
        result = classifier.predict(text)
        pred   = result['prediction'].upper()
        conf   = result['confidence']
        print(f"  {pred:<8}  {conf.get('allow',0):>6.2f} {conf.get('deny',0):>6.2f}   {text[:48]}")