import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
import os

DATA = os.path.expanduser("~/mlips_project/data/combined.csv")
OUT_MODELS = os.path.expanduser("~/mlips_project/models")
os.makedirs(OUT_MODELS, exist_ok=True)

df = pd.read_csv(DATA)
df = df[df['label'].isin(['SQLI','XSS','BENIGN'])]
X_text = df['text'].astype(str)
y = df['label'].astype(str)

vec = TfidfVectorizer(ngram_range=(1,3), analyzer='char_wb', max_features=10000)
X = vec.fit_transform(X_text)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

models = {
    "LogisticRegression": LogisticRegression(max_iter=500),
    "RandomForest": RandomForestClassifier(n_estimators=50, n_jobs=-1),
    "MultinomialNB": MultinomialNB(),
    "LinearSVC": LinearSVC(max_iter=5000)
}

results = []
best_f1 = -1
best_name = None
for name, m in models.items():
    print("Training", name)
    m.fit(X_train, y_train)
    y_pred = m.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    print(name, "acc:", acc, "f1:", f1)
    print(classification_report(y_test, y_pred, zero_division=0))
    results.append({"model":name,"accuracy":acc,"f1":f1})
    joblib.dump(m, os.path.join(OUT_MODELS, f"{name}.joblib"))
    if f1 > best_f1:
        best_f1 = f1
        best_name = name

joblib.dump(vec, os.path.join(OUT_MODELS, "tfidf_vectorizer.joblib"))
pd.DataFrame(results).to_csv(os.path.join(OUT_MODELS, "model_comparison.csv"), index=False)
print("Best model:", best_name, "f1=", best_f1)
