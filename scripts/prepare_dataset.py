import os, pandas as pd

DATA_DIR = os.path.join(os.path.expanduser("~"), "mlips_project", "data")
OUT_CSV = os.path.join(DATA_DIR, "combined.csv")

def guess_columns(df):
    cols = list(df.columns)
    text_candidates = [c for c in cols if any(k in c.lower() for k in ['url','payload','query','request','input','attack','data','string','content'])]
    label_candidates = [c for c in cols if any(k in c.lower() for k in ['label','class','type','target','y'])]
    text_col = text_candidates[0] if text_candidates else None
    label_col = label_candidates[0] if label_candidates else None
    if text_col is None:
        for c in cols:
            if df[c].dtype == object and df[c].astype(str).str.len().mean() > 5:
                text_col = c
                break
    return text_col, label_col

combined_rows = []
for fname in os.listdir(DATA_DIR):
    if not fname.lower().endswith(('.csv','.txt','.tsv','.json')):
        continue
    path = os.path.join(DATA_DIR, fname)
    try:
        if fname.lower().endswith('.json'):
            df = pd.read_json(path, lines=True)
        else:
            df = pd.read_csv(path, low_memory=False)
    except Exception as e:
        print("Skipping", fname, "read error:", e)
        continue
    text_col, label_col = guess_columns(df)
    if text_col is None:
        continue
    if label_col is None:
        df['__label__'] = 'BENIGN'
        label_col = '__label__'
    df = df[[text_col, label_col]].dropna()
    df.columns = ['text','label']
    combined_rows.append(df)

if combined_rows:
    combined = pd.concat(combined_rows, ignore_index=True)
    def norm_label(l):
        s = str(l).upper()
        if 'SQL' in s or 'INJECTION' in s:
            return 'SQLI'
        if 'XSS_R' in s or 'CROSS' in s:
            return 'XSS'
        return 'BENIGN'
    combined['label'] = combined['label'].apply(norm_label)
    combined.to_csv(OUT_CSV, index=False)
    print("Combined CSV written:", OUT_CSV, "rows:", len(combined))
else:
    print("No usable files found")
