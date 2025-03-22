import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import numpy as np
import pickle

# Path to your dataset CSV file
dataset_path = r"C:\Users\roman\OneDrive\Desktop\VSCodeProjects\Python Projects\sql project\Modified_SQL_Dataset.csv"

# Load dataset using pandas
data = pd.read_csv(dataset_path)

# Ensure your CSV has columns named 'query' and 'label'
queries = data["Query"].tolist()
labels = data["Label"].tolist()

# Hyperparameters for tokenization and padding
vocab_size = 5000       # Adjust as needed based on dataset size
maxlen = 100            # Adjust if your queries are longer
oov_token = "<OOV>"

# Tokenize the queries
tokenizer = Tokenizer(num_words=vocab_size, oov_token=oov_token)
tokenizer.fit_on_texts(queries)
sequences = tokenizer.texts_to_sequences(queries)
padded_sequences = pad_sequences(sequences, maxlen=maxlen, padding='post')

# Build a simple LSTM model
model = keras.Sequential([
    keras.layers.Embedding(vocab_size, 32, input_length=maxlen),
    keras.layers.Bidirectional(keras.layers.LSTM(32)),
    keras.layers.Dense(32, activation='relu'),
    keras.layers.Dense(1, activation='sigmoid')
])

model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
model.summary()

# Train the model (adjust epochs as needed)
model.fit(padded_sequences, np.array(labels), epochs=20, verbose=2)

# Save the trained model and tokenizer
model.save("sql_model_tf.h5")
with open("tokenizer.pickle", "wb") as handle:
    pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)

print("Training complete. Model and tokenizer saved.")
