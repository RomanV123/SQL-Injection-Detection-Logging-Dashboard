import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences # type: ignore
import pickle

# Load the trained model and tokenizer (ensure these files are in your project directory)
model = tf.keras.models.load_model("sql_model_tf.h5")
with open("tokenizer.pickle", "rb") as handle:
    tokenizer = pickle.load(handle)

def ai_detect_suspicious_query_tf(query_text, threshold=0.5):
    """
    Uses the TensorFlow model to classify a SQL query.
    Returns a tuple: (is_suspicious, confidence)
      - is_suspicious: True if the model's prediction exceeds the threshold.
      - confidence: The predicted probability (between 0 and 1).
    """
    # Convert the query text to a sequence and pad it
    sequence = tokenizer.texts_to_sequences([query_text])
    padded_sequence = pad_sequences(sequence, maxlen=50, padding='post')
    # Predict the probability (a value between 0 and 1)
    prediction = model.predict(padded_sequence)[0][0]
    is_suspicious = prediction > threshold
    return is_suspicious, prediction
