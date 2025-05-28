from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification,  AutoModelForSeq2SeqLM
from transformers import MarianMTModel, MarianTokenizer
import re


tokenizer = AutoTokenizer.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.1")
model = AutoModelForSequenceClassification.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.1")

# tokenizer = AutoTokenizer.from_pretrained("ealvaradob/bert-finetuned-phishing")
# model = AutoModelForSequenceClassification.from_pretrained("ealvaradob/bert-finetuned-phishing")  

from deep_translator import GoogleTranslator


def predict_email(text):

    if re.search(r'[а-яА-Я]', text):
                try:
                    print("подаем:", text)
                    text = GoogleTranslator(source='auto', target='en').translate(text)
                    print(text) #test
                except Exception as e:
                    return {'error': f"Ошибка перевода: {e}"}


    # Preprocess and tokenize
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=512
    )
    
    # Get prediction
    with torch.no_grad():
        outputs = model(**inputs)
        predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
    
    # Get probabilities for each class
    probs = predictions[0].tolist()
    
    # Create labels dictionary
    labels = {
        "legitimate_email": probs[0],
        "phishing_url": probs[1],
        "legitimate_url": probs[2],
        "phishing_url_alt": probs[3]
    }
    
    # Determine the most likely classification
    max_label = max(labels.items(), key=lambda x: x[1])
    
    return {
        "prediction": max_label[0],
        "confidence": max_label[1],
        "all_probabilities": labels
    }



text = '''

 “Истекает срок действия пароля”

Тема: Срок действия вашего пароля истекает

Уважаемый пользователь,

Ваш текущий пароль устареет через 24 часа.
Для продолжения работы в системе необходимо обновить пароль:

Сменить пароль сейчас

Не обновив пароль вовремя, вы можете потерять доступ к важным функциям.

'''

result = predict_email(text)
print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['confidence']:.2%}")
print("\nAll probabilities:")
for label, prob in result['all_probabilities'].items():
    print(f"{label}: {prob:.2%}")