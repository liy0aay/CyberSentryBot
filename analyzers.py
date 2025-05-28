"""
Модуль для анализа фишинга через VirusTotal и NLP.

Классы:
    - VirusTotalClient: Проверка URL через VirusTotal API
    - BaseAnalyzer: Базовый интерфейс для анализаторов сообщений
    - PhishingAnalyzer: Анализ текста и ссылок на фишинг

Функциональность:
    - Извлечение ссылок из текста
    - Перевод текста на английский язык при необходимости
    - Классификация текста как фишинг/безопасный с указанием уверенности
    - Проверка URL-адресов через VirusTotal API с выводом уровня угрозы


Требования:
    - Python 3.8+
    - requests
    - transformers
    - torch
    - deep-translator
"""
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import re
from deep_translator import GoogleTranslator
from typing import List
import base64
from urllib.parse import urlparse
import requests

class BaseAnalyzer:
    """Базовый класс для анализаторов сообщений."""
    pass

class VirusTotalClient:
    """Клиент для взаимодействия с VirusTotal API.

    Атрибуты:
        api_key (str): API ключ для доступа к VirusTotal.
        base_url (str): Базовый URL эндпоинта API.
    """
    def __init__(self, api_key: str):
        """Инициализирует клиента VirusTotal.

        Args:
            api_key (str): API ключ для доступа к VirusTotal.
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/urls"
        

    def check_url(self, url: str) -> str:
        """Проверяет URL через API VirusTotal и возвращает статус.

        Args:
            url (str): Ссылка или домен для анализа.

        Returns:
            str: Результат анализа, включая уровень угрозы или сообщение об ошибке.
        """
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": self.api_key}
            response = requests.get(f"{self.base_url}/{url_id}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
                if malicious > 0:
                    return f"⚠️ Вредоносная ссылка ({malicious} антивирусов отметили как опасную)"
                else:
                    return "✅ Ссылка безопасна"
            elif response.status_code == 404:
                return "ℹ️ Ссылка не найдена в базе VirusTotal"
            else:
                return f"Ошибка проверки ссылки: {response.status_code}"
        except Exception as e:
            return f"Ошибка при проверке ссылки: {e}"

class PhishingAnalyzer(BaseAnalyzer):
    """Анализатор фишинга, использующий NLP модель и VirusTotal API.

    Атрибуты:
        vt_client (VirusTotalClient): Клиент для работы с VirusTotal.
        nlp_model: Загруженная NLP модель (transformers).
        tokenizer: Токенизатор модели.
    """

    def __init__(self, vt_client: VirusTotalClient, nlp_model=None, tokenizer=None):
        """Инициализирует анализатор фишинга.

        Args:
            vt_client (VirusTotalClient): Экземпляр клиента VirusTotal.
            nlp_model: Загруженная NLP модель.
            tokenizer: Токенизатор для NLP модели.
        """
        self.vt_client = vt_client
        self.nlp_model = nlp_model
        self.tokenizer = tokenizer

    def extract_domain(self, url: str) -> str:
        """Извлекает доменное имя из URL.

        Args:
            url (str): URL строка.

        Returns:
            str: Домен из URL.
        """
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
            url = 'http://' + url
        parsed = urlparse(url)
        return parsed.netloc

    def _extract_urls(self, text: str) -> List[str]:
        """Извлекает все URL-адреса из текста.

        Args:
            text (str): Входной текст.

        Returns:
            List[str]: Список URL-адресов, найденных в тексте.
        """
        url_pattern = (
            r'(?i)\b('
            r'(?:https?://|ftp://)?'  # протокол 
            r'(?:www\.)?'  # www 
            r'[a-z0-9\-._~%]+'
            r'(?:\.[a-z]{2,})+'  # домен
            r'(?:/[^\s]*)?'  # путь 
            r')'
        )
        return [u for u in re.findall(url_pattern, text) if '.' in u]

    def analyze_message(self, text: str) -> List[str]:
        """Проводит полный анализ сообщения на фишинг.

        Args:
            text (str): Входной текст сообщения.

        Returns:
            List[str]: Список строк с результатами анализа (текст и ссылки).
        """
        results = []

        text_result = self.analyze_text(text)
        if 'error' in text_result:
            return [f"Ошибка анализа текста: {text_result['error']}"]

        results.append(f"📝 Текст: {text_result['verdict']} ({text_result['confidence']:.1%})")

        urls = self._extract_urls(text)
        
        for url in urls:
            domain = self.extract_domain(url)
            url_result = self.vt_client.check_url(domain)
            results.append(f"🔗 Ссылка: {url_result}")
        return results

    def analyze_text(self, text: str) -> dict:
        """Классифицирует текст как фишинг или безопасный с уверенностью.

        Args:
            text (str): Входной текст.

        Returns:
            dict: Словарь с вердиктом (`phishing` или `safe`), уровнем уверенности
                  и подробностями (оценки по классам).
        """
        if re.search(r'[а-яА-Я]', text):
            try:
                text = GoogleTranslator(source='auto', target='en').translate(text)
            except Exception as e:
                return {'error': f"Ошибка перевода: {e}"}

        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512
        )

        with torch.no_grad():
            outputs = self.nlp_model(**inputs)
            temperature = 2.0
            scaled_logits = outputs.logits / temperature
            probs = torch.nn.functional.softmax(scaled_logits, dim=-1).squeeze()

        phishing_score = probs[1] + probs[3]
        legitimate_score = probs[0] + probs[2] 

        verdict = 'phishing' if phishing_score > 0.7 else 'safe'
        confidence = max(phishing_score, legitimate_score)
        print (f'{verdict}: уверенность {confidence}%')

        return {
            'verdict': verdict,
            'confidence': confidence,
            'details': {
                'legitimate_email': f"{probs[0]:.1%}",
                'phishing_url': f"{probs[1]:.1%}",
                'legitimate_url': f"{probs[2]:.1%}",
                'phishing_url_alt': f"{probs[3]:.1%}"
            }
        }
    
    

    

