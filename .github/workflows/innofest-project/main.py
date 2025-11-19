import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import time
import sys
from flask import Flask, render_template, request, jsonify
import pickle
import os

app = Flask(__name__)

TRUSTED_DOMAINS = {
    'google.com',
    'youtube.com',
    'qalan.kz', 
    'facebook.com',
    'twitter.com',
    'instagram.com',
    'github.com',
    'wikipedia.org',
    'amazon.com',
    'microsoft.com'
}

def is_trusted_domain(domain: str) -> bool:
    if not domain:
        return False
    d = domain.lower().split(':')[0]
    if d.startswith('www.'):
        d = d[4:]
    for trusted in TRUSTED_DOMAINS:
        if d == trusted or d.endswith('.' + trusted):
            return True
    return False


MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
LOADED_MODEL = None

def load_model():
    global LOADED_MODEL
    try:
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as f:
                LOADED_MODEL = pickle.load(f)
                print('Loaded model from', MODEL_PATH)
        else:
            LOADED_MODEL = None
    except Exception as e:
        print('Failed to load model:', e)
        LOADED_MODEL = None

load_model()

def get_model_score_from_url(url: str):
    global LOADED_MODEL
    if LOADED_MODEL is None:
        return None, None
    try:
        # Предполагаем, что pipeline принимает строку URL
        probs = LOADED_MODEL.predict_proba([url])
        # В train_model мы метили фишинг как 1, поэтому probs[0][1] — вероятность фишинга
        phishing_prob = float(probs[0][1])
        safety_score = int(round((1.0 - phishing_prob) * 100))
        safety_score = max(0, min(100, safety_score))
        return safety_score, phishing_prob
    except Exception as e:
        print('Model scoring failed:', e)
        return None, None


def map_score_to_label(score: int) -> str:
    """Преобразует числовой score в текстовую метку для UI/API."""
    if score is None:
        return "⚠ Подозрительный сайт"
    if score >= 70:
        return "✅ Безопасный сайт"
    if score >= 40:
        return "⚠ Подозрительный сайт"
    return "❌ Возможный фишинговый сайт"

def check_site_content(url):
    try:
        # Добавляем user-agent чтобы сайты не блокировали запросы
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        content_features = {
            'forms': False,
            'password_fields': False,
            'external_scripts': False,
            'hidden_elements': False,
            'suspicious_redirects': False
        }
        
        # Проверяем наличие форм
        forms = soup.find_all('form')
        content_features['forms'] = len(forms) > 0
        
        # Проверяем поля для паролей
        password_fields = soup.find_all('input', {'type': 'password'})
        content_features['password_fields'] = len(password_fields) > 0
        
        # Проверяем внешние скрипты
        scripts = soup.find_all('script', {'src': True})
        content_features['external_scripts'] = any(not script['src'].startswith(('//', 'https://' + urlparse(url).netloc)) for script in scripts)
        
        # Проверяем скрытые элементы
        hidden = soup.find_all(['input', 'div'], {'style': re.compile(r'display:\s*none|visibility:\s*hidden')})
        content_features['hidden_elements'] = len(hidden) > 0
        
        # Проверяем подозрительные редиректы
        meta_refresh = soup.find_all('meta', {'http-equiv': 'refresh'})
        content_features['suspicious_redirects'] = len(meta_refresh) > 0
        
        return True, content_features
        
    except Exception as e:
        # Возвращаем ошибку в виде словаря, чтобы сохранить сообщение об ошибке
        return False, {'error': str(e)}

def check_brand_spoofing(domain):
    # Словарь известных брендов и их возможных подмен
    brand_patterns = {
        'google': ['g00gle', 'googie', 'g0ogle', 'gooogle'],
        'facebook': ['faceb00k', 'faccebook', 'faceboook', 'facebock'],
        'amazon': ['amaz0n', 'amazzon', 'amazonn', 'ammazon'],
        'paypal': ['paypa1', 'paypai', 'payp@l', 'payppal'],
        'microsoft': ['micros0ft', 'mikrosoft', 'micrrosoft', 'micro$oft'],
        'apple': ['app1e', 'appl3', '@pple', 'appple'],
        'netflix': ['netf1ix', 'netfflix', 'netfl1x', 'netflix-'],
        'twitter': ['tw1tter', 'twiter', 'twltter', 'tvvitter'],
        'instagram': ['1nstagram', 'instagramm', 'lnstagram', 'instagrram'],
        'roblox': ['rob1ox', 'robl0x', 'robllox', 'roblux'],
        'youtube': ['yout00be', 'youutube', 'y0utube', 'youtubee'],
        'whatsapp': ['whatsaap', 'whats@pp', 'whatsapp-', 'whatsapp1'],
        'telegram': ['te1egram', 'telegramm', 'teiegram', 'tel3gram']
    }
    
    domain = domain.lower()
    found_spoofs = []
    
    for brand, spoofs in brand_patterns.items():
        # Проверяем точное название бренда
        if brand in domain and not any(spoof in domain for spoof in spoofs):
            continue
            
        # Проверяем подмены
        for spoof in spoofs:
            if spoof in domain:
                found_spoofs.append(f"{brand} -> {spoof}")
                
    return found_spoofs

def extract_features(url):
    features = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # 1. Есть ли HTTPS
    features.append(1 if url.startswith("https") else 0)

    # 2. Длина адреса (слишком длинный — подозрительно)
    features.append(1 if len(url) > 70 else 0)

    # 3. Подозрительные символы
    features.append(1 if "@" in url or "-" in url else 0)

    # 4. Подозрительные слова
    suspicious_words = ["login", "verify", "update", "secure", "account", "free", "bonus"]
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)

    # 5. Цифры в доменном имени
    domain = urlparse(url).netloc
    features.append(1 if any(char.isdigit() for char in domain) else 0)

    # Проверка на подмену известных брендов
    spoofed_brands = check_brand_spoofing(domain)
    features.append(1 if spoofed_brands else 0)
    
    success, content_features = check_site_content(url)

    if success:
        # Добавляем новые признаки из контента
        features.append(1 if content_features.get('forms') and content_features.get('password_fields') else 0)
        features.append(1 if content_features.get('external_scripts') else 0)
        features.append(1 if content_features.get('hidden_elements') else 0)
        features.append(1 if content_features.get('suspicious_redirects') else 0)

        # Возвращаем полноценные данные о содержимом
        return features, content_features, spoofed_brands
    else:
        # Если не удалось получить содержимое — возвращаем сообщение об ошибке в content_features
        return features, content_features, spoofed_brands

def predict_phishing(features):
    # Простая хевристика для превращения признаков в текстовую метку
    score = sum(features)
    if score <= 2:
        return "✅ Безопасный сайт"
    elif score <= 4:
        return "⚠ Подозрительный сайт"
    else:
        return "❌ Возможный фишинговый сайт"


def compute_score_from_features(features):
    """Преобразует массив бинарных признаков в балл от 0 до 100.

    Простая формула: (1 - normalized_sum) * 100, где более высокое значение признака — более риск.
    При необходимости заменить моделью (см. train_model.py).
    """
    if not features:
        return None
    max_possible = len(features)
    s = sum(features)
    # Чем больше признаков, тем больше риск -> score безопасности уменьшается
    risk_ratio = s / max_possible
    score = int(round((1.0 - risk_ratio) * 100))
    # Ограничим 0..100
    return max(0, min(100, score))

# Основная программа
def run_cli():
    """Запуск интерактивного CLI (вызвать как `python main.py cli`)."""
    print("🔍 CyberAI Detector — Проверка сайтов на фишинг\n")
    url = input("Введите ссылку сайта: ")

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Быстрая проверка белого списка
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if is_trusted_domain(domain):
        print('\nРезультат анализа:')
        print('✅ Безопасный сайт (белый список)')
        return

    # Попробуем получить оценку из модели, если она загружена
    model_score, phishing_prob = get_model_score_from_url(url)
    if model_score is not None:
        result = map_score_to_label(model_score)
        print("\nРезультат анализа (модель):")
        print(result)
        print(f"Оценка: {model_score}/100 | Вероятность фишинга (модель): {phishing_prob:.2f}")
        return

    print("\nАнализируем сайт, пожалуйста подождите...")
    features, content_data, spoofed_brands = extract_features(url)

    # Если при получении содержимого произошла ошибка, пометим сайт как подозрительный и выведем сообщение об ошибке
    if content_data and isinstance(content_data, dict) and 'error' in content_data:
        result = "⚠ Подозрительный сайт"
        error_message = content_data.get('error')
    else:
        result = predict_phishing(features)
        error_message = None

    # Вычислим числовую оценку на основе признаков (fallback)
    numeric_score = compute_score_from_features(features) or 0

    print("\nРезультат анализа:")
    print(result)
    print(f"Оценка: {numeric_score}/100")

    if spoofed_brands:
        print("\n⚠ Обнаружены попытки подмены известных брендов:")
        for spoof in spoofed_brands:
            print(f"  • {spoof}")

    if error_message:
        print(f"\nОшибка при получении содержимого сайта: {error_message}")
    elif content_data:
        print("\nДополнительная информация о сайте:")
        print(f"✓ Формы ввода: {'обнаружены' if content_data.get('forms') else 'не обнаружены'}")
        print(f"✓ Поля для паролей: {'присутствуют' if content_data.get('password_fields') else 'отсутствуют'}")
        print(f"✓ Внешние скрипты: {'обнаружены' if content_data.get('external_scripts') else 'не обнаружены'}")
        print(f"✓ Скрытые элементы: {'присутствуют' if content_data.get('hidden_elements') else 'отсутствуют'}")
        print(f"✓ Подозрительные редиректы: {'обнаружены' if content_data.get('suspicious_redirects') else 'не обнаружены'}")
    else:
        print("\nНе удалось проверить содержимое сайта.")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    url = request.json.get('url')
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    # Быстрая проверка белого списка: если домен доверенный — сразу возвращаем безопасный
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if is_trusted_domain(domain):
        return jsonify({
            'result': '✅ Безопасный сайт',
            'trusted': True,
            'spoofed_brands': [],
            'content_data': {},
            'error': None
        })

    features, content_data, spoofed_brands = extract_features(url)
    # Если при получении содержимого произошла ошибка, пометим сайт как подозрительный
    if content_data and isinstance(content_data, dict) and 'error' in content_data:
        result = "⚠ Подозрительный сайт"
        error_message = content_data.get('error')
    else:
        result = predict_phishing(features)
        error_message = None

    # Вычисляем числовую оценку безопасности
    numeric_score = compute_score_from_features(features)
    if numeric_score is None:
        numeric_score = 0

    response = {
        'result': result,
        'trusted': False,
        'score': numeric_score,
        'rating': f"{numeric_score}/100",
        'spoofed_brands': spoofed_brands,
        'content_data': content_data if content_data else {},
        'error': error_message
    }

    return jsonify(response)

if __name__ == '__main__':
    # Если вызвать скрипт с аргументом `cli`, запустится CLI-интерфейс.
    # Иначе — запускается веб-сервер.
    if len(sys.argv) > 1 and sys.argv[1] in ('cli', '--cli'):
        run_cli()
    else:
        app.run(debug=True)