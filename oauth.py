from flask import Flask, redirect, request, session, url_for
import requests
import hashlib
import base64
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = '7e8c4b9b97a94548bb91a52bcd1d3f6d'

client_id = 'Ov23liSanxXZltUw7Yqi'
client_secret = '14fe490970195f483d4afec058b2b8161be74a07'

# Функція для генерації PKCE code_verifier
def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')

# Функція для генерації PKCE code_challenge
def generate_code_challenge(code_verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')

@app.route('/')
def home():
    return '''
    <html>
    <head>
        <title>Головна Сторінка</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                text-align: center; 
                margin-top: 50px;
                background: linear-gradient(to bottom right, #74ebd5, #ACB6E5); 
                color: white;
            }
            h1 { color: #333; }
            p { font-size: 18px; color: grey; }
            a { 
                padding: 10px 20px; 
                background-color: #4CAF50; 
                color: white; 
                text-decoration: none; 
                border-radius: 5px; 
                font-weight: bold;
                transition: background-color 0.3s;
            }
            a:hover { 
                background-color: #45a049; 
            }
            .container {
                background-color: rgba(255, 255, 255, 0.8);
                padding: 20px;
                border-radius: 15px;
                display: inline-block;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Ласкаво просимо!</h1>
            <p>Щоб увійти, натисніть кнопку нижче.</p>
            <a href="/login">Увійти через GitHub</a>
        </div>
    </body>
    </html>
    '''

@app.route('/login')
def login():
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    session['code_verifier'] = code_verifier

    authorization_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri=http://localhost:5000/callback"
        f"&scope=read:user"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    code_verifier = session.get('code_verifier')

    if code is None or code_verifier is None:
        return "Помилка авторизації. Код або code_verifier не отримано."

    token_url = 'https://github.com/login/oauth/access_token'
    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'redirect_uri': 'http://localhost:5000/callback',
        'code_verifier': code_verifier
    }
    headers = {'Accept': 'application/json'}

    token_response = requests.post(token_url, data=token_data, headers=headers)
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    refresh_token = token_json.get('refresh_token')
    expires_in = token_json.get('expires_in')

    if access_token is None:
        return "Не вдалося отримати access token."

    session['access_token'] = access_token
    session['refresh_token'] = refresh_token

    # Обробка випадку, коли expires_in дорівнює None
    if expires_in:
        session['token_expiry'] = (datetime.now() + timedelta(seconds=expires_in)).isoformat()
    else:
        # Якщо expires_in не надано, припускаємо термін дії токену на 1 годину
        session['token_expiry'] = (datetime.now() + timedelta(hours=1)).isoformat()

    return redirect(url_for('profile'))

# Функція для перевірки, чи є токен ще дійсним
def token_valid():
    token_expiry = session.get('token_expiry')
    if token_expiry:
        return datetime.now() < datetime.fromisoformat(token_expiry)
    return False

# Функція для оновлення токену
def refresh_token():
    refresh_token = session.get('refresh_token')
    if refresh_token is None:
        return False

    token_url = 'https://github.com/login/oauth/access_token'
    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }
    headers = {'Accept': 'application/json'}

    token_response = requests.post(token_url, data=token_data, headers=headers)
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    expires_in = token_json.get('expires_in')

    if access_token:
        session['access_token'] = access_token
        if expires_in:
            session['token_expiry'] = (datetime.now() + timedelta(seconds=expires_in)).isoformat()
        else:
            session['token_expiry'] = (datetime.now() + timedelta(hours=1)).isoformat()
        return True
    return False

@app.route('/profile')
def profile():
    if not token_valid():
        if not refresh_token():
            return redirect(url_for('login'))

    access_token = session.get('access_token')
    headers = {'Authorization': f'Bearer {access_token}'}
    user_info_response = requests.get('https://api.github.com/user', headers=headers)
    user_info = user_info_response.json()

    if 'login' not in user_info:
        return f"Не вдалося отримати інформацію про користувача. Відповідь сервера: {user_info}"

    # Отримання деталей користувача
    username = user_info.get('login')
    name = user_info.get('name', 'Не вказано')
    location = user_info.get('location', 'Не вказано')
    public_repos = user_info.get('public_repos', 'Невідомо')
    profile_url = user_info.get('html_url', '#')
    created_at = user_info.get('created_at', 'Невідомо')

    # Поточний час
    now = datetime.now()
    current_time = now.strftime('%Y-%m-%d %H:%M:%S') 

    return f'''
    <html>
    <head>
        <title>Профіль користувача</title>
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                text-align: center; 
                margin-top: 50px;
                background: linear-gradient(to bottom right, #ACB6E5, #74ebd5); 
                color: white;
            }}
            h1 {{ color: #333; }}
            p {{ font-size: 18px; color: black; }}
            a {{ 
                color: #007bff; 
                text-decoration: none; 
                font-weight: bold; 
            }}
            a:hover {{ text-decoration: underline; }}
            .container {{
                background-color: rgba(255, 255, 255, 0.9);
                padding: 20px;
                border-radius: 15px;
                display: inline-block;
                max-width: 600px;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Інформація про користувача</h1>
            <p><strong>Логін:</strong> {username}</p>
            <p><strong>Повне ім'я:</strong> {name}</p>
            <p><strong>Місцезнаходження:</strong> {location}</p>
            <p><strong>Публічні репозиторії:</strong> {public_repos}</p>
            <p><strong>GitHub Профіль:</strong> <a href="{profile_url}">{profile_url}</a></p>
            <p><strong>Дата створення профілю:</strong> {created_at}</p>
            <p><strong>Поточний час:</strong> {current_time}</p>
        </div>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(debug=True)
