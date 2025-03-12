import json
import requests
import jwt
from jwt import PyJWKClient

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://keycloak:8080"],
    allow_credentials=True,
    allow_methods=["*"],  # Разрешить все методы (GET, POST, и т.д.)
    allow_headers=["*"],  # Разрешить все заголовки
)

# URL для получения JWKS
JWKS_URL = "http://keycloak:8080/realms/reports-realm/protocol/openid-connect/certs"
REQUIRED_GENERATE_REPORT_ROLE = "prothetic_user"
ALLOWED_ISSUER = "http://localhost:8080/realms/reports-realm"

@app.get("/reports")
def generate_report(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    # Проверяем валидность подписи токена
    parsed_token = verify_jwt(token)

    # Проверяем необходимую роль пользователя
    if not has_required_role(parsed_token):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "status": "success",
        "data": {
            "total_users": 150,
            "active_users": 75
        }
    }
    return report

def verify_jwt(token: str):
    try:
        # Проверка доступности URL перед использованием
        response = requests.get(JWKS_URL, timeout=5)
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="JWKS URL недоступен")
        
        # Получаем JWKS (JSON Web Key Set)
        jwks_client = PyJWKClient(JWKS_URL)
    
        # Извлекаем ключ
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Декодирование и валидация подписи
        decoded_token = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],  # Алгоритм подписи
            issuer=ALLOWED_ISSUER  # Проверяем, кто выдал токен
        )
        return decoded_token
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


def has_required_role(parsed_token: str) -> bool:
    try:
        roles = parsed_token.get("realm_access", {}).get("roles", [])
        return REQUIRED_GENERATE_REPORT_ROLE in roles
    except (json.JSONDecodeError, KeyError, TypeError):
        return False    

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)
