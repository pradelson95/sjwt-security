from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import jwt  # PyJWT
from sjwt import SJWT 
from exceptions import SJWTError, SJWTSignatureError, SJWTExpiredTokenError
import uvicorn

app = FastAPI()

# Configuração de CORS para o seu HTML
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_methods=["*"], 
    allow_headers=["*"]
)

# --- CONFIGURAÇÃO ---
SECRET_JWT_NORMAL = "clave-secreta-jwt-normal"
# Chaves de 32 bytes para o seu SJWT
KEY_AES = b'\x14\x9e\x8e\x1c\x94\x13\xad\x15\xfa\x8e\x1c\x94\x13\xad\x15\xfa' * 2
KEY_SIGN = b'\xfa\x15\xad\x13\x94\x1c\x8e\xfa\x15\xad\x13\x94\x1c\x8e\x14\xfa' * 2

sjwt_manager = SJWT(secret_key=KEY_AES, sign_key=KEY_SIGN)

# --- ROTA 1: GERAR TOKENS (O que o seu HTML precisa) ---
@app.get("/generate-tokens")
def generate():
    payload = {
        "user_id": 123, 
        "role": "admin", 
        "secret_info": "Dados-Criptografados-2026"
    }
    
    # 1. JWT Normal (Inseguro para dados sensíveis)
    normal_jwt = jwt.encode(payload, SECRET_JWT_NORMAL, algorithm="HS256")
    
    # 2. Seu SJWT (Seguro e Criptografado)
    sjwt_token = sjwt_manager.encode(payload)
    
    return {
        "normal_jwt": normal_jwt,
        "sjwt_token": sjwt_token
    }

# --- ROTA 2: VERIFICAR SJWT (Com tratamento de erros) ---
@app.get("/verify-sjwt")
def verify_token(token: str):
    if not token:
        raise HTTPException(status_code=400, detail="Token vazio")
    
    clean_token = token.replace("Bearer ", "").strip()
    
    try:
        result = sjwt_manager.decode(clean_token)
        return {"status": "sucesso", "dados": result}
    except SJWTSignatureError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except SJWTExpiredTokenError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except SJWTError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="Erro interno")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)