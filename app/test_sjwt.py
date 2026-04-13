import pytest
import os
import time
from sjwt import SJWT
from exceptions import SJWTError, SJWTSignatureError, SJWTExpiredTokenError, SJWTInvalidTokenError

@pytest.fixture
def sjwt_instance():
    key_aes = os.urandom(32)
    key_sign = os.urandom(32)
    return SJWT(secret_key=key_aes, sign_key=key_sign)

# 1. TEST CORREGIDO: Usamos comparaciones individuales o removemos exp/iat
def test_encode_decode_success(sjwt_instance):
    payload = {"user_id": 1, "role": "admin"}
    token = sjwt_instance.encode(payload)
    decoded = sjwt_instance.decode(token)
    
    # Verificamos solo lo que nos importa
    assert decoded["user_id"] == payload["user_id"]
    assert decoded["role"] == payload["role"]
    # Verificamos que los campos de seguridad existan
    assert "exp" in decoded
    assert "iat" in decoded

def test_tampered_token_signature(sjwt_instance):
    token = sjwt_instance.encode({"data": "secret"})
    tampered_token = token[:-1] + ("0" if token[-1] != "0" else "1")
    with pytest.raises(SJWTSignatureError):
        sjwt_instance.decode(tampered_token)

def test_expired_token(sjwt_instance):
    payload = {"user": "test"}
    token = sjwt_instance.encode(payload, ttl=1)
    time.sleep(2)
    with pytest.raises(SJWTExpiredTokenError):
        sjwt_instance.decode(token)

# 2. TEST CORREGIDO: Validamos que al menos tenga los campos de seguridad
def test_empty_payload(sjwt_instance):
    payload = {}
    token = sjwt_instance.encode(payload)
    decoded = sjwt_instance.decode(token)
    assert "exp" in decoded
    assert "iat" in decoded

def test_payload_is_encrypted(sjwt_instance):
    payload = {"secret": "my_password_123"}
    token = sjwt_instance.encode(payload)
    assert "my_password_123" not in token

def test_invalid_key_length():
    with pytest.raises(ValueError):
        SJWT(secret_key=b"curta", sign_key=b"curta")

def test_malformed_token_short(sjwt_instance):
    with pytest.raises(SJWTInvalidTokenError):
        sjwt_instance.decode("token_muy_corto_invalido_totalmente")

# 3. TEST CORREGIDO: Para payloads complejos
def test_complex_payload(sjwt_instance):
    payload = {
        "id": 99,
        "active": True,
        "roles": ["user", "editor"],
        "meta": {"ip": "127.0.0.1"}
    }
    token = sjwt_instance.encode(payload)
    decoded = sjwt_instance.decode(token)
    
    # Validamos uno por uno
    assert decoded["id"] == 99
    assert decoded["active"] is True
    assert decoded["roles"] == ["user", "editor"]
    assert decoded["meta"]["ip"] == "127.0.0.1"

def test_random_nonces(sjwt_instance):
    payload = {"same": "data"}
    token1 = sjwt_instance.encode(payload)
    token2 = sjwt_instance.encode(payload)
    assert token1 != token2

def test_decode_with_wrong_key():
    sjwt1 = SJWT(os.urandom(32), os.urandom(32))
    sjwt2 = SJWT(os.urandom(32), os.urandom(32))
    token = sjwt1.encode({"id": 1})
    with pytest.raises(SJWTSignatureError):
        sjwt2.decode(token)