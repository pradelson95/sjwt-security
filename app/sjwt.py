import os
import json
import base64
import hmac
import hashlib
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from exceptions import SJWTError, SJWTInvalidTokenError, SJWTSignatureError, SJWTExpiredTokenError, SJWTDecodeError

class SJWT:
    """
    Stateless JSON Web Token (SJWT)
    Librería personalizada para tokens cifrados con AES-GCM y firmados con HMAC.
    """
    def __init__(self, secret_key: bytes, sign_key: bytes):
        if len(secret_key) != 32 or len(sign_key) != 32:
            raise ValueError("Las llaves deben ser de 32 bytes (256 bits).")
        self.secret_key = secret_key
        self.sign_key = sign_key

    def _add_padding(self, b64_string: str) -> str:
        return b64_string + "=" * (4 - len(b64_string) % 4) if len(b64_string) % 4 else b64_string

    def encode(self, payload: dict, ttl: int = 3600) -> str:
        data = payload.copy()
        data["iat"] = int(time.time())
        data["exp"] = int(time.time()) + ttl
        
        aesgcm = AESGCM(self.secret_key)
        nonce = os.urandom(12)
        json_data = json.dumps(data).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, json_data, None)
        
        full_body = nonce + ciphertext
        signature = hmac.new(self.sign_key, full_body, hashlib.sha256).digest()
        
        token_bytes = full_body + signature
        return base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip("=")

    def decode(self, token: str) -> dict:
        """
        Decodifica un token SJWT.
        Lanza excepciones específicas si el token es inválido, expirado o manipulado.
        """
        try:
            # 1. Decodificación Base64
            try:
                token_padded = self._add_padding(token)
                raw = base64.urlsafe_b64decode(token_padded.encode('utf-8'))
            except Exception:
                raise SJWTInvalidTokenError("El formato Base64 del token es inválido.")

            # 2. Separación de cuerpo y firma
            if len(raw) < 44:  # 12 (nonce) + mín_payload + 32 (signature)
                raise SJWTInvalidTokenError("El token es demasiado corto para ser válido.")
                
            body = raw[:-32]
            signature = raw[-32:]
            
            # 3. Verificación de integridad (HMAC)
            expected_sig = hmac.new(self.sign_key, body, hashlib.sha256).digest()
            if not hmac.compare_digest(expected_sig, signature):
                raise SJWTSignatureError("La firma no coincide. El token ha sido manipulado.")

            # 4. Descifrado (AES-GCM)
            nonce = body[:12]
            ciphertext = body[12:]
            aesgcm = AESGCM(self.secret_key)
            
            try:
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            except Exception:
                raise SJWTDecodeError("Fallo al descifrar el contenido. Las llaves podrían ser incorrectas.")

            # 5. Validación de Datos y Expiración
            payload = json.loads(decrypted_bytes.decode('utf-8'))
            
            if payload.get("exp", 0) < time.time():
                raise SJWTExpiredTokenError("El token ha expirado.")
                
            return payload

        # Capturamos nuestras propias excepciones para que sigan subiendo
        except (SJWTSignatureError, SJWTExpiredTokenError, SJWTDecodeError, SJWTInvalidTokenError):
            raise
        # Cualquier otro error inesperado se reporta como error general de la librería
        except Exception as e:
            raise SJWTError(f"Error inesperado al procesar el token: {str(e)}")