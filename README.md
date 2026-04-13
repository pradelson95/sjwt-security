# 🔐 SJWT — Secure JSON Web Token

**SJWT (Stateless JSON Web Token)** SJWT (Stateless JSON Web Token) é uma biblioteca de autenticação em Python que expande o modelo tradicional de tokens ao combinar assinatura e criptografia. Enquanto o JWT padrão garante apenas a integridade dos dados, o SJWT também protege a confidencialidade, impedindo que o conteúdo do token seja lido por terceiros.

A diferencia del JWT tradicional, donde el payload es visible, SJWT garantiza:

- 🔒 **Confidencialidad** (nadie puede leer el contenido)
- 🛡️ **Integridad** (nadie puede modificarlo)
- ⚡ **Stateless** (sin sesiones en servidor)

---

## 🚀 Características

- ✅ Cifrado con **AES-GCM (256 bits)**
- ✅ Firma con **HMAC-SHA256**
- ✅ Tokens compactos (Base64 URL-safe)
- ✅ Expiración automática (`exp`)
- ✅ Tiempo de emisión (`iat`)
- ✅ Manejo profesional de excepciones
- ✅ Sin dependencias externas pesadas (solo `cryptography`)

---

# 🎯 Por que este demo existe?

Muitos desenvolvedores usam JWT pensando:

> “Se está assinado, então está seguro”

Isso é **meio verdade**.

✔️ O JWT garante integridade  
❌ O JWT NÃO garante confidencialidade  

E esse detalhe muda tudo.

---

# 🚀 Por que SJWT?

JWT é muito usado, mas existe um problema importante:

> ❌ JWT NÃO criptografa os dados  
> ❌ Apenas codifica usando Base64  

Isso significa que qualquer pessoa com o token pode ver o conteúdo.


## 📦 Instalación

```bash
pip freeze > requirements.txt
