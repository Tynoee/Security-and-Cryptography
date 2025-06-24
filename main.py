from fastapi import FastAPI
from app.api import routes  # This assumes you have your FastAPI routes here

app = FastAPI(
    title="Cryptographic Toolkit API",
    description="""
This API provides endpoints for performing various cryptographic operations including:
- **SHA-256 Hashing**
- **RSA Encryption/Decryption**
- **Caesar Cipher**
- **Vigenère Cipher**
- **Digital Signatures**

You can test each endpoint directly via the Swagger UI below.
""",
    version="1.0.0",
    docs_url="/docs",              # Swagger UI available here
    redoc_url="/redoc",            # Optional ReDoc UI
    openapi_url="/openapi.json"    # OpenAPI schema
)

# Register routes
app.include_router(routes.router)

# Optional root route
@app.get("/", tags=["Docs"])
def read_root():
    return {
        "message": "Welcome to the Cryptographic Toolkit API",
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }
