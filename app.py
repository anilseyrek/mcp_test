#!/usr/bin/env python3
"""
FastMCP at "/" with FastAPI routes for OAuth discovery + health.
"""

# ------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------
from fastmcp import FastMCP, Context
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from config import config
from auth import oauth_protected_resource_handler
from logger import logger
from middleware import auth_middleware


# ------------------------------------------------------------------------------
# MCP server and tools
# ------------------------------------------------------------------------------
mcp = FastMCP(config.SERVER_NAME, stateless_http=True)

@mcp.tool(name="greet_user", description="Greets the user with a personalized message.")
async def greet_user(name: str, ctx: Context | None = None) -> dict:
    logger.info(f"Invoked greet_user tool for name: {name}")
    return {"content": [{"type": "text", "text": f"Hi {name}, welcome to Scalekit!"}]}

# Produce the ASGI app (MCP at root "/")
mcp_app = mcp.http_app(path="/")


# ------------------------------------------------------------------------------
# FastAPI app (uses MCP lifespan)
# ------------------------------------------------------------------------------
app = FastAPI(lifespan=mcp_app.lifespan)

# Your existing HTTP auth middleware (keeps 401 + WWW-Authenticate behavior)
app.middleware("http")(auth_middleware)

# CORS on the outer app (covers MCP too) - must be after auth middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["WWW-Authenticate"],
    max_age=86400,
)


# ------------------------------------------------------------------------------
# Public routes (declare BEFORE mounting MCP)
# ------------------------------------------------------------------------------
@app.get("/.well-known/oauth-protected-resource")
async def oauth_endpoint():
    return await oauth_protected_resource_handler()

@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server():
    """OAuth 2.1 Authorization Server Metadata endpoint."""
    if not config.SK_ENV_URL:
        logger.warning("SK_ENV_URL not configured for OAuth authorization server metadata")
        return {
            "error": "Authorization server not configured"
        }, 500
    
    # Construct authorization server metadata
    # For ScaleKit, the authorization server is typically the environment URL
    metadata = {
        "issuer": config.SK_ENV_URL,
        "authorization_endpoint": f"{config.SK_ENV_URL}/oauth/authorize",
        "token_endpoint": f"{config.SK_ENV_URL}/oauth/token",
        "jwks_uri": f"{config.SK_ENV_URL}/.well-known/jwks.json",
        "response_types_supported": ["code", "token"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "scopes_supported": ["openid", "profile", "email"],
    }
    
    logger.info(f"OAuth authorization server metadata requested: {config.SK_ENV_URL}")
    return metadata

@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    """OpenID Connect Discovery endpoint."""
    if not config.SK_ENV_URL:
        logger.warning("SK_ENV_URL not configured for OpenID Connect configuration")
        return {
            "error": "Authorization server not configured"
        }, 500
    
    # Construct OpenID Connect discovery metadata
    metadata = {
        "issuer": config.SK_ENV_URL,
        "authorization_endpoint": f"{config.SK_ENV_URL}/oauth/authorize",
        "token_endpoint": f"{config.SK_ENV_URL}/oauth/token",
        "userinfo_endpoint": f"{config.SK_ENV_URL}/oauth/userinfo",
        "jwks_uri": f"{config.SK_ENV_URL}/.well-known/jwks.json",
        "response_types_supported": ["code", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified", "name", "picture"],
    }
    
    logger.info(f"OpenID Connect configuration requested: {config.SK_ENV_URL}")
    return metadata

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "server": config.SERVER_NAME,
        "version": config.SERVER_VERSION
    }


# ------------------------------------------------------------------------------
# Mount MCP at "/" LAST so the above routes still win on exact match
# ------------------------------------------------------------------------------
app.mount("/", mcp_app)


# ------------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    logger.info(f"Server running on http://0.0.0.0:{config.PORT} (MCP at /)")
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=config.PORT,
        log_level=config.LOG_LEVEL.lower(),
        reload=True,
    )