"""
ScaleKit Authentication Middleware

This module implements OAuth 2.1 authentication middleware using ScaleKit SDK.
It validates Bearer tokens for all MCP requests and ensures proper authorization
according to the OAuth 2.1 specification.
"""

import json
from fastapi import Request
from fastapi.responses import Response
from config import config
from logger import logger
from scalekit import ScalekitClient
from scalekit.common.scalekit import TokenValidationOptions

# OAuth 2.1 configuration - will be set dynamically per request
def get_www_authenticate_header(request: Request) -> dict:
    """Generate WWW-Authenticate header with correct host from request."""
    # Get the actual host from the request (handles Railway's x-forwarded-host)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", f"localhost:{config.PORT}")
    # Get the protocol (Railway uses https)
    protocol = request.headers.get("x-forwarded-proto", "http")
    base_url = f"{protocol}://{host}"
    
    return {
        "WWW-Authenticate": f'Bearer realm="OAuth", resource_metadata="{base_url}/.well-known/oauth-protected-resource"'
    }

# Initialize ScaleKit client for token validation
try:
    scalekit_client = ScalekitClient(
        env_url=config.SK_ENV_URL,
        client_id=config.SK_CLIENT_ID,
        client_secret=config.SK_CLIENT_SECRET
    )
    SCALEKIT_AVAILABLE = True
    logger.info("ScaleKit client initialized successfully")
except Exception as e:
    logger.warning(f"ScaleKit SDK not available: {e}")
    scalekit_client = None
    SCALEKIT_AVAILABLE = False

async def auth_middleware(request: Request, call_next):
    """
    Authentication middleware for MCP requests following ScaleKit OAuth 2.1 specification.
    
    This middleware:
    1. Allows public access to well-known endpoints and health checks
    2. Extracts Bearer tokens from Authorization headers
    3. Validates tokens using ScaleKit SDK
    4. Returns proper OAuth 2.1 error responses on failure
    """
    try:
        # Log all request headers in a pretty format
        headers_dict = dict(request.headers)
        logger.info(f"Request headers for {request.method} {request.url.path}:")
        for header, value in headers_dict.items():
            logger.info(f"  {header}: {value}")

        # Allow public access to OAuth discovery, health, and MCP root endpoints
        if ".well-known" in request.url.path or request.url.path == "/health":
            return await call_next(request)
        
        # Extract Bearer token
        auth_header = request.headers.get("authorization")
        logger.info(f"Auth request for {request.method} {request.url.path}")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            logger.warning(f"Missing Bearer token for {request.method} {request.url.path}")
            return Response(
                content='{"error": "Missing Bearer token"}',
                media_type="application/json",
                status_code=401,
                headers=get_www_authenticate_header(request)
            )
        
        token = auth_header.split("Bearer ")[1].strip()
        logger.info(f"Token extracted, length: {len(token)}")
        
        if not SCALEKIT_AVAILABLE:
            logger.error("ScaleKit SDK not available for token validation")
            return Response(
                content='{"error": "Authentication service unavailable"}',
                media_type="application/json",
                status_code=401,
                headers=get_www_authenticate_header(request)
            )
        
        try:
            # Token validation with ScaleKit
            logger.info("Validating token with ScaleKit...")
            logger.info(f"SK_ENV_URL: {config.SK_ENV_URL}")
            logger.info(f"EXPECTED_AUDIENCE: {config.EXPECTED_AUDIENCE}")

            # Build validation options
            options = TokenValidationOptions(
                issuer=config.SK_ENV_URL,
                audience=[config.EXPECTED_AUDIENCE] if config.EXPECTED_AUDIENCE else None
            )

            is_valid = scalekit_client.validate_access_token(token, options=options)
            logger.info(f"Token validation result: {is_valid}")
            
            if not is_valid:
                logger.warning(f"Token validation failed for {request.method} {request.url.path}")
                logger.warning(f"Check that SK_ENV_URL matches token issuer and EXPECTED_AUDIENCE matches token audience")
                return Response(
                    content='{"error": "Invalid token"}',
                    media_type="application/json",
                    status_code=401,
                    headers=get_www_authenticate_header(request)
                )
            
            logger.info(f"Authentication successful for {request.method} {request.url.path}")
            return await call_next(request)
            
        except Exception as e:
            logger.error(f"Token validation exception: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response(
                content='{"error": "Token validation failed"}',
                media_type="application/json",
                status_code=401,
                headers=get_www_authenticate_header(request)
            )
        
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return Response(
            content='{"error": "Authentication failed"}',
            media_type="application/json",
            status_code=401,
            headers=get_www_authenticate_header(request)
        )