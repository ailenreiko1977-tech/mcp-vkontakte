import asyncio
import hashlib
import jwt
from mcp.server.auth.provider import AccessToken


def principal(issuer, subject):
    return hashlib.sha256((issuer+"\0"+subject).encode()).hexdigest()


class Verifier:
    """Verify signature, issuer, audience, expiry and scope; never trust a supplied user ID."""
    def __init__(self, settings):
        self.settings=settings
        self.keys=jwt.PyJWKClient(settings.issuer+"/protocol/openid-connect/certs",cache_keys=True,lifespan=300,timeout=10)

    async def verify_token(self, token):
        try:
            key=await asyncio.to_thread(self.keys.get_signing_key_from_jwt,token)
            claims=jwt.decode(token,key.key,algorithms=["RS256"],issuer=self.settings.issuer,audience=self.settings.resource,
                              options={"require":["exp","iat","sub","iss","aud"]},leeway=5)
            if not isinstance(claims.get("scope"),str):
                return None
            scopes=claims["scope"].split()
            if self.settings.scope not in scopes or not isinstance(claims["sub"],str) or not claims["sub"]:
                return None
            return AccessToken(token=token,client_id=claims.get("azp","mcp"),scopes=scopes,expires_at=claims["exp"],
                subject=principal(self.settings.issuer,claims["sub"]),resource=self.settings.resource)
        except (jwt.PyJWTError,ValueError,TypeError,KeyError):
            return None
