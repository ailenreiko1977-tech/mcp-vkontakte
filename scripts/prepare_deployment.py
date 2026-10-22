"""Generate local secrets and a Keycloak realm. Never prints secret values.

Run ON THE VPS, not in a public Git repository checkout with tracked secrets.
This script refuses to replace existing files. It does not launch services.
"""
import argparse
import json
from pathlib import Path
import re
import secrets
from cryptography.fernet import Fernet


def realm(domain,dashboard_secret):
    origin="https://"+domain
    scope={"name":"vk-mcp","protocol":"openid-connect","attributes":{"include.in.token.scope":"true"},
        "protocolMappers":[{"name":"mcp-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper",
            "consentRequired":False,"config":{"included.custom.audience":origin+"/mcp","access.token.claim":"true","id.token.claim":"false"}}]}
    clients=[]
    for name in ("chatgpt","claude","codex"):
        clients.append({"clientId":"vk-mcp-"+name,"enabled":True,"protocol":"openid-connect","publicClient":True,
            "standardFlowEnabled":True,"directAccessGrantsEnabled":False,"serviceAccountsEnabled":False,"consentRequired":True,
            "redirectUris":[],"webOrigins":[],"defaultClientScopes":["vk-mcp"],
            "attributes":{"pkce.code.challenge.method":"S256"}})
    clients.append({"clientId":"vk-dashboard","enabled":True,"protocol":"openid-connect","publicClient":False,
        "secret":dashboard_secret,"standardFlowEnabled":True,"directAccessGrantsEnabled":False,
        "redirectUris":[origin+"/callback"],"webOrigins":[origin],"defaultClientScopes":[],
        "attributes":{"pkce.code.challenge.method":"S256"}})
    return {"realm":"vk","enabled":True,"sslRequired":"external","registrationAllowed":False,
        "resetPasswordAllowed":True,"rememberMe":False,"bruteForceProtected":True,"failureFactor":5,
        "accessTokenLifespan":300,"ssoSessionIdleTimeout":1800,"ssoSessionMaxLifespan":28800,
        "passwordPolicy":"length(14) and digits(1) and lowerCase(1) and upperCase(1)",
        "clientScopes":[scope],"clients":clients}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--domain",required=True)
    args=parser.parse_args()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?",args.domain) or "." not in args.domain:
        parser.error("Provide an ASCII domain name only")
    root=Path(__file__).resolve().parents[1]
    target=root/".secrets"
    if target.exists():
        raise SystemExit(".secrets already exists; refusing to overwrite credentials")
    dashboard_secret=secrets.token_urlsafe(48)
    db_secret=secrets.token_urlsafe(48)
    admin_secret=secrets.token_urlsafe(48)
    origin="https://"+args.domain
    files={
        "app.env":f"PUBLIC_URL={origin}\nOIDC_ISSUER={origin}/auth/realms/vk\nENCRYPTION_KEY={Fernet.generate_key().decode()}\nCOOKIE_SECRET={secrets.token_urlsafe(48)}\nOIDC_CLIENT_ID=vk-dashboard\nOIDC_CLIENT_SECRET={dashboard_secret}\nDB_PATH=/data/vk.sqlite3\n",
        "keycloak.env":f"KC_DB_PASSWORD={db_secret}\nKC_BOOTSTRAP_ADMIN_USERNAME=admin\nKC_BOOTSTRAP_ADMIN_PASSWORD={admin_secret}\n",
        "postgres.env":f"POSTGRES_DB=keycloak\nPOSTGRES_USER=keycloak\nPOSTGRES_PASSWORD={db_secret}\n",
        "compose.env":f"DOMAIN={args.domain}\n",
        "realm.json":json.dumps(realm(args.domain,dashboard_secret),indent=2)+"\n",
    }
    target.mkdir(mode=0o700)
    for name,value in files.items():
        path=target/name
        with path.open("x",encoding="utf-8",newline="\n") as out: out.write(value)
        path.chmod(0o600)
    print("Created local deployment configuration in .secrets; no secret values displayed. Services were not started.")


if __name__=="__main__": main()
