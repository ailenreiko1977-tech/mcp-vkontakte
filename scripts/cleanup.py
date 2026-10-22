"""Remove expired sessions and old action payloads. Run daily in the app container."""
import time
from vk_mcp.config import Settings
from vk_mcp.store import Store


def main():
    settings=Settings.from_env()
    store=Store(settings.db_path,settings.encryption_key)
    with store.connect() as db:
        db.execute("DELETE FROM sessions WHERE expires<?",(time.time(),))
        db.execute("DELETE FROM actions WHERE expires<?",(time.time()-86400,))
        db.execute("DELETE FROM quotas WHERE bucket<?",(int(time.time())//60-2,))
        db.execute("PRAGMA incremental_vacuum")
    print("Expired data removed; backup retention is configured separately.")


if __name__=="__main__": main()
