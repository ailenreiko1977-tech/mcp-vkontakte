import time
from .catalog import Catalog, PolicyError
from .analytics import compare_samples
from .vk import VKClient


class Service:
    def __init__(self, settings, store, vk=None):
        self.settings=settings
        self.store=store
        self.catalog=Catalog()
        self.vk=vk or VKClient(store)

    async def read(self, owner, alias, method, params):
        entry=self.catalog.validate(method,params)
        return await self.vk.call(owner,alias,entry,params)

    def prepare(self, owner, alias, method, params):
        self.store.rate_limit(owner,30)
        entry=self.catalog.validate(method,params,write=True)
        connection=self.store.connection(owner,alias)
        if connection["kind"]=="service":
            raise PolicyError("Service keys cannot be used for changes; use an appropriate VK account or community token")
        payload={"alias":alias,"method":method,"params":params,"revision":connection["revision"]}
        action_id,digest=self.store.prepare(owner,payload)
        return {"action_id":action_id,"method":method,"parameters":params,"state":"pending",
                "approval_url":self.settings.public_url+"/actions/"+action_id,"expires_in_seconds":900,
                "instruction":"Show the user this URL. Only the signed-in user can submit the exact action in the browser; there is no MCP confirmation tool."}

    async def approve(self, owner, action_id, digest):
        # Atomic claim happens BEFORE network; even ambiguous delivery is never auto-retried.
        payload=self.store.claim(owner,action_id,digest)
        try:
            entry=self.catalog.validate(payload["method"],payload["params"],write=True)
            if self.store.connection(owner,payload["alias"])["revision"]!=payload["revision"]:
                raise PolicyError("Connection changed after preparation; prepare a new action")
            result=await self.vk.call(owner,payload["alias"],entry,payload["params"],write=True)
        except PolicyError as exc:
            self.store.finish(owner,action_id,"failed_or_unknown",{"error":str(exc)})
            raise
        except Exception:
            self.store.finish(owner,action_id,"failed_or_unknown",{"error":"Unexpected failure; verify VK before retrying"})
            raise PolicyError("Unexpected failure; verify VK before retrying") from None
        self.store.finish(owner,action_id,"completed",result)
        return result

    async def snapshot(self, owner, alias, group_id, start_time, end_time, max_pages=3):
        if not isinstance(group_id,int) or group_id<=0 or not 1<=max_pages<=10 or not 0<=start_time<end_time<=time.time()+60:
            raise PolicyError("Invalid community, time window or page limit")
        info=await self.read(owner,alias,"groups.getById",{"group_ids":[str(group_id)],"fields":["members_count"]})
        groups=info["data"].get("groups",[]) if isinstance(info["data"],dict) else info["data"]
        if not groups:
            raise PolicyError("Community not accessible")
        posts=[]
        complete=False
        for page in range(max_pages):
            response=await self.read(owner,alias,"wall.get",{"owner_id":-group_id,"count":100,"offset":page*100,"filter":"owner"})
            items=response["data"].get("items",[])
            posts.extend(p for p in items if start_time<=p.get("date",0)<end_time)
            unpinned=[p for p in items if not p.get("is_pinned")]
            if len(items)<100 or (unpinned and all(p.get("date",0)<start_time for p in unpinned)):
                complete=True
                break
        return {"group_id":group_id,"name":groups[0].get("name"),"members_count":groups[0].get("members_count"),
                "posts":posts,"coverage":"API period traversed; visibility restrictions may remain" if complete else "partial; page limit reached",
                "fetched_at":int(time.time()),"untrusted_content":True}
