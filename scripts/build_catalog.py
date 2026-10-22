"""Build a fixed catalog from pinned sources; never runs downloaded project code.

Usage: python scripts/build_catalog.py ../vk-mcp-research
"""
import json
from pathlib import Path
import re
import subprocess
import sys

# Deliberate read allowlist: 'get' can create a link or return access secrets.
READ = set("""
market.get market.getAlbumById market.getAlbums market.getById market.getCategories
market.getComments market.getGroupOrders market.getOrderById market.getOrderItems market.getOrders
market.getProperties market.search market.searchItems market.searchItemsBasic
groups.get groups.getAddresses groups.getBanned groups.getById groups.getCatalogInfo
groups.getInvitedUsers groups.getInvites groups.getMembers groups.getOnlineStatus groups.getRequests
groups.getSettings groups.getTagList groups.getTokenPermissions groups.isMember groups.search
ads.checkLink ads.getAccounts ads.getAds ads.getAdsLayout ads.getAdsTargeting ads.getBudget
ads.getCampaigns ads.getCategories ads.getClients ads.getDemographics ads.getFloodStats
ads.getLookalikeRequests ads.getMusicians ads.getMusiciansByIds ads.getOfficeUsers ads.getPostsReach
ads.getRejectionReason ads.getStatistics ads.getSuggestions ads.getTargetGroups ads.getTargetingStats
messages.getByConversationMessageId messages.getById messages.getChat messages.getChatPreview
messages.getConversationMembers messages.getConversations messages.getConversationsById
messages.getHistory messages.getHistoryAttachments messages.getImportantMessages messages.getIntentUsers
messages.getLastActivity messages.getMessagesReactions messages.getReactedPeers messages.getReactionsAssets
messages.isMessagesFromGroupAllowed messages.search messages.searchConversations
stats.get stats.getPostReach wall.checkCopyrightLink wall.get wall.getById wall.getComment wall.getComments wall.getReposts wall.search
photos.get photos.getAlbums photos.getAlbumsCount photos.getAll photos.getAllComments photos.getById
photos.getComments photos.getNewTags photos.getTags photos.getUserPhotos photos.search
video.get video.getAlbumById video.getAlbums video.getAlbumsByVideo video.getComments video.getOembed video.search
docs.get docs.getById docs.getTypes docs.search board.getComments board.getTopics
leadForms.get leadForms.getLeads storage.get storage.getKeys utils.checkLink utils.getLastShortenedLinks
utils.getLinkStats utils.getServerTime utils.resolveScreenName users.get users.getFollowers users.getSubscriptions users.search
donut.getFriends donut.getSubscription donut.getSubscriptions donut.isDon prettyCards.get prettyCards.getById
podcasts.searchPodcast notifications.get pages.get pages.getHistory pages.getTitles pages.getVersion
friends.get friends.getLists friends.getMutual friends.getOnline friends.getRequests friends.getSuggestions
friends.areFriends leadForms.list market.filterCategories video.liveGetCategories
newsfeed.get newsfeed.search newsfeed.getMentions likes.getList likes.isLiked polls.getById polls.getVoters
stories.get stories.getById stories.getStats
""".split())
EXTRA = "friends newsfeed likes polls stories".split()
KEYWORDS = {
 "wall":"стена посты публикации контент комментарии", "groups":"сообщества группы поиск участники",
 "messages":"сообщения диалоги ответы", "stats":"статистика охват посещения",
 "photos":"фото фотографии альбомы", "market":"товары магазин заказы", "ads":"реклама расходы статистика",
 "newsfeed":"поиск публикаций упоминания лента", "friends":"друзья", "users":"пользователи профили",
 "stories":"истории", "video":"видео", "polls":"опросы", "likes":"реакции лайки",
}


def revision(path):
    return subprocess.check_output(["git","-C",str(path),"rev-parse","HEAD"],text=True).strip()


def schema_of(param):
    # VK uses non-standard format/entity/required metadata. Keep JSON Schema keywords only.
    result = {k:v for k,v in param.items() if k in {"type","description","enum","minimum","maximum","minLength","maxLength","minItems","maxItems"}}
    if result.get("type") == "array":
        items = param.get("items",{})
        if items.get("type") in ("string","integer","number","boolean"):
            result["items"] = {k:v for k,v in items.items() if k in ("type","enum","minimum","maximum")}
        else:
            result["items"] = {"type":"string"}
    if result.get("type") not in ("string","integer","number","boolean","array","object"):
        result = {"type":"string","description":param.get("description",param["name"])}
    return result


def main():
    research = Path(sys.argv[1]).resolve()
    upstream = (research/"ilyautov/vk_mcp/endpoints.yaml").read_text(encoding="utf-8")
    # We reuse method selection, not upstream runtime or safety labels.
    names = set(re.findall(r"^  path: /method/([A-Za-z]+\.[A-Za-z]+)$",upstream,re.M))
    official = {}
    for path in sorted((research/"vk-api-schema").glob("*/methods.json")):
        for method in json.loads(path.read_text(encoding="utf-8")).get("methods",[]):
            official[method["name"]] = method
            if path.parent.name in EXTRA:
                names.add(method["name"])
    methods=[]
    for name in sorted(names):
        spec=official.get(name)
        if not spec:
            continue
        section, verb=name.split(".")
        access="read" if name in READ else "approval"
        reason=""
        if name not in READ and (verb.startswith(("get","is","check","search")) or section in ("ads","orders","donut","storage")
            or re.search(r"Callback|LongPoll|Upload|Permissions|Token|Address|Officers|Owner|Manager|Chat|Invite|Link|removeUser|ban|Ban",name)
            or name in ("groups.edit","groups.setSettings","groups.enableOnline","groups.disableOnline","utils.getShortLink","pages.saveAccess","market.editOrder")):
            access="disabled"
            reason="Security settings, credentials, financial changes, raw uploads, or an unreviewed side effect are outside v0.1"
        params=[p for p in spec.get("parameters",[]) if p["name"] not in ("access_token","v","client_secret","sig")]
        # The pinned official wall.get schema omits owner_id although the method
        # describes user/community walls. Keep this small reviewed override explicit.
        if name=="wall.get" and not any(p["name"]=="owner_id" for p in params):
            params.append({"name":"owner_id","type":"integer","description":"Signed owner ID: positive user, negative community (reviewed schema override)."})
        methods.append({"method":name,"section":section,"access":access,"reason":reason,
            "description":spec.get("description",name),"keywords":KEYWORDS.get(section,""),
            "token_types":spec.get("access_token_type",[]),
            "documentation":"https://dev.vk.com/ru/method/"+name,
            "schema":{"type":"object","properties":{p["name"]:schema_of(p) for p in params},
                "required":[p["name"] for p in params if p.get("required")],"additionalProperties":False}})
    output={"provenance":{"vk_schema_commit":revision(research/"vk-api-schema"),
        "selection_commit":revision(research/"ilyautov"),"api_version":"5.199",
        "note":"Token-type metadata comes from the official schema and is not a guarantee of live access."},"methods":methods}
    target=Path(__file__).resolve().parents[1]/"vk_mcp/data/catalog.json"
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(output,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print({kind:sum(r["access"]==kind for r in methods) for kind in ("read","approval","disabled")})


if __name__=="__main__":
    main()
