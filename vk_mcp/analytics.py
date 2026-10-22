"""Descriptive statistics; no claims about causation, sales or hidden reach."""
from datetime import datetime, timezone
import math
from statistics import median
from .catalog import PolicyError


def number(value):
    return isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value) and value>=0


def compare_samples(samples, start_time, end_time):
    if not 0<=start_time<end_time:
        raise PolicyError("Use one valid time window for all communities")
    if not 1<=len(samples)<=10:
        raise PolicyError("Compare 1 to 10 communities")
    result=[]
    for sample in samples:
        group_id=sample.get("group_id")
        if not isinstance(group_id,int) or isinstance(group_id,bool) or group_id<=0:
            raise PolicyError("group_id must be positive")
        raw=sample.get("posts",[])
        if not isinstance(raw,list) or len(raw)>1000:
            raise PolicyError("Maximum 1000 posts per sample")
        posts=[]
        seen=set()
        for post in raw:
            if not isinstance(post,dict) or post.get("owner_id")!=-group_id or not isinstance(post.get("id"),int):
                raise PolicyError("Post must have an integer ID and match the community owner")
            date=post.get("date")
            if not isinstance(date,int) or isinstance(date,bool):
                raise PolicyError("Post date must be a Unix timestamp")
            if post["id"] in seen or not start_time<=date<end_time or post.get("is_pinned"):
                continue
            seen.add(post["id"])
            posts.append(post)
        metrics={}
        for name in ("likes","comments","reposts","views"):
            values=[]
            for p in posts:
                raw_value=p.get(name)
                value=raw_value.get("count") if isinstance(raw_value,dict) else raw_value
                if number(value): values.append(value)
            metrics[name]={"observed_posts":len(values),"missing_posts":len(posts)-len(values),
                           "sum":sum(values) if values else None,"median":median(values) if values else None}
        er_views=[]
        er_members=[]
        members=sample.get("members_count")
        for p in posts:
            vals=[p.get(k,{}).get("count") if isinstance(p.get(k),dict) else p.get(k) for k in ("likes","comments","reposts","views")]
            if all(number(v) for v in vals[:3]):
                interactions=sum(vals[:3])
                if number(vals[3]) and vals[3]>0: er_views.append(100*interactions/vals[3])
                if number(members) and members>0: er_members.append(100*interactions/members)
        formats={}
        hours={}
        for p in posts:
            types=sorted({a.get("type","unknown") for a in p.get("attachments",[]) if isinstance(a,dict)})
            label="+".join(types) if types else "text"
            formats[label]=formats.get(label,0)+1
            hour=datetime.fromtimestamp(p["date"],timezone.utc).hour
            hours[str(hour)]=hours.get(str(hour),0)+1
        result.append({"group_id":group_id,"name":sample.get("name"),"source":"https://vk.com/club"+str(group_id),
            "sample_posts":len(posts),"coverage":sample.get("coverage","unknown; supplied sample"),
            "posts_per_day_in_sample":len(posts)/((end_time-start_time)/86400),"metrics":metrics,
            "er_views_median_percent":median(er_views) if er_views else None,"er_views_posts":len(er_views),
            "er_current_members_median_percent":median(er_members) if er_members else None,
            "er_current_members_posts":len(er_members),"format_counts":formats,"hour_counts_utc":hours,
            "post_sources":["https://vk.com/wall"+str(p["owner_id"])+"_"+str(p["id"]) for p in posts]})
    return {"period":{"start_inclusive":start_time,"end_exclusive":end_time},"communities":result,
        "formulas":{"ER_views":"100*(likes+comments+reposts)/views, per post; then median",
                    "ER_members":"100*(likes+comments+reposts)/current_members_count, per post; then median"},
        "limitations":["Views are not unique reach; interactions are not unique people.",
          "Missing values stay missing; zero is used only when present in source data.",
          "Pinned posts are excluded. Reposts and ads remain in the sample unless the caller filters them.",
          "Counts are observed now; posts of different ages are not directly comparable.",
          "Current member count does not reconstruct historical audience size.",
          "Frequency describes the supplied sample; complete collection is not implied.",
          "Public engagement does not establish sales, conversion, paid promotion or causal success."],
        "untrusted_content":True}
