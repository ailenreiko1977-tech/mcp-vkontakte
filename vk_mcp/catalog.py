"""Only reviewed, explicitly listed methods can reach VK; no arbitrary URLs."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator


class PolicyError(ValueError):
    pass


class Catalog:
    def __init__(self):
        document = json.loads(Path(__file__).with_name("data").joinpath("catalog.json").read_text(encoding="utf-8"))
        self.meta = document["provenance"]
        self.methods = {entry["method"]: entry for entry in document["methods"]}

    def get(self, method):
        if method not in self.methods:
            raise PolicyError("Method is not in the reviewed catalog")
        return self.methods[method]

    def validate(self, method, params, *, write=False):
        entry = self.get(method)
        if entry["access"] == "disabled":
            raise PolicyError("Method is disabled: " + entry["reason"])
        if (entry["access"] != "read") != write:
            raise PolicyError("Use prepare_action for changes and call_read for reads")
        if len(json.dumps(params, ensure_ascii=False).encode()) > 32_768:
            raise PolicyError("Parameters exceed 32 KiB")
        if "count" in params and (not isinstance(params["count"],int) or isinstance(params["count"],bool) or not 1<=params["count"]<= (100 if method=="wall.get" else 1000)):
            raise PolicyError("Page size exceeds server limits")
        errors = list(Draft202012Validator(entry["schema"]).iter_errors(params))
        if errors:
            # Never echo parameter values: they may contain personal data or secrets.
            raise PolicyError("Parameters do not match the schema; call describe_method")
        return entry

    def search(self, query="", section=None, offset=0, limit=20):
        if not 0 <= offset <= 10000 or not 1 <= limit <= 50:
            raise PolicyError("Invalid pagination")
        words = query.casefold().split()
        rows = [r for r in self.methods.values() if (not section or r["section"] == section)
                and all(w in (r["method"] + " " + r["description"] + " " + r.get("keywords", "")).casefold() for w in words)]
        return {"total": len(rows), "items": [{k: r[k] for k in ("method", "section", "description", "access", "token_types")} for r in rows[offset:offset+limit]],
                "next_offset": offset + limit if offset + limit < len(rows) else None}
