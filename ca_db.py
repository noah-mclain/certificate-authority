import json
import ca_config


def load_db() -> dict:
    if ca_config.DB_FILE.exists():
        with open(ca_config.DB_FILE) as f:
            data = json.load(f)
        return {"certificates": data.get("certificates", [])}
    return {"certificates": []}


def save_db(db: dict) -> None:
    ca_config.DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = ca_config.DB_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(db, f, indent=2)
    tmp.replace(ca_config.DB_FILE)
