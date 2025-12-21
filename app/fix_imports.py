from pathlib import Path
import re

p = Path("main.py")
txt = p.read_text(encoding="utf-8")

# remove import duplicado acidental
txt = re.sub(r"\nfrom sqlalchemy import func, case, case\s*\n", "\n", txt)

# garante import correto
txt = re.sub(
    r"^from sqlalchemy import func\s*$",
    "from sqlalchemy import func, case",
    txt,
    flags=re.M
)

p.write_text(txt, encoding="utf-8")
print("OK: imports ajustados")
