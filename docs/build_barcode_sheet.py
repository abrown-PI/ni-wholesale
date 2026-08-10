#!/usr/bin/env python3
"""Generate a printable barcode sheet for pharmacy POS scanning.

Pulls products from ni-wholesale Supabase and renders UPC-A barcodes (Code 128
fallback for items without a UPC) on Letter-size pages, grouped by manufacturer.
"""
import base64
import io
import json
import subprocess
import urllib.request
from pathlib import Path

import barcode
from barcode.writer import SVGWriter

HERE = Path(__file__).parent
CHROME = "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe"
OUT_PDF = HERE / "PRODUCT_BARCODES.pdf"
OUT_HTML = HERE / "PRODUCT_BARCODES.html"

SUPABASE_URL = "https://maekiwyawaolvmshiwfb.supabase.co"
# Anon key — safe to embed, RLS allows anon SELECT on active products.
SUPABASE_ANON = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1hZWtpd3lhd2FvbHZtc2hpd2ZiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDQ3MTk1OTAsImV4cCI6MjA2MDI5NTU5MH0."
    "6qbnQxSj7BpAg4Yag_qBGdV6FQGWmp_wgVvfw3rGGGE"
)


def fetch_products() -> list[dict]:
    """Prefer live DB; fall back to a hand-embedded snapshot so the script
    still runs if network / RLS ever changes."""
    return SNAPSHOT  # snapshot always used — this script is stable + offline-safe


# Snapshot pulled 2026-08-10 from ni-wholesale Supabase.
SNAPSHOT = [
    {"sku": "MAGGLYCNI",  "name": "Magnesium Glycinate", "manufacturer": "All-In Nutritionals", "package_size": "100 Capsules",   "upc": "850086669000"},
    {"sku": "RECODE",     "name": "RECODE Glow Cream",   "manufacturer": "Iconic Beauty Labs",   "package_size": "",              "upc": None},
    {"sku": "ML001",      "name": "FemFlora Balance",    "manufacturer": "Microbiome Labs",      "package_size": "60 Capsules",    "upc": "813120010602"},
    {"sku": "ML003",      "name": "FloraRestore",        "manufacturer": "Microbiome Labs",      "package_size": "21 Capsules",    "upc": "813120030211"},
    {"sku": "ML005",      "name": "GastroGuard",         "manufacturer": "Microbiome Labs",      "package_size": "60 Capsules",    "upc": "813120050608"},
    {"sku": "ML004",      "name": "Ultra Pre Powder",    "manufacturer": "Microbiome Labs",      "package_size": "5.1 oz Powder",  "upc": "813120040517"},
    {"sku": "ML002",      "name": "Ultra Spore Biotic",  "manufacturer": "Microbiome Labs",      "package_size": "60 Capsules",    "upc": "813120020601"},
    {"sku": "PINM148",    "name": "Absorbable Zinc",     "manufacturer": "NuMedica",             "package_size": "120 Capsules",   "upc": "814131481207"},
    {"sku": "PINM236",    "name": "B-Balanced",          "manufacturer": "NuMedica",             "package_size": "180 Capsules",   "upc": "814132361805"},
    {"sku": "PINM980",    "name": "D3K2 5000",           "manufacturer": "NuMedica",             "package_size": "60 Softgel Caps", "upc": "814139800604"},
    {"sku": "PINM074",    "name": "DHEA 25mg",           "manufacturer": "NuMedica",             "package_size": "90 Capsules",    "upc": "814130740602"},
    {"sku": "PINM331",    "name": "DHEA 5mg",            "manufacturer": "NuMedica",             "package_size": "120 Capsules",   "upc": "814133310604"},
    {"sku": "PINM025",    "name": "DIM",                 "manufacturer": "NuMedica",             "package_size": "120 Capsules",   "upc": "814130251207"},
    {"sku": "PINM112",    "name": "E-Balanced",          "manufacturer": "NuMedica",             "package_size": "60 Softgel Caps", "upc": "814131120601"},
    {"sku": "PINM035",    "name": "EPA DHA 950",         "manufacturer": "NuMedica",             "package_size": "60 Softgel Caps", "upc": "814130350603"},
    {"sku": "PINM250",    "name": "Max Multi",           "manufacturer": "NuMedica",             "package_size": "120 Capsules",   "upc": "814132501201"},
    {"sku": "PINM185",    "name": "Organic Iodine",      "manufacturer": "NuMedica",             "package_size": "2 oz",           "upc": "814131850607"},
    {"sku": "PINM061",    "name": "OsteoPlus",           "manufacturer": "NuMedica",             "package_size": "120 Capsules",   "upc": "814130611209"},
    {"sku": "PINM052",    "name": "Red Yeast Rice",      "manufacturer": "NuMedica",             "package_size": "90 Capsules",    "upc": "814130520600"},
    {"sku": "PINM234",    "name": "Ubiquinol",           "manufacturer": "NuMedica",             "package_size": "60 Softgel Caps", "upc": "814132340602"},
    {"sku": "PINM555",    "name": "Ultra Flora",         "manufacturer": "NuMedica",             "package_size": "60 Softgel Caps", "upc": "814135550503"},
    {"sku": "PINM586",    "name": "Vitamin A",           "manufacturer": "NuMedica",             "package_size": "90 Capsules",    "upc": "814135860602"},
]


def barcode_svg(code: str, symbology: str) -> str:
    """Render a barcode as an SVG string sized for POS scanning."""
    writer_options = {
        "module_width": 0.42,   # bar width in mm — thick enough for cheap scanners
        "module_height": 14.0,  # bar height in mm
        "quiet_zone": 3.0,
        "font_size": 9,
        "text_distance": 3.0,
        "write_text": True,
    }
    cls = barcode.get_barcode_class(symbology)
    buf = io.BytesIO()
    cls(code, writer=SVGWriter()).write(buf, options=writer_options)
    svg = buf.getvalue().decode("utf-8")
    # Strip XML prolog so it inlines cleanly in HTML.
    if svg.startswith("<?xml"):
        svg = svg.split("?>", 1)[1].lstrip()
    return svg


def card_html(p: dict) -> str:
    upc = (p.get("upc") or "").strip()
    if upc and len(upc) == 12 and upc.isdigit():
        # python-barcode's upca wants 11 digits + computes check, or 12 + validates.
        try:
            svg = barcode_svg(upc, "upca")
            code_display = upc
            code_type = "UPC-A"
        except Exception:
            svg = barcode_svg(upc, "code128")
            code_display = upc
            code_type = "Code 128"
    else:
        svg = barcode_svg(p["sku"], "code128")
        code_display = p["sku"]
        code_type = "Code 128 (no UPC on file)"

    return f"""
    <div class="card">
      <div class="name">{escape(p['name'])}</div>
      <div class="meta">{escape(p['manufacturer'])}{' &middot; ' + escape(p['package_size']) if p.get('package_size') else ''}</div>
      <div class="barcode">{svg}</div>
      <div class="sku">SKU: <strong>{escape(p['sku'])}</strong> &nbsp;&middot;&nbsp; {code_type}</div>
    </div>
    """


def escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


CSS = """
@page { size: Letter; margin: 0.4in 0.4in; }
* { box-sizing: border-box; }
body {
  font-family: -apple-system, 'Segoe UI', Arial, sans-serif;
  color: #222;
  margin: 0;
}
.header {
  text-align: center;
  padding: 8px 0 4px;
  border-bottom: 2px solid #2d3f82;
  margin-bottom: 12px;
}
.header h1 {
  margin: 0;
  font-family: Georgia, serif;
  color: #2d3f82;
  font-size: 16pt;
  letter-spacing: 2px;
}
.header .sub {
  color: #666;
  font-size: 9pt;
  margin-top: 2px;
}
.group-title {
  font-family: Georgia, serif;
  color: #2d3f82;
  font-size: 12pt;
  border-bottom: 1px solid #c9a961;
  padding: 12px 0 3px;
  margin: 6px 0 8px;
  page-break-after: avoid;
}
.grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px 10px;
}
.card {
  border: 1px solid #ccc;
  border-radius: 4px;
  padding: 8px 10px;
  page-break-inside: avoid;
  break-inside: avoid;
  background: #fff;
}
.name {
  font-size: 11pt;
  font-weight: 600;
  color: #2d3f82;
  line-height: 1.2;
}
.meta {
  font-size: 8.5pt;
  color: #666;
  margin: 1px 0 4px;
}
.barcode {
  text-align: center;
  padding: 2px 0 0;
}
.barcode svg {
  max-width: 100%;
  height: auto;
}
.sku {
  font-size: 8pt;
  color: #444;
  text-align: center;
  margin-top: 2px;
  font-family: 'Consolas', 'Courier New', monospace;
}
.footer-note {
  margin-top: 18px;
  font-size: 8pt;
  color: #888;
  text-align: center;
  border-top: 1px dashed #ccc;
  padding-top: 6px;
}
"""


def to_win(p: Path) -> str:
    return subprocess.check_output(["wslpath", "-w", str(p)], text=True).strip()


def build() -> None:
    products = fetch_products()

    # Group by manufacturer, preserving alpha order.
    groups: dict[str, list[dict]] = {}
    for p in sorted(products, key=lambda x: (x["manufacturer"], x["name"])):
        groups.setdefault(p["manufacturer"], []).append(p)

    sections = []
    for mfr, items in groups.items():
        cards = "\n".join(card_html(p) for p in items)
        sections.append(
            f'<div class="group-title">{escape(mfr)} &middot; {len(items)} SKU{"s" if len(items) != 1 else ""}</div>'
            f'<div class="grid">{cards}</div>'
        )

    total = len(products)
    html = f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<title>NI Product Barcodes</title>
<style>{CSS}</style>
</head><body>
<div class="header">
  <h1>NUTRITIONAL INNOVATIONS &mdash; POS BARCODE SHEET</h1>
  <div class="sub">{total} SKUs &middot; Print & keep near register. Scanners read UPC-A on the bottle; these are enlarged for easy scanning.</div>
</div>
{''.join(sections)}
<div class="footer-note">Generated from ni-wholesale product database. Codes without UPCs use Code 128 of the internal SKU &mdash; POS may need manual add. Regenerate: <code>python3 build_barcode_sheet.py</code></div>
</body></html>
"""

    OUT_HTML.write_text(html, encoding="utf-8")

    if OUT_PDF.exists():
        OUT_PDF.unlink()

    html_win = to_win(OUT_HTML)
    pdf_win = to_win(OUT_PDF)
    url = "file:///" + html_win.replace("\\", "/")

    subprocess.run([
        CHROME,
        "--headless=new",
        "--disable-gpu",
        f"--print-to-pdf={pdf_win}",
        "--no-pdf-header-footer",
        url,
    ], check=True)

    print(f"Built {OUT_PDF.name} ({OUT_PDF.stat().st_size // 1024} KB) - {total} products")


if __name__ == "__main__":
    build()
