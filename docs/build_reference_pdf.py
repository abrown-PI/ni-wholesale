#!/usr/bin/env python3
"""Convert PRODUCT_REFERENCE.md into a styled HTML, then let Chrome print it to PDF."""
import subprocess
from pathlib import Path

import markdown

HERE = Path(__file__).parent
MD = HERE / "PRODUCT_REFERENCE.md"
HTML = HERE / "PRODUCT_REFERENCE.html"
PDF = HERE / "PRODUCT_REFERENCE.pdf"
CHROME = "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe"

CSS = """
@page { size: Letter; margin: 0.6in 0.7in; }
body {
  font-family: -apple-system, 'Segoe UI', Arial, sans-serif;
  color: #222;
  line-height: 1.5;
  font-size: 11pt;
  max-width: 780px;
  margin: 0 auto;
}
h1 {
  color: #2d3f82;
  font-size: 24pt;
  border-bottom: 3px solid #c9a961;
  padding-bottom: 8px;
  margin-top: 32px;
}
h2 {
  color: #2d3f82;
  font-size: 16pt;
  border-bottom: 1px solid #c9a961;
  padding-bottom: 4px;
  margin-top: 28px;
  page-break-after: avoid;
}
h3 { color: #2d3f82; font-size: 12pt; margin-top: 16px; }
h1 + h1, h2 + h2 { page-break-before: always; }
hr { border: none; border-top: 1px dashed #ccc; margin: 24px 0; }
ul { margin: 4px 0 12px 20px; padding: 0; }
li { margin: 2px 0; }
p { margin: 6px 0; }
strong { color: #2d3f82; }
em { color: #666; font-style: italic; }
blockquote {
  background: #f5f2ea;
  border-left: 3px solid #c9a961;
  padding: 8px 14px;
  margin: 12px 0;
  font-size: 10pt;
  color: #555;
}
table {
  border-collapse: collapse;
  width: 100%;
  margin: 12px 0;
  font-size: 10pt;
}
th, td { padding: 6px 10px; border: 1px solid #ddd; text-align: left; }
th { background: #2d3f82; color: #fff; }
tr:nth-child(even) td { background: #faf8f4; }
code { background: #f5f2ea; padding: 1px 4px; border-radius: 2px; font-size: 10pt; }
a { color: #2d3f82; text-decoration: none; }
.header {
  text-align: center;
  padding: 12px 0 8px;
  border-bottom: 2px solid #2d3f82;
  margin-bottom: 24px;
  font-family: Georgia, serif;
  color: #2d3f82;
  font-size: 13pt;
  letter-spacing: 2px;
}
h1:first-of-type { margin-top: 0; }
h2 { page-break-inside: avoid; }
"""

md_text = MD.read_text(encoding="utf-8")
html_body = markdown.markdown(md_text, extensions=["extra", "toc", "sane_lists"])

full_html = f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<title>NI Wholesale — Product Reference</title>
<style>{CSS}</style>
</head><body>
<div class="header">NUTRITIONAL INNOVATIONS &mdash; WHOLESALE</div>
{html_body}
</body></html>
"""
HTML.write_text(full_html, encoding="utf-8")

if PDF.exists():
    PDF.unlink()

# Chrome is a Windows binary — it can't read Linux paths. Translate both
# the input HTML and output PDF to Windows-style paths via wslpath.
def to_win(p: Path) -> str:
    return subprocess.check_output(["wslpath", "-w", str(p)], text=True).strip()

html_win = to_win(HTML)
pdf_win = to_win(PDF)
html_url = "file:///" + html_win.replace("\\", "/")

subprocess.run([
    CHROME,
    "--headless=new",
    "--disable-gpu",
    f"--print-to-pdf={pdf_win}",
    "--no-pdf-header-footer",
    html_url,
], check=True)

print(f"HTML: {HTML}")
print(f"PDF:  {PDF}")
