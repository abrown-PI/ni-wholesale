#!/usr/bin/env python3
"""Generate NI product info cards modeled on the DIM template.

One card per product + one general summary card. Each card has:
  Left panel: colored banner, product name banner, bottle image, QR code + "Order Now"
  Right panel: name, headline claim, description, directions, specifications,
               PI logo, badges, FDA disclaimer, store URL

QR codes deep-link to the product on pharmacyinnovationsstore.net when a slug
is known, otherwise land on the store homepage.
"""
import base64
import io
import subprocess
import urllib.request
from pathlib import Path

import qrcode
import qrcode.constants

HERE = Path(__file__).parent
IMG_DIR = HERE.parent / "images" / "products"
CHROME = "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe"
OUT_HTML = HERE / "PRODUCT_CARDS.html"
OUT_PDF = HERE / "PRODUCT_CARDS.pdf"

STORE_HOME = "https://pharmacyinnovationsstore.net"
LOGO_PATH = HERE / "pi-logo.png"


def b64_of(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def b64_of_url(url: str) -> str:
    with urllib.request.urlopen(url, timeout=15) as r:
        return base64.b64encode(r.read()).decode("ascii")


def qr_data_uri(url: str) -> str:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=1,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#1e3a8a", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def img_data_uri(path: Path) -> str:
    return "data:image/png;base64," + b64_of(path)


def url_data_uri(url: str) -> str:
    return "data:image/png;base64," + b64_of_url(url)


PI_LOGO_URI = img_data_uri(LOGO_PATH)


# ---------------------------------------------------------------------------
# Product catalog. Each entry: everything needed to render one card.
# ---------------------------------------------------------------------------
PRODUCTS = [
    {
        "sku": "PINM025",
        "name": "DIM",
        "headline": "Support for Healthy Estrogen Metabolism in Men & Women*",
        "banner": "Support for Healthy Estrogen Metabolism*",
        "serving_highlight": "150 mg of DIM Per Serving",
        "manufacturer": "NuMedica",
        "package_size": "120 Capsules",
        "servings": "60 servings (2 capsules each)",
        "image": "DIM-Estro.png",
        "slug": "dim",
        "description": (
            "Supports healthy estrogen metabolism in men and women.* DIM is an advanced "
            "metabolite of Indole-3-Carbinol, the indole found in cruciferous vegetables. "
            "Indoles support healthy estrogen metabolism and an optimal ratio of estrogen "
            "metabolites, including 2-hydroxyestrogen and 16-hydroxyestrogen. BioPerine® "
            "and curcumin combination has been added to enhance the bioavailability, extent "
            "of absorption and serum concentration of the bioactive curcuminoids.*"
        ),
        "directions": "Take two capsules once per day or as directed by your healthcare practitioner.",
        "specs": [
            ("Serving Size", "2 Capsules"),
            ("Servings Per Container", "60"),
            ("Available in", "120 Capsules"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "MAGGLYCNI",
        "name": "Magnesium Glycinate 600",
        "headline": "Calm, Sleep & Muscle Support*",
        "banner": "Highly Absorbable Magnesium*",
        "serving_highlight": "600 mg Magnesium (chelated with glycine)",
        "manufacturer": "All-In Nutritionals",
        "package_size": "100 Capsules",
        "servings": "Serving as directed by practitioner",
        "image_url": "https://maekiwyawaolvmshiwfb.supabase.co/storage/v1/object/public/product-images/products/1784990405807_c43x37_Mag_Glycinate_600.png",
        "slug": "magnesium-glycinate-600-100-capsules",
        "description": (
            "Highly bioavailable magnesium chelated with glycine to support muscle function, "
            "nerve health, and a calm relaxation response with gentle GI tolerability. "
            "A go-to for restless legs, tight muscles, and quality sleep support.*"
        ),
        "directions": "As directed by your healthcare practitioner (label serving is typically 2 capsules daily).",
        "specs": [
            ("Serving Size", "2 Capsules"),
            ("Magnesium per serving", "600 mg"),
            ("Available in", "100 Capsules"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "ML001",
        "name": "FemFlora Balance",
        "headline": "Vaginal, Urinary & Immune Balance*",
        "banner": "Targeted Women's Probiotic*",
        "serving_highlight": "5.5 Billion CFU + 500 mg Cranberry",
        "manufacturer": "Microbiome Labs",
        "package_size": "60 Capsules",
        "servings": "30 servings (2 capsules each)",
        "image": "FemFlora-Balance-Front.png",
        "slug": "femflora-balance",
        "description": (
            "Daily support for vaginal pH, yeast balance, bacterial balance, urinary tract "
            "health, plus general immune and digestive support. Combines targeted Lactobacillus "
            "strains (ASTARTE™ crispatus, rhamnosus, gasseri, jensenii, LA-5® acidophilus) "
            "with cranberry powder.*"
        ),
        "directions": "Take 2 capsules per day (ages 18+).",
        "specs": [
            ("Serving Size", "2 Capsules"),
            ("Servings Per Container", "30"),
            ("Available in", "60 Capsules"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "ML003",
        "name": "FloraRestore",
        "headline": "Gut Recovery During & After Antibiotics*",
        "banner": "The Antibiotic Companion*",
        "serving_highlight": "8 Billion CFU per capsule",
        "manufacturer": "Microbiome Labs",
        "package_size": "21 Capsules",
        "servings": "Week 1: 2 per day. Week 2+: 1 per day.",
        "image": "FloraRestore-Front.png",
        "slug": "florarestore",
        "description": (
            "Designed to maintain healthy microbial composition during and after antibiotics "
            "or other microbe-disrupting medications. Holds up in the presence of those meds "
            "where standard probiotics wouldn't. Uses Saccharomyces boulardii, Bacillus clausii, "
            "subtilis HU58™, and coagulans strains.*"
        ),
        "directions": "Ages 5+. Week 1: 1 capsule twice daily with food. Week 2 onward: 1 capsule daily with food.",
        "specs": [
            ("Serving Size", "1 Capsule"),
            ("Servings Per Container", "21"),
            ("CFU per capsule", "8 Billion"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "ML005",
        "name": "GastroGuard",
        "headline": "Digestive Comfort, Bloating & Stomach Acid Balance*",
        "banner": "Everyday Digestive Support*",
        "serving_highlight": "Artichoke + Licorice + Ginger",
        "manufacturer": "Microbiome Labs",
        "package_size": "60 Capsules",
        "servings": "30 servings (2 capsules each)",
        "image": "GastroGuard-Front.png",
        "slug": "gastroguard",
        "description": (
            "Promotes normal digestion, regulates stomach acid, maintains healthy H. pylori "
            "levels, and reduces occasional gas and bloating. Uses artichoke leaf extract, "
            "deglycyrrhizinated licorice (GutGard®), and standardized ginger root extract.*"
        ),
        "directions": "Ages 8+. Take 1 capsule twice daily before meals.",
        "specs": [
            ("Serving Size", "1 Capsule"),
            ("Servings Per Container", "60"),
            ("Available in", "60 Capsules"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "ML004",
        "name": "Ultra Pre Powder",
        "headline": "Precision Prebiotic for Microbial Diversity*",
        "banner": "Feeds Your Good Bacteria*",
        "serving_highlight": "3.8 g functional fiber blend per scoop",
        "manufacturer": "Microbiome Labs",
        "package_size": "5.1 oz Powder",
        "servings": "30 servings (1 scoop each)",
        "image": "Ultra-Pre-Powder-Front.png",
        "slug": "ultra-pre-powder",
        "description": (
            "Non-digestible oligosaccharides that feed beneficial gut bacteria and increase "
            "microbial diversity. Combines Bimuno® galactooligosaccharides, PreticX® "
            "xylooligosaccharides, and Livaux® / ACTAZIN® kiwifruit powders. Pairs "
            "well with probiotics.*"
        ),
        "directions": "Ages 4+. Start with ½ scoop daily for 1 week, then 1 scoop daily mixed into 16 oz or more of cold water, juice, or smoothie.",
        "specs": [
            ("Serving Size", "1 scoop (4.8 g)"),
            ("Servings Per Container", "30"),
            ("Total blend", "3.8 g per serving"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "ML002",
        "name": "Ultra Spore Biotic",
        "headline": "Spore-Based Daily Probiotic for Gut Barrier Support*",
        "banner": "Shelf-Stable Daily Probiotic*",
        "serving_highlight": "4 Billion CFU spore-based blend",
        "manufacturer": "Microbiome Labs",
        "package_size": "60 Capsules",
        "servings": "30 servings (2 capsules each)",
        "image": "Ultra-Spore-Biotic-Front.png",
        "slug": "ultra-spore-biotic",
        "description": (
            "A spore-based daily probiotic that supports gut barrier function and microbial "
            "diversity. Doesn't need refrigeration. Bacillus indicus HU36™, licheniformis, "
            "clausii, subtilis HU58™, and coagulans.*"
        ),
        "directions": "Ages 5+. Week 1: 1 capsule every other day. Week 2: 1 capsule daily. Max 2 per day.",
        "specs": [
            ("Serving Size", "2 Capsules"),
            ("Servings Per Container", "30"),
            ("Available in", "60 Capsules"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "PINM148",
        "name": "Absorbable Zinc",
        "headline": "Immune, Prostate & Tissue Support*",
        "banner": "TRAACS® Chelated Zinc*",
        "serving_highlight": "30 mg zinc bisglycinate chelate",
        "manufacturer": "NuMedica",
        "package_size": "120 Capsules",
        "servings": "120 servings",
        "image": "Zinc-Glycinate.png",
        "slug": "absorbable-zinc",
        "description": (
            "Immune, prostate, and tissue-synthesis support. Uses TRAACS® zinc bisglycinate "
            "chelate that stays intact in the gut for meaningfully better absorption than typical "
            "zinc oxide or citrate forms.*"
        ),
        "directions": "Take 1 capsule once per day.",
        "specs": [
            ("Serving Size", "1 Capsule"),
            ("Zinc per capsule", "30 mg"),
            ("Available in", "120 Capsules"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "PINM236",
        "name": "B-Balanced",
        "headline": "Activated B-Complex for Energy & Stress Response*",
        "banner": "Full-Spectrum Activated B's*",
        "serving_highlight": "Bioavailable 5-MTHF folate + B12",
        "manufacturer": "NuMedica",
        "package_size": "180 Capsules",
        "servings": "180 servings",
        "image": "B-Replete.png",
        "slug": "b-balanced",
        "description": (
            "Full-spectrum B-complex with activated forms — supports adrenal function, "
            "energy, healthy stress response, and homocysteine metabolism. Uses 5-MTHF "
            "(Quatrefolic®), the most bioavailable folate form.*"
        ),
        "directions": "Take 1 capsule 1–2 times per day.",
        "specs": [
            ("Serving Size", "1 Capsule"),
            ("Folate", "680 mcg DFE"),
            ("Vitamin B₁₂", "800 mcg"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "PINM980",
        "name": "D3K2 5000",
        "headline": "Vitamin D3 with K2 for Bone & Calcium Support*",
        "banner": "Vitamin D3 + K2 Combined*",
        "serving_highlight": "5,000 IU D3 + 200 mcg K2 per softgel",
        "manufacturer": "NuMedica",
        "package_size": "60 Softgel Caps",
        "servings": "60 servings",
        "image": "D3-5000+K2.png",
        "slug": "d3k25000",
        "description": (
            "Vitamin D3 paired with K2 for bone support and proper calcium utilization. "
            "Uses VitaMK7® menaquinone-7 form of K2. Soy-free.*"
        ),
        "directions": "Take 1 softgel once per day.",
        "specs": [
            ("Serving Size", "1 Softgel"),
            ("Vitamin D₃", "5,000 IU (125 mcg)"),
            ("Vitamin K₂", "200 mcg"),
        ],
        "badges": ["gluten", "veg", "soyfree"],
    },
    {
        "sku": "PINM074",
        "name": "DHEA 25 mg",
        "headline": "The Adrenal \"Mother Hormone\"*",
        "banner": "Higher-Strength DHEA*",
        "serving_highlight": "25 mg DHEA per capsule",
        "manufacturer": "NuMedica",
        "package_size": "90 Capsules",
        "servings": "90 servings",
        "image": "DHEA-25-mg.png",
        "slug": "dhea-25mg",
        "description": (
            "Higher-strength DHEA. The adrenal-produced \"mother hormone\" converts to estrogen, "
            "testosterone, and progesterone. This formula is 98.5% pure DHEA. Levels decline "
            "meaningfully after age 30.*"
        ),
        "directions": "Take 1 capsule once per day. Consult practitioner if pregnant or nursing.",
        "specs": [
            ("Serving Size", "1 Capsule"),
            ("DHEA per capsule", "25 mg"),
            ("Available in", "90 Capsules"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "PINM331",
        "name": "DHEA 5 mg",
        "headline": "Low-Dose DHEA for Baseline Support*",
        "banner": "Gentle Strength DHEA*",
        "serving_highlight": "5 mg DHEA per capsule",
        "manufacturer": "NuMedica",
        "package_size": "120 Capsules",
        "servings": "120 servings",
        "image": "DHEA-25-mg.png",   # no separate 5mg image; reuse
        "slug": "dhea-25mg",          # 5mg not on store, land on 25mg page
        "description": (
            "Low-dose DHEA — the adrenal \"mother hormone\" that converts to estrogen, "
            "testosterone, and progesterone. DHEA levels decline after age 30. This 5 mg "
            "strength is common for women's baseline support or gentle titration.*"
        ),
        "directions": "As directed by your healthcare practitioner.",
        "specs": [
            ("Serving Size", "1 Capsule"),
            ("DHEA per capsule", "5 mg"),
            ("Available in", "120 Capsules"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "PINM112",
        "name": "E-Balanced",
        "headline": "Broad-Spectrum Vitamin E Antioxidant*",
        "banner": "Full Tocopherol Complex*",
        "serving_highlight": "300 mg total tocopherols",
        "manufacturer": "NuMedica",
        "package_size": "60 Softgel Caps",
        "servings": "60 servings",
        "image": "Elite-E.png",
        "slug": "e-balanced",
        "description": (
            "Broad-spectrum vitamin E — natural tocopherol blend with an emphasis on "
            "gamma tocopherol for antioxidant support. Includes a mixed tocotrienol complex.*"
        ),
        "directions": "Take 1 softgel once per day.",
        "specs": [
            ("Serving Size", "1 Softgel"),
            ("Vitamin E (d-alpha)", "151 mg (225 IU)"),
            ("Total Tocopherols", "300 mg"),
        ],
        "badges": ["gluten"],
    },
    {
        "sku": "PINM035",
        "name": "EPA DHA 950",
        "headline": "High-Potency Omega-3 for Heart, Brain & Joints*",
        "banner": "Molecularly Distilled Fish Oil*",
        "serving_highlight": "820 mg EPA+DHA per softgel",
        "manufacturer": "NuMedica",
        "package_size": "60 Softgel Caps",
        "servings": "60 servings",
        "image": "Omega-950.png",
        "slug": "epadha950",
        "description": (
            "Ultra-pure, molecularly distilled omega-3 fish oil (anchovy, mackerel, sardine). "
            "Supports cardiovascular, joint, brain, and nervous system health; helps maintain "
            "healthy triglycerides and cholesterol.*"
        ),
        "directions": "Take 1 softgel 1–3 times daily.",
        "specs": [
            ("Serving Size", "1 Softgel"),
            ("EPA", "430 mg"),
            ("DHA", "390 mg"),
        ],
        "badges": ["gluten"],
    },
    {
        "sku": "PINM250",
        "name": "Max Multi",
        "headline": "Herb-Free Comprehensive Daily Multi (No Iron)*",
        "banner": "Complete Daily Foundation*",
        "serving_highlight": "TRAACS® chelated minerals",
        "manufacturer": "NuMedica",
        "package_size": "120 Capsules",
        "servings": "30 servings (4 capsules each)",
        "image": "MultiMedica-without-Iron.png",
        "slug": "max-multi",
        "description": (
            "Herb-free comprehensive daily multi with Albion® TRAACS® chelated minerals. "
            "Supports prostate, liver, and adrenal function plus broad-spectrum antioxidant "
            "coverage. Iron-free — great for men and post-menopausal women.*"
        ),
        "directions": "Take 4 capsules once per day.",
        "specs": [
            ("Serving Size", "4 Capsules"),
            ("Servings Per Container", "30"),
            ("Available in", "120 Capsules"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "PINM185",
        "name": "Organic Iodine",
        "headline": "Liquid Iodine for Thyroid Support*",
        "banner": "Alfalfa & Kelp Iodine Complex*",
        "serving_highlight": "200 mcg iodine per 3-drop dose",
        "manufacturer": "NuMedica",
        "package_size": "2 fl oz (liquid)",
        "servings": "~400 servings",
        "image": "Thyroxidine.png",
        "slug": "organic-iodine",
        "description": (
            "Liquid iodine for thyroid support — needed for T3/T4 synthesis. Also supports "
            "metabolism, cognition, and hair/nail/skin health. Sourced from organic alfalfa "
            "and kelp with potassium iodide.*"
        ),
        "directions": "3 drops (0.15 mL) in water once per day.",
        "specs": [
            ("Serving Size", "3 drops (0.15 mL)"),
            ("Iodine per serving", "200 mcg"),
            ("Available in", "2 fl oz"),
        ],
        "badges": ["gluten", "veg"],
    },
    {
        "sku": "PINM061",
        "name": "OsteoPlus",
        "headline": "MCHC-Based Comprehensive Bone Support*",
        "banner": "Bone Density Support*",
        "serving_highlight": "800 mg calcium + 2,000 mg MCHC",
        "manufacturer": "NuMedica",
        "package_size": "120 Capsules",
        "servings": "30 servings (4 capsules each)",
        "image": "OsteoMedica.png",
        "slug": "osteoplus",
        "description": (
            "Comprehensive bone support using MCHC (microcrystalline hydroxyapatite concentrate) "
            "from New Zealand pasture-fed cattle. Cold-processed to preserve collagen and bone "
            "growth factors. 30+ years of research behind MCHC for bone mineral density.*"
        ),
        "directions": "Take 4 capsules once per day.",
        "specs": [
            ("Serving Size", "4 Capsules"),
            ("Calcium", "800 mg"),
            ("MCHC", "2,000 mg"),
        ],
        "badges": ["gluten"],
    },
    {
        "sku": "PINM052",
        "name": "Red Yeast Rice",
        "headline": "Cardiovascular & Cholesterol Support*",
        "banner": "Citrinin-Free Formula*",
        "serving_highlight": "905 mg red yeast rice per capsule",
        "manufacturer": "NuMedica",
        "package_size": "90 Capsules",
        "servings": "90 servings",
        "image": "Red-Yeast-Rice.png",
        "slug": "red-yeast-rice",
        "description": (
            "Cardiovascular and cholesterol support. Extra-strength, citrinin-free preparation "
            "of Monascus purpureus fermented on rice grains.*"
        ),
        "directions": "Take 1 capsule once per day (adults).",
        "specs": [
            ("Serving Size", "1 Capsule"),
            ("Red Yeast Rice", "905 mg"),
            ("Available in", "90 Capsules"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "PINM234",
        "name": "Ubiquinol",
        "headline": "Active Form of CoQ10 for Cellular Energy*",
        "banner": "Reduced-Form CoQ10*",
        "serving_highlight": "100 mg ubiquinol per softgel",
        "manufacturer": "NuMedica",
        "package_size": "60 Softgel Caps",
        "servings": "60 servings",
        "image": "CoQ-Clear-100-Ubiquinol.png",
        "slug": "ubiquinol-capsules",
        "description": (
            "The reduced (active) form of CoQ10 — better absorbed than standard ubiquinone. "
            "Uses natural food-grade citrus oil for solubility. Supports cellular energy and "
            "cardiovascular health.*"
        ),
        "directions": "Take 1 softgel 1–2 times daily with meals.",
        "specs": [
            ("Serving Size", "1 Softgel"),
            ("Ubiquinol", "100 mg"),
            ("Available in", "60 Softgels"),
        ],
        "badges": ["gluten"],
    },
    {
        "sku": "PINM555",
        "name": "Ultra Flora",
        "headline": "High-Potency 50 Billion CFU Daily Probiotic*",
        "banner": "Broad-Spectrum 12 Strains*",
        "serving_highlight": "50 Billion CFU per serving",
        "manufacturer": "NuMedica",
        "package_size": "60 Capsules",
        "servings": "30 servings (2 capsules each)",
        "image": "Hi-Flora.png",
        "slug": "ultra-flora",
        "description": (
            "High-potency daily probiotic — 50 billion CFU from 12 clinically studied strains. "
            "Includes a spore-forming Bacillus subtilis strain that survives stomach acid before "
            "activating in the gut.*"
        ),
        "directions": "Take 2 capsules once per day.",
        "specs": [
            ("Serving Size", "2 Capsules"),
            ("Servings Per Container", "30"),
            ("CFU per serving", "50 Billion"),
        ],
        "badges": ["gluten", "veg", "vegcap"],
    },
    {
        "sku": "PINM586",
        "name": "Vitamin A",
        "headline": "Vision, Tissue & Cellular Function Support*",
        "banner": "Retinyl Palmitate*",
        "serving_highlight": "25,000 IU per capsule",
        "manufacturer": "NuMedica",
        "package_size": "90 Capsules",
        "servings": "90 servings",
        "image": "Vitamin-A.png",
        "slug": "vita",
        "description": (
            "Vitamin A support for vision, tissue, and cellular function. Retinyl palmitate "
            "form for reliable delivery.*"
        ),
        "directions": "Take 1 capsule once per day.",
        "specs": [
            ("Serving Size", "1 Capsule"),
            ("Vitamin A", "7,500 mcg RAE (25,000 IU)"),
            ("Available in", "90 Capsules"),
        ],
        "badges": ["gluten"],
    },
    {
        "sku": "RECODE",
        "name": "RECODE Glow Cream",
        "headline": "Peptide-Based Firming Cream for Elasticity & Radiance*",
        "banner": "Advanced Peptide Skincare*",
        "serving_highlight": "Copper peptide (GHK-Cu) + Acetyl Octapeptide-3",
        "manufacturer": "Iconic Beauty Labs",
        "package_size": "1.7 fl oz",
        "servings": "AM & PM use",
        "image_url": "https://maekiwyawaolvmshiwfb.supabase.co/storage/v1/object/public/product-images/products/1784825785299_t2xxwz_Recode_Glow_Cream.png",
        "slug": "recode-glow-cream",
        "description": (
            "Peptide-based firming cream targeting elasticity, radiance, and fine lines. "
            "Uses copper peptide (GHK-Cu) and Acetyl Octapeptide-3 alongside clinical-grade "
            "actives for a professional-strength daily result.*"
        ),
        "directions": "Apply a small amount to clean, wet or dry skin morning and night. Avoid contact with eyes.",
        "specs": [
            ("Type", "Face Cream"),
            ("Application", "AM & PM"),
            ("Available in", "1.7 fl oz"),
        ],
        "badges": [],
    },
]


BADGE_LIB = {
    "gluten": ("Independently Tested", "GLUTEN-FREE", "#5a4a3a"),
    "veg":    ("Suitable for",         "VEGETARIANS", "#4a7c59"),
    "vegcap": ("Vegetable",            "CAPSULES",    "#4a7c59"),
    "soyfree":("Soy",                  "FREE",        "#c9a961"),
    "nongmo": ("Non",                  "GMO",         "#4a7c59"),
}


def badge_html(kind: str) -> str:
    top, bottom, color = BADGE_LIB[kind]
    return f"""
      <div class="badge">
        <div class="badge-dot" style="background:{color}"></div>
        <div><div class="badge-top">{top}</div><div class="badge-bot">{bottom}</div></div>
      </div>
    """


def escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def resolve_image(p: dict) -> str:
    if "image" in p and p["image"]:
        return img_data_uri(IMG_DIR / p["image"])
    if "image_url" in p and p["image_url"]:
        return url_data_uri(p["image_url"])
    return ""


def card_html(p: dict) -> str:
    if p.get("slug"):
        url = f"{STORE_HOME}/products/{p['slug']}"
    else:
        url = STORE_HOME
    qr_uri = qr_data_uri(url)
    bottle_uri = resolve_image(p)

    specs_rows = "".join(
        f'<div class="spec-row"><strong>{escape(k)}</strong> {escape(v)}</div>'
        for k, v in p["specs"]
    )
    badges = "".join(badge_html(k) for k in p.get("badges", []))
    # Keep the display URL short and readable — the QR is the actual deep link.
    display_url = "pharmacyinnovationsstore.net"

    return f"""
    <section class="card">
      <div class="left">
        <div class="banner-top">{escape(p['banner'])}</div>
        <div class="name-banner">{escape(p['name'])}</div>
        <div class="bottle-hero">
          {'<img src="' + bottle_uri + '" alt="' + escape(p['name']) + '">' if bottle_uri else ''}
        </div>
        <div class="qr-block">
          <img src="{qr_uri}" alt="QR to product">
          <div class="qr-label">Order Now</div>
        </div>
      </div>
      <div class="right">
        <div class="name">{escape(p['name'])}</div>
        <div class="serving">{escape(p['serving_highlight'])}</div>
        <div class="claim">{escape(p['headline'])}</div>
        <p class="body">{escape(p['description'])}</p>
        <div class="two-col">
          <div>
            <div class="col-title">Directions</div>
            <p class="col-body">{escape(p['directions'])}</p>
          </div>
          <div>
            <div class="col-title">Specifications</div>
            {specs_rows}
          </div>
        </div>
        <div class="footer">
          <div class="footer-left">
            <img src="{PI_LOGO_URI}" class="pi-logo" alt="Pharmacy Innovations">
            <div class="store-url">{escape(display_url)}</div>
          </div>
          <div class="badges">{badges}</div>
        </div>
        <div class="disclaimer">
          *These statements have not been evaluated by the Food and Drug Administration.
          This product is not intended to diagnose, treat, cure or prevent any disease.
        </div>
      </div>
    </section>
    """


def general_card_html() -> str:
    qr_uri = qr_data_uri(STORE_HOME)
    return f"""
    <section class="card general">
      <div class="left">
        <div class="banner-top">Physician-Grade Supplements</div>
        <div class="name-banner">Pharmacy Innovations Store</div>
        <div class="bottle-hero general-hero">
          <img src="{PI_LOGO_URI}" alt="Pharmacy Innovations" style="max-width:80%;">
        </div>
        <div class="qr-block">
          <img src="{qr_uri}" alt="QR to store">
          <div class="qr-label">Shop Now</div>
        </div>
      </div>
      <div class="right">
        <div class="name">Shop Our Full Line</div>
        <div class="serving">Practitioner-selected, patient-priced</div>
        <div class="claim">Order any of our supplements online for personal use.*</div>
        <p class="body">
          Pharmacy Innovations carries a curated line of physician-grade supplements
          formulated with clinically studied ingredients from trusted manufacturers.
          Whether you're looking for probiotic support, hormone balance,
          bone health, or foundational vitamins &mdash; our online store has you covered.
        </p>
        <p class="body">
          <strong>Scan the QR code</strong> or visit <strong>pharmacyinnovationsstore.net</strong> to
          browse the full catalog, read product details, and place an order for pickup or shipping.
        </p>
        <div class="two-col">
          <div>
            <div class="col-title">Featured Categories</div>
            <p class="col-body">
              &bull; Women's Health &nbsp; &bull; Men's Health<br>
              &bull; Gut Health &amp; Digestion<br>
              &bull; Immunity &amp; Defense &nbsp; &bull; Sleep Support<br>
              &bull; Stress &amp; Anxiety &nbsp; &bull; Vitamins &amp; Supplements
            </p>
          </div>
          <div>
            <div class="col-title">Why Shop With Us</div>
            <div class="spec-row"><strong>Trusted Brands</strong> NuMedica, Microbiome Labs &amp; more</div>
            <div class="spec-row"><strong>Independently Tested</strong> Gluten-free where labeled</div>
            <div class="spec-row"><strong>Local Support</strong> Ask our pharmacy team any time</div>
          </div>
        </div>
        <div class="footer">
          <div class="footer-left">
            <img src="{PI_LOGO_URI}" class="pi-logo" alt="Pharmacy Innovations">
            <div class="store-url">pharmacyinnovationsstore.net</div>
          </div>
          <div class="badges"></div>
        </div>
        <div class="disclaimer">
          *These statements have not been evaluated by the Food and Drug Administration.
          These products are not intended to diagnose, treat, cure or prevent any disease.
        </div>
      </div>
    </section>
    """


CSS = """
@page { size: 11in 8.5in; margin: 0; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, 'Segoe UI', Arial, sans-serif; color: #222; background: #fff; }

.card {
  display: flex;
  width: 11in;
  height: 8.5in;
  page-break-after: always;
  break-after: page;
  overflow: hidden;
}
.card:last-child { page-break-after: auto; }

/* LEFT PANEL */
.left {
  width: 38%;
  background: linear-gradient(135deg, #e8ecf5 0%, #d6dfef 60%, #c4d1e6 100%);
  display: flex;
  flex-direction: column;
  position: relative;
  padding: 0;
}
.banner-top {
  background: #1e3a8a;
  color: #fff;
  padding: 14px 24px;
  font-size: 15pt;
  font-weight: 500;
  text-align: center;
  letter-spacing: 0.3px;
}
.name-banner {
  background: #2d4ba0;
  color: #fff;
  padding: 22px 24px;
  font-size: 34pt;
  font-weight: 700;
  text-align: center;
  letter-spacing: 2px;
  text-transform: uppercase;
}
.bottle-hero {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px 30px;
  min-height: 0;
}
.bottle-hero img {
  max-width: 85%;
  max-height: 100%;
  object-fit: contain;
  filter: drop-shadow(0 6px 12px rgba(0,0,0,0.15));
}
.general-hero { padding: 30px 40px; }

.qr-block {
  position: absolute;
  bottom: 20px;
  left: 20px;
  background: #1e3a8a;
  padding: 12px 12px 8px;
  border-radius: 6px;
  text-align: center;
  box-shadow: 0 3px 8px rgba(0,0,0,0.25);
}
.qr-block img {
  width: 110px;
  height: 110px;
  display: block;
  background: #fff;
  padding: 4px;
  border-radius: 4px;
}
.qr-label {
  color: #fff;
  font-size: 10pt;
  font-style: italic;
  margin-top: 6px;
  letter-spacing: 0.5px;
}

/* RIGHT PANEL */
.right {
  width: 62%;
  padding: 30px 34px 24px;
  display: flex;
  flex-direction: column;
  background: #fff;
}
.name {
  color: #1e88e5;
  font-size: 42pt;
  font-weight: 800;
  line-height: 1;
  letter-spacing: -1px;
}
.serving {
  color: #333;
  font-size: 13pt;
  margin: 6px 0 12px;
  font-weight: 400;
}
.claim {
  color: #1e3a8a;
  font-size: 13pt;
  font-weight: 700;
  margin-bottom: 10px;
  line-height: 1.25;
}
.body {
  font-size: 11pt;
  line-height: 1.5;
  color: #333;
  margin-bottom: 14px;
}

.two-col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  margin-top: auto;
  padding-top: 14px;
}
.col-title {
  color: #111;
  font-size: 14pt;
  font-weight: 700;
  border-bottom: 2px solid #333;
  padding-bottom: 3px;
  margin-bottom: 8px;
}
.col-body {
  font-size: 11pt;
  line-height: 1.45;
  color: #333;
}
.spec-row {
  font-size: 11pt;
  color: #333;
  margin: 3px 0;
}
.spec-row strong {
  font-weight: 700;
}

.footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 14px;
  margin-top: 18px;
  border-top: 1px solid #ddd;
  padding-top: 12px;
}
.footer-left {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.pi-logo {
  height: 34px;
  width: auto;
}
.store-url {
  font-size: 10pt;
  color: #333;
  letter-spacing: 0.3px;
}
.badges {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-shrink: 0;
  max-width: 60%;
  justify-content: flex-end;
}
.badge {
  display: flex;
  align-items: center;
  gap: 5px;
  flex-shrink: 0;
}
.badge-dot {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  flex-shrink: 0;
}
.badge-top {
  font-size: 6.5pt;
  color: #555;
  text-transform: none;
  line-height: 1;
  white-space: nowrap;
}
.badge-bot {
  font-size: 8pt;
  color: #111;
  font-weight: 700;
  letter-spacing: 0.3px;
  line-height: 1.1;
  white-space: nowrap;
}
.disclaimer {
  font-size: 7.5pt;
  color: #666;
  text-align: center;
  margin-top: 8px;
  font-style: italic;
  line-height: 1.3;
}
"""


def to_win(p: Path) -> str:
    return subprocess.check_output(["wslpath", "-w", str(p)], text=True).strip()


def build() -> None:
    parts = [general_card_html()]
    for p in PRODUCTS:
        parts.append(card_html(p))
    body = "\n".join(parts)

    html = f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<title>NI Product Cards</title>
<style>{CSS}</style>
</head><body>
{body}
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

    print(f"Built {OUT_PDF.name} ({OUT_PDF.stat().st_size // 1024} KB) - "
          f"{len(PRODUCTS) + 1} cards (general + {len(PRODUCTS)} products)")


if __name__ == "__main__":
    build()
