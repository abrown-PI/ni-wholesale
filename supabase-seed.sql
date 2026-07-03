-- ═══════════════════════════════════════════════════════════
-- NI Wholesale — Seed Data + Storefront RLS Fix
-- Run AFTER supabase-schema.sql
-- ═══════════════════════════════════════════════════════════

-- ───── RLS FIX: allow anonymous storefront visitors to browse products ─────
-- The schema's default policy required auth.role() = 'authenticated' which
-- would break the public storefront. We replace it with public read.
drop policy if exists "Authenticated read products" on public.products;
drop policy if exists "Public read products" on public.products;
create policy "Public read products" on public.products
    for select using (true);

-- Also relax product_variants so future variant support works on the storefront.
drop policy if exists "Authenticated read product_variants" on public.product_variants;
drop policy if exists "Public read product_variants" on public.product_variants;
create policy "Public read product_variants" on public.product_variants
    for select using (true);

-- ───── SEED PRODUCTS (21 rows) ─────
-- Rekeyed NuMedica SKUs from NM* → PINM* per new pricing schedule.
-- Wholesale = round(cost / 0.90, 2)  (10% gross margin).
-- Original vendor part numbers retained in vendor_part_num for reference.

insert into public.products
    (sku, name, vendor_product_name, vendor, manufacturer, vendor_part_num, upc,
     package_size, category, cost_per_unit, wholesale_price, retail_price,
     profit_margin, stock, low_stock_threshold, min_order_qty, internal_notes,
     images, status)
values
    ('PINM236','B-Balanced','B Replete','NuMedica','NuMedica','NM236','814132361805',
     '180 Capsules',null,55.00,61.11,90.00,10,18,10,1,'',
     '[{"url":"images/products/B-Replete.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM234','Ubiquinol','CoQ Clear Ubiquinol','NuMedica','NuMedica','NM234','814132340602',
     '60 Softgel Caps',null,35.95,39.94,64.95,10,18,10,1,'',
     '[{"url":"images/products/CoQ-Clear-100-Ubiquinol.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM980','D3K25000','D3-5000+K2-200','NuMedica','NuMedica','NM980','814139800604',
     '60 Softgel Caps',null,22.45,24.94,44.90,10,36,10,1,'',
     '[{"url":"images/products/D3-5000+K2.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM331','DHEA 5mg','DHEA 5mg','NuMedica','NuMedica','NM331','814133310604',
     '120 Capsules',null,9.75,10.83,19.90,10,18,10,1,'',
     '[]'::jsonb,'active'),

    ('PINM074','DHEA 25mg','DHEA 25mg','NuMedica','NuMedica','NM074','814130740602',
     '90 Capsules',null,11.45,12.72,22.90,10,24,10,1,'',
     '[{"url":"images/products/DHEA-25-mg.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM112','E-Balanced','Elite E Complex','NuMedica','NuMedica','NM112','814131120601',
     '60 Softgel Caps',null,18.95,21.06,37.90,10,0,10,1,'',
     '[{"url":"images/products/Elite-E.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM555','Ultra Flora','HiFlora 50','NuMedica','NuMedica','NM555','814135550503',
     '60 Softgel Caps',null,32.95,36.61,62.95,10,17,10,1,'1 unit expires 8/26',
     '[{"url":"images/products/Hi-Flora.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM250','Max Multi','MultiMedica without Iron','NuMedica','NuMedica','NM250','814132501201',
     '120 Capsules',null,19.95,22.17,39.90,10,32,10,1,'',
     '[{"url":"images/products/MultiMedica-without-Iron.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM035','EPADHA950','Omega 950','NuMedica','NuMedica','NM035','814130350603',
     '60 Softgel Caps',null,19.95,22.17,38.90,10,29,10,1,'',
     '[{"url":"images/products/Omega-950.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM061','OsteoPlus','OsteoMedica','NuMedica','NuMedica','NM061','814130611209',
     '120 Capsules',null,17.95,19.94,35.90,10,18,10,1,'',
     '[{"url":"images/products/OsteoMedica.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM052','Red Yeast Rice','Red Yeast Rice','NuMedica','NuMedica','NM052','814130520600',
     '90 Capsules',null,18.75,20.83,37.50,10,0,10,1,'',
     '[{"url":"images/products/Red-Yeast-Rice.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM185','Organic Iodine','Thyroxodine','NuMedica','NuMedica','NM185','814131850607',
     '2 oz',null,15.95,17.72,31.90,10,0,10,1,'',
     '[{"url":"images/products/Thyroxidine.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM586','Vit A','Vitamin A','NuMedica','NuMedica','NM586','814135860602',
     '90 Capsules',null,7.95,8.83,15.90,10,0,10,1,'',
     '[{"url":"images/products/Vitamin-A.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM148','Absorbable Zinc','Zinc Glycinate','NuMedica','NuMedica','NM148','814131481207',
     '120 Capsules',null,10.95,12.17,21.90,10,9,10,1,'',
     '[{"url":"images/products/Zinc-Glycinate.png","isPrimary":true}]'::jsonb,'active'),

    ('PINM025','DIM','DIM','NuMedica','NuMedica','NM25','814130251207',
     '120 Capsules',null,25.95,28.83,49.95,10,36,10,1,'',
     '[{"url":"images/products/DIM-Estro.png","isPrimary":true}]'::jsonb,'active'),

    ('RECODE','Recode','Recode G you are.','Iconic Beauty Labs','Iconic Beauty Labs',null,null,
     null,null,55.00,61.11,90.00,10,16,10,1,'1 sample on hand (not for sale)',
     '[]'::jsonb,'active'),

    ('ML001','FemFlora Balance','Vaginal Balance','Microbiome Labs','Microbiome Labs','ML001','813120010602',
     '60 Capsules','Probiotics',16.83,null,33.65,null,12,10,1,'Private label of Microbiome Labs Vaginal Balance',
     '[{"url":"images/products/FemFlora-Balance-Front.png","isPrimary":true},{"url":"images/products/FemFlora-Balance-Left.png"},{"url":"images/products/FemFlora-Balance-Right.png"}]'::jsonb,'active'),

    ('ML002','Ultra Spore Biotic','MegaSporeBiotic','Microbiome Labs','Microbiome Labs','ML002','813120020601',
     '60 Capsules','Probiotics',36.43,null,66.25,null,12,10,1,'Private label of Microbiome Labs MegaSporeBiotic',
     '[{"url":"images/products/Ultra-Spore-Biotic-Front.png","isPrimary":true},{"url":"images/products/Ultra-Spore-Biotic-Left.png"},{"url":"images/products/Ultra-Spore-Biotic-Right.png"}]'::jsonb,'active'),

    ('ML003','FloraRestore','RestorFlora','Microbiome Labs','Microbiome Labs','ML003','813120030211',
     '21 Capsules','Probiotics',9.72,10.80,22.87,null,12,10,1,'Private label of Microbiome Labs RestorFlora',
     '[{"url":"images/products/FloraRestore-Front.png","isPrimary":true},{"url":"images/products/FloraRestore-Left.png"},{"url":"images/products/FloraRestore-Right.png"}]'::jsonb,'active'),

    ('ML004','Ultra Pre Powder','MegaPre Precision Prebiotic','Microbiome Labs','Microbiome Labs','ML004','813120040517',
     '5.1 oz Powder','Probiotics',36.61,null,66.58,null,12,10,1,'Private label of Microbiome Labs MegaPre Powder',
     '[{"url":"images/products/Ultra-Pre-Powder-Front.png","isPrimary":true},{"url":"images/products/Ultra-Pre-Powder-Left.png"},{"url":"images/products/Ultra-Pre-Powder-Left2.png"},{"url":"images/products/Ultra-Pre-Powder-Right.png"}]'::jsonb,'active'),

    ('ML005','GastroGuard','MegaGuard','Microbiome Labs','Microbiome Labs','ML005','813120050608',
     '60 Capsules','Specialty',null,null,null,null,12,10,1,'Private label of Microbiome Labs MegaGuard',
     '[{"url":"images/products/GastroGuard-Front.png","isPrimary":true},{"url":"images/products/GastroGuard-Left.png"},{"url":"images/products/GastroGuard-Right.png"}]'::jsonb,'active')

on conflict (sku) do update set
    name                = excluded.name,
    vendor_product_name = excluded.vendor_product_name,
    vendor              = excluded.vendor,
    manufacturer        = excluded.manufacturer,
    vendor_part_num     = excluded.vendor_part_num,
    upc                 = excluded.upc,
    package_size        = excluded.package_size,
    category            = excluded.category,
    cost_per_unit       = excluded.cost_per_unit,
    wholesale_price     = excluded.wholesale_price,
    retail_price        = excluded.retail_price,
    profit_margin       = excluded.profit_margin,
    stock               = excluded.stock,
    low_stock_threshold = excluded.low_stock_threshold,
    min_order_qty       = excluded.min_order_qty,
    internal_notes      = excluded.internal_notes,
    images              = excluded.images,
    status              = excluded.status;
