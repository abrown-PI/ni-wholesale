-- ═══════════════════════════════════════════════════════════
-- 01 — Product schema upgrade (NI ⇒ Reviv-style products + variants)
--
-- SAFE: this migration is additive. It does NOT drop any existing
-- columns. Old columns (product_id, sell_price, active, low_stock,
-- taxable text, notes, date_added) stay alongside new ones until a
-- later cleanup migration.
--
-- BEFORE RUNNING:
--   1. Take a Supabase backup (Database → Backups → Create backup)
--   2. Run this in Supabase → SQL Editor → New Query → Paste → Run
--   3. Verify product rows look right (see VERIFICATION section at bottom)
-- ═══════════════════════════════════════════════════════════

-- ───── 1. Add new columns to products ─────
alter table public.products add column if not exists sku text;
alter table public.products add column if not exists name text;
alter table public.products add column if not exists description text not null default '';
alter table public.products add column if not exists manufacturer text;
alter table public.products add column if not exists wholesale_price numeric(10,2);
alter table public.products add column if not exists cost_per_unit numeric(10,2);
alter table public.products add column if not exists profit_margin numeric(5,2);
alter table public.products add column if not exists status text;
alter table public.products add column if not exists tester_stock integer not null default 0;
alter table public.products add column if not exists low_stock_threshold integer;
alter table public.products add column if not exists min_order_qty integer not null default 1;
alter table public.products add column if not exists taxable_bool boolean;
alter table public.products add column if not exists internal_notes text not null default '';
alter table public.products add column if not exists created_by uuid references public.profiles on delete set null;
alter table public.products add column if not exists updated_at timestamptz not null default now();

-- ───── 2. Backfill new columns from old ones ─────

-- name ← product_name
update public.products set name = product_name where name is null;

-- cost_per_unit ← cost
update public.products set cost_per_unit = cost where cost_per_unit is null and cost is not null;

-- wholesale_price ← sell_price
update public.products set wholesale_price = sell_price where wholesale_price is null and sell_price is not null;

-- low_stock_threshold ← low_stock
update public.products set low_stock_threshold = coalesce(low_stock, 10) where low_stock_threshold is null;

-- status ← active ('Y'→active, 'N'→inactive)
update public.products set status = case when active = 'N' then 'inactive' else 'active' end where status is null;

-- taxable_bool ← taxable ('Y'→true, anything else→false)
update public.products set taxable_bool = (taxable = 'Y') where taxable_bool is null;

-- internal_notes ← notes (notes was a single freeform field)
update public.products set internal_notes = coalesce(notes, '') where internal_notes = '';

-- sku: try product_id first, then vendor_part_num, then synthetic NI-<short id>
update public.products set sku = nullif(trim(product_id), '')
    where sku is null and nullif(trim(product_id), '') is not null;

-- Only fill from vendor_part_num if it's still unique vs already-assigned skus
update public.products p set sku = nullif(trim(p.vendor_part_num), '')
    where p.sku is null
      and nullif(trim(p.vendor_part_num), '') is not null
      and not exists (
          select 1 from public.products p2
          where p2.id <> p.id and p2.sku = nullif(trim(p.vendor_part_num), '')
      );

-- Synthetic fallback for anything still null (rare): NI-<first 8 chars of uuid>
update public.products set sku = 'NI-' || upper(substring(replace(id::text, '-', ''), 1, 8))
    where sku is null;

-- ───── 3. Detect duplicate SKUs (will block unique constraint if any) ─────
do $$
declare
    dup_count integer;
begin
    select count(*) into dup_count from (
        select sku from public.products group by sku having count(*) > 1
    ) d;
    if dup_count > 0 then
        raise exception 'Cannot apply UNIQUE on products.sku — % duplicate SKU(s) found. Resolve them and re-run.', dup_count;
    end if;
end $$;

-- ───── 4. Apply constraints now that data is backfilled ─────
alter table public.products alter column sku set not null;
do $$ begin
    if not exists (
        select 1 from pg_constraint where conname = 'products_sku_key' and conrelid = 'public.products'::regclass
    ) then
        alter table public.products add constraint products_sku_key unique (sku);
    end if;
end $$;

alter table public.products alter column name set not null;
alter table public.products alter column status set default 'active';
alter table public.products alter column status set not null;
alter table public.products alter column low_stock_threshold set default 10;
alter table public.products alter column low_stock_threshold set not null;
alter table public.products alter column taxable_bool set default true;
alter table public.products alter column taxable_bool set not null;

-- Normalize images default if missing
alter table public.products alter column images set not null;
alter table public.products alter column images set default '[]'::jsonb;

-- Normalize stock default
alter table public.products alter column stock set not null;
alter table public.products alter column stock set default 0;

-- ───── 5. PRODUCT VARIANTS table ─────
create table if not exists public.product_variants (
    id uuid primary key default uuid_generate_v4(),
    product_id uuid not null references public.products on delete cascade,
    variant_name text not null,
    sku text unique not null,
    upc text,

    stock integer not null default 0,
    tester_stock integer not null default 0,
    low_stock_threshold integer, -- null = inherit
    min_order_qty integer,       -- null = inherit

    cost_per_unit numeric(10,2),   -- null = inherit
    wholesale_price numeric(10,2), -- null = inherit
    retail_price numeric(10,2),    -- null = inherit

    status text not null default 'active',
    sort_order integer not null default 0,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- ───── 6. inventory_transactions / order_items: link to variant ─────
alter table public.inventory_transactions add column if not exists variant_id uuid references public.product_variants on delete set null;
alter table public.order_items add column if not exists variant_id uuid references public.product_variants on delete set null;
alter table public.order_items add column if not exists sku text;

-- ───── 7. updated_at trigger ─────
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
    new.updated_at = now();
    return new;
end; $$;

drop trigger if exists products_set_updated_at on public.products;
create trigger products_set_updated_at
    before update on public.products
    for each row execute function public.set_updated_at();

drop trigger if exists product_variants_set_updated_at on public.product_variants;
create trigger product_variants_set_updated_at
    before update on public.product_variants
    for each row execute function public.set_updated_at();

-- ───── 8. RLS on product_variants ─────
alter table public.product_variants enable row level security;

drop policy if exists "Authenticated read product_variants" on public.product_variants;
create policy "Authenticated read product_variants" on public.product_variants
    for select using (auth.role() = 'authenticated');

drop policy if exists "Admins write product_variants" on public.product_variants;
create policy "Admins write product_variants" on public.product_variants
    for all using (public.is_admin());

-- ───── 9. Storage bucket for product images (if not already created) ─────
insert into storage.buckets (id, name, public)
values ('product-images', 'product-images', true)
on conflict (id) do nothing;

do $$ begin
    if not exists (select 1 from pg_policies where policyname = 'Public read product images' and tablename = 'objects') then
        create policy "Public read product images" on storage.objects
            for select using (bucket_id = 'product-images');
    end if;
    if not exists (select 1 from pg_policies where policyname = 'Admins upload product images' and tablename = 'objects') then
        create policy "Admins upload product images" on storage.objects
            for insert with check (bucket_id = 'product-images' and public.is_admin());
    end if;
    if not exists (select 1 from pg_policies where policyname = 'Admins update product images' and tablename = 'objects') then
        create policy "Admins update product images" on storage.objects
            for update using (bucket_id = 'product-images' and public.is_admin());
    end if;
    if not exists (select 1 from pg_policies where policyname = 'Admins delete product images' and tablename = 'objects') then
        create policy "Admins delete product images" on storage.objects
            for delete using (bucket_id = 'product-images' and public.is_admin());
    end if;
end $$;

-- ───── 10. New indexes ─────
create index if not exists idx_products_sku on public.products(sku);
create index if not exists idx_products_status on public.products(status);
create index if not exists idx_variants_product on public.product_variants(product_id);
create index if not exists idx_variants_sku on public.product_variants(sku);

-- ═══════════════════════════════════════════════════════════
-- VERIFICATION (run these after the migration, separately)
-- ═══════════════════════════════════════════════════════════
-- select count(*) as total, count(distinct sku) as unique_skus from public.products;
-- select sku, name, status, wholesale_price, stock from public.products limit 20;
-- select count(*) as variants from public.product_variants;

-- ═══════════════════════════════════════════════════════════
-- DEPRECATED COLUMNS (kept for now, drop in a later migration after app
-- code transitions to read the new column names):
--   products.product_id     → use products.sku
--   products.product_name   → use products.name
--   products.cost           → use products.cost_per_unit
--   products.sell_price     → use products.wholesale_price
--   products.low_stock      → use products.low_stock_threshold
--   products.active         → use products.status
--   products.taxable (text) → use products.taxable_bool
--   products.notes          → use products.internal_notes
--   products.date_added     → use products.created_at
-- ═══════════════════════════════════════════════════════════
