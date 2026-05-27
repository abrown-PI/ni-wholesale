-- ═══════════════════════════════════════════════════════════
-- 02 — Purchase Orders (new feature)
--
-- SAFE: this migration is additive. It creates two NEW tables
-- (purchase_orders, purchase_order_items) and a sequence for
-- human-friendly PO numbers. Nothing existing is dropped or
-- altered.
--
-- BEFORE RUNNING:
--   1. Take a Supabase backup (Database -> Backups -> Create backup)
--   2. Confirm migration 01-product-schema-upgrade.sql has been run
--   3. Run this in Supabase -> SQL Editor -> New Query -> Paste -> Run
--   4. Verify rows look right (see VERIFICATION section at bottom)
-- ═══════════════════════════════════════════════════════════

-- ───── 1. PURCHASE ORDERS table ─────
create table if not exists public.purchase_orders (
    id uuid primary key default uuid_generate_v4(),
    po_number serial unique,
    vendor_id uuid references public.vendors on delete set null,
    vendor_name text,
    status text not null default 'draft', -- 'draft' | 'submitted' | 'received' | 'cancelled'
    subtotal numeric(10,2) not null default 0,
    notes text default '',
    internal_notes text default '',
    created_by uuid references public.profiles on delete set null,
    submitted_at timestamptz,
    received_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- ───── 2. PURCHASE ORDER ITEMS table ─────
create table if not exists public.purchase_order_items (
    id uuid primary key default uuid_generate_v4(),
    po_id uuid not null references public.purchase_orders on delete cascade,
    product_id uuid references public.products on delete set null,
    variant_id uuid references public.product_variants on delete set null,
    sku text,
    product_name text,
    quantity integer not null default 0,
    received_qty integer not null default 0,
    unit_cost numeric(10,2) not null default 0,
    total numeric(10,2) not null default 0,
    notes text,
    created_at timestamptz default now()
);

-- ───── 3. updated_at trigger on purchase_orders ─────
-- public.set_updated_at() already exists from migration 01; reuse it.
drop trigger if exists purchase_orders_set_updated_at on public.purchase_orders;
create trigger purchase_orders_set_updated_at
    before update on public.purchase_orders
    for each row execute function public.set_updated_at();

-- ───── 4. Indexes ─────
create index if not exists idx_purchase_orders_status on public.purchase_orders(status);
create index if not exists idx_purchase_orders_vendor on public.purchase_orders(vendor_id);
create index if not exists idx_purchase_orders_created on public.purchase_orders(created_at desc);
create index if not exists idx_po_items_po on public.purchase_order_items(po_id);
create index if not exists idx_po_items_product on public.purchase_order_items(product_id);

-- ───── 5. RLS ─────
alter table public.purchase_orders enable row level security;
alter table public.purchase_order_items enable row level security;

do $$ begin
    if not exists (
        select 1 from pg_policies
        where policyname = 'Admins manage purchase_orders' and tablename = 'purchase_orders'
    ) then
        create policy "Admins manage purchase_orders" on public.purchase_orders
            for all using (public.is_admin());
    end if;

    if not exists (
        select 1 from pg_policies
        where policyname = 'Admins manage purchase_order_items' and tablename = 'purchase_order_items'
    ) then
        create policy "Admins manage purchase_order_items" on public.purchase_order_items
            for all using (public.is_admin());
    end if;
end $$;

-- ═══════════════════════════════════════════════════════════
-- VERIFICATION (run these after the migration, separately)
-- ═══════════════════════════════════════════════════════════
-- select count(*) as purchase_orders_count from public.purchase_orders;
-- select count(*) as purchase_order_items_count from public.purchase_order_items;
-- select po_number, vendor_name, status, subtotal, created_at from public.purchase_orders order by created_at desc limit 10;
-- select policyname, tablename from pg_policies where tablename in ('purchase_orders','purchase_order_items');
-- select indexname, tablename from pg_indexes where tablename in ('purchase_orders','purchase_order_items');
