-- ═══════════════════════════════════════════════════════════
-- 07 — Coupons (coupons + coupon_redemptions)
--
-- SAFE: purely additive + idempotent. Adds public.coupons (the
-- code definitions) and public.coupon_redemptions (audit log of
-- successful redemptions). Replicates the schema used by Reviv
-- wholesale so logic can later port over without churn.
--
-- BEFORE RUNNING:
--   1. Back up Supabase (Database → Backups → Create backup)
--   2. Run this in SQL Editor → New Query → Paste → Run
--   3. Verify with the queries at the bottom
-- ═══════════════════════════════════════════════════════════

-- ───── 1. coupons ─────
create table if not exists public.coupons (
    id uuid primary key default uuid_generate_v4(),
    code text unique not null,
    description text default '',
    discount_type text not null,                 -- 'percent' | 'fixed' | 'free_shipping'
    discount_value numeric(10,2) not null default 0,
    min_subtotal numeric(10,2),
    max_uses integer,
    uses_count integer not null default 0,
    one_per_customer boolean not null default false,
    expires_at timestamptz,
    customer_id uuid references public.customers on delete cascade, -- null = shareable
    active boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- ───── 2. coupon_redemptions ─────
create table if not exists public.coupon_redemptions (
    id uuid primary key default uuid_generate_v4(),
    coupon_id uuid not null references public.coupons on delete cascade,
    customer_id uuid references public.customers on delete cascade,
    order_id uuid references public.orders on delete set null,
    discount_amount numeric(10,2),
    created_at timestamptz not null default now()
);

-- ───── 3. Indexes ─────
create index if not exists idx_coupons_code on public.coupons(code);
create index if not exists idx_coupons_active on public.coupons(active);
create index if not exists idx_coupons_customer on public.coupons(customer_id);
create index if not exists idx_coupon_redemptions_coupon on public.coupon_redemptions(coupon_id);
create index if not exists idx_coupon_redemptions_customer on public.coupon_redemptions(customer_id);
create index if not exists idx_coupon_redemptions_order on public.coupon_redemptions(order_id);

-- ───── 4. updated_at trigger on coupons ─────
drop trigger if exists coupons_set_updated_at on public.coupons;
create trigger coupons_set_updated_at
    before update on public.coupons
    for each row execute function public.set_updated_at();

-- ───── 5. RLS ─────
alter table public.coupons enable row level security;
alter table public.coupon_redemptions enable row level security;

-- Admins manage everything on coupons. Authenticated users can SELECT
-- so the storefront can match a code typed at checkout. (Real-world
-- validation should still happen server-side once Supabase is wired.)
drop policy if exists "Admins manage coupons" on public.coupons;
create policy "Admins manage coupons" on public.coupons
    for all using (public.is_admin());

drop policy if exists "Authenticated read coupons" on public.coupons;
create policy "Authenticated read coupons" on public.coupons
    for select using (auth.role() = 'authenticated');

-- Admins manage all redemptions. Users can read their own (tied via
-- profiles.customer_id) so a customer self-service portal can list
-- "coupons you've used" without leaking other customers' history.
drop policy if exists "Admins manage coupon_redemptions" on public.coupon_redemptions;
create policy "Admins manage coupon_redemptions" on public.coupon_redemptions
    for all using (public.is_admin());

drop policy if exists "Users view own coupon_redemptions" on public.coupon_redemptions;
create policy "Users view own coupon_redemptions" on public.coupon_redemptions
    for select using (
        exists (
            select 1 from public.profiles
            where id = auth.uid()
              and customer_id = coupon_redemptions.customer_id
        )
    );

-- ═══════════════════════════════════════════════════════════
-- VERIFICATION (run separately after the migration)
-- ═══════════════════════════════════════════════════════════
-- select column_name, data_type from information_schema.columns
--   where table_schema = 'public' and table_name = 'coupons' order by ordinal_position;
-- select column_name, data_type from information_schema.columns
--   where table_schema = 'public' and table_name = 'coupon_redemptions' order by ordinal_position;
-- select indexname from pg_indexes where tablename in ('coupons','coupon_redemptions') order by 1;
-- select count(*) as coupon_count from public.coupons;
-- select count(*) as redemption_count from public.coupon_redemptions;

-- ═══════════════════════════════════════════════════════════
-- DEPRECATED notes:
--   orders.coupon_code + orders.discount_amount were added in
--   migration 05 with a note that "no validation logic yet — Coupons
--   bucket". This migration introduces that bucket. The columns on
--   public.orders remain authoritative for the per-order snapshot;
--   coupon_redemptions adds the audit log + usage counting.
-- ═══════════════════════════════════════════════════════════
