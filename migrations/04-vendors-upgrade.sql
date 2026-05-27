-- ═══════════════════════════════════════════════════════════
-- 04 — Vendors upgrade (add Reviv-style fields)
--
-- SAFE: purely additive. Renames `contact` → `contact_name` via
-- additive add + backfill + drop of old column. New columns get
-- sensible defaults.
--
-- BEFORE RUNNING:
--   1. Back up Supabase
--   2. Run in SQL Editor → New Query → Paste → Run
--   3. Verify with the queries at the bottom
-- ═══════════════════════════════════════════════════════════

-- ───── 1. Add new columns ─────
alter table public.vendors add column if not exists contact_name text;
alter table public.vendors add column if not exists website text;
alter table public.vendors add column if not exists address text;
alter table public.vendors add column if not exists city text;
alter table public.vendors add column if not exists state text;
alter table public.vendors add column if not exists zip text;
alter table public.vendors add column if not exists payment_terms text default 'Net-30';
alter table public.vendors add column if not exists min_order numeric(10,2) default 0;
alter table public.vendors add column if not exists account_number text;
alter table public.vendors add column if not exists notes text not null default '';
alter table public.vendors add column if not exists status text not null default 'active';
alter table public.vendors add column if not exists updated_at timestamptz not null default now();

-- ───── 2. Backfill: copy old `contact` into `contact_name` ─────
do $$ begin
    if exists (
        select 1 from information_schema.columns
        where table_schema = 'public' and table_name = 'vendors' and column_name = 'contact'
    ) then
        execute 'update public.vendors set contact_name = contact where contact_name is null and contact is not null';
    end if;
end $$;

-- ───── 3. updated_at trigger ─────
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
    new.updated_at = now();
    return new;
end; $$;

drop trigger if exists vendors_set_updated_at on public.vendors;
create trigger vendors_set_updated_at
    before update on public.vendors
    for each row execute function public.set_updated_at();

-- ═══════════════════════════════════════════════════════════
-- VERIFICATION
-- ═══════════════════════════════════════════════════════════
-- select name, contact_name, payment_terms, min_order, status from public.vendors order by name;

-- ═══════════════════════════════════════════════════════════
-- DEPRECATED (drop in a later cleanup migration after app code transitions):
--   vendors.contact → use vendors.contact_name
-- ═══════════════════════════════════════════════════════════
