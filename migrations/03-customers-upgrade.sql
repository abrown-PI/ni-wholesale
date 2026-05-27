-- ═══════════════════════════════════════════════════════════
-- 03 — Customers upgrade (flat → parent + locations + team users)
--
-- SAFE: additive. Existing customer rows stay put — we add new columns
-- alongside old ones and backfill. Old columns (name, location_id,
-- ship_to, bill_to, profile_id, customer_id text) are kept for now;
-- a later cleanup migration can drop them once app code transitions.
--
-- BEFORE RUNNING:
--   1. Back up Supabase (Database → Backups → Create backup)
--   2. Run this in SQL Editor → New Query → Paste → Run
--   3. Verify with the queries at the bottom
-- ═══════════════════════════════════════════════════════════

-- ───── 1. Add new columns to customers ─────
alter table public.customers add column if not exists company_name text;
alter table public.customers add column if not exists account_code text;
alter table public.customers add column if not exists contact_name text;
alter table public.customers add column if not exists billing_address text;
alter table public.customers add column if not exists billing_city text;
alter table public.customers add column if not exists billing_state text;
alter table public.customers add column if not exists billing_zip text;
alter table public.customers add column if not exists pharmacy_type text;
alter table public.customers add column if not exists license_number text;
alter table public.customers add column if not exists dea_number text;
alter table public.customers add column if not exists npi_number text;
alter table public.customers add column if not exists payment_terms text not null default 'Net-30';
alter table public.customers add column if not exists status text not null default 'active';
alter table public.customers add column if not exists notes text not null default '';
alter table public.customers add column if not exists updated_at timestamptz not null default now();

-- ───── 2. Backfill new columns from old ones ─────
-- company_name ← name
update public.customers set company_name = name where company_name is null;

-- account_code ← customer_id (the legacy text code like 'PI_612_FL')
update public.customers set account_code = customer_id where account_code is null and customer_id is not null;

-- billing_address ← bill_to (single text blob → store as-is in billing_address; city/state/zip stay null until manually parsed)
update public.customers set billing_address = bill_to where billing_address is null and bill_to is not null;

-- ───── 3. Apply NOT NULL on company_name after backfill ─────
alter table public.customers alter column company_name set not null;

-- ───── 4. CUSTOMER LOCATIONS table ─────
create table if not exists public.customer_locations (
    id uuid primary key default uuid_generate_v4(),
    customer_id uuid not null references public.customers on delete cascade,
    location_name text not null,
    address text,
    city text,
    state text,
    zip text,
    contact_name text,
    phone text,
    email text,
    status text not null default 'active',
    created_at timestamptz not null default now()
);

-- ───── 5. Backfill: if existing customer has location_id or ship_to, create a location row ─────
insert into public.customer_locations (customer_id, location_name, address)
select c.id,
       coalesce(nullif(trim(c.location_id), ''), 'Main') as location_name,
       nullif(trim(c.ship_to), '')
from public.customers c
where (nullif(trim(c.location_id), '') is not null or nullif(trim(c.ship_to), '') is not null)
  and not exists (
      select 1 from public.customer_locations cl
      where cl.customer_id = c.id
        and cl.location_name = coalesce(nullif(trim(c.location_id), ''), 'Main')
  );

-- ───── 6. PROFILES → CUSTOMERS link ─────
-- Allow multiple profiles per customer (team users). Direction flipped from the old
-- customers.profile_id (which assumed one-profile-per-customer).
alter table public.profiles add column if not exists customer_id uuid references public.customers on delete set null;

-- Backfill: if a customer had profile_id set, copy that linkage to profiles.customer_id
update public.profiles p
set customer_id = c.id
from public.customers c
where c.profile_id = p.id and p.customer_id is null;

-- ───── 7. updated_at trigger ─────
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
    new.updated_at = now();
    return new;
end; $$;

drop trigger if exists customers_set_updated_at on public.customers;
create trigger customers_set_updated_at
    before update on public.customers
    for each row execute function public.set_updated_at();

-- ───── 8. RLS on customer_locations + extended policies ─────
alter table public.customer_locations enable row level security;

do $$ begin
    if not exists (select 1 from pg_policies where policyname = 'Admins manage customer_locations' and tablename = 'customer_locations') then
        create policy "Admins manage customer_locations" on public.customer_locations
            for all using (public.is_admin());
    end if;
    if not exists (select 1 from pg_policies where policyname = 'Users view own customer locations' and tablename = 'customer_locations') then
        create policy "Users view own customer locations" on public.customer_locations
            for select using (
                exists (select 1 from public.profiles where id = auth.uid() and customer_id = customer_locations.customer_id)
            );
    end if;
    if not exists (select 1 from pg_policies where policyname = 'Users view own customer' and tablename = 'customers') then
        create policy "Users view own customer" on public.customers
            for select using (
                exists (select 1 from public.profiles where id = auth.uid() and customer_id = customers.id)
            );
    end if;
end $$;

-- ───── 9. New indexes ─────
create index if not exists idx_customers_status on public.customers(status);
create index if not exists idx_customers_company on public.customers(company_name);
create index if not exists idx_customer_locations_customer on public.customer_locations(customer_id);
create index if not exists idx_profiles_customer on public.profiles(customer_id);

-- ═══════════════════════════════════════════════════════════
-- VERIFICATION (run these after the migration, separately)
-- ═══════════════════════════════════════════════════════════
-- select count(*) as customers_total, count(distinct company_name) as unique_companies from public.customers;
-- select count(*) as locations_total from public.customer_locations;
-- select c.company_name, c.account_code, c.status, count(cl.id) as location_count
--   from public.customers c left join public.customer_locations cl on cl.customer_id = c.id
--   group by c.id, c.company_name, c.account_code, c.status
--   order by c.company_name;
-- select count(*) as profiles_with_customer from public.profiles where customer_id is not null;

-- ═══════════════════════════════════════════════════════════
-- DEPRECATED COLUMNS (kept for now, drop in a later migration after app
-- code transitions to read the new column names):
--   customers.name        → use customers.company_name
--   customers.customer_id → use customers.account_code
--   customers.location_id → moved to customer_locations.location_name
--   customers.ship_to     → moved to customer_locations.address
--   customers.bill_to     → copied to customers.billing_address (text blob)
--   customers.profile_id  → flipped to profiles.customer_id (allows team users)
-- ═══════════════════════════════════════════════════════════
