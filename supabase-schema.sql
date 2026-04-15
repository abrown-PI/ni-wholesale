-- ═══════════════════════════════════════════════════════════
-- NI Wholesale Database Schema
-- Run this in Supabase → SQL Editor → New Query → Paste → Run
-- ═══════════════════════════════════════════════════════════

-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- ───── PROFILES (extends auth.users) ─────
create table if not exists public.profiles (
    id uuid primary key references auth.users on delete cascade,
    email text not null,
    full_name text,
    role text not null default 'pharmacy', -- 'admin' | 'pharmacy' | 'staff'
    pharmacy_name text,
    phone text,
    ship_to text,
    bill_to text,
    stripe_customer_id text,
    created_at timestamptz default now()
);

-- ───── VENDORS ─────
create table if not exists public.vendors (
    id uuid primary key default uuid_generate_v4(),
    name text unique not null,
    contact text,
    email text,
    phone text,
    created_at timestamptz default now()
);

-- ───── MANUFACTURER CODES ─────
create table if not exists public.mfg_codes (
    id uuid primary key default uuid_generate_v4(),
    name text not null,
    code text not null,
    derived text,
    notes text,
    created_at timestamptz default now()
);

-- ───── PRODUCTS ─────
create table if not exists public.products (
    id uuid primary key default uuid_generate_v4(),
    product_id text,
    product_name text not null,
    vendor_product_name text,
    vendor text,
    vendor_part_num text,
    upc text,
    package_size text,
    category text,
    cost numeric(10,2),
    sell_price numeric(10,2),
    retail_price numeric(10,2),
    stock integer default 0,
    low_stock integer default 10,
    taxable text,
    active text default 'Y',
    notes text,
    paid_from text,
    images jsonb default '[]'::jsonb,
    stripe_product_id text,
    stripe_price_id text,
    date_added timestamptz default now()
);

-- ───── CUSTOMERS ─────
create table if not exists public.customers (
    id uuid primary key default uuid_generate_v4(),
    name text not null,
    location_id text,
    customer_id text,
    ship_to text,
    bill_to text,
    phone text,
    email text,
    profile_id uuid references public.profiles on delete set null,
    created_at timestamptz default now()
);

-- ───── INVENTORY TRANSACTIONS ─────
create table if not exists public.inventory_transactions (
    id uuid primary key default uuid_generate_v4(),
    date date not null default current_date,
    type text not null, -- 'IN' | 'OUT' | 'ADJ'
    vendor text,
    reference text,
    product_name text not null,
    product_id uuid references public.products on delete set null,
    qty integer not null,
    unit_cost numeric(10,2),
    customer_name text,
    sold_by text,
    notes text,
    entered_by uuid references public.profiles on delete set null,
    created_at timestamptz default now()
);

-- ───── ORDERS ─────
create table if not exists public.orders (
    id uuid primary key default uuid_generate_v4(),
    order_number text unique,
    customer_id uuid references public.customers on delete set null,
    customer_name text,
    customer_email text,
    items jsonb default '[]'::jsonb, -- [{productId, name, qty, price, ...}]
    subtotal numeric(10,2),
    tax numeric(10,2),
    shipping numeric(10,2),
    total numeric(10,2),
    status text default 'Pending', -- Pending, Processing, Shipped, Completed, Canceled
    payment_status text default 'Unpaid', -- Unpaid, Paid, Refunded
    stripe_session_id text,
    stripe_payment_intent text,
    placed_by uuid references public.profiles on delete set null,
    notes text,
    placed_at timestamptz default now(),
    updated_at timestamptz default now()
);

-- ───── ORDER ITEMS (normalized — optional, items jsonb works too) ─────
create table if not exists public.order_items (
    id uuid primary key default uuid_generate_v4(),
    order_id uuid references public.orders on delete cascade,
    product_id uuid references public.products on delete set null,
    product_name text,
    qty integer,
    unit_price numeric(10,2),
    line_total numeric(10,2)
);

-- ═══════════════════════════════════════════════════════════
-- ROW LEVEL SECURITY (RLS)
-- ═══════════════════════════════════════════════════════════

-- Enable RLS on every table
alter table public.profiles enable row level security;
alter table public.vendors enable row level security;
alter table public.mfg_codes enable row level security;
alter table public.products enable row level security;
alter table public.customers enable row level security;
alter table public.inventory_transactions enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;

-- Helper function: is current user an admin/staff?
create or replace function public.is_admin()
returns boolean language sql security definer as $$
    select exists (
        select 1 from public.profiles
        where id = auth.uid() and role in ('admin','staff')
    );
$$;

-- Profiles: users can see/update own profile; admins see all
create policy "Users view own profile" on public.profiles
    for select using (auth.uid() = id or public.is_admin());
create policy "Users update own profile" on public.profiles
    for update using (auth.uid() = id);
create policy "Admins manage profiles" on public.profiles
    for all using (public.is_admin());

-- Auto-create profile on signup
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer as $$
begin
    insert into public.profiles (id, email, full_name)
    values (new.id, new.email, new.raw_user_meta_data->>'full_name');
    return new;
end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

-- Products/Vendors/MfgCodes: readable by all authenticated users, writable by admins
create policy "Authenticated read products" on public.products
    for select using (auth.role() = 'authenticated');
create policy "Admins write products" on public.products
    for all using (public.is_admin());

create policy "Authenticated read vendors" on public.vendors
    for select using (auth.role() = 'authenticated');
create policy "Admins write vendors" on public.vendors
    for all using (public.is_admin());

create policy "Authenticated read mfg_codes" on public.mfg_codes
    for select using (auth.role() = 'authenticated');
create policy "Admins write mfg_codes" on public.mfg_codes
    for all using (public.is_admin());

-- Customers: admins only
create policy "Admins manage customers" on public.customers
    for all using (public.is_admin());

-- Inventory: admins/staff only
create policy "Admins manage inventory" on public.inventory_transactions
    for all using (public.is_admin());

-- Orders: pharmacies see own, admins see all
create policy "Pharmacies view own orders" on public.orders
    for select using (placed_by = auth.uid() or public.is_admin());
create policy "Pharmacies create orders" on public.orders
    for insert with check (placed_by = auth.uid());
create policy "Admins manage orders" on public.orders
    for update using (public.is_admin());

create policy "Pharmacies view own order items" on public.order_items
    for select using (
        exists (select 1 from public.orders o where o.id = order_id and (o.placed_by = auth.uid() or public.is_admin()))
    );
create policy "Admins manage order items" on public.order_items
    for all using (public.is_admin());

-- ═══════════════════════════════════════════════════════════
-- INDEXES
-- ═══════════════════════════════════════════════════════════
create index if not exists idx_products_vendor on public.products(vendor);
create index if not exists idx_products_upc on public.products(upc);
create index if not exists idx_products_active on public.products(active);
create index if not exists idx_inventory_vendor on public.inventory_transactions(vendor);
create index if not exists idx_inventory_product on public.inventory_transactions(product_name);
create index if not exists idx_inventory_date on public.inventory_transactions(date);
create index if not exists idx_orders_status on public.orders(status);
create index if not exists idx_orders_placed_by on public.orders(placed_by);
