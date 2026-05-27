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
    contact_name text,
    email text,
    phone text,
    website text,
    address text,
    city text,
    state text,
    zip text,
    payment_terms text default 'Net-30',
    min_order numeric(10,2) default 0,
    account_number text,
    notes text default '',
    status text not null default 'active',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- ───── PRODUCTS ─────
create table if not exists public.products (
    id uuid primary key default uuid_generate_v4(),
    sku text unique not null,
    name text not null,
    description text not null default '',
    category text,
    package_size text,
    status text not null default 'active', -- 'active' | 'inactive' | 'draft'

    vendor text,
    manufacturer text,
    vendor_product_name text,
    vendor_part_num text,
    upc text,

    cost_per_unit numeric(10,2),
    wholesale_price numeric(10,2),
    retail_price numeric(10,2),
    profit_margin numeric(5,2),

    stock integer not null default 0,
    tester_stock integer not null default 0,
    low_stock_threshold integer not null default 10,
    min_order_qty integer not null default 1,

    images jsonb not null default '[]'::jsonb, -- [{url, isPrimary, alt}]
    taxable boolean not null default true,
    paid_from text,
    internal_notes text not null default '',

    stripe_product_id text,
    stripe_price_id text,

    created_by uuid references public.profiles on delete set null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- ───── PRODUCT VARIANTS (optional — for multi-SKU products) ─────
-- Variants inherit prices from parent product when set to null.
create table if not exists public.product_variants (
    id uuid primary key default uuid_generate_v4(),
    product_id uuid not null references public.products on delete cascade,
    variant_name text not null,
    sku text unique not null,
    upc text,

    stock integer not null default 0,
    tester_stock integer not null default 0,
    low_stock_threshold integer, -- null = inherit from parent product
    min_order_qty integer,       -- null = inherit

    cost_per_unit numeric(10,2),   -- null = inherit
    wholesale_price numeric(10,2), -- null = inherit
    retail_price numeric(10,2),    -- null = inherit

    status text not null default 'active',
    sort_order integer not null default 0,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- ───── CUSTOMERS (parent pharmacy organizations) ─────
create table if not exists public.customers (
    id uuid primary key default uuid_generate_v4(),
    company_name text not null,
    account_code text, -- human-readable code (e.g., 'PI_612_FL')
    contact_name text,
    email text,
    phone text,

    -- Billing address
    billing_address text,
    billing_city text,
    billing_state text,
    billing_zip text,

    -- Pharmacy-specific
    pharmacy_type text, -- 'Independent' | 'Compounding' | 'Hospital' | 'Clinic' | 'Other'
    license_number text,
    dea_number text,
    npi_number text,

    payment_terms text not null default 'Net-30', -- 'Net-30' | 'Net-60' | 'Prepay' | 'Credit Card'
    status text not null default 'active', -- 'active' | 'suspended' | 'pending'
    notes text default '',

    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- ───── CUSTOMER LOCATIONS (sub-accounts under a customer) ─────
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

-- ───── PROFILE → CUSTOMER LINK ─────
-- profiles.customer_id allows multiple users to share a customer account (team).
alter table public.profiles add column if not exists customer_id uuid references public.customers on delete set null;

-- ───── INVENTORY TRANSACTIONS ─────
create table if not exists public.inventory_transactions (
    id uuid primary key default uuid_generate_v4(),
    date date not null default current_date,
    type text not null, -- 'IN' | 'OUT' | 'ADJ'
    vendor text,
    reference text,
    product_name text not null,
    product_id uuid references public.products on delete set null,
    variant_id uuid references public.product_variants on delete set null,
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
    customer_location_id uuid references public.customer_locations on delete set null,
    customer_name text,
    customer_email text,
    items jsonb default '[]'::jsonb, -- [{productId, variantId, sku, name, qty, price, ...}] (legacy/back-compat; prefer order_items table)

    -- Shipping address (snapshot at order time)
    ship_to_name text,
    ship_to_address text,
    ship_to_city text,
    ship_to_state text,
    ship_to_zip text,
    ship_to_phone text,

    -- Billing address (snapshot; may equal ship-to)
    bill_to_name text,
    bill_to_address text,
    bill_to_city text,
    bill_to_state text,
    bill_to_zip text,

    subtotal numeric(10,2),
    tax numeric(10,2),
    shipping numeric(10,2),
    total numeric(10,2),
    discount_amount numeric(10,2) default 0,
    coupon_code text, -- column only; no validation logic yet (Coupons bucket)
    refund_amount numeric(10,2) default 0,
    refunded_at timestamptz,

    payment_method text default 'card', -- 'card' | 'invoice' | 'cash' | 'check'
    payment_status text default 'Unpaid', -- Unpaid, Paid, Refunded
    status text default 'pending', -- 'pending' | 'processing' | 'shipped' | 'delivered' | 'cancelled'

    -- Fulfillment
    tracking_number text,
    carrier text, -- 'USPS' | 'UPS' | 'FedEx' | 'DHL' | 'Other'
    shipped_at timestamptz,
    delivered_at timestamptz,
    cancelled_at timestamptz,
    cancel_reason text,

    notes text, -- customer-visible
    internal_notes text default '', -- admin-only

    stripe_session_id text,
    stripe_payment_intent text,

    placed_by uuid references public.profiles on delete set null,
    placed_at timestamptz default now(),
    updated_at timestamptz default now()
);

-- ───── ORDER ITEMS (normalized — preferred over orders.items jsonb) ─────
create table if not exists public.order_items (
    id uuid primary key default uuid_generate_v4(),
    order_id uuid references public.orders on delete cascade,
    product_id uuid references public.products on delete set null,
    variant_id uuid references public.product_variants on delete set null,
    product_name text,
    sku text,
    qty integer,
    received_qty integer default 0, -- for partial fulfillment
    unit_price numeric(10,2) not null default 0,
    line_total numeric(10,2)
);

-- ───── PURCHASE ORDERS ─────
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

-- ───── PURCHASE ORDER ITEMS ─────
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

-- ───── SETTINGS (key/value store) ─────
create table if not exists public.settings (
    key text primary key,
    value jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now()
);

-- ───── COUPONS ─────
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

-- ───── COUPON REDEMPTIONS (audit log + usage counting) ─────
create table if not exists public.coupon_redemptions (
    id uuid primary key default uuid_generate_v4(),
    coupon_id uuid not null references public.coupons on delete cascade,
    customer_id uuid references public.customers on delete cascade,
    order_id uuid references public.orders on delete set null,
    discount_amount numeric(10,2),
    created_at timestamptz not null default now()
);

-- ───── EMAIL QUEUE (would-send queue while localStorage-only) ─────
create table if not exists public.email_queue (
    id uuid primary key default uuid_generate_v4(),
    to_email text not null,
    to_name text,
    subject text not null,
    body text not null,                     -- rendered plain text or HTML
    template_key text,                      -- e.g., 'customer_approved'
    template_vars jsonb default '{}'::jsonb,
    status text not null default 'pending', -- 'pending' | 'sent' | 'failed'
    related_account_id text,                -- legacy ACCOUNTS_KEY id (text, not uuid)
    related_customer_id uuid references public.customers on delete set null,
    related_order_id uuid references public.orders on delete set null,
    error_message text,
    created_at timestamptz not null default now(),
    sent_at timestamptz
);

-- ═══════════════════════════════════════════════════════════
-- updated_at TRIGGER
-- ═══════════════════════════════════════════════════════════
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

drop trigger if exists purchase_orders_set_updated_at on public.purchase_orders;
create trigger purchase_orders_set_updated_at
    before update on public.purchase_orders
    for each row execute function public.set_updated_at();

drop trigger if exists customers_set_updated_at on public.customers;
create trigger customers_set_updated_at
    before update on public.customers
    for each row execute function public.set_updated_at();

drop trigger if exists vendors_set_updated_at on public.vendors;
create trigger vendors_set_updated_at
    before update on public.vendors
    for each row execute function public.set_updated_at();

drop trigger if exists settings_set_updated_at on public.settings;
create trigger settings_set_updated_at
    before update on public.settings
    for each row execute function public.set_updated_at();

drop trigger if exists coupons_set_updated_at on public.coupons;
create trigger coupons_set_updated_at
    before update on public.coupons
    for each row execute function public.set_updated_at();

-- ═══════════════════════════════════════════════════════════
-- ROW LEVEL SECURITY (RLS)
-- ═══════════════════════════════════════════════════════════

-- Enable RLS on every table
alter table public.profiles enable row level security;
alter table public.vendors enable row level security;
alter table public.products enable row level security;
alter table public.product_variants enable row level security;
alter table public.customers enable row level security;
alter table public.customer_locations enable row level security;
alter table public.inventory_transactions enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.purchase_orders enable row level security;
alter table public.purchase_order_items enable row level security;
alter table public.settings enable row level security;
alter table public.email_queue enable row level security;
alter table public.coupons enable row level security;
alter table public.coupon_redemptions enable row level security;

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

-- Products/Variants/Vendors: readable by all authenticated users, writable by admins
create policy "Authenticated read products" on public.products
    for select using (auth.role() = 'authenticated');
create policy "Admins write products" on public.products
    for all using (public.is_admin());

create policy "Authenticated read product_variants" on public.product_variants
    for select using (auth.role() = 'authenticated');
create policy "Admins write product_variants" on public.product_variants
    for all using (public.is_admin());

create policy "Authenticated read vendors" on public.vendors
    for select using (auth.role() = 'authenticated');
create policy "Admins write vendors" on public.vendors
    for all using (public.is_admin());

-- Customers: admins manage all; users tied to a customer can read their own
create policy "Admins manage customers" on public.customers
    for all using (public.is_admin());
create policy "Users view own customer" on public.customers
    for select using (
        exists (select 1 from public.profiles where id = auth.uid() and customer_id = customers.id)
    );

create policy "Admins manage customer_locations" on public.customer_locations
    for all using (public.is_admin());
create policy "Users view own customer locations" on public.customer_locations
    for select using (
        exists (select 1 from public.profiles where id = auth.uid() and customer_id = customer_locations.customer_id)
    );

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

-- Purchase Orders: admins/staff only (pharmacies have no access)
create policy "Admins manage purchase_orders" on public.purchase_orders
    for all using (public.is_admin());

create policy "Admins manage purchase_order_items" on public.purchase_order_items
    for all using (public.is_admin());

-- Settings + Email Queue: admins/staff only
create policy "Admins manage settings" on public.settings
    for all using (public.is_admin());

create policy "Admins manage email_queue" on public.email_queue
    for all using (public.is_admin());

-- Coupons: admins manage all; authenticated users can SELECT so the
-- storefront can match a code typed at checkout.
create policy "Admins manage coupons" on public.coupons
    for all using (public.is_admin());
create policy "Authenticated read coupons" on public.coupons
    for select using (auth.role() = 'authenticated');

-- Coupon redemptions: admins manage all; users can read their own
-- (linked via profiles.customer_id).
create policy "Admins manage coupon_redemptions" on public.coupon_redemptions
    for all using (public.is_admin());
create policy "Users view own coupon_redemptions" on public.coupon_redemptions
    for select using (
        exists (
            select 1 from public.profiles
            where id = auth.uid()
              and customer_id = coupon_redemptions.customer_id
        )
    );

-- ═══════════════════════════════════════════════════════════
-- STORAGE BUCKET FOR PRODUCT IMAGES
-- ═══════════════════════════════════════════════════════════
insert into storage.buckets (id, name, public)
values ('product-images', 'product-images', true)
on conflict (id) do nothing;

create policy "Public read product images" on storage.objects
    for select using (bucket_id = 'product-images');
create policy "Admins upload product images" on storage.objects
    for insert with check (bucket_id = 'product-images' and public.is_admin());
create policy "Admins update product images" on storage.objects
    for update using (bucket_id = 'product-images' and public.is_admin());
create policy "Admins delete product images" on storage.objects
    for delete using (bucket_id = 'product-images' and public.is_admin());

-- ═══════════════════════════════════════════════════════════
-- INDEXES
-- ═══════════════════════════════════════════════════════════
create index if not exists idx_products_sku on public.products(sku);
create index if not exists idx_products_vendor on public.products(vendor);
create index if not exists idx_products_upc on public.products(upc);
create index if not exists idx_products_status on public.products(status);
create index if not exists idx_variants_product on public.product_variants(product_id);
create index if not exists idx_variants_sku on public.product_variants(sku);
create index if not exists idx_inventory_vendor on public.inventory_transactions(vendor);
create index if not exists idx_inventory_product on public.inventory_transactions(product_name);
create index if not exists idx_inventory_date on public.inventory_transactions(date);
create index if not exists idx_orders_status on public.orders(status);
create index if not exists idx_orders_placed_by on public.orders(placed_by);
create index if not exists idx_orders_customer_id on public.orders(customer_id);
create index if not exists idx_orders_created_at on public.orders(placed_at desc);
create index if not exists idx_orders_shipped_at on public.orders(shipped_at) where shipped_at is not null;
create index if not exists idx_purchase_orders_status on public.purchase_orders(status);
create index if not exists idx_purchase_orders_vendor on public.purchase_orders(vendor_id);
create index if not exists idx_purchase_orders_created on public.purchase_orders(created_at desc);
create index if not exists idx_po_items_po on public.purchase_order_items(po_id);
create index if not exists idx_po_items_product on public.purchase_order_items(product_id);
create index if not exists idx_customers_status on public.customers(status);
create index if not exists idx_customers_company on public.customers(company_name);
create index if not exists idx_customer_locations_customer on public.customer_locations(customer_id);
create index if not exists idx_profiles_customer on public.profiles(customer_id);
create index if not exists idx_email_queue_status on public.email_queue(status);
create index if not exists idx_email_queue_created on public.email_queue(created_at desc);
create index if not exists idx_coupons_code on public.coupons(code);
create index if not exists idx_coupons_active on public.coupons(active);
create index if not exists idx_coupons_customer on public.coupons(customer_id);
create index if not exists idx_coupon_redemptions_coupon on public.coupon_redemptions(coupon_id);
create index if not exists idx_coupon_redemptions_customer on public.coupon_redemptions(customer_id);
create index if not exists idx_coupon_redemptions_order on public.coupon_redemptions(order_id);
