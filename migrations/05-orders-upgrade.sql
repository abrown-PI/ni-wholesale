-- ═══════════════════════════════════════════════════════════
-- 05 — Orders upgrade (Reviv-style: addresses, fulfillment, payment)
--
-- SAFE: purely additive + idempotent. Adds new columns to
-- public.orders + public.order_items, normalizes status values,
-- and adds useful indexes. No data destruction.
--
-- BEFORE RUNNING:
--   1. Back up Supabase (Database → Backups → Create backup)
--   2. Run this in SQL Editor → New Query → Paste → Run
--   3. Verify with the queries at the bottom
-- ═══════════════════════════════════════════════════════════

-- ───── 1. Add new columns to public.orders ─────
alter table public.orders add column if not exists customer_location_id uuid references public.customer_locations on delete set null;

-- Shipping snapshot
alter table public.orders add column if not exists ship_to_name text;
alter table public.orders add column if not exists ship_to_address text;
alter table public.orders add column if not exists ship_to_city text;
alter table public.orders add column if not exists ship_to_state text;
alter table public.orders add column if not exists ship_to_zip text;
alter table public.orders add column if not exists ship_to_phone text;

-- Billing snapshot
alter table public.orders add column if not exists bill_to_name text;
alter table public.orders add column if not exists bill_to_address text;
alter table public.orders add column if not exists bill_to_city text;
alter table public.orders add column if not exists bill_to_state text;
alter table public.orders add column if not exists bill_to_zip text;

-- Payment
alter table public.orders add column if not exists payment_method text default 'card';

-- Fulfillment
alter table public.orders add column if not exists tracking_number text;
alter table public.orders add column if not exists carrier text;
alter table public.orders add column if not exists shipped_at timestamptz;
alter table public.orders add column if not exists delivered_at timestamptz;
alter table public.orders add column if not exists cancelled_at timestamptz;
alter table public.orders add column if not exists cancel_reason text;

-- Notes / discounts / refunds
alter table public.orders add column if not exists internal_notes text default '';
alter table public.orders add column if not exists coupon_code text;          -- column only; no logic yet (Coupons bucket)
alter table public.orders add column if not exists discount_amount numeric(10,2) default 0; -- column only
alter table public.orders add column if not exists refund_amount numeric(10,2) default 0;
alter table public.orders add column if not exists refunded_at timestamptz;

-- ───── 2. Normalize status values to lowercase enum ─────
-- Old values seen in the wild: 'Pending' | 'Processing' | 'Shipped' | 'Completed' | 'Complete' | 'Canceled' | 'Cancelled'
-- New canonical: 'pending' | 'processing' | 'shipped' | 'delivered' | 'cancelled'
update public.orders set status = lower(status) where status is not null;
update public.orders set status = 'delivered' where status in ('completed', 'complete');
update public.orders set status = 'cancelled' where status = 'canceled';

-- ───── 3. Default lowercase 'pending' going forward ─────
alter table public.orders alter column status set default 'pending';

-- ───── 4. order_items additions ─────
-- Add received_qty for partial fulfillment. (We leave unit_price nullable here
-- for safety on existing rows; the canonical schema.sql declares it NOT NULL
-- for fresh installs.)
alter table public.order_items add column if not exists received_qty integer default 0;

-- ───── 5. Indexes ─────
create index if not exists idx_orders_customer_id on public.orders(customer_id);
create index if not exists idx_orders_created_at on public.orders(placed_at desc);
create index if not exists idx_orders_shipped_at on public.orders(shipped_at) where shipped_at is not null;

-- ═══════════════════════════════════════════════════════════
-- VERIFICATION (run separately after the migration)
-- ═══════════════════════════════════════════════════════════
-- select status, count(*) from public.orders group by status order by 1;
-- select count(*) as orders_total,
--        count(customer_location_id) as with_location,
--        count(tracking_number) as with_tracking,
--        count(shipped_at) as shipped
--   from public.orders;
-- select column_name from information_schema.columns
--   where table_schema = 'public' and table_name = 'orders' order by ordinal_position;
-- select column_name from information_schema.columns
--   where table_schema = 'public' and table_name = 'order_items' order by ordinal_position;

-- ═══════════════════════════════════════════════════════════
-- DEPRECATED notes (semantics changed, kept for back-compat):
--   orders.items (jsonb)      → prefer rows in public.order_items
--   orders.status capitalized → now lowercase enum
--                               ('pending'|'processing'|'shipped'|'delivered'|'cancelled')
--   orders.status 'Completed' → migrated to 'delivered'
--   orders.status 'Canceled'  → migrated to 'cancelled'
-- ═══════════════════════════════════════════════════════════
