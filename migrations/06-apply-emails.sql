-- ═══════════════════════════════════════════════════════════
-- 06 — Apply Flow + Emails (settings + email_queue)
--
-- SAFE: purely additive + idempotent. Adds public.settings
-- (key/value store) and public.email_queue (would-send queue).
-- Also seeds default email templates without overwriting any
-- user edits already present.
--
-- BEFORE RUNNING:
--   1. Back up Supabase (Database → Backups → Create backup)
--   2. Run this in SQL Editor → New Query → Paste → Run
--   3. Verify with the queries at the bottom
-- ═══════════════════════════════════════════════════════════

-- ───── 1. settings (key/value store) ─────
create table if not exists public.settings (
    key text primary key,
    value jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now()
);

-- ───── 2. email_queue ─────
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
create index if not exists idx_email_queue_status on public.email_queue(status);
create index if not exists idx_email_queue_created on public.email_queue(created_at desc);

-- ───── 3. updated_at trigger on settings ─────
drop trigger if exists settings_set_updated_at on public.settings;
create trigger settings_set_updated_at
    before update on public.settings
    for each row execute function public.set_updated_at();

-- ───── 4. RLS — admins only ─────
alter table public.settings enable row level security;
alter table public.email_queue enable row level security;

drop policy if exists "Admins manage settings" on public.settings;
create policy "Admins manage settings" on public.settings
    for all using (public.is_admin());

drop policy if exists "Admins manage email_queue" on public.email_queue;
create policy "Admins manage email_queue" on public.email_queue
    for all using (public.is_admin());

-- ───── 5. Seed default email templates + from-info ─────
-- Uses on conflict do nothing so admin edits are never overwritten.

insert into public.settings (key, value) values
('email_from', jsonb_build_object(
    'fromName', 'Nutritional Innovations',
    'fromEmail', 'orders@nutritionalinnovations.net',
    'replyTo', 'orders@nutritionalinnovations.net',
    'adminNotify', 'orders@nutritionalinnovations.net'
))
on conflict (key) do nothing;

insert into public.settings (key, value) values
('email_template_new_application', jsonb_build_object(
    'subject', 'New wholesale application: {{company_name}}',
    'body', E'A new wholesale application has been submitted.\n\nCompany: {{company_name}}\nContact: {{contact_name}}\nEmail: {{contact_email}}\nPhone: {{contact_phone}}\nLicense #: {{license_number}}\nState: {{license_state}}\n\nReview it in the admin portal under Accounts.\n\n— NI Wholesale System'
))
on conflict (key) do nothing;

insert into public.settings (key, value) values
('email_template_application_received', jsonb_build_object(
    'subject', 'We received your NI Wholesale application',
    'body', E'Hi {{contact_name}},\n\nThanks for applying to Nutritional Innovations Wholesale. We have received your application for {{company_name}} and our team will review it shortly. We will email you again once it has been approved.\n\nIf you have any questions in the meantime, just reply to this email.\n\n— The Nutritional Innovations Team'
))
on conflict (key) do nothing;

insert into public.settings (key, value) values
('email_template_customer_approved', jsonb_build_object(
    'subject', 'Welcome to Nutritional Innovations Wholesale, {{company_name}}',
    'body', E'Hi {{contact_name}},\n\nGood news — your wholesale application for {{company_name}} has been approved.\n\nYou can now log in at {{site_url}} with the email address you submitted and the password you chose during signup.\n\nIf you have any questions, just reply to this email.\n\n— The Nutritional Innovations Team'
))
on conflict (key) do nothing;

insert into public.settings (key, value) values
('email_template_customer_declined', jsonb_build_object(
    'subject', 'Your NI Wholesale application',
    'body', E'Hi {{contact_name}},\n\nThank you for applying to Nutritional Innovations Wholesale. After reviewing your application for {{company_name}}, we are unable to approve it at this time.\n\nReason: {{decline_reason}}\n\nIf you believe this is an error or would like to provide additional information, just reply to this email.\n\n— The Nutritional Innovations Team'
))
on conflict (key) do nothing;

insert into public.settings (key, value) values
('email_template_order_confirmation', jsonb_build_object(
    'subject', 'Your NI order {{order_num}} has been received',
    'body', E'Hi {{contact_name}},\n\nThank you for your order with Nutritional Innovations. Here are the details:\n\nOrder #: {{order_num}}\nTotal: {{order_total}}\n\nWe will send you a shipping confirmation as soon as your order is on its way.\n\n— The Nutritional Innovations Team'
))
on conflict (key) do nothing;

insert into public.settings (key, value) values
('email_template_order_shipped', jsonb_build_object(
    'subject', 'Your NI order {{order_num}} has shipped',
    'body', E'Hi {{contact_name}},\n\nGood news — your order {{order_num}} from Nutritional Innovations just shipped.\n\nTracking: {{tracking_number}} ({{carrier}})\n\nMost orders arrive within 3-5 business days. If you have any questions, just reply to this email.\n\n— The Nutritional Innovations Team'
))
on conflict (key) do nothing;

insert into public.settings (key, value) values
('email_template_order_cancelled', jsonb_build_object(
    'subject', 'Your NI order {{order_num}} has been cancelled',
    'body', E'Hi {{contact_name}},\n\nWe wanted to let you know that your order {{order_num}} from Nutritional Innovations has been cancelled.\n\nReason: {{cancel_reason}}\n\nIf this was unexpected or you have any questions, just reply to this email.\n\n— The Nutritional Innovations Team'
))
on conflict (key) do nothing;

-- ═══════════════════════════════════════════════════════════
-- VERIFICATION (run separately after the migration)
-- ═══════════════════════════════════════════════════════════
-- select key from public.settings order by key;
-- select count(*) from public.email_queue;
-- select column_name from information_schema.columns
--   where table_schema = 'public' and table_name = 'settings'  order by ordinal_position;
-- select column_name from information_schema.columns
--   where table_schema = 'public' and table_name = 'email_queue' order by ordinal_position;

-- ═══════════════════════════════════════════════════════════
-- DEPRECATED notes:
--   none — this is a new feature, no prior schema in use.
-- ═══════════════════════════════════════════════════════════
