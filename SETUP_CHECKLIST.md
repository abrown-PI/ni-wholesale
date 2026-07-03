# NI Wholesale — Standalone Business Setup Checklist

Things NI needs as its own operational entity, separate from Reviv and (partly) from Pharmacy Innovations. Cross off as you go.

## Domain & DNS

- [ ] **Register a production domain** — options:
    - `niwholesale.com` (clean, keyword-heavy)
    - `nutritionalinnovations.net` (already reserved? check)
    - `wholesale.pharmacyinnovations.net` (subdomain, no new registration needed)
- [ ] Point domain at Vercel (add CNAME or A records once picked)
- [ ] SSL: Vercel auto-provisions when domain is added in Vercel dashboard

## Email

- [x] **New M365 tenant `nutritionalinnovations.onmicrosoft.com`** created (2026-07-03) — separate tenant since NI is legally separate. Admin: `abrown@nutritionalinnovations.net` (transitioning from `.onmicrosoft.com`).
- [ ] Add `nutritionalinnovations.net` as verified custom domain in the M365 tenant
    - TXT verification record placed at A2 Hosting DNS (authoritative for the domain — NOT stableserver.net)
    - Awaiting DNS propagation
- [ ] Add MX + TXT (SPF) + CNAME (Autodiscover, DKIM) records after domain is verified
    - Note: existing SPF at A2 Hosting is `v=spf1 +a +mx +ip4:68.66.216.32 ~all` — must MERGE with Microsoft's, not replace
- [ ] Test send/receive at `abrown@nutritionalinnovations.net` before going further
- [ ] Add shared mailboxes: `orders@`, `support@`, `no-reply@` — free, no license needed

- [ ] **Resend for transactional email** — blocked on NI email address
    - Sign up at resend.com using `abrown@nutritionalinnovations.net` once available
    - Verify sending domain `mail.nutritionalinnovations.net` or `nutritionalinnovations.net` via DKIM + SPF + DMARC
    - Add `RESEND_API_KEY` to Supabase Edge Function secrets
    - Wire welcome email into `approve-customer` Edge Function
    - Migrate `emailQueue` from localStorage to Resend + Supabase

## Hosting & code

- [x] GitHub repo (`abrown-PI/ni-wholesale`)
- [x] Vercel project (currently `ni-wholesale.vercel.app`)
- [x] Supabase project (`maekiwyawaolvmshiwfb`, region us-east-1)
- [x] Edge Function `approve-customer` deployed (v2, supports `attachAdditionalCustomerIds` for multi-entity)
- [x] Products migrated to Supabase (all read/write goes through DB)
- [x] Apply/login/change-password wired to Supabase Auth
- [x] Orders write to Supabase at checkout
- [x] Multi-entity purchasing: `customer_users` join table, entity switcher UI, approve modal multi-attach
- [x] `customers` extended with `netsuite_entity_id`, `tax_id`, `resale_cert_number`, `parent_customer_id` fields
- [ ] Custom domain wired into Vercel (`wholesale.nutritionalinnovations.net` or similar — once domain choice made)

## Payments (Phase 2 — not blocking today)

- [ ] **Stripe account for NI** — separate from Reviv's Stripe (different bank routing, different tax profile)
- [ ] Bank account + routing on file for Stripe payouts
- [ ] Add Stripe keys to Vercel + Edge Function env vars
- [ ] Wire card checkout (currently `paymentMethod: card` just marks Unpaid — no actual charge)
- [ ] Set up Stripe webhook to update `orders.payment_status` on `checkout.session.completed`

## Legal / operational

- [x] **Business entity confirmed: NI is legally separate from PI** (2026-07-03) — needs own M365 tenant, own Resend, own Stripe
- [x] Terms of Service page (`/terms`) — customer-facing, linked in footer
- [x] Privacy Policy page (`/privacy`) — customer-facing, linked in footer
- [ ] Wholesale-specific: state resale certificates on file per pharmacy customer

## Content / brand

- [x] NI logo + brand assets (already in repo)
- [x] Product photos for 21 SKUs (mostly in `images/products/`; Recode needs one)
- [ ] Home page hero copy / value prop
- [ ] Category taxonomy — currently mixed (Probiotics, Specialty, blank)

## Observability / support

- [ ] Vercel Analytics (built-in, click on in dashboard)
- [ ] Supabase logs (built-in — you can query `postgres` + `edge-function` service logs)
- [ ] Support email autoresponder (via 365 or Resend)
- [ ] Customer-facing support channel: email? phone? Both?

## Data / integration

- [ ] Product image storage: migrate from `images/products/*.png` in repo → Supabase Storage (`product-images` bucket, already provisioned)
- [ ] Product feed exports for Paladin/PK inventory sync (already exists in code as CSV export)
- [ ] Order → PioneerRx or Paladin integration (future)

## Deferred (Phase 3+)

- [ ] Auto-apply shipping rates (currently manual)
- [ ] Coupons: migrate from localStorage to Supabase
- [ ] Emails: migrate the full email queue → Resend
- [ ] Multi-admin: add other PI staff as admins via Supabase Auth
- [ ] Order fulfillment workflow (pick tickets, shipping labels)
- [ ] Analytics: PostHog or GA4 for storefront traffic
