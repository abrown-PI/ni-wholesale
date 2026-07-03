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

- [ ] **Microsoft 365 setup** — one of:
    - **Option A (simpler):** Add a **shared mailbox** under the existing PI 365 tenant (`orders@<ni-domain>`). No new license needed. Ashley admins in PI's Exchange admin.
    - **Option B (fully separate):** New M365 tenant for NI. Own admin, own users, own billing. ~$6-22/user/month depending on plan. Only necessary if NI is legally separate.
- [ ] Add MX + TXT records to DNS (Microsoft supplies exact values in tenant setup)
- [ ] Test send/receive at `orders@<ni-domain>` before going further

- [ ] **Resend for transactional email** (see below section) — sends welcome emails, order confirmations, shipped notifications
    - Coexists with 365: 365 handles the human `orders@` inbox, Resend handles the automated `no-reply@` or `orders@` sends from the app

## Hosting & code

- [x] GitHub repo (`abrown-PI/ni-wholesale`)
- [x] Vercel project (currently `ni-wholesale.vercel.app`)
- [x] Supabase project (`maekiwyawaolvmshiwfb`, region us-east-1)
- [x] Edge Function `approve-customer` deployed
- [ ] Custom domain wired into Vercel (once domain registered)

## Payments (Phase 2 — not blocking today)

- [ ] **Stripe account for NI** — separate from Reviv's Stripe (different bank routing, different tax profile)
- [ ] Bank account + routing on file for Stripe payouts
- [ ] Add Stripe keys to Vercel + Edge Function env vars
- [ ] Wire card checkout (currently `paymentMethod: card` just marks Unpaid — no actual charge)
- [ ] Set up Stripe webhook to update `orders.payment_status` on `checkout.session.completed`

## Legal / operational

- [ ] Business entity check: is NI legally separate from PI, or a DBA/product line under PI? Affects Stripe tax + M365 tenant choice
- [ ] Terms of Service page (customer-facing) — link at footer
- [ ] Privacy Policy page — required by Stripe + Resend
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
