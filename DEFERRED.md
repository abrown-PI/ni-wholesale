# NI Wholesale — Deferred Items

Things we intentionally left out of an earlier pass so we could ship the core feature first. Track here so they don't get lost.

## From Variants UI (Task #11)
- **Storefront variant selection** — when a product has variants, the storefront card shows "Multiple options — view" and the detail modal shows a read-only variant table with a "Variant selection coming soon" banner. Need to extend `addToCart()`, `renderCart()`, `confirmOrder()`, `submitOrder()` to carry `variantId` end-to-end and decrement variant-level stock instead of product-level.
- **Inventory transactions tied to variants** — `inventory_transactions` schema has `variant_id` column, but `saveInventoryTransaction` and `confirmReceivePO` don't populate it. Transactions remain product-level. Variant-aware ledger would need: variant picker in the Record Transaction / Receive Inventory modals, and rendering per-variant balances.

## From Purchase Orders (Task #12)
- **CSV / Excel export for POs** — not built. Mirror pattern from `exportInventoryCSV()` / catalog Excel export.
- **PO vendor switch on edit** — currently blocked (force delete + recreate). Could be relaxed by clearing lines first.
- **`createdBy` on POs** — left blank client-side; populate when auth is wired.
- **PO duplicate / reorder shortcut** — "Reorder from PO-N" button would copy lines from a past PO.

## From Customers (Task #13, current round)
- **Team user management UI** — multiple `profiles` linking to one `customer`. Admin UI to invite/remove team members per customer. Reviv has this at `/admin/team` and `/api/admin/team`.
- **Customer self-service portal** — Reviv's `/shop/account` lets customers view their own orders, locations, team. Defer to Shop/Apply bucket.
- ~~**Full Apply form**~~ — DONE in Task #18 (rich Apply modal with company info, contact, licensing, billing, shipping locations, notes, password).
- ~~**Apply → auto-create customer + location + welcome email**~~ — DONE in Task #18 (Approve Application modal creates `customer` + `customerLocations` and queues `customer_approved` email).

## From Orders (Task #17)
- **Stripe refund flow** — `refundAmount`/`refundedAt` columns and a manual input are exposed on the order, but no Stripe API call is wired. Needs Stripe + audit log. Orders + Stripe bucket.
- **Resend email integration** — Mark Shipped should auto-email the customer with tracking. Today it only updates the record. Emails bucket.
- ~~**Coupon validation**~~ — DONE in Task #19. `couponCode` on order edit modal now has an Apply button that runs `validateCoupon()` and populates `discountAmount`. See "From Coupons (Task #19)" section below for remaining follow-ups (cancel-refund, real-time, etc.).
- **Tax calculation per state** — currently a single tax % input on the order edit modal. Needs a saved tax table per state (or external service) and auto-apply based on ship-to state.
- **Saved shipping methods / rates table** — shipping is a single dollar input today. Reviv has a rates table; defer to Settings/Shipping bucket.
- **Customer-facing order detail page** — Reviv has `/shop/orders/[id]` so a customer can see their own order status & tracking. NI today shows nothing customer-facing post-submit. Shop bucket.
- **Order export to QuickBooks / accounting** — CSV export exists but no QBO/Xero IIF/JSON export. Accounting bucket.
- **Per-variant order lines** — order edit modal picks products, not variants. Same gap as the Variants UI deferral.
- **Partial fulfillment UI** — `order_items.received_qty` column added but no UI to receive partial shipments.

## From Apply Flow + Emails (Task #18)
- **Real email sending (Resend integration)** — emails are queued only today (`DATA.emailQueue` / `public.email_queue`). The Email Queue page exposes Mailto links and a Mark Sent button so admins can copy/send manually. When Supabase + Resend land, swap the queue worker in.
- **Hashed/bcrypted passwords** — passwords are still stored plaintext in `localStorage` under `ni_accounts`. Reviv migrated this to Supabase Auth; NI needs the same when auth is wired.
- **Password reset flow** — not built. An admin would have to reset by editing the localStorage entry. Needs a "Forgot password" link + token flow when auth lands.
- **Email open/click tracking** — not built; no pixel, no link wrapping.
- **Bulk email tools** — not built; queue is one-row-per-event today.
- **Templated transactional HTML emails** — templates are plain text today (`{{var}}` interpolation). HTML versions, MJML, and brand styling deferred.
- **Customer-portal password change UI** — not built; a logged-in customer can't change their own password.
- **Approval audit log** — accounts get `approvedAt` / `declinedAt` / `declineReason`, but no `approvedBy` / signed audit trail. Hook this up when admin auth identities exist.

## From Coupons (Task #19)
- **Real-time validation at cart load** — coupon is only re-validated when the user types something or `renderCart()` runs. A coupon that goes inactive while a user is sitting on the cart page won't auto-clear until they next interact. Hook into a periodic refresh or a Supabase realtime subscription once that lands.
- **Cancel order should refund redemption** — `cancelOrder()` does not currently decrement `coupon.usesCount` or remove the matching `couponRedemptions` row. A cancelled order still counts toward `maxUses`. Need to call `decrementCouponRedemption(order.couponCode, order.id)` from `confirmCancelOrder` (only when order had a coupon).
- **Bulk coupon codes** — generate N codes at once (e.g. "Create 50 codes for a campaign"). Today admins create one at a time in the modal. Add an "Import / Generate" mode that accepts a count + prefix.
- **First-order-only restriction** — orthogonal to `onePerCustomer` (which limits to one use per customer, ever). A "first-order-only" rule would only apply if the customer has zero placed orders at the time of redemption.
- **Product/category restrictions** — coupon valid only on a list of `productIds` or `category`. Schema would add a `coupons.product_scope jsonb` column.
- **Stacking rules** — orders can carry only one coupon today. Reviv has the same limit. Decide: explicit "can stack with X" flag, or a numeric priority/ordering.
- **Customer-facing coupon list** — show "Coupons available to you" on the storefront account page (list shareable + customer-specific codes still valid for that customer).
- **Free shipping over $X** — special case of conditional discount. Would either fold into the existing `free_shipping` discount type with a `minSubtotal`, or become its own rule.
- **Coupon analytics** — usage by code/customer over time, $ saved, conversion lift. Today the admin table shows raw counts only.
- **Expiry date with time** — modal expiry is date-only; server-side schema is `timestamptz`. JS stores end-of-day for now. Add an optional time picker for promo windows that need hour-precision.

## Cross-cutting (not started)
- **Supabase wiring on JS side** — `index.html` is still localStorage-only. Nothing reads/writes Supabase. Will land alongside the Next.js rebuild or via a smaller sync layer.
- **Stripe checkout** — schema has `stripe_*` columns; no JS wiring. Shop/Stripe bucket.
- **Resend email integration** — no email sending anywhere. Apply/Coupons/Emails bucket.
- ~~**Coupons**~~ — DONE in Task #19. Admin Coupons page, %/$ off + free shipping, customer-specific, expiry, max uses, min subtotal, one-per-customer, cart + admin order-edit wire-up, redemption ledger.
- **Print packing slip / shipping label** — Reviv generates packing slips via `pdf-lib`. Orders bucket.
- **Admin can build orders for customers** — Reviv has `/admin/orders/new`. Orders bucket.
- **Refund flow** — partial/full Stripe refunds. Orders + Stripe bucket.
- **Mark Shipped** — tracking number, carrier, customer notification. Orders + Emails bucket.
- ~~**Settings: General / Shipping / Email templates**~~ — DONE. Email Settings landed in Task #18; General + Shipping landed in Task #20. See "From Settings (Task #20)" below for remaining follow-ups.

## From Settings (Task #20)
- **Tax table per state** — currently a single global default tax %. Needs a state→rate map and auto-apply based on ship-to.
- **External shipping rate APIs** — real-time USPS/UPS/FedEx rate quotes. Currently only static rates.
- **Settings audit log** — who changed what, when.
- **Multi-currency support** — currency dropdown is USD-only. International expansion would need this.
- **Settings backup/restore** — admin can export settings as JSON and re-import.
- **Logo upload** — currently just a URL field. No file upload to Supabase Storage yet.

## From Checkout / Stripe (Task #21)
- **Real Stripe integration** — currently stubbed. Requires server-side checkout session creation (Stripe Checkout) or Stripe Elements with publishable key. NI's localStorage-only architecture blocks real charges.
- **Saved payment methods** — Reviv stores `stripe_customer_id` on profiles; once a customer has paid once, future checkouts can reuse. Not implemented.
- **Webhook handling** — real Stripe needs `/api/stripe/webhook` to confirm payments asynchronously. Not implemented.
- **3DS / SCA** — Strong Customer Authentication challenge flow.
- **Apple Pay / Google Pay** — Stripe supports these via Elements.
- **Recurring/subscription billing** — wholesale repeat orders could be auto-charged. Not implemented.
- **PCI compliance review** — required before going live with real card processing.
- **Tax calculation per ship-to state** — currently uses a global default tax %.
- **Inventory hold on checkout start** — currently stock decrements only at place-order. A race condition between checkout-start and place-order could oversell.
- **Abandoned cart recovery** — no email or save-for-later if customer leaves mid-checkout.
