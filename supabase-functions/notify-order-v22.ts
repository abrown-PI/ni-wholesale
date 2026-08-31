// NI Wholesale — Notify Order Edge Function (v22, weekly-digest mode + skip Customer CSV when netsuite_entity_id set + action=digest)
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.51.0';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const RESEND_API_KEY = Deno.env.get('RESEND_API_KEY') || '';
const RESEND_FROM_EMAIL = Deno.env.get('RESEND_FROM_EMAIL') || 'no-reply@mail.nutritionalinnovations.net';
const RESEND_FROM_NAME = Deno.env.get('RESEND_FROM_NAME') || 'Nutritional Innovations Wholesale';
const ORDERS_EMAIL = Deno.env.get('ORDERS_EMAIL') || 'orders@nutritionalinnovations.net';
const ACCOUNTING_EMAIL = Deno.env.get('ACCOUNTING_EMAIL') || 'abrown@pharmacyinnovations.net';
const NETSUITE_NOTIFY_EMAILS = Deno.env.get('NETSUITE_NOTIFY_EMAILS') || 'abrown@pharmacyinnovations.net';
const SITE_URL = Deno.env.get('SITE_URL') || 'https://nutritionalinnovations.net';
const LOGO_URL = Deno.env.get('EMAIL_LOGO_URL') || `${SITE_URL}/ni-logo.png`;

const BRAND_BLUE = '#2d3f82';
const BRAND_CREAM = '#f5f2ea';
const BRAND_GOLD = '#c9a961';

const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' };
const jsonHeaders = { ...corsHeaders, 'Content-Type': 'application/json' };
function esc(s: unknown): string { return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
function fmtMoney(n: unknown): string { const num = Number(n); return isFinite(num) ? num.toFixed(2) : '0.00'; }
function fmtDateUS(iso: string | null): string { const d = iso ? new Date(iso) : new Date(); return `${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}/${d.getFullYear()}`; }
function addDays(iso: string | null, days: number): string { const d = iso ? new Date(iso) : new Date(); d.setDate(d.getDate() + days); return `${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}/${d.getFullYear()}`; }
function termsToDays(t: string | null): number { const m = /^net\s*-?\s*(\d+)$/i.exec(t || ''); return m ? Number(m[1]) : 30; }
function csvEscape(v: unknown): string { if (v === null || v === undefined) return ''; const s = String(v); if (/[,"\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`; return s; }
function b64Utf8(s: string): string { const bytes = new TextEncoder().encode(s); let bin = ''; for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]); return btoa(bin); }
function bytesToB64(bytes: Uint8Array): string { let bin = ''; for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]); return btoa(bin); }
let LOGO_DATA_URI: string | null = null;
async function preloadLogoDataUri(): Promise<void> { if (LOGO_DATA_URI !== null) return; try { const res = await fetch(LOGO_URL); if (!res.ok) { LOGO_DATA_URI = ''; return; } const buf = await res.arrayBuffer(); LOGO_DATA_URI = `data:image/png;base64,${bytesToB64(new Uint8Array(buf))}`; } catch { LOGO_DATA_URI = ''; } }
function logoHeader(): string { const src = LOGO_DATA_URI || LOGO_URL; return `<div style="text-align:center;padding:16px 0 20px;border-bottom:1px solid #eee;margin-bottom:20px"><a href="${SITE_URL}" style="text-decoration:none;color:${BRAND_BLUE};font-family:Georgia,serif;font-size:20px;font-weight:700"><img src="${src}" alt="Nutritional Innovations" width="220" style="display:block;border:0;max-width:220px;height:auto;margin:0 auto"></a></div>`; }
async function resendSend(payload: Record<string, unknown>): Promise<{ ok: boolean; id?: string; error?: string }> { if (!RESEND_API_KEY) return { ok: false, error: 'RESEND_API_KEY not set' }; try { const res = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }); const data = await res.json().catch(() => ({})); if (!res.ok) return { ok: false, error: (data as { message?: string }).message || `HTTP ${res.status}` }; return { ok: true, id: (data as { id?: string }).id }; } catch (e) { return { ok: false, error: e instanceof Error ? e.message : String(e) }; } }

function manageOrderCta(orderNum: string, orderId: string): string {
  const url = `${SITE_URL}/admin?order=${encodeURIComponent(orderId)}`;
  return `<div style="background:#fef9e7;border:1px solid ${BRAND_GOLD};padding:20px;margin:16px 0;text-align:center"><a href="${url}" style="display:inline-block;background:${BRAND_BLUE};color:#fff;padding:14px 32px;text-decoration:none;font-size:12px;font-weight:700;letter-spacing:1px;text-transform:uppercase">Manage Order #${esc(orderNum)}</a><p style="font-size:12px;color:#555;margin:12px 0 0;line-height:1.5">&#128230; <strong style="color:${BRAND_BLUE}">When you ship this order, please enter tracking info</strong> on the order page above so the customer gets a shipping notification with tracking.</p></div>`;
}

function packingSlipDoc(orderNum: string, o: Record<string, unknown>, cust: Record<string, unknown>, loc: Record<string, unknown> | null, items: Record<string, unknown>[]): string { const bill = { name: o.bill_to_name || o.ship_to_name || cust.company_name || '', address: o.bill_to_address || o.ship_to_address || '', city: o.bill_to_city || o.ship_to_city || '', state: o.bill_to_state || o.ship_to_state || '', zip: o.bill_to_zip || o.ship_to_zip || '' }; const ship = { name: o.ship_to_name || cust.company_name || '', address: o.ship_to_address || '', city: o.ship_to_city || '', state: o.ship_to_state || '', zip: o.ship_to_zip || '', phone: o.ship_to_phone || '' }; const logoSrc = LOGO_DATA_URI || LOGO_URL; const rows = items.map((it) => `<tr><td class="qty">${Number(it.qty || 0)}</td><td class="sku">${esc(it.sku || '')}</td><td class="name">${esc(it.product_name || it.sku || '')}</td><td class="check">&#9744;</td></tr>`).join(''); const totalUnits = items.reduce((s, it) => s + Number(it.qty || 0), 0); return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Packing Slip &mdash; Order #${esc(orderNum)}</title><style>@page{size:letter;margin:0.5in;}*{box-sizing:border-box;}body{font-family:Georgia,'Times New Roman',serif;color:#2b2b2b;margin:0;padding:32px;background:#fff;}.brandbar{background:${BRAND_BLUE};color:#fff;padding:20px 24px;border-radius:4px 4px 0 0;display:flex;justify-content:space-between;align-items:center;}.brandbar img{height:44px;filter:brightness(0) invert(1);}.brandbar .doctitle{font-family:Georgia,serif;font-size:22px;letter-spacing:2px;}.subbar{background:${BRAND_CREAM};padding:14px 24px;border-left:4px solid ${BRAND_GOLD};display:flex;justify-content:space-between;font-size:12px;}.subbar strong{color:${BRAND_BLUE};font-family:Arial,sans-serif;text-transform:uppercase;letter-spacing:1px;font-size:11px;display:block;margin-bottom:2px;}.addresses{display:flex;gap:24px;padding:24px;font-size:13px;line-height:1.5;}.addresses .col{flex:1;padding:16px;background:${BRAND_CREAM};border-top:3px solid ${BRAND_BLUE};}.addresses h3{margin:0 0 8px;font-family:Arial,sans-serif;font-size:11px;color:${BRAND_BLUE};text-transform:uppercase;letter-spacing:2px;}table.items{width:100%;border-collapse:collapse;margin:0 0 24px;font-family:Arial,sans-serif;font-size:13px;}table.items thead th{background:${BRAND_BLUE};color:#fff;text-align:left;padding:10px 12px;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:1px;}table.items tbody td{padding:10px 12px;border-bottom:1px solid #e5e0d5;vertical-align:middle;}table.items tbody tr:nth-child(even) td{background:#faf8f4;}table.items td.qty{text-align:center;font-weight:700;font-size:16px;color:${BRAND_BLUE};width:60px;}table.items td.sku{font-family:'Courier New',monospace;font-size:12px;color:#666;width:130px;}table.items td.check{text-align:center;color:#ccc;font-size:20px;width:70px;}table.items th.qty,table.items th.check{text-align:center;}.totalbar{background:${BRAND_BLUE};color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;font-family:Arial,sans-serif;font-size:13px;text-transform:uppercase;letter-spacing:1px;}.totalbar .n{background:${BRAND_GOLD};color:#fff;padding:4px 12px;border-radius:3px;font-size:16px;font-weight:700;}.note{margin:20px 0;padding:14px 18px;background:#fef9e7;border-left:4px solid ${BRAND_GOLD};font-size:13px;}.note strong{color:${BRAND_BLUE};}.footer{margin-top:32px;padding-top:16px;border-top:1px solid #eee;font-family:Arial,sans-serif;font-size:11px;color:#999;display:flex;justify-content:space-between;}.signoff{margin-top:24px;padding-top:16px;font-family:Arial,sans-serif;font-size:12px;color:#666;display:flex;gap:40px;}.signoff .line{flex:1;}.signoff .line span{display:block;border-bottom:1px solid #999;height:24px;}@media print{body{padding:0;}}</style></head><body><div class="brandbar"><img src="${esc(logoSrc)}" alt="Nutritional Innovations"><div class="doctitle">PACKING SLIP</div></div><div class="subbar"><div><strong>Order #</strong>${esc(orderNum)}</div>${o.po_number ? `<div><strong>Customer PO #</strong>${esc(o.po_number)}</div>` : ''}<div><strong>Date</strong>${esc(fmtDateUS(String(o.placed_at || o.shipped_at || '')))}</div>${o.tracking_number ? `<div><strong>Tracking</strong>${esc(o.tracking_number)}</div>` : ''}<div><strong>Location</strong>${esc((loc?.location_name as string) || '')}</div></div><div class="addresses"><div class="col"><h3>Ship To</h3>${esc(ship.name)}<br>${esc(ship.address)}<br>${esc([ship.city, ship.state].filter(Boolean).join(', '))} ${esc(ship.zip)}${ship.phone ? `<br>${esc(ship.phone)}` : ''}</div><div class="col"><h3>Bill To</h3>${esc(bill.name)}<br>${esc(bill.address)}<br>${esc([bill.city, bill.state].filter(Boolean).join(', '))} ${esc(bill.zip)}</div></div><table class="items"><thead><tr><th class="qty">Qty</th><th style="width:130px">SKU</th><th>Item</th><th class="check">Pack&nbsp;&#9744;</th></tr></thead><tbody>${rows}</tbody></table><div class="totalbar"><div>Total Units</div><div class="n">${totalUnits}</div></div>${o.notes ? `<div class="note"><strong>Customer note:</strong><br>${esc(o.notes)}</div>` : ''}<div class="signoff"><div class="line"><span></span>Packed by</div><div class="line"><span></span>Date</div><div class="line"><span></span>Verified by</div></div><div class="footer"><div>Nutritional Innovations &middot; ${esc(SITE_URL.replace('https://', ''))}</div><div>Print &amp; include with shipment</div></div></body></html>`; }
function packingSlipAttachment(orderNum: string, o: Record<string, unknown>, cust: Record<string, unknown>, loc: Record<string, unknown> | null, items: Record<string, unknown>[]): Record<string, unknown> { const html = packingSlipDoc(orderNum, o, cust, loc, items); return { filename: `packing-slip-${orderNum}.html`, content: b64Utf8(html), content_type: 'text/html' }; }

type LineType = 'item' | 'shipping' | 'tax' | 'discount';
interface CsvMapping { external_id_prefix?: string; external_id_pad_digits?: number; line_labels?: { shipping?: string; tax?: string; discount?: string }; line_skus?: { shipping?: string; tax?: string; discount?: string }; columns: { name: string; source: string; value?: string }[]; }
const DEFAULT_INVOICE_MAPPING: CsvMapping = { external_id_prefix: 'NI-', external_id_pad_digits: 5, line_labels: { shipping: 'Shipping & handling', tax: 'Sales tax', discount: 'Discount' }, line_skus: { shipping: '4002- Shipping', tax: 'TAX', discount: 'DISCOUNT' }, columns: [] };

function resolve(sourceKey: string, ctx: Record<string, unknown>): string {
  if (!sourceKey || sourceKey === 'static') return '';
  const order: Record<string, unknown> = (ctx.order as Record<string, unknown>) || {};
  const customer: Record<string, unknown> = (ctx.customer as Record<string, unknown>) || {};
  const location: Record<string, unknown> = (ctx.location as Record<string, unknown>) || {};
  const item: Record<string, unknown> | null = (ctx.item as Record<string, unknown> | null) || null;
  const settings: Record<string, unknown> = (ctx.settings as Record<string, unknown>) || {};
  const lineType = ctx.lineType as LineType;
  const mapping = ctx.mapping as CsvMapping;
  const firstItemExpenseAccount = String(ctx.firstItemExpenseAccount || '');
  const addressRowType = ctx.addressRowType as ('billing' | 'shipping' | undefined);
  const defaultBilling = ctx.defaultBilling as (boolean | undefined);
  const isDefault = defaultBilling !== undefined ? defaultBilling : addressRowType === 'billing';
  switch (sourceKey) {
    case 'order.order_number': return String(order.order_number || '');
    case 'order.invoice_number': return String(order.invoice_number || (String(order.order_number || '').padStart(5, '0') ? ('NI-' + String(order.order_number || '').padStart(5, '0')) : ''));
    case 'order.po_number': return String(order.po_number || '');
    case 'order.placed_at': return String(order.placed_at || '');
    case 'order.shipped_at': return String(order.shipped_at || '');
    case 'order.tracking_number': return String(order.tracking_number || '');
    case 'order.carrier': return String(order.carrier || '');
    case 'order.subtotal': return fmtMoney(order.subtotal);
    case 'order.tax': return fmtMoney(order.tax);
    case 'order.shipping': return fmtMoney(order.shipping);
    case 'order.total': return fmtMoney(order.total);
    case 'order.discount_amount': return fmtMoney(order.discount_amount);
    case 'order.notes': return String(order.notes || '');
    case 'order.payment_method': return String(order.payment_method || '');
    case 'customer.company_name': return String(customer.company_name || '');
    case 'customer.contact_name': return String(customer.contact_name || '');
    case 'customer.email': return String(customer.email || '');
    case 'customer.phone': return String(customer.phone || '');
    case 'customer.billing_address': return String(customer.billing_address || '');
    case 'customer.billing_city': return String(customer.billing_city || '');
    case 'customer.billing_state': return String(customer.billing_state || '');
    case 'customer.billing_zip': return String(customer.billing_zip || '');
    case 'customer.billing_full_address': {
      const line1 = String(customer.billing_address || '');
      const cs = [customer.billing_city, customer.billing_state].filter(Boolean).join(', ');
      const tail = [cs, String(customer.billing_zip || '')].filter(Boolean).join(' ');
      return [line1, tail].filter(Boolean).join(', ');
    }
    case 'customer.payment_terms': return String(customer.payment_terms || '');
    case 'customer.tax_id': return String(customer.tax_id || '');
    case 'customer.netsuite_entity_id': return String(customer.netsuite_entity_id || '');
    case 'customer.resale_cert_number': return String(customer.resale_cert_number || '');
    case 'customer.pharmacy_type': return String(customer.pharmacy_type || '');
    case 'location.location_name': return String(location.location_name || '');
    case 'location.address': return String(location.address || '');
    case 'location.city': return String(location.city || '');
    case 'location.state': return String(location.state || '');
    case 'location.zip': return String(location.zip || '');
    case 'location.full_address': {
      const line1 = String(location.address || '');
      const cs = [location.city, location.state].filter(Boolean).join(', ');
      const tail = [cs, String(location.zip || '')].filter(Boolean).join(' ');
      return [line1, tail].filter(Boolean).join(', ');
    }
    case 'location.contact_name': return String(location.contact_name || '');
    case 'location.phone': return String(location.phone || '');
    case 'location.billing_entity_name': return String(location.billing_entity_name || '');
    case 'location.netsuite_entity_id': return String(location.netsuite_entity_id || '');
    case 'location.netsuite_location_id': return String(location.netsuite_location_id || '');
    case 'location.netsuite_subsidiary_id': return String(location.netsuite_subsidiary_id || '');
    case 'location.billing_entity_name_or_customer': return String(location.billing_entity_name || customer.company_name || '');
    case 'location.netsuite_entity_id_or_customer': return String(location.netsuite_entity_id || customer.netsuite_entity_id || '');
    case 'location.license_number': return String(location.license_number || '');
    case 'location.dea_number': return String(location.dea_number || '');
    case 'location.npi_number': return String(location.npi_number || '');
    case 'location.address_or_billing': return String(location.address || customer.billing_address || '');
    case 'location.city_or_billing': return String(location.city || customer.billing_city || '');
    case 'location.state_or_billing': return String(location.state || customer.billing_state || '');
    case 'location.zip_or_billing': return String(location.zip || customer.billing_zip || '');
    case 'address.full_current': {
      if (addressRowType === 'billing') {
        const line1 = String(customer.billing_address || '');
        const cs = [customer.billing_city, customer.billing_state].filter(Boolean).join(', ');
        const tail = [cs, String(customer.billing_zip || '')].filter(Boolean).join(' ');
        return [line1, tail].filter(Boolean).join(', ');
      }
      const line1 = String(location.address || '');
      const cs = [location.city, location.state].filter(Boolean).join(', ');
      const tail = [cs, String(location.zip || '')].filter(Boolean).join(' ');
      return [line1, tail].filter(Boolean).join(', ');
    }
    case 'address.line1_current': return addressRowType === 'billing' ? String(customer.billing_address || '') : String(location.address || '');
    case 'address.city_current': return addressRowType === 'billing' ? String(customer.billing_city || '') : String(location.city || '');
    case 'address.state_current': return addressRowType === 'billing' ? String(customer.billing_state || '') : String(location.state || '');
    case 'address.zip_current': return addressRowType === 'billing' ? String(customer.billing_zip || '') : String(location.zip || '');
    case 'address.location_name_current': return isDefault ? 'Billing' : (String(location.location_name || '') || 'Ship-To');
    case 'settings.ni_vendor_id_in_pi': return String(settings.ni_vendor_id_in_pi || '');
    case 'settings.default_expense_account_id': return String(settings.default_expense_account_id || '');
    case 'settings.company_name': return String(settings.company_name || 'Nutritional Innovations');
    case 'settings.accounting_email': return String(settings.accounting_notify_email || '');
    case 'computed.external_id': return String(ctx.externalId || '');
    case 'computed.external_customer_id': return String(ctx.externalCustomerId || ctx.externalId || '');
    case 'computed.default_billing_yes_no': return isDefault ? 'Yes' : 'No';
    case 'computed.default_billing_bool': return isDefault ? 'T' : 'F';
    case 'computed.invoice_date': return String(ctx.invoiceDate || '');
    case 'computed.due_date': return String(ctx.dueDate || '');
    case 'computed.memo': return String(ctx.memo || '');
    case 'computed.billing_attention': return String(customer.contact_name || customer.company_name || '');
    case 'computed.shipping_attention': return String(location.contact_name || customer.contact_name || customer.company_name || '');
    case 'item.sku': return item ? String(item.sku || '') : '';
    case 'item.sku_or_label': { if (lineType === 'item') return item ? String(item.sku || '') : ''; const skus = mapping.line_skus || {}; if (lineType === 'shipping') return skus.shipping || 'SHIPPING'; if (lineType === 'tax') return skus.tax || 'TAX'; if (lineType === 'discount') return skus.discount || 'DISCOUNT'; return ''; }
    case 'item.sku_item_only':        return lineType === 'item' ? (item ? String(item.sku || '') : '') : '';
    case 'item.qty_item_only':        return lineType === 'item' ? String(item ? (item.qty || 0) : 0) : '';
    case 'item.unit_price_item_only': return lineType === 'item' ? fmtMoney(item ? item.unit_price : 0) : '';
    case 'item.line_total_item_only': return lineType === 'item' ? fmtMoney(item ? item.line_total : 0) : '';
    case 'item.expense_account_for_bill': return lineType === 'item' ? '' : firstItemExpenseAccount;
    case 'item.expense_amount_for_bill':
      if (lineType === 'item') return '';
      if (lineType === 'shipping') return fmtMoney(order.shipping);
      if (lineType === 'tax') return fmtMoney(order.tax);
      if (lineType === 'discount') return fmtMoney(-Number(order.discount_amount || 0));
      return '';
    case 'item.product_name': return item ? String(item.product_name || item.sku || '') : '';
    case 'item.name_or_label':
      if (lineType === 'item') return item ? String(item.product_name || item.sku || '') : '';
      if (lineType === 'shipping') return String(mapping.line_labels?.shipping || 'Shipping & Handling');
      if (lineType === 'tax') return String(mapping.line_labels?.tax || 'Sales tax');
      if (lineType === 'discount') return String(mapping.line_labels?.discount || 'Discount');
      return '';
    case 'item.qty': return lineType === 'item' ? String(item ? (item.qty || 0) : 0) : '1';
    case 'item.unit_price': return lineType === 'item' ? fmtMoney(item ? item.unit_price : 0) : '0.00';
    case 'item.line_total': return lineType === 'item' ? fmtMoney(item ? item.line_total : 0) : '0.00';
    case 'item.rate':
      if (lineType === 'item') return fmtMoney(item ? item.unit_price : 0);
      if (lineType === 'shipping') return fmtMoney(order.shipping);
      if (lineType === 'tax') return fmtMoney(order.tax);
      if (lineType === 'discount') return fmtMoney(-Number(order.discount_amount || 0));
      return '';
    case 'item.amount':
      if (lineType === 'item') return fmtMoney(item ? item.line_total : 0);
      if (lineType === 'shipping') return fmtMoney(order.shipping);
      if (lineType === 'tax') return fmtMoney(order.tax);
      if (lineType === 'discount') return fmtMoney(-Number(order.discount_amount || 0));
      return '';
    default: return '';
  }
}
async function loadMapping(supa: ReturnType<typeof createClient>, key: string, fallback: CsvMapping): Promise<CsvMapping> { try { const r = await supa.from('settings').select('value').eq('key', key).single(); if (r.data && r.data.value) return r.data.value as CsvMapping; } catch { /* fall through */ } return fallback; }
async function loadSiteSettings(supa: ReturnType<typeof createClient>): Promise<Record<string, string>> { const out: Record<string, string> = {}; try { const r = await supa.from('settings').select('key,value').in('key', ['accounting_notify_email','ni_vendor_id_in_pi','default_expense_account_id','company_name','notify_accounting_mode']); (r.data || []).forEach((row: { key: string; value: unknown }) => { out[row.key] = typeof row.value === 'string' ? row.value : String(row.value ?? ''); }); } catch { /* fall through */ } return out; }
interface DeliveryConfig { invoice?: { recipient?: string; importUrl?: string }; bill?: { recipient?: string; importUrl?: string }; customer?: { recipient?: string; importUrl?: string }; item?: { recipient?: string; importUrl?: string }; }
async function loadDelivery(supa: ReturnType<typeof createClient>): Promise<DeliveryConfig> { try { const r = await supa.from('settings').select('value').eq('key', 'netsuite_delivery').single(); if (r.data && r.data.value) return r.data.value as DeliveryConfig; } catch { /* silent */ } return {}; }
async function firstItemExpenseAccount(supa: ReturnType<typeof createClient>, items: Record<string, unknown>[]): Promise<string> { const first = items && items[0]; if (!first) return ''; const q = first.sku ? await supa.from('products').select('expense_account, product_class').eq('sku', first.sku).maybeSingle() : { data: null }; const prod = q.data as { expense_account?: string; product_class?: string } | null; if (prod && prod.expense_account) return prod.expense_account; const cls = prod?.product_class; if (!cls) return ''; const c = await supa.from('product_classes').select('expense_account').eq('slug', cls).maybeSingle(); return (c.data as { expense_account?: string } | null)?.expense_account || ''; }
async function generateCsv(supa: ReturnType<typeof createClient>, key: 'invoice' | 'bill', order: Record<string, unknown>, customer: Record<string, unknown>, location: Record<string, unknown> | null, items: Record<string, unknown>[], settings: Record<string, string>): Promise<{ csv: string; filename: string }> { const settingsKey = key === 'invoice' ? 'netsuite_csv_mapping' : 'netsuite_bill_csv_mapping'; const fallback = key === 'invoice' ? DEFAULT_INVOICE_MAPPING : { columns: [] }; const mapping = await loadMapping(supa, settingsKey, fallback); const cols = mapping.columns || []; if (!cols.length) throw new Error(`${key} CSV mapping has no columns configured`); /* External ID: bill prefers its OWN prefix+pad if the admin set them (e.g., NIBILL so PI's NetSuite can tell NI vendor bills apart from Reviv's). If bill's fields are blank, fall back to the invoice mapping so today's intercompany-pair convention still holds. */ const invoiceMapping = key === 'invoice' ? mapping : await loadMapping(supa, 'netsuite_csv_mapping', DEFAULT_INVOICE_MAPPING); const pad = Number(mapping.external_id_pad_digits || invoiceMapping.external_id_pad_digits) || 5; const prefix = mapping.external_id_prefix || invoiceMapping.external_id_prefix || 'NI-'; const orderNumPadded = String(order.order_number || '').padStart(pad, '0'); const externalId = prefix + orderNumPadded; const externalCustomerId = 'NI-CUST-' + String(customer.id || '').slice(0, 8); const invoiceDate = fmtDateUS(String(order.shipped_at || order.placed_at || '')); const terms = String(customer.payment_terms || 'Net 30'); const dueDate = addDays(String(order.shipped_at || order.placed_at || ''), termsToDays(terms)); const memoBits = [`NI Wholesale order #${orderNumPadded}`]; if (order.po_number) memoBits.push(`PO#: ${order.po_number}`); if (order.tracking_number) memoBits.push(`${order.carrier || 'Tracking'}: ${order.tracking_number}`); const memo = memoBits.join(' | '); const firstItemExpAcct = key === 'bill' ? await firstItemExpenseAccount(supa, items) : ''; function renderRow(item: Record<string, unknown> | null, lineType: LineType): string[] { const ctx = { order, customer, location: location || {}, item, lineType, mapping, settings, externalId, externalCustomerId, invoiceDate, dueDate, memo, firstItemExpenseAccount: firstItemExpAcct }; return cols.map((c) => c.source === 'static' ? String(c.value || '') : resolve(c.source, ctx)); } const rows: string[][] = []; for (const it of items) rows.push(renderRow(it, 'item')); if (order.shipping && Number(order.shipping) > 0) rows.push(renderRow(null, 'shipping')); if (order.tax && Number(order.tax) > 0) rows.push(renderRow(null, 'tax')); if (key === 'invoice' && order.discount_amount && Number(order.discount_amount) > 0) rows.push(renderRow(null, 'discount')); let csv = cols.map((c) => csvEscape(c.name)).join(',') + '\r\n'; for (const r of rows) csv += r.map(csvEscape).join(',') + '\r\n'; const filename = key === 'invoice' ? `ni-invoice-${orderNumPadded}.csv` : `ni-bill-${orderNumPadded}.csv`; return { csv, filename }; }

// Multi-row Customer CSV: billing row (customer.billing_*) + one row per active
// customer_location whose address doesn't match billing. If customer has no
// billing address, first location is promoted to be the billing row.
async function generateCustomerCsv(supa: ReturnType<typeof createClient>, customer: Record<string, unknown>, locations: Record<string, unknown>[], settings: Record<string, string>): Promise<{ csv: string; filename: string }> {
  const mapping = await loadMapping(supa, 'netsuite_customer_csv_mapping', { columns: [] });
  const cols = mapping.columns || [];
  if (!cols.length) throw new Error('Customer CSV mapping not configured');
  const pad = Number(mapping.external_id_pad_digits) || 5;
  const prefix = mapping.external_id_prefix || 'NI-CUST-';
  const externalCustomerId = prefix + String(customer.id || '').slice(0, pad).padStart(pad, '0');
  function normAddr(a: unknown, c: unknown, s: unknown, z: unknown): string {
    return `${a ?? ''}|${c ?? ''}|${s ?? ''}|${z ?? ''}`.toLowerCase().replace(/[^a-z0-9|]+/g, '');
  }
  const hasBilling = !!(customer.billing_address || customer.billing_city || customer.billing_state || customer.billing_zip);
  const billingKey = hasBilling ? normAddr(customer.billing_address, customer.billing_city, customer.billing_state, customer.billing_zip) : '';
  function ctxFor(location: Record<string, unknown> | null, defaultBilling: boolean): Record<string, unknown> {
    return { customer, location: location || {}, mapping, settings, addressRowType: location ? 'shipping' : 'billing', defaultBilling, externalId: externalCustomerId, externalCustomerId };
  }
  function renderRow(ctx: Record<string, unknown>): string[] {
    return cols.map((c) => c.source === 'static' ? String(c.value || '') : resolve(c.source, ctx));
  }
  const rows: string[][] = [];
  if (hasBilling) {
    rows.push(renderRow(ctxFor(null, true)));
    for (const loc of (locations || [])) {
      if (normAddr(loc.address, loc.city, loc.state, loc.zip) !== billingKey) rows.push(renderRow(ctxFor(loc, false)));
    }
  } else if ((locations || []).length > 0) {
    const first = locations[0];
    rows.push(renderRow(ctxFor(first, true)));
    const firstKey = normAddr(first.address, first.city, first.state, first.zip);
    for (const loc of locations.slice(1)) {
      if (normAddr(loc.address, loc.city, loc.state, loc.zip) !== firstKey) rows.push(renderRow(ctxFor(loc, false)));
    }
  } else {
    rows.push(renderRow(ctxFor(null, true)));
  }
  const header = cols.map((c) => csvEscape(c.name)).join(',');
  const body = rows.map((r) => r.map(csvEscape).join(',')).join('\r\n');
  const csv = `${header}\r\n${body}\r\n`;
  const nameSlug = String(customer.company_name || 'customer').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'customer';
  return { csv, filename: `ni-customer-${nameSlug}.csv` };
}

function fromField(): string { return `${RESEND_FROM_NAME} <${RESEND_FROM_EMAIL}>`; }
function padOrderNumber(n: unknown, pad = 5): string { return String(n ?? '').padStart(pad, '0'); }
function lineItemsTable(items: Record<string, unknown>[]): string { const rows = items.map((it) => `<tr><td style="padding:6px 8px;border-bottom:1px solid #eee">${esc(it.product_name || it.sku || '')}</td><td style="padding:6px 8px;border-bottom:1px solid #eee;text-align:center">${Number(it.qty || 0)}</td><td style="padding:6px 8px;border-bottom:1px solid #eee;text-align:right">$${fmtMoney(it.unit_price)}</td><td style="padding:6px 8px;border-bottom:1px solid #eee;text-align:right">$${fmtMoney(it.line_total)}</td></tr>`).join(''); return `<table style="width:100%;border-collapse:collapse;font-size:13px;margin:12px 0"><thead><tr style="background:${BRAND_CREAM}"><th style="padding:6px 8px;text-align:left">Item</th><th style="padding:6px 8px;text-align:center">Qty</th><th style="padding:6px 8px;text-align:right">Unit</th><th style="padding:6px 8px;text-align:right">Line Total</th></tr></thead><tbody>${rows}</tbody></table>`; }
function totalsBlock(o: Record<string, unknown>): string { const rows: string[] = []; rows.push(`<tr><td style="padding:2px 0">Subtotal</td><td style="padding:2px 0;text-align:right">$${fmtMoney(o.subtotal)}</td></tr>`); if (o.discount_amount && Number(o.discount_amount) > 0) rows.push(`<tr><td style="padding:2px 0">Discount${o.coupon_code ? ` (${esc(o.coupon_code)})` : ''}</td><td style="padding:2px 0;text-align:right">-$${fmtMoney(o.discount_amount)}</td></tr>`); if (o.shipping && Number(o.shipping) > 0) rows.push(`<tr><td style="padding:2px 0">Shipping</td><td style="padding:2px 0;text-align:right">$${fmtMoney(o.shipping)}</td></tr>`); if (o.tax && Number(o.tax) > 0) rows.push(`<tr><td style="padding:2px 0">Tax</td><td style="padding:2px 0;text-align:right">$${fmtMoney(o.tax)}</td></tr>`); rows.push(`<tr><td style="padding:6px 0 0;font-weight:700;border-top:1px solid #ddd">Total</td><td style="padding:6px 0 0;text-align:right;font-weight:700;border-top:1px solid #ddd">$${fmtMoney(o.total)}</td></tr>`); return `<table style="width:220px;margin:12px 0 0 auto;font-size:13px"><tbody>${rows.join('')}</tbody></table>`; }
function importLinkBlock(url: string, label: string): string { if (!url) return ''; return `<p style="font-size:13px;margin:12px 0">&#128279; <a href="${esc(url)}" target="_blank" rel="noopener" style="color:${BRAND_BLUE}"><strong>${esc(label)}</strong></a></p>`; }
function packingSlipCallout(): string { return `<p style="font-size:13px;margin:16px 0;padding:12px 14px;background:${BRAND_CREAM};border-left:3px solid ${BRAND_BLUE}">&#128196; A branded <strong>packing slip</strong> is attached as an HTML file &mdash; open it in your browser and print for the shipment.</p>`; }
function stepHeader(n: string, title: string, color: string): string { return `<div style="display:flex;align-items:center;gap:12px;margin:24px 0 12px"><div style="background:${color};color:#fff;font-family:Arial,sans-serif;font-weight:700;width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0">${esc(n)}</div><h2 style="font-family:Georgia,serif;font-size:18px;margin:0;color:${color}">${esc(title)}</h2></div>`; }
function intercompanyWarning(companyName: string): string { return `<div style="background:#fff3cd;border:2px solid ${BRAND_GOLD};border-radius:6px;padding:16px 20px;margin:16px 0;font-family:Arial,sans-serif"><div style="display:flex;align-items:flex-start;gap:12px"><div style="font-size:24px;line-height:1">&#9888;&#65039;</div><div style="flex:1"><div style="font-weight:700;font-size:14px;color:#8a6d3b;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Intercompany — Two entries required</div><div style="font-size:13px;line-height:1.5;color:#5a4820"><strong>After</strong> the NI Customer Invoice is created in NetSuite, please also create the matching <strong>Vendor Bill</strong> inside <strong>${esc(companyName)}</strong>'s subsidiary so both sides of the intercompany transaction post. Both CSVs are attached below.</div></div></div></div>`; }
function newCustomerBanner(companyName: string, customerCsvFilename: string, isIntercompany: boolean): string { return `<div style="background:#EBF5EE;border:2px solid #16A34A;padding:16px 20px;margin:16px 0;font-family:Arial,sans-serif"><div style="display:flex;gap:12px;align-items:flex-start"><div style="font-size:22px;line-height:1">&#127381;</div><div style="flex:1"><p style="margin:0 0 6px;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#166534;font-weight:600">New Customer &mdash; Import Customer CSV First</p><p style="margin:0 0 10px;font-size:13px;line-height:1.6;color:#14532D">This is <strong>${esc(companyName)}</strong>'s first order flowing to accounting. The <strong>${esc(customerCsvFilename)}</strong> attachment must be imported into NetSuite <strong>before</strong> the invoice/bill CSVs so the customer record exists and the External ID resolves. Import order: <strong>Customer → Invoice${isIntercompany ? ' → Vendor Bill' : ''}</strong>.</p></div></div></div><div style="background:#FEF3C7;border-left:4px solid #D97706;padding:14px 18px;margin:0 0 16px;font-family:Arial,sans-serif"><p style="margin:0 0 6px;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#92400E;font-weight:700">&#8617;&#65039; Reply Required — NetSuite Customer Internal ID</p><p style="margin:0;font-size:13px;line-height:1.6;color:#78350F">Once you've created <strong>${esc(companyName)}</strong> in NetSuite, please <strong>reply to this email with the NetSuite Customer Internal ID</strong> (e.g., 5432). The team will paste it into NI on the customer's profile so future orders reference the correct NetSuite record automatically and CSV imports stop needing a fresh Customer CSV.</p></div>`; }

serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers: jsonHeaders });
  try {
    const body = await req.json().catch(() => null);
    const action = body?.action as ('placed' | 'shipped' | 'customer-csv' | 'digest') | undefined;
    const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    await preloadLogoDataUri();

    // ── Ad-hoc Customer CSV send-to-accounting ────────────────────────────
    // action='customer-csv' with customerId builds the multi-row Customer
    // CSV and emails it to the accounting notify recipients. Used by the
    // Send to Accounting button on the customer detail page.
    if (action === 'customer-csv') {
      const customerId = body?.customerId as string | undefined;
      if (!customerId) return new Response(JSON.stringify({ error: 'customerId required' }), { status: 400, headers: jsonHeaders });
      const cRes = await supa.from('customers').select('*').eq('id', customerId).single();
      if (cRes.error || !cRes.data) return new Response(JSON.stringify({ error: 'Customer not found' }), { status: 404, headers: jsonHeaders });
      const lRes = await supa.from('customer_locations').select('*').eq('customer_id', customerId).eq('status', 'active').order('created_at', { ascending: true });
      const cust = cRes.data as Record<string, unknown>;
      const locs = (lRes.data || []) as Record<string, unknown>[];
      const settings = await loadSiteSettings(supa);
      let built: { csv: string; filename: string };
      try { built = await generateCustomerCsv(supa, cust, locs, settings); }
      catch (e) { return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), { status: 500, headers: jsonHeaders }); }
      const delivery = await loadDelivery(supa);
      const to = (delivery.customer?.recipient || '').trim() || settings.accounting_notify_email || NETSUITE_NOTIFY_EMAILS.split(',')[0].trim();
      const importUrl = (delivery.customer?.importUrl || '').trim();
      const companyName = String(cust.company_name || '');
      const html = `<div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;padding:24px;color:#2b2b2b">${logoHeader()}<h1 style="font-family:Georgia,serif;font-size:20px;color:${BRAND_BLUE};margin:0 0 8px">Create NetSuite Customer record for ${esc(companyName)}</h1><p style="font-size:13px;line-height:1.6">Please import the attached CSV into NetSuite so the ${esc(companyName)} customer record (with all addresses attached) is created and the External ID resolves for future invoice imports.</p><p style="font-size:13px;line-height:1.6;background:${BRAND_CREAM};padding:10px 14px;border-left:3px solid ${BRAND_BLUE};margin:12px 0">&#128206; Attached: <strong>${esc(built.filename)}</strong> — ready for NetSuite CSV Import (Lists → Relationships → Customers).</p>${importLinkBlock(importUrl, 'Open NetSuite Customer Import screen')}<div style="background:#FEF3C7;border-left:4px solid #D97706;padding:14px 18px;margin:16px 0"><p style="margin:0 0 6px;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#92400E;font-weight:700">&#8617;&#65039; Reply Required — NetSuite Customer Internal ID</p><p style="margin:0;font-size:13px;line-height:1.6;color:#78350F">Once you've created <strong>${esc(companyName)}</strong> in NetSuite, please <strong>reply to this email with the NetSuite Customer Internal ID</strong> so we can paste it into NI on the customer's profile.</p></div></div>`;
      const to_arr = to.split(',').map((s) => s.trim()).filter(Boolean);
      const sent = await resendSend({ from: fromField(), to: to_arr, subject: `Create NetSuite Customer record for ${companyName}`, html, attachments: [{ filename: built.filename, content: b64Utf8(built.csv) }] });
      if (!sent.ok) return new Response(JSON.stringify({ error: sent.error }), { status: 502, headers: jsonHeaders });
      return new Response(JSON.stringify({ ok: true, filename: built.filename }), { status: 200, headers: jsonHeaders });
    }

    // ── Weekly accounting digest ─────────────────────────────────────────
    // action='digest' sweeps every invoice-paid order flagged
    // netsuite_csv_ready_at (set when the order was marked shipped in
    // weekly-digest mode) that hasn't yet been emailed to accounting.
    // Produces ONE combined Invoice CSV and (if any orders are
    // intercompany) ONE combined Vendor Bill CSV. Attaches a per-customer
    // Customer CSV for each brand-new customer without a NetSuite Internal
    // ID. Stamps every included order's netsuite_csv_sent_at on success.
    // Optional body.orderIds: string[] to force a specific set of orders
    // instead of scanning ready-for-digest (used for admin ad-hoc "send
    // just these" runs).
    if (action === 'digest') {
      const settings = await loadSiteSettings(supa);
      const delivery = await loadDelivery(supa);
      const invoiceRecipient = (delivery.invoice?.recipient || '').trim() || settings.accounting_notify_email || NETSUITE_NOTIFY_EMAILS.split(',')[0].trim();
      const billRecipient    = (delivery.bill?.recipient    || '').trim() || settings.accounting_notify_email || NETSUITE_NOTIFY_EMAILS.split(',')[0].trim();
      const invoiceImportUrl = (delivery.invoice?.importUrl || '').trim();
      const billImportUrl    = (delivery.bill?.importUrl    || '').trim();
      const explicitIds = Array.isArray(body?.orderIds) ? (body.orderIds as string[]) : null;
      let q = supa.from('orders').select('*').eq('payment_method', 'invoice').is('netsuite_csv_sent_at', null).order('order_number', { ascending: true });
      if (explicitIds && explicitIds.length) q = q.in('id', explicitIds);
      else q = q.not('netsuite_csv_ready_at', 'is', null);
      const oRes = await q;
      if (oRes.error) return new Response(JSON.stringify({ error: oRes.error.message }), { status: 500, headers: jsonHeaders });
      const orders = (oRes.data || []) as Record<string, unknown>[];
      if (!orders.length) return new Response(JSON.stringify({ ok: true, message: 'No orders ready for digest', count: 0 }), { status: 200, headers: jsonHeaders });

      // Hydrate items + customer + location for every order in parallel.
      const custIds = Array.from(new Set(orders.map((o) => o.customer_id).filter(Boolean))) as string[];
      const locIds  = Array.from(new Set(orders.map((o) => o.customer_location_id).filter(Boolean))) as string[];
      const orderIds = orders.map((o) => o.id as string);
      const itemsRes = await supa.from('order_items').select('*').in('order_id', orderIds);
      const custsRes = custIds.length ? await supa.from('customers').select('*').in('id', custIds) : { data: [] as Record<string, unknown>[] };
      const locsRes  = locIds.length  ? await supa.from('customer_locations').select('*').in('id', locIds) : { data: [] as Record<string, unknown>[] };
      const itemsByOrder: Record<string, Record<string, unknown>[]> = {};
      ((itemsRes.data as Record<string, unknown>[]) || []).forEach((it) => { const k = String(it.order_id); if (!itemsByOrder[k]) itemsByOrder[k] = []; itemsByOrder[k].push(it); });
      const custById: Record<string, Record<string, unknown>> = {};
      ((custsRes.data as Record<string, unknown>[]) || []).forEach((c) => { custById[String(c.id)] = c; });
      const locById: Record<string, Record<string, unknown>> = {};
      ((locsRes.data as Record<string, unknown>[]) || []).forEach((l) => { locById[String(l.id)] = l; });

      // Per-order CSV row extraction. generateCsv returns "header\r\n row \r\n row \r\n".
      // We keep the first order's header and pull all subsequent rows.
      function extractRows(csv: string): { header: string; rows: string[] } {
        const lines = csv.split(/\r?\n/).filter((l) => l.length > 0);
        return { header: lines[0] || '', rows: lines.slice(1) };
      }

      let invoiceHeader = '';
      const invoiceRows: string[] = [];
      let billHeader = '';
      const billRows: string[] = [];
      const perCustomerFirstOrder: Record<string, { cust: Record<string, unknown>; sample_order_num: string }> = {};
      const perOrderSummary: { orderNum: string; company: string; total: string; isIntercompany: boolean; billError?: string }[] = [];
      const includedOrderIds: string[] = [];
      const buildErrors: string[] = [];
      let grandTotal = 0;

      for (const o of orders) {
        const its = itemsByOrder[String(o.id)] || [];
        const cust = (o.customer_id ? custById[String(o.customer_id)] : {}) || {};
        const loc  = (o.customer_location_id ? locById[String(o.customer_location_id)] : null);
        const isIntercompany = !!cust.is_intercompany;
        const orderNum = padOrderNumber(o.order_number, 5);
        const company = String(cust.company_name || o.customer_name || '(unknown)');
        try {
          const invBuilt = await generateCsv(supa, 'invoice', o, cust, loc, its, settings);
          const parsed = extractRows(invBuilt.csv);
          if (!invoiceHeader) invoiceHeader = parsed.header;
          invoiceRows.push(...parsed.rows);
        } catch (e) { buildErrors.push(`Order #${orderNum} invoice CSV: ${e instanceof Error ? e.message : String(e)}`); continue; }
        let billErr: string | undefined;
        if (isIntercompany) {
          try {
            const billBuilt = await generateCsv(supa, 'bill', o, cust, loc, its, settings);
            const parsed = extractRows(billBuilt.csv);
            if (!billHeader) billHeader = parsed.header;
            billRows.push(...parsed.rows);
          } catch (e) { billErr = e instanceof Error ? e.message : String(e); buildErrors.push(`Order #${orderNum} bill CSV: ${billErr}`); }
        }
        // First-order detection per customer, same rule as shipped flow.
        if (o.customer_id && !cust.netsuite_entity_id && !perCustomerFirstOrder[String(o.customer_id)]) {
          const cnt = await supa.from('orders').select('id', { count: 'exact', head: true }).eq('customer_id', o.customer_id).not('netsuite_csv_sent_at', 'is', null).neq('id', o.id);
          if ((cnt.count ?? 0) === 0) perCustomerFirstOrder[String(o.customer_id)] = { cust, sample_order_num: orderNum };
        }
        includedOrderIds.push(String(o.id));
        perOrderSummary.push({ orderNum, company, total: fmtMoney(o.total), isIntercompany, billError: billErr });
        grandTotal += Number(o.total) || 0;
      }

      if (!invoiceRows.length) return new Response(JSON.stringify({ error: 'Digest built no invoice rows', build_errors: buildErrors }), { status: 500, headers: jsonHeaders });

      const digestDate = fmtDateUS(new Date().toISOString());
      const dateSlug = new Date().toISOString().slice(0, 10);
      const invoiceCombined = `${invoiceHeader}\r\n${invoiceRows.join('\r\n')}\r\n`;
      const billCombined = billRows.length ? `${billHeader}\r\n${billRows.join('\r\n')}\r\n` : '';

      const finalAttachments: Record<string, unknown>[] = [];
      // Per-customer Customer CSVs first so accounting imports them before the invoice CSV.
      const newCustomerCsvSummary: { company: string; filename: string }[] = [];
      for (const cid of Object.keys(perCustomerFirstOrder)) {
        const { cust } = perCustomerFirstOrder[cid];
        try {
          const lRes = await supa.from('customer_locations').select('*').eq('customer_id', cid).eq('status', 'active').order('created_at', { ascending: true });
          const built = await generateCustomerCsv(supa, cust, (lRes.data || []) as Record<string, unknown>[], settings);
          finalAttachments.push({ filename: built.filename, content: b64Utf8(built.csv) });
          newCustomerCsvSummary.push({ company: String(cust.company_name || ''), filename: built.filename });
        } catch (e) { buildErrors.push(`Customer CSV for ${cust.company_name}: ${e instanceof Error ? e.message : String(e)}`); }
      }
      const invoiceFilename = `ni-invoices-digest-${dateSlug}.csv`;
      const billFilename    = `ni-bills-digest-${dateSlug}.csv`;
      finalAttachments.push({ filename: invoiceFilename, content: b64Utf8(invoiceCombined) });
      if (billCombined) finalAttachments.push({ filename: billFilename, content: b64Utf8(billCombined) });

      // Recipient set: invoice + bill (dedupe).
      const toSet = new Set<string>();
      invoiceRecipient.split(',').map((s) => s.trim()).filter(Boolean).forEach((r) => toSet.add(r));
      if (billCombined) billRecipient.split(',').map((s) => s.trim()).filter(Boolean).forEach((r) => toSet.add(r));

      const subject = `NI accounting digest — ${digestDate} — ${perOrderSummary.length} order${perOrderSummary.length === 1 ? '' : 's'}${newCustomerCsvSummary.length ? ` (${newCustomerCsvSummary.length} new)` : ''} — $${fmtMoney(grandTotal)}`;
      const summaryRows = perOrderSummary.map((s) => `<tr><td style="padding:6px 10px;border-bottom:1px solid #eee;font-family:'Courier New',monospace">#${esc(s.orderNum)}</td><td style="padding:6px 10px;border-bottom:1px solid #eee">${esc(s.company)}${s.isIntercompany ? ` <span style="font-size:10px;color:${BRAND_GOLD};font-weight:700;letter-spacing:1px">INTERCO</span>` : ''}</td><td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:right">$${s.total}</td>${s.billError ? `<td style="padding:6px 10px;border-bottom:1px solid #eee;color:#b53f3f;font-size:11px">bill error: ${esc(s.billError)}</td>` : '<td style="padding:6px 10px;border-bottom:1px solid #eee"></td>'}</tr>`).join('');
      const newCustBlock = newCustomerCsvSummary.length ? `<div style="background:#EBF5EE;border:2px solid #16A34A;padding:14px 18px;margin:16px 0;font-family:Arial,sans-serif"><p style="margin:0 0 8px;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#166534;font-weight:600">&#127381; ${newCustomerCsvSummary.length} New Customer${newCustomerCsvSummary.length === 1 ? '' : 's'} in this digest</p><p style="margin:0 0 6px;font-size:13px;line-height:1.5;color:#14532D">Import these Customer CSV files into NetSuite <strong>before</strong> the combined invoice CSV so the External IDs resolve:</p><ul style="margin:6px 0 0 20px;padding:0;font-size:13px;color:#14532D">${newCustomerCsvSummary.map((c) => `<li>${esc(c.company)} &mdash; <code>${esc(c.filename)}</code></li>`).join('')}</ul><p style="margin:8px 0 0;font-size:12px;line-height:1.5;color:#14532D">Please <strong>reply to this email</strong> with each new customer's NetSuite Internal ID so we can stop attaching their Customer CSV going forward.</p></div>` : '';
      const errorsBlock = buildErrors.length ? `<div style="background:#fdecea;border-left:4px solid #b53f3f;padding:12px 16px;margin:16px 0;font-size:13px;color:#7f1d1d"><strong>${buildErrors.length} non-fatal build issue${buildErrors.length === 1 ? '' : 's'}:</strong><ul style="margin:6px 0 0 20px;padding:0">${buildErrors.map((e) => `<li>${esc(e)}</li>`).join('')}</ul></div>` : '';
      const html = `<div style="font-family:Arial,sans-serif;max-width:720px;margin:0 auto;padding:24px;color:#2b2b2b">${logoHeader()}<h1 style="font-family:Georgia,serif;font-size:20px;color:${BRAND_BLUE};margin:0 0 4px">Weekly NI accounting digest &mdash; ${esc(digestDate)}</h1><p style="font-size:13px;color:#555;margin:0 0 16px">${perOrderSummary.length} shipped invoice-paid order${perOrderSummary.length === 1 ? '' : 's'} rolled up into one combined CSV, ready for NetSuite CSV Import.</p>${newCustBlock}${errorsBlock}<h2 style="font-family:Georgia,serif;font-size:16px;color:${BRAND_BLUE};margin:20px 0 6px">Orders in this digest</h2><table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px"><thead><tr style="background:${BRAND_CREAM}"><th style="padding:6px 10px;text-align:left">Order</th><th style="padding:6px 10px;text-align:left">Customer</th><th style="padding:6px 10px;text-align:right">Total</th><th style="padding:6px 10px;text-align:left"></th></tr></thead><tbody>${summaryRows}<tr style="background:${BRAND_BLUE};color:#fff"><td style="padding:8px 10px" colspan="2"><strong>Grand total</strong></td><td style="padding:8px 10px;text-align:right"><strong>$${fmtMoney(grandTotal)}</strong></td><td></td></tr></tbody></table><p style="font-size:13px;background:${BRAND_CREAM};padding:10px 14px;border-left:3px solid ${BRAND_BLUE};margin:12px 0">&#128206; Attached: <strong>${esc(invoiceFilename)}</strong>${billCombined ? ` and <strong>${esc(billFilename)}</strong>` : ''} &mdash; ready for NetSuite CSV Import.</p>${importLinkBlock(invoiceImportUrl, 'Open NetSuite Invoice Import screen')}${billCombined ? importLinkBlock(billImportUrl, 'Open NetSuite Vendor Bill Import screen') : ''}</div>`;

      const sent = await resendSend({ from: fromField(), to: Array.from(toSet), subject, html, attachments: finalAttachments });
      if (!sent.ok) return new Response(JSON.stringify({ error: sent.error, build_errors: buildErrors }), { status: 502, headers: jsonHeaders });

      // Stamp every successfully-included order so it drops out of the next digest.
      const sentAt = new Date().toISOString();
      await supa.from('orders').update({ netsuite_csv_sent_at: sentAt }).in('id', includedOrderIds);
      return new Response(JSON.stringify({ ok: true, count: includedOrderIds.length, order_ids: includedOrderIds, new_customer_csvs: newCustomerCsvSummary, build_errors: buildErrors, sent_at: sentAt }), { status: 200, headers: jsonHeaders });
    }

    // ── Order-scoped actions ──────────────────────────────────────────────
    const orderId = body?.orderId as string | undefined;
    const sendOnlyRaw = Array.isArray(body?.sendOnly) ? body.sendOnly as string[] : null;
    const sendOnly = sendOnlyRaw && sendOnlyRaw.length ? new Set(sendOnlyRaw) : null;
    const wants = (group: 'customer' | 'ordersTeam' | 'accounting') => !sendOnly || sendOnly.has(group);
    if (!orderId || !action) return new Response(JSON.stringify({ error: 'orderId and action required' }), { status: 400, headers: jsonHeaders });
    const { data: order, error: oErr } = await supa.from('orders').select('*').eq('id', orderId).single(); if (oErr || !order) return new Response(JSON.stringify({ error: 'Order not found' }), { status: 404, headers: jsonHeaders });
    const { data: items } = await supa.from('order_items').select('*').eq('order_id', orderId);
    const { data: customer } = order.customer_id ? await supa.from('customers').select('*').eq('id', order.customer_id).single() : { data: null };
    const { data: location } = order.customer_location_id ? await supa.from('customer_locations').select('*').eq('id', order.customer_location_id).single() : { data: null };
    const o = order as Record<string, unknown>; const its = (items || []) as Record<string, unknown>[]; const cust = (customer || {}) as Record<string, unknown>; const loc = (location || null) as Record<string, unknown> | null;
    const settings = await loadSiteSettings(supa);
    const delivery = await loadDelivery(supa);
    const invoiceRecipient = (delivery.invoice?.recipient || '').trim() || settings.accounting_notify_email || NETSUITE_NOTIFY_EMAILS.split(',')[0].trim();
    const billRecipient    = (delivery.bill?.recipient    || '').trim() || settings.accounting_notify_email || NETSUITE_NOTIFY_EMAILS.split(',')[0].trim();
    const invoiceImportUrl = (delivery.invoice?.importUrl || '').trim();
    const billImportUrl    = (delivery.bill?.importUrl    || '').trim();
    const pad = 5; const orderNum = padOrderNumber(o.order_number, pad); const results: Record<string, unknown> = {};
    const shipToBlock = `<div style="font-size:13px;line-height:1.5;margin:12px 0"><strong>Ship to</strong><br>${esc(o.ship_to_name || cust.company_name || '')}<br>${esc(o.ship_to_address || '')}<br>${esc([o.ship_to_city, o.ship_to_state].filter(Boolean).join(', '))} ${esc(o.ship_to_zip || '')}</div>`;
    const poLine = o.po_number ? `<p style="font-size:13px;margin:0 0 12px"><strong>Customer PO #:</strong> ${esc(o.po_number)}</p>` : '';
    const itemsHtml = lineItemsTable(its); const totalsHtml = totalsBlock(o);
    const packSlipAttach = packingSlipAttachment(orderNum, o, cust, loc, its);
    if (action === 'placed') {
      if (wants('customer') && o.customer_email) {
        const html = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#2b2b2b">${logoHeader()}<h2 style="font-family:Georgia,serif;color:${BRAND_BLUE};margin-top:0">Order #${esc(orderNum)} received</h2>${poLine}<p>Thank you for your order. We'll begin processing it and send tracking info once it ships.</p>${itemsHtml}${totalsHtml}${shipToBlock}<p style="font-size:12px;color:#666;margin-top:24px">Questions? Reply to this email or contact <a href="mailto:${esc(ORDERS_EMAIL)}" style="color:${BRAND_BLUE}">${esc(ORDERS_EMAIL)}</a>.</p></div>`;
        results.customerConfirm = await resendSend({ from: fromField(), to: [o.customer_email], reply_to: ORDERS_EMAIL, subject: `NI Wholesale order #${orderNum} confirmed`, html });
      }
      if (wants('ordersTeam')) {
        const html = `<div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;padding:24px;color:#2b2b2b">${logoHeader()}<h2 style="margin-top:0">New Order #${esc(orderNum)} — ${esc(cust.company_name || o.customer_name || '(unknown)')}</h2><p style="font-size:13px"><strong>Location:</strong> ${esc((loc?.location_name as string) || '—')} &nbsp;•&nbsp; <strong>Payment:</strong> ${esc(o.payment_method || '')}${o.po_number ? ' &nbsp;•&nbsp; <strong>PO #:</strong> ' + esc(o.po_number) : ''}</p>${manageOrderCta(orderNum, orderId)}${itemsHtml}${totalsHtml}${shipToBlock}${o.notes ? `<div style="background:${BRAND_CREAM};padding:10px 14px;border-left:3px solid ${BRAND_BLUE};margin:12px 0;font-size:13px"><strong>Customer note:</strong><br>${esc(o.notes)}</div>` : ''}${packingSlipCallout()}</div>`;
        results.ordersTeam = await resendSend({ from: fromField(), to: [ORDERS_EMAIL], reply_to: o.customer_email || ORDERS_EMAIL, subject: `New Order #${orderNum} from ${cust.company_name || 'unknown'}`, html, attachments: [packSlipAttach] });
      }
      // No accounting heads-up at placement — accounting only gets the
      // combined CSV email when the order is marked shipped. Avoids
      // duplicate/premature emails to the accounting inbox.
    } else if (action === 'shipped') {
      if (wants('customer') && o.customer_email) {
        const trackingLine = o.tracking_number ? `<p style="font-size:14px"><strong>Carrier:</strong> ${esc(o.carrier || '')} &nbsp;·&nbsp; <strong>Tracking:</strong> ${esc(o.tracking_number)}</p>` : '';
        const html = `<div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;padding:24px;color:#2b2b2b">${logoHeader()}<h2 style="font-family:Georgia,serif;color:${BRAND_BLUE};margin-top:0">Order #${esc(orderNum)} has shipped</h2>${poLine}${trackingLine}${itemsHtml}${shipToBlock}${packingSlipCallout()}</div>`;
        results.customerShipped = await resendSend({ from: fromField(), to: [o.customer_email], reply_to: ORDERS_EMAIL, subject: `NI Wholesale order #${orderNum} has shipped`, html, attachments: [packSlipAttach] });
      }
      if (wants('accounting') && (String(o.payment_method || '')).toLowerCase() === 'invoice' && cust.company_name) {
        const accountingMode = (settings.notify_accounting_mode || 'weekly-digest').toLowerCase();
        // Weekly-digest mode: don't email accounting now. Flag the order as
        // ready-for-digest; the scheduled `digest` action (or the manual
        // "Send digest now" button) will sweep it up on the weekly cadence.
        if (accountingMode === 'weekly-digest') {
          const now = new Date().toISOString();
          await supa.from('orders').update({ netsuite_csv_ready_at: now }).eq('id', orderId);
          results.accountingEmail = { ok: true, queued: 'weekly-digest', ready_at: now };
        } else { try {
          const invoiceBuilt = await generateCsv(supa, 'invoice', o, cust, loc, its, settings);
          const attachments: Record<string, unknown>[] = [];
          const isIntercompany = !!cust.is_intercompany;
          let billBuiltFilename = '';
          let billBuildError = '';
          if (isIntercompany) {
            try {
              const billBuilt = await generateCsv(supa, 'bill', o, cust, loc, its, settings);
              attachments.push({ filename: billBuilt.filename, content: b64Utf8(billBuilt.csv) });
              billBuiltFilename = billBuilt.filename;
            } catch (be) { billBuildError = be instanceof Error ? be.message : String(be); }
          }
          // First-order detection: count prior orders for this customer that
          // have already been sent to accounting. If none, attach Customer CSV
          // first + prepend [NEW CUSTOMER] to subject + show the banners.
          let isFirstOrder = false;
          let customerCsvBuilt: { csv: string; filename: string } | null = null;
          if (o.customer_id) {
            const cnt = await supa.from('orders').select('id', { count: 'exact', head: true }).eq('customer_id', o.customer_id).not('netsuite_csv_sent_at', 'is', null).neq('id', orderId);
            isFirstOrder = ((cnt.count ?? 0) === 0);
          }
          // Safety net: if the customer already has a NetSuite Internal ID
          // stamped on their profile, accounting has told us they exist in
          // NetSuite. Never attach the Customer CSV in that case.
          if (cust.netsuite_entity_id) isFirstOrder = false;
          if (isFirstOrder) {
            try {
              const lRes = await supa.from('customer_locations').select('*').eq('customer_id', o.customer_id).eq('status', 'active').order('created_at', { ascending: true });
              customerCsvBuilt = await generateCustomerCsv(supa, cust, (lRes.data || []) as Record<string, unknown>[], settings);
            } catch (ce) { console.warn('First-order Customer CSV attach failed:', ce); }
          }
          // Attach in order: Customer CSV (if first order) -> Invoice -> Bill.
          const finalAttachments: Record<string, unknown>[] = [];
          if (customerCsvBuilt) finalAttachments.push({ filename: customerCsvBuilt.filename, content: b64Utf8(customerCsvBuilt.csv) });
          finalAttachments.push({ filename: invoiceBuilt.filename, content: b64Utf8(invoiceBuilt.csv) });
          for (const a of attachments) finalAttachments.push(a);

          const newCustBlock = customerCsvBuilt ? newCustomerBanner(String(cust.company_name), customerCsvBuilt.filename, isIntercompany) : '';
          const invoiceStep = `${stepHeader('1', 'Create NI Customer Invoice', BRAND_BLUE)}<p style="font-size:13px;line-height:1.6;margin:0 0 12px">Please create a Customer Invoice for the following order in <strong>NI's</strong> NetSuite books. Payment method is <strong>Invoice</strong>.</p>${itemsHtml}${totalsHtml}${shipToBlock}<p style="font-size:13px;line-height:1.6;background:${BRAND_CREAM};padding:10px 14px;border-left:3px solid ${BRAND_BLUE};margin:12px 0">&#128206; Attached: <strong>${esc(invoiceBuilt.filename)}</strong> — ready for NetSuite CSV Import (Transactions → Invoices).</p>${importLinkBlock(invoiceImportUrl, 'Open NetSuite Invoice Import screen')}`;
          const billStep = isIntercompany ? `${intercompanyWarning(String(cust.company_name))}${stepHeader('2', 'Create Matching Vendor Bill (Intercompany)', BRAND_GOLD)}<p style="font-size:13px;line-height:1.6;margin:0 0 12px">Inside <strong>${esc(cust.company_name)}</strong>'s subsidiary, create a <strong>Vendor Bill</strong> that mirrors the invoice above. Same order, same amount — NI is the vendor here.</p>${billBuiltFilename ? `<p style="font-size:13px;line-height:1.6;background:${BRAND_CREAM};padding:10px 14px;border-left:3px solid ${BRAND_GOLD};margin:12px 0">&#128206; Attached: <strong>${esc(billBuiltFilename)}</strong> — ready for NetSuite CSV Import (Transactions → Vendor Bills) inside ${esc(cust.company_name)}'s subsidiary.</p>` : `<p style="font-size:13px;color:#b53f3f;background:#fdecea;padding:10px 14px;border-left:3px solid #b53f3f;margin:12px 0">&#9888;&#65039; Bill CSV failed to generate: ${esc(billBuildError)}. Please build the Vendor Bill manually or fix the Bill CSV mapping.</p>`}${importLinkBlock(billImportUrl, 'Open NetSuite Vendor Bill Import screen')}` : '';
          const subject = (customerCsvBuilt ? '[NEW CUSTOMER] ' : '') + (isIntercompany
            ? `Create NI Invoice + matching Vendor Bill for order #${orderNum} (${cust.company_name})`
            : `Create NetSuite invoice for NI order #${orderNum} (${cust.company_name})`);
          const html = `<div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;padding:24px;color:#2b2b2b">${logoHeader()}<h1 style="font-family:Georgia,serif;font-size:20px;color:${BRAND_BLUE};margin:0 0 4px">NetSuite entries needed for order #${esc(orderNum)}</h1>${poLine}${newCustBlock}${invoiceStep}${billStep}</div>`;
          const toSet = new Set<string>();
          invoiceRecipient.split(',').map((s) => s.trim()).filter(Boolean).forEach((r) => toSet.add(r));
          if (isIntercompany) billRecipient.split(',').map((s) => s.trim()).filter(Boolean).forEach((r) => toSet.add(r));
          results.accountingEmail = await resendSend({ from: fromField(), to: Array.from(toSet), subject, html, attachments: finalAttachments });
          if ((results.accountingEmail as { ok?: boolean }).ok) {
            await supa.from('orders').update({ netsuite_csv_sent_at: new Date().toISOString() }).eq('id', orderId);
          }
        } catch (invErr) { results.accountingEmail = { ok: false, error: invErr instanceof Error ? invErr.message : String(invErr) }; } }
      }
    } else return new Response(JSON.stringify({ error: 'invalid action; must be placed, shipped, customer-csv, or digest' }), { status: 400, headers: jsonHeaders });
    return new Response(JSON.stringify({ ok: true, action, orderId, sendOnly: sendOnlyRaw, results }), { status: 200, headers: jsonHeaders });
  } catch (e) { return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), { status: 500, headers: jsonHeaders }); }
});
