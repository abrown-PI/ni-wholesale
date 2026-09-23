// NI Wholesale — Stripe Webhook receiver.
// Verifies incoming Stripe webhook signature, then on `checkout.session.completed`
// flips the order to paid, links the payment intent, decrements product stock
// atomically (via the same adjust_product_stock RPC we use everywhere else),
// and writes matching OUT rows to inventory_transactions so the ledger stays
// honest. Idempotent — safe if Stripe retries or double-fires.

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.51.0';

const STRIPE_WEBHOOK_SECRET = Deno.env.get('STRIPE_WEBHOOK_SECRET') || '';
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

const corsHeaders = { 'Access-Control-Allow-Origin': '*' };

// Verifies a Stripe signature header against the raw body + shared secret.
// Stripe format: "t=<timestamp>,v1=<hex>". We recompute HMAC-SHA256 of
// "<timestamp>.<body>" using STRIPE_WEBHOOK_SECRET and compare to v1.
async function verifyStripeSignature(rawBody: string, header: string, secret: string): Promise<boolean> {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(
    header.split(',').map((p) => {
      const [k, v] = p.split('=');
      return [k.trim(), v?.trim() || ''];
    }),
  );
  const timestamp = parts['t'];
  const expected = parts['v1'];
  if (!timestamp || !expected) return false;

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${timestamp}.${rawBody}`));
  const hex = Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Constant-time compare
  if (hex.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < hex.length; i++) diff |= hex.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

async function recordSaleAndDecrement(orderId: string) {
  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

  const { data: order } = await supa
    .from('orders')
    .select('id, order_number, customer_id, stock_decremented_at')
    .eq('id', orderId)
    .single();
  if (!order) return { ok: false, error: 'order not found' };
  if (order.stock_decremented_at) return { ok: true, skipped: true };

  const { data: items } = await supa
    .from('order_items')
    .select('id, product_id, product_name, sku, quantity, unit_price')
    .eq('order_id', orderId);

  const reference = order.order_number
    ? `Order ${order.order_number}`
    : `Order ${orderId.slice(0, 8)}`;

  let customerName: string | null = null;
  if (order.customer_id) {
    const { data: c } = await supa
      .from('customers')
      .select('company_name, contact_name')
      .eq('id', order.customer_id)
      .single();
    if (c) customerName = c.company_name || c.contact_name || null;
  }

  for (const line of items || []) {
    const qty = Math.max(0, Math.floor(Number(line.quantity) || 0));
    if (qty === 0 || !line.product_id) continue;

    // Atomic single-statement UPDATE — cannot race with concurrent orders.
    // Clamps at zero server-side.
    const { error: rpcErr } = await supa.rpc('adjust_product_stock', {
      p_product_id: line.product_id,
      p_delta: -qty,
    });
    if (rpcErr) {
      console.error(`adjust_product_stock failed for ${line.sku}:`, rpcErr);
      continue;
    }

    await supa.from('inventory_transactions').insert({
      type: 'OUT',
      reference,
      product_id: line.product_id,
      qty,
      unit_cost: line.unit_price ?? null,
      customer_id: order.customer_id || null,
      customer_name: customerName,
      notes: `Sold: ${line.product_name} (${line.sku})`,
    });
  }

  await supa
    .from('orders')
    .update({ stock_decremented_at: new Date().toISOString() })
    .eq('id', orderId);

  return { ok: true };
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: corsHeaders });

  const rawBody = await req.text();
  const sig = req.headers.get('stripe-signature') || '';

  const verified = await verifyStripeSignature(rawBody, sig, STRIPE_WEBHOOK_SECRET);
  if (!verified) {
    console.error('Stripe webhook signature verification failed');
    return new Response('Invalid signature', { status: 400, headers: corsHeaders });
  }

  let event: { type: string; data: { object: Record<string, unknown> } };
  try {
    event = JSON.parse(rawBody);
  } catch {
    return new Response('Invalid JSON', { status: 400, headers: corsHeaders });
  }

  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

  try {
    if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
      const session = event.data.object as Record<string, unknown>;
      const orderId = ((session.metadata as Record<string, string> | null) || {}).orderId;
      const paymentStatus = String(session.payment_status || '');

      if (orderId && paymentStatus === 'paid') {
        const intent = typeof session.payment_intent === 'string' ? session.payment_intent : null;
        const sessionId = typeof session.id === 'string' ? session.id : null;
        await supa
          .from('orders')
          .update({
            payment_status: 'paid',
            stripe_session_id: sessionId,
            stripe_payment_intent: intent,
          })
          .eq('id', orderId);

        // Fire the decrement + ledger write. Idempotent so double-fires are
        // safe. If the client-side path had already fired (rare on NI since
        // the previous flow was stubbed), this is a fast skip.
        const result = await recordSaleAndDecrement(orderId);
        if (!result.ok) console.error('recordSaleAndDecrement failed:', result.error);
      }
    } else if (event.type === 'checkout.session.expired' || event.type === 'checkout.session.async_payment_failed') {
      const session = event.data.object as Record<string, unknown>;
      const orderId = ((session.metadata as Record<string, string> | null) || {}).orderId;
      if (orderId) {
        await supa.from('orders').update({ payment_status: 'failed' }).eq('id', orderId);
      }
    }

    return new Response(JSON.stringify({ received: true }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (err) {
    console.error('stripe-webhook handler error:', err);
    return new Response(JSON.stringify({ error: 'Handler error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
