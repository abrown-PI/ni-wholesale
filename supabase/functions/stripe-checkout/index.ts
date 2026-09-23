// NI Wholesale — Stripe Checkout Session creator.
// Called from the client-side checkout flow when payment_method='card'.
// Creates a Stripe hosted checkout session and returns its URL. The client
// redirects the customer to that URL, they pay on Stripe's page, and Stripe
// posts to the stripe-webhook function when the payment succeeds.

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';

const STRIPE_SECRET_KEY = Deno.env.get('STRIPE_SECRET_KEY') || '';
const SITE_URL = Deno.env.get('SITE_URL') || 'https://nutritionalinnovations.net';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const jsonHeaders = { ...corsHeaders, 'Content-Type': 'application/json' };

interface LineItem {
  name: string;
  sku?: string;
  quantity: number;
  unitPrice: number;
}
interface Payload {
  items: LineItem[];
  orderId: string;
  orderNumber: number;
  customerEmail: string;
  customerName?: string;
  shipping?: number;
  discountAmount?: number;
}

// Stripe expects the payload as URL-encoded form data with square-bracket
// index syntax for nested arrays. Rolling this by hand instead of pulling in
// the full Stripe SDK because Deno + Supabase edge functions keep things
// leaner without it.
function encodeStripeForm(params: Record<string, string | number>): string {
  return Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join('&');
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });

  if (!STRIPE_SECRET_KEY) {
    return new Response(
      JSON.stringify({ error: 'STRIPE_SECRET_KEY not configured on this project' }),
      { status: 500, headers: jsonHeaders },
    );
  }

  try {
    const body = (await req.json()) as Payload;
    const { items, orderId, orderNumber, customerEmail, shipping, discountAmount } = body;

    if (!orderId || !Array.isArray(items) || items.length === 0) {
      return new Response(
        JSON.stringify({ error: 'orderId and non-empty items are required' }),
        { status: 400, headers: jsonHeaders },
      );
    }

    // Build the Stripe form params. line_items[0][price_data][...] format.
    const form: Record<string, string | number> = {
      mode: 'payment',
      'payment_method_types[0]': 'card',
      customer_email: customerEmail || '',
      success_url: `${SITE_URL}/?order=${orderId}&payment=success`,
      cancel_url: `${SITE_URL}/?order=${orderId}&payment=cancelled`,
      'metadata[orderId]': orderId,
      'metadata[orderNumber]': String(orderNumber ?? ''),
    };

    let idx = 0;
    for (const item of items) {
      const qty = Math.max(1, Math.floor(item.quantity || 0));
      const cents = Math.round(Number(item.unitPrice || 0) * 100);
      form[`line_items[${idx}][price_data][currency]`] = 'usd';
      form[`line_items[${idx}][price_data][product_data][name]`] = item.name || 'Item';
      if (item.sku) form[`line_items[${idx}][price_data][product_data][description]`] = `SKU: ${item.sku}`;
      form[`line_items[${idx}][price_data][unit_amount]`] = cents;
      form[`line_items[${idx}][quantity]`] = qty;
      idx++;
    }

    const shipCents = Math.round(Number(shipping || 0) * 100);
    if (shipCents > 0) {
      form[`line_items[${idx}][price_data][currency]`] = 'usd';
      form[`line_items[${idx}][price_data][product_data][name]`] = 'Shipping';
      form[`line_items[${idx}][price_data][unit_amount]`] = shipCents;
      form[`line_items[${idx}][quantity]`] = 1;
      idx++;
    }

    // Stripe supports a `discounts` param that takes a coupon id. We create
    // a one-shot coupon on the fly for the flat dollar discount so the
    // customer-visible line-item total matches what they saw in cart.
    const discountValue = Number(discountAmount || 0);
    if (discountValue > 0) {
      const couponRes = await fetch('https://api.stripe.com/v1/coupons', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: encodeStripeForm({
          amount_off: Math.round(discountValue * 100),
          currency: 'usd',
          duration: 'once',
          name: `Order ${orderNumber} discount`,
          'metadata[orderId]': orderId,
        }),
      });
      if (couponRes.ok) {
        const coupon = await couponRes.json();
        form['discounts[0][coupon]'] = coupon.id;
      } else {
        const err = await couponRes.text();
        console.error('Coupon create failed, proceeding without discount:', err);
      }
    }

    const sessionRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: encodeStripeForm(form),
    });

    if (!sessionRes.ok) {
      const errText = await sessionRes.text();
      console.error('Stripe session create failed:', errText);
      return new Response(
        JSON.stringify({ error: 'Failed to create Stripe checkout session', detail: errText }),
        { status: 502, headers: jsonHeaders },
      );
    }

    const session = await sessionRes.json();
    return new Response(
      JSON.stringify({ url: session.url, sessionId: session.id }),
      { status: 200, headers: jsonHeaders },
    );
  } catch (err) {
    console.error('stripe-checkout error:', err);
    return new Response(
      JSON.stringify({ error: err instanceof Error ? err.message : 'Server error' }),
      { status: 500, headers: jsonHeaders },
    );
  }
});
