// NI Wholesale — Resend webhook receiver. Updates email_queue rows with
// delivery/bounce/open events. Configure in Resend dashboard:
//   https://<project-ref>.supabase.co/functions/v1/resend-webhook?secret=<RESEND_WEBHOOK_SECRET>
// Subscribe to: email.sent, email.delivered, email.bounced, email.complained,
// email.opened, email.clicked, email.delivery_delayed.

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.51.0';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const WEBHOOK_SECRET = Deno.env.get('RESEND_WEBHOOK_SECRET') || '';

const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' };

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method === 'GET') return new Response(JSON.stringify({ ok: true, hint: 'POST-only for Resend' }), { headers: { ...cors, 'Content-Type': 'application/json' } });
  if (req.method !== 'POST') return new Response('method not allowed', { status: 405, headers: cors });

  if (WEBHOOK_SECRET) {
    const url = new URL(req.url);
    if (url.searchParams.get('secret') !== WEBHOOK_SECRET) {
      return new Response(JSON.stringify({ error: 'invalid secret' }), { status: 401, headers: { ...cors, 'Content-Type': 'application/json' } });
    }
  }

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return new Response(JSON.stringify({ error: 'invalid json' }), { status: 400, headers: { ...cors, 'Content-Type': 'application/json' } }); }

  const type = String(body.type || '');
  const data = (body.data as Record<string, unknown>) || {};
  const emailId = String(data.email_id || data.id || '');
  const createdAt = String(body.created_at || new Date().toISOString());
  if (!emailId) return new Response(JSON.stringify({ ok: true, ignored: 'missing email_id' }), { headers: { ...cors, 'Content-Type': 'application/json' } });

  const shortEvent = type.startsWith('email.') ? type.slice('email.'.length) : type;
  const patch: Record<string, unknown> = { last_event: shortEvent, last_event_at: createdAt };
  if (shortEvent === 'bounced' || shortEvent === 'complained') {
    patch.status = 'failed';
    patch.error_message = ((data.bounce as { message?: string } | undefined)?.message) || (data as { reason?: string }).reason || shortEvent;
  } else if (shortEvent === 'delivered') {
    patch.status = 'delivered';
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  const { error } = await supabase.from('email_queue').update(patch).eq('resend_id', emailId);
  if (error) {
    console.error('[resend-webhook] update failed:', error);
    return new Response(JSON.stringify({ ok: false, error: error.message }), { status: 500, headers: { ...cors, 'Content-Type': 'application/json' } });
  }
  return new Response(JSON.stringify({ ok: true, event: shortEvent, resend_id: emailId }), { headers: { ...cors, 'Content-Type': 'application/json' } });
});
