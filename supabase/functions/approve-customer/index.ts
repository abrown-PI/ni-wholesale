// NI Wholesale — Approve Customer Edge Function (v9, set-password link flow)
//
// Change from v8: no more auto-generated temp passwords shown to anyone. On
// approval we create the auth user with an unusable random placeholder, then
// generate a Supabase recovery link and email that. Customer picks their own
// password by clicking the link. Eliminates the "wonky password" UX problem.

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.51.0';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const RESEND_API_KEY = Deno.env.get('RESEND_API_KEY') || '';
const RESEND_FROM_EMAIL = Deno.env.get('RESEND_FROM_EMAIL') || 'no-reply@mail.nutritionalinnovations.net';
const RESEND_FROM_NAME = Deno.env.get('RESEND_FROM_NAME') || 'Nutritional Innovations Wholesale';
const SITE_URL = Deno.env.get('SITE_URL') || 'https://nutritionalinnovations.net';
const LOGO_URL = Deno.env.get('EMAIL_LOGO_URL') || `${SITE_URL}/ni-logo.png`;

const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' };
const jsonHeaders = { ...corsHeaders, 'Content-Type': 'application/json' };

// Random 48-char string used as an unusable placeholder on the auth user.
// Never surfaced anywhere — the customer sets their own via the recovery link.
function placeholderPassword(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function escapeHtml(s: string): string { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
function bytesToB64(bytes: Uint8Array): string { let bin = ''; for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]); return btoa(bin); }

let LOGO_ATTACHMENT: Record<string, unknown> | null = null;
async function getLogoAttachment(): Promise<Record<string, unknown> | null> {
  if (LOGO_ATTACHMENT) return LOGO_ATTACHMENT;
  try {
    const res = await fetch(LOGO_URL); if (!res.ok) return null;
    const buf = await res.arrayBuffer();
    LOGO_ATTACHMENT = { filename: 'ni-logo.png', content: bytesToB64(new Uint8Array(buf)), content_id: 'ni-logo', content_type: 'image/png', disposition: 'inline' };
    return LOGO_ATTACHMENT;
  } catch { return null; }
}
function logoHeader(): string { return `<div style="text-align:center;padding:8px 0 18px;border-bottom:1px solid #eee;margin-bottom:20px"><a href="${SITE_URL}" style="text-decoration:none"><img src="cid:ni-logo" alt="Nutritional Innovations" style="height:48px;display:inline-block;border:0"></a></div>`; }

interface EmailResult { sent: boolean; skipped?: boolean; error?: string; id?: string; }

async function sendWelcomeEmail(customer: Record<string, unknown>, setPasswordLink: string): Promise<EmailResult> {
  if (!RESEND_API_KEY) return { sent: false, skipped: true, error: 'RESEND_API_KEY not set' };
  const contact = String(customer.contact_name || 'there');
  const company = String(customer.company_name || 'your pharmacy');
  const email = String(customer.email || '');
  const html = `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#2b2b2b">
${logoHeader()}
<p style="font-size:16px;margin-top:0">Hi ${escapeHtml(contact)},</p>
<p style="font-size:15px;line-height:1.5">Your wholesale account for <strong>${escapeHtml(company)}</strong> at Nutritional Innovations has been approved.</p>
<p style="font-size:15px;line-height:1.5">Click the button below to choose your password and sign in. The link is valid for 24 hours.</p>
<div style="text-align:center;margin:26px 0">
  <a href="${setPasswordLink}" style="display:inline-block;background:#2d3f82;color:#fff;padding:14px 32px;text-decoration:none;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase;border-radius:4px">Set Your Password &amp; Sign In</a>
</div>
<div style="background:#f5f2ea;padding:12px 16px;border-left:3px solid #2d3f82;margin:16px 0;font-size:13px">
  <div style="font-size:11px;color:#666;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">For future reference</div>
  <div><strong>Sign-in URL:</strong> <a href="${SITE_URL}" style="color:#2d3f82">${SITE_URL}</a></div>
  <div><strong>Email:</strong> ${escapeHtml(email)}</div>
</div>
<p style="font-size:13px;line-height:1.5;color:#666">If the link above expires, visit the sign-in URL and click &ldquo;Forgot password&rdquo; to get a fresh link.</p>
<p style="font-size:14px;line-height:1.5;color:#666">Questions? Reply to this email or contact <a href="mailto:orders@nutritionalinnovations.net" style="color:#2d3f82">orders@nutritionalinnovations.net</a>.</p>
<hr style="border:none;border-top:1px solid #e0dcd2;margin:20px 0"/>
<p style="font-size:12px;color:#999;margin-bottom:0">Nutritional Innovations Wholesale</p>
</div>`;
  const attachments: Record<string, unknown>[] = [];
  const logo = await getLogoAttachment(); if (logo) attachments.push(logo);

  // Log the send attempt to email_queue for the communications log.
  const supaAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  let logId: string | null = null;
  try {
    const attempt = await supaAdmin.from('email_queue').insert({
      to_email: email,
      subject: 'Welcome to Nutritional Innovations Wholesale',
      body: html,
      template_key: 'approve_welcome_setpwd',
      status: 'queued',
      related_customer_id: String(customer.id || ''),
    }).select('id').single();
    if (attempt.data && (attempt.data as { id?: string }).id) logId = (attempt.data as { id: string }).id;
  } catch (logErr) { console.warn('[email-log] queue insert failed:', logErr); }

  try {
    const res = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: `${RESEND_FROM_NAME} <${RESEND_FROM_EMAIL}>`, to: [email], subject: 'Welcome to Nutritional Innovations Wholesale', html, attachments }) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const errMsg = (data as { message?: string }).message || `HTTP ${res.status}`;
      if (logId) { try { await supaAdmin.from('email_queue').update({ status: 'failed', error_message: errMsg, attempted_at: new Date().toISOString() }).eq('id', logId); } catch {} }
      return { sent: false, error: errMsg };
    }
    const resendId = (data as { id?: string }).id;
    if (logId) { try { await supaAdmin.from('email_queue').update({ status: 'sent', sent_at: new Date().toISOString(), attempted_at: new Date().toISOString(), resend_id: resendId || null }).eq('id', logId); } catch {} }
    return { sent: true, id: resendId };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (logId) { try { await supaAdmin.from('email_queue').update({ status: 'failed', error_message: msg, attempted_at: new Date().toISOString() }).eq('id', logId); } catch {} }
    return { sent: false, error: msg };
  }
}

serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers: jsonHeaders });

  try {
    const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    const authHeader = req.headers.get('Authorization') || '';
    const jwt = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (!jwt) return new Response(JSON.stringify({ error: 'Missing Authorization header' }), { status: 401, headers: jsonHeaders });
    const { data: userRes, error: userErr } = await supabaseAdmin.auth.getUser(jwt);
    if (userErr || !userRes.user) return new Response(JSON.stringify({ error: 'Invalid token' }), { status: 401, headers: jsonHeaders });
    const { data: callerProfile } = await supabaseAdmin.from('profiles').select('role').eq('id', userRes.user.id).single();
    if (!callerProfile || callerProfile.role !== 'admin') return new Response(JSON.stringify({ error: 'Admin role required' }), { status: 403, headers: jsonHeaders });

    const body = await req.json().catch(() => null);
    const customerId: string | undefined = body && body.customerId;
    const extraCustomerIds: string[] = Array.isArray(body && body.attachAdditionalCustomerIds) ? body.attachAdditionalCustomerIds.filter((x: unknown) => typeof x === 'string') : [];
    if (!customerId) return new Response(JSON.stringify({ error: 'customerId required' }), { status: 400, headers: jsonHeaders });

    const { data: customer } = await supabaseAdmin.from('customers').select('*').eq('id', customerId).single();
    if (!customer) return new Response(JSON.stringify({ error: 'Customer not found' }), { status: 404, headers: jsonHeaders });
    if (!customer.email) return new Response(JSON.stringify({ error: 'Customer has no email' }), { status: 400, headers: jsonHeaders });

    // Look up existing auth user by email
    const { data: existingLookup } = await supabaseAdmin.auth.admin.listUsers({ perPage: 200 });
    const existing = existingLookup.users.find((u) => (u.email || '').toLowerCase() === customer.email.toLowerCase());

    let newUserId: string | null = null;
    if (existing) {
      newUserId = existing.id;
    } else {
      // Create the auth user with an unusable random placeholder password.
      const { data: authData, error: authErr } = await supabaseAdmin.auth.admin.createUser({
        email: customer.email,
        password: placeholderPassword(),
        email_confirm: true,
        user_metadata: {
          company_name: customer.company_name,
          contact_name: customer.contact_name,
          customer_id: customer.id,
          must_change_password: true,
        },
      });
      if (authErr || !authData.user) return new Response(JSON.stringify({ error: (authErr && authErr.message) || 'Failed to create auth user' }), { status: 400, headers: jsonHeaders });
      newUserId = authData.user.id;
    }

    await supabaseAdmin.from('customers').update({ status: 'active' }).eq('id', customerId);
    await supabaseAdmin.from('profiles').update({ customer_id: customerId, role: 'pharmacy' }).eq('id', newUserId);

    const memberships = [{ user_id: newUserId, customer_id: customerId, role: 'purchaser', is_default: true }];
    for (const extraId of extraCustomerIds) { if (extraId !== customerId) memberships.push({ user_id: newUserId, customer_id: extraId, role: 'purchaser', is_default: false }); }
    for (const m of memberships) { await supabaseAdmin.from('customer_users').upsert(m, { onConflict: 'user_id,customer_id' }); }

    // Generate the recovery link so they can choose their password.
    let emailResult: EmailResult = { sent: false, skipped: true };
    if (!existing) {
      const { data: linkData, error: linkErr } = await supabaseAdmin.auth.admin.generateLink({
        type: 'recovery',
        email: customer.email,
        options: { redirectTo: `${SITE_URL}#/set-password` },
      });
      if (linkErr || !linkData?.properties?.action_link) {
        console.error('generateLink error on approval:', linkErr);
        return new Response(JSON.stringify({ error: 'Account created but couldn\'t generate the set-password link: ' + (linkErr?.message || 'unknown') }), { status: 500, headers: jsonHeaders });
      }
      emailResult = await sendWelcomeEmail(customer, linkData.properties.action_link);
    }

    return new Response(JSON.stringify({
      success: true,
      email: customer.email,
      userPreexisted: !!existing,
      emailSent: !!emailResult.sent,
      emailError: emailResult.error || null,
      customerName: customer.company_name,
      contactName: customer.contact_name,
      attachedCustomerIds: memberships.map((m) => m.customer_id),
    }), { status: 200, headers: jsonHeaders });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), { status: 500, headers: jsonHeaders });
  }
});
