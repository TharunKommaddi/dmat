// Supabase Edge Function: create-razorpay-order
//
// Deploy this via the Supabase Dashboard: Edge Functions -> Deploy a new function
// -> name it "create-razorpay-order" -> paste this file's contents -> Deploy.
//
// Requires two secrets set first (Edge Functions -> Manage secrets, or
// `supabase secrets set RAZORPAY_KEY_ID=... RAZORPAY_KEY_SECRET=...`):
//   RAZORPAY_KEY_ID     — the test-mode key_id (e.g. rzp_test_xxxxxxxxxxxx)
//   RAZORPAY_KEY_SECRET — the test-mode key_secret (NEVER put this in frontend code)
//
// This function creates a Razorpay Order using Razorpay's Orders API, called
// server-side as required by Razorpay's own documented integration flow — the
// frontend must never construct the order itself, since it doesn't hold the
// key_secret and shouldn't be trusted with the "real" price.
//
// UNTESTED against a live Razorpay account — I have no execution or deploy
// access to verify this runs correctly. Test in Razorpay's test mode before
// relying on it, and report back the exact error text if it fails so it can
// be diagnosed precisely rather than guessed at.

import { createClient } from "jsr:@supabase/supabase-js@2";

const RAZORPAY_KEY_ID = Deno.env.get("RAZORPAY_KEY_ID");
const RAZORPAY_KEY_SECRET = Deno.env.get("RAZORPAY_KEY_SECRET");
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;

// Plan prices in INR, defined server-side only — the frontend never sends a
// price. This prevents a tampered client request from paying a different
// amount than intended.
const PLAN_PRICES_INR: Record<string, number> = {
  practice: 499,
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
    return new Response(
      JSON.stringify({ error: "Razorpay keys are not configured on the server yet." }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    // Verify the caller is a genuine, currently-authenticated Supabase user
    // before creating an order for them — an unauthenticated request should
    // never be able to trigger order creation.
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Not authenticated." }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: userData, error: userError } = await supabase.auth.getUser();
    if (userError || !userData.user) {
      return new Response(JSON.stringify({ error: "Not authenticated." }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { plan } = await req.json();
    const priceInRupees = PLAN_PRICES_INR[plan];
    if (!priceInRupees) {
      return new Response(JSON.stringify({ error: "Unknown plan." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Razorpay requires amount in paise (the smallest currency subunit),
    // confirmed from Razorpay's own Orders API documentation — this is a
    // commonly made mistake if omitted (₹499 must be sent as 49900, not 499).
    const amountInPaise = priceInRupees * 100;

    const razorpayAuth = btoa(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`);
    const orderRes = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: {
        Authorization: `Basic ${razorpayAuth}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        amount: amountInPaise,
        currency: "INR",
        receipt: `${userData.user.id}_${Date.now()}`,
        notes: { user_id: userData.user.id, plan },
      }),
    });

    const orderData = await orderRes.json();
    if (!orderRes.ok) {
      return new Response(JSON.stringify({ error: orderData.error?.description || "Failed to create Razorpay order." }), {
        status: 502,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(
      JSON.stringify({
        order_id: orderData.id,
        amount: orderData.amount,
        currency: orderData.currency,
        key_id: RAZORPAY_KEY_ID, // safe to return — this is the public key_id, not the secret
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
