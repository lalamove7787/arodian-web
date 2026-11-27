// Owner-only user administration for the SPK app.
// Verifies the caller's Supabase session, checks the owner role in
// public.profiles, then uses the service-role client for Auth admin actions.
// Secrets live only in Vercel environment variables.
const { createClient } = require("@supabase/supabase-js");

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }
  const url = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceKey) {
    return res.status(500).json({ error: "Server not configured" });
  }
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) {
    return res.status(401).json({ error: "Missing token" });
  }

  const admin = createClient(url, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { data: userData, error: userErr } = await admin.auth.getUser(token);
  if (userErr || !userData || !userData.user) {
    return res.status(401).json({ error: "Invalid token" });
  }
  const { data: profile, error: profErr } = await admin
    .from("profiles")
    .select("role, is_active")
    .eq("id", userData.user.id)
    .single();
  if (profErr || !profile || profile.role !== "owner" || !profile.is_active) {
    return res.status(403).json({ error: "Owner only" });
  }

  const body = req.body || {};
  try {
    if (body.action === "create_user") {
      const { email, password, full_name } = body;
      if (!email || !password) {
        return res.status(400).json({ error: "email & password required" });
      }
      const { data, error } = await admin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name: full_name || "" },
      });
      if (error) return res.status(400).json({ error: error.message });
      return res
        .status(200)
        .json({ user: { id: data.user.id, email: data.user.email } });
    }
    if (body.action === "reset_password") {
      const { user_id, password } = body;
      if (!user_id || !password) {
        return res.status(400).json({ error: "user_id & password required" });
      }
      const { error } = await admin.auth.admin.updateUserById(user_id, {
        password,
      });
      if (error) return res.status(400).json({ error: error.message });
      return res.status(200).json({ ok: true });
    }
    return res.status(400).json({ error: "Unknown action" });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
};
