# PixelMail

Internal messaging only. Sign up with a unique PixelMail username and password. Messages stay in private mailboxes on the dedicated Sydney Supabase project. The browser uses a public anon key; the registration edge function keeps its privileged key server-side.

Enable GitHub Pages with GitHub Actions as the source (Settings → Pages → Build and deployment). The deployment workflow publishes only the frontend. Run the workflow manually to repeat live account and attachment tests. Sign-up is limited to 30 attempts per hour and 1,000 profiles. Maximum five files and 25 MiB combined per message; each account has up to 100 MiB and 100 uploaded objects, with a shared 700 MiB storage ceiling to protect the free plan. Save your password securely: email-based recovery and 2FA are not available. Scheduled sending is local-demo only. External email is not supported.
