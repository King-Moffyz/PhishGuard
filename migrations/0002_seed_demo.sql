-- Seed a demo organisation + monitored mailbox so the dashboard's "Analyze an Email" panel
-- and API examples work out of the box, without a manual INSERT step after first boot.
-- IDs match VITE_DEFAULT_ORG_ID / VITE_DEFAULT_ACCOUNT_ID in .env.example.

INSERT INTO organisations (org_id, name, domain)
VALUES ('11111111-1111-1111-1111-111111111111', 'Acme Corp (Demo)', 'acme.example')
ON CONFLICT (org_id) DO NOTHING;

INSERT INTO email_accounts (account_id, org_id, mailbox_address, display_name, department)
VALUES (
    '22222222-2222-2222-2222-222222222222',
    '11111111-1111-1111-1111-111111111111',
    'analyst@acme.example',
    'SOC Analyst Mailbox',
    'Security'
)
ON CONFLICT (account_id) DO NOTHING;
