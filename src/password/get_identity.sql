SELECT u.id AS uid, u.org_id AS oid, u.superuser AS su, fail,
       i.digest_argon AS password_digest,
       coalesce(o.hard_pass, false) AS hard_pass
 FROM identities i
       INNER JOIN users u ON u.id = i.user_id
       LEFT JOIN orgs o ON o.id = u.org_id
 WHERE u.email = $1
 LIMIT 1
