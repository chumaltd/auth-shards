WITH ids as (select (iw.count + ii.count + ig.count) as count from
                                                                (select count(id) from webauthns where user_id = $2) iw,
                                                                (select count(user_id) from identities where  user_id = $2) ii,
                                                                (select count(uid) from google_identities where  user_id = $2) ig)
DELETE from webauthns
    using users, ids
    where webauthns.id = $1 and users.id = $2
    and users.id = webauthns.user_id
    and ids.count >= 2
    returning webauthns.id
