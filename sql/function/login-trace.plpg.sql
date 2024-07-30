/*
 * a_id: users.id
 * a_authn: Authorization method by AuthType
 * a_success: Login succeeded or not.
 * a_log: Record to actlogs or not.
 */
CREATE OR REPLACE PROCEDURE login_trace(IN a_id uuid, a_authn smallint, a_success boolean, a_log boolean) AS $$
  BEGIN
    update users set act_at = now() where id = a_id;

    if a_log then
      insert into actlogs (user_id, action, success)
        values (a_id, a_authn, a_success)
        on conflict do nothing;
    end if;

    if a_authn = 2 or a_authn = 3 or a_authn = 4 then
      /* NOTE: PasswordStrong, PasswordWeak, PasswordWeakUnmet */
      update identities set fail = case
                                   when a_success then 0
                                   else fail + 1 end
        where user_id = a_id;
    end if;
  END;
$$ LANGUAGE plpgsql;
