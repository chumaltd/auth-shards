/*
 * a_id: users.id
 * a_pass: Password login or not.
 * a_success: Login succeeded or not.
 */
CREATE OR REPLACE PROCEDURE login_trace(IN a_id uuid, a_pass boolean, a_success boolean) AS $$
  BEGIN
    /* TODO: Add activity log table */
    UPDATE users SET act_at = now() WHERE id = a_id;

    IF a_pass THEN
      IF a_success THEN
        UPDATE identities SET fail = 0 WHERE user_id = a_id;
      ELSE
        UPDATE identities SET fail = fail + 1 WHERE user_id = a_id;
      END IF;
    END IF;
  END;
$$ LANGUAGE plpgsql;
