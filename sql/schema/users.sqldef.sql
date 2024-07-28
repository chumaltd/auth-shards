CREATE TABLE "public"."users" (
    "id" uuid NOT NULL DEFAULT public.gen_random_uuid(),
    "org_id" uuid,
    "name" character varying,
    "email" character varying NOT NULL,
    "superuser" boolean NOT NULL DEFAULT false,
    "name_confirmed" boolean NOT NULL DEFAULT false,
    "session_token" character varying,
    "mail_at" timestamp(6),
    "created_at" timestamp(6) NOT NULL DEFAULT now(),
    "updated_at" timestamp(6) NOT NULL DEFAULT now(),
    "act_at" timestamp(6) NOT NULL DEFAULT now(),
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX unique_users_email ON public.users USING btree (email);

CREATE INDEX index_users_on_act_at ON public.users USING btree (act_at);
