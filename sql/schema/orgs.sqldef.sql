CREATE TABLE "public"."orgs" (
    "id" uuid NOT NULL DEFAULT public.gen_random_uuid(),
    "name" character varying,
    "hard_pass" boolean NOT NULL DEFAULT false,
    "created_at" timestamp(6) NOT NULL DEFAULT now(),
    "updated_at" timestamp(6) NOT NULL DEFAULT now(),
    PRIMARY KEY ("id")
);
