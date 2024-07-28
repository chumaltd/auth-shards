CREATE TABLE "public"."identities" (
    "user_id" uuid NOT NULL,
    "digest_argon" character varying,
    "fail" smallint NOT NULL DEFAULT 0,
    "created_at" timestamp(6) NOT NULL DEFAULT now(),
    "updated_at" timestamp(6) NOT NULL DEFAULT now(),
    PRIMARY KEY ("user_id")
);
