CREATE TABLE "public"."google_identities" (
    "uid" character varying,
    "user_id" uuid NOT NULL,
    "created_at" timestamp(6) NOT NULL DEFAULT now(),
    PRIMARY KEY ("uid"),
    UNIQUE ("user_id")
);
