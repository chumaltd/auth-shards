CREATE TABLE "public"."webauthns" (
    "id" bytea NOT NULL,
    "user_id" uuid NOT NULL,
    "credential" jsonb NOT NULL,
    "description" character varying,
    "created_at" timestamp(6) NOT NULL DEFAULT now(),
    "updated_at" timestamp(6) NOT NULL DEFAULT now(),
    PRIMARY KEY ("id")
);
