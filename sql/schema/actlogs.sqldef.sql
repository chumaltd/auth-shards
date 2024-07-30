CREATE TABLE "public"."actlogs" (
  "user_id" uuid NOT NULL,
  "action" smallint NOT NULL,
  "success" boolean NOT NULL DEFAULT true,
  "created_at" timestamp(6) NOT NULL DEFAULT now(),
  PRIMARY KEY ("user_id", "created_at")
);
