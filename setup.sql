CREATE TABLE "public"."jwt_user" (
    "uid" character varying(255)  NOT NULL,
    "name" character varying(255)  NOT NULL,
    "email" character varying(255)  NOT NULL,

    CONSTRAINT jwt_user_pkey
    PRIMARY KEY (uid), 
    CONSTRAINT myname
    UNIQUE (uid, email)
);

create table "public"."user_auth" (
    
    "id" serial primary key,
    "uid" VARCHAR(255) not null unique,
    "email" VARCHAR(255) not null unique,
    "hash" varchar(255) not null ,
    
   FOREIGN KEY(uid, email) REFERENCES public.jwt_user(uid, email)  
  );

