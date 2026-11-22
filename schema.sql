create extension if not exists "pgcrypto";

create table if not exists public.users (
    id uuid primary key default gen_random_uuid(),
    username text unique not null,
    tg_chat_id text,
    otp_code text,
    otp_verified boolean not null default false,
    is_online boolean not null default false,
    last_seen timestamptz not null default now(),
    created_at timestamptz not null default now()
);

create table if not exists public.messages (
    id uuid primary key default gen_random_uuid(),
    sender_id uuid not null references public.users(id) on delete cascade,
    receiver_id uuid not null references public.users(id) on delete cascade,
    content text not null,
    is_read boolean not null default false,
    created_at timestamptz not null default now()
);

create index if not exists idx_messages_pair_time
    on public.messages (sender_id, receiver_id, created_at);

create index if not exists idx_messages_unread
    on public.messages (receiver_id, sender_id)
    where is_read = false;