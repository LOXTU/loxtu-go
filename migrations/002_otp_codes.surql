DEFINE TABLE otp_codes SCHEMAFULL;
DEFINE FIELD code_hash ON otp_codes TYPE string;
DEFINE FIELD attempts ON otp_codes TYPE int DEFAULT 0;
DEFINE FIELD expires_at ON otp_codes TYPE datetime;

-- Auto-cleanup expired OTP codes on any write activity
DEFINE EVENT delete_expired_otp ON otp_codes WHEN $event = "CREATE" OR $event = "UPDATE" THEN {
    REMOVE otp_codes WHERE expires_at < time::now();
};