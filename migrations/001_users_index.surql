DEFINE TABLE users SCHEMAFULL;
DEFINE FIELD user_id ON users TYPE string;
DEFINE FIELD email_hash ON users TYPE string;
DEFINE FIELD tenant_id ON users TYPE string;
DEFINE FIELD status ON users TYPE string;
DEFINE FIELD role ON users TYPE string;
DEFINE FIELD encrypted_dek ON users TYPE option<bytes>;
DEFINE FIELD masked_email ON users TYPE string;
DEFINE FIELD created_at ON users TYPE datetime;
DEFINE FIELD updated_at ON users TYPE datetime;
DEFINE FIELD login_count ON users TYPE int DEFAULT 0;
DEFINE FIELD failed_login_count ON users TYPE int DEFAULT 0;
DEFINE FIELD registration_attempts ON users TYPE int DEFAULT 0;

DEFINE INDEX idx_email_hash ON users FIELDS email_hash UNIQUE;