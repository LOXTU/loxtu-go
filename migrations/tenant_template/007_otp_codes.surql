-- ==================================================================
-- ФАЙЛ:    tenant_template/002_otp_codes.surrealql
-- КУДА:    NS=<tenant_id>, DB=<tenant_id> (loxtu, aerlingus, public)
-- АГЕНТУ:  Хранит состояние одноразовых паролей (OTP) для аутентификации.
--          КРИТИЧЕСКИ ВАЖНО: НИКОГДА не хранит plaintext код. 
--          Только хэш (SHA-256 + pepper). Привязывается к user_id_hash 
--          для обеспечения stateless-флоу без передачи PII.
-- ==================================================================

DEFINE TABLE otp_codes SCHEMAFULL PERMISSIONS NONE;

-- ── Идентификация ────────────────────────────────────────────────
DEFINE FIELD user_id_hash ON otp_codes TYPE string;
    -- Хэш идентификатора пользователя (SHA-256(user_id + pepper)).
    -- Позволяет найти и привязать активный OTP к пользователю, 
    -- не раскрывая реальный user_id или email (защита PII).

DEFINE FIELD code_hash ON otp_codes TYPE string;
    -- SHA-256(otp_code + pepper).
    -- Сравнение при вводе происходит ТОЛЬКО по хэшу. 
    -- Plaintext код существует только в памяти Go-процесса на момент генерации и отправки.

-- ── Безопасность и Lifecycle (NIS2 Compliance) ───────────────────
DEFINE FIELD attempts ON otp_codes TYPE int DEFAULT 0;
    -- Счётчик неудачных попыток ввода.
    -- При достижении лимита (например, 3) код считается недействительным, 
    -- даже если expires_at ещё не наступил (защита от brute-force).

DEFINE FIELD expires_at ON otp_codes TYPE datetime;
    -- Время истечения срока действия (обычно time::now() + 5m).
    -- После этого времени код автоматически считается недействительным.

DEFINE FIELD created_at ON otp_codes TYPE datetime DEFAULT time::now();
    -- Время создания записи (для аудита, отладки и аналитики).

-- ── Индексы ──────────────────────────────────────────────────────
DEFINE INDEX idx_otp_codes_user_id_hash ON otp_codes FIELDS user_id_hash;
    -- Быстрый поиск активного OTP по пользователю.
    -- Если бизнес-логика требует только один активный OTP на пользователя одновременно, 
    -- можно добавить модификатор UNIQUE.

-- ── Автоматическая очистка (Garbage Collection) ──────────────────
DEFINE EVENT delete_expired_otp ON otp_codes 
    WHEN $event = "CREATE" OR $event = "UPDATE" 
    THEN {
        -- "Ленивая" очистка: удаляем все протухшие записи при любой активности с таблицей.
        -- ВАЖНО: Основная проверка валидности всегда должна выполняться в Go-коде 
        -- через явное сравнение с expires_at и attempts, а не полагаться только на наличие записи.
        DELETE otp_codes WHERE expires_at < time::now();
    };