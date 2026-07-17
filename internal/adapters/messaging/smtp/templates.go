package smtp

import "fmt"

// GenerateOTPEmail returns a responsive HTML email with the 6-digit code.
func GenerateOTPEmail(code string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    @import url('https://api.fontshare.com/v2/css?f[]=clash-display@200,400,700&f[]=satoshi@400,500,700&display=swap');
    body { margin: 0; padding: 0; background-color: #f4f6f9; font-family: 'Satoshi', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    .container { max-width: 480px; margin: 40px auto; background: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 8px 32px rgba(0,0,0,0.08); }
    .header { background: linear-gradient(135deg, #1a1f2e 0%%, #2a3040 100%%); padding: 36px 24px; text-align: center; }
    .header h1 { color: #ffffff; margin: 0; font-family: 'Clash Display', sans-serif; font-size: 28px; font-weight: 400; letter-spacing: 4px; }
    .body { padding: 36px 28px; }
    .body p { color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 20px; font-family: 'Satoshi', sans-serif; }
    .code-box { background: linear-gradient(135deg, #f8fafc 0%%, #eef2f6 100%%); border: none; border-radius: 16px; padding: 28px 20px; text-align: center; margin: 28px 0; box-shadow: inset 0 1px 2px rgba(255,255,255,0.8), 0 2px 8px rgba(0,0,0,0.04); }
    .code { font-size: 44px; font-weight: 700; letter-spacing: 10px; color: #1a1f2e; font-family: 'Clash Display', 'Courier New', monospace; }
    .expiry { color: #64748b; font-size: 13px; text-align: center; margin: 16px 0 0; font-family: 'Satoshi', sans-serif; }
    .warning { background: #fef2f2; border-left: 4px solid #ef4444; padding: 12px 16px; border-radius: 8px; margin: 24px 0; }
    .warning p { color: #dc2626; font-size: 13px; margin: 0; font-family: 'Satoshi', sans-serif; }
    .footer { padding: 24px 28px; background: #f8fafc; text-align: center; }
    .footer p { color: #94a3b8; font-size: 12px; margin: 0; font-family: 'Satoshi', sans-serif; letter-spacing: 1px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>LOXTU</h1>
    </div>
    <div class="body">
      <p>Your verification code to sign in:</p>
      <div class="code-box">
        <div class="code">%s</div>
      </div>
      <p class="expiry">This code expires in <strong>5 minutes</strong>.</p>
      <div class="warning">
        <p>⚠️ If you did not request this code, please ignore this email and ensure your account security.</p>
      </div>
    </div>
    <div class="footer">
      <p>LOXTU Limited</p>
    </div>
  </div>
</body>
</html>`, code)
}
