import { useState, type FormEvent } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, Lock, User, Eye, EyeOff, AlertTriangle, ArrowRight } from 'lucide-react';
import { LogoMark } from '../components/states';
import { loginUser } from '../data/api';

export function LoginScreen() {
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as any)?.from?.pathname || '/';

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Harap masukkan username dan password.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await loginUser(username.trim(), password);
      navigate(from, { replace: true });
    } catch (err: any) {
      const msg = err?.message || 'Login gagal. Periksa kredensial atau koneksi backend.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleQuickFill = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
    setError(null);
  };

  return (
    <div className="login-page">
      <div className="login-card">
        {/* Header */}
        <div className="login-card__header">
          <div className="login-card__logo-row">
            <LogoMark size={44} />
            <div className="login-card__title-box">
              <h1 className="login-card__title">AEGIS PLATFORM</h1>
              <span className="login-card__badge">Multi-Tenant Security Gateway</span>
            </div>
          </div>
          <p className="login-card__subtitle">
            Sistem Pemantauan Keamanan Siber & Deteksi Ancaman Infrastruktur Kritis
          </p>
        </div>

        {/* Error notification */}
        {error && (
          <div className="login-alert" role="alert">
            <AlertTriangle className="login-alert__icon" aria-hidden />
            <div className="login-alert__text">{error}</div>
          </div>
        )}

        {/* Credentials Form */}
        <form onSubmit={handleSubmit} className="login-form">
          <div className="login-field">
            <label className="login-field__label" htmlFor="username">
              Username Operator
            </label>
            <div className="login-field__control">
              <User className="login-field__icon" aria-hidden />
              <input
                id="username"
                type="text"
                className="login-field__input"
                placeholder="misal: operator_alpha atau admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                required
                disabled={loading}
              />
            </div>
          </div>

          <div className="login-field">
            <label className="login-field__label" htmlFor="password">
              Kata Sandi / Password
            </label>
            <div className="login-field__control">
              <Lock className="login-field__icon" aria-hidden />
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                className="login-field__input"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                disabled={loading}
              />
              <button
                type="button"
                className="login-field__action"
                onClick={() => setShowPassword(!showPassword)}
                title={showPassword ? 'Sembunyikan' : 'Tampilkan'}
                tabIndex={-1}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="login-submit-btn"
            disabled={loading}
          >
            {loading ? (
              <span className="login-submit-btn__spinner">Memverifikasi Otoritas...</span>
            ) : (
              <>
                <span>Masuk ke Konsol Kendali</span>
                <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>

        {/* Quick-Access Tenant Presets */}
        <div className="login-presets">
          <div className="login-presets__heading">
            <span>Akses Cepat Pengujian Multi-Tenant:</span>
          </div>
          <div className="login-presets__grid">
            <button
              type="button"
              className="login-preset-chip"
              onClick={() => handleQuickFill('operator_alpha', 'Alpha@Aegis2026!')}
            >
              <div className="login-preset-chip__name">Unit Alpha</div>
              <div className="login-preset-chip__scope">Scope: Terisolasi (Hanya Server Unit Alpha)</div>
            </button>

            <button
              type="button"
              className="login-preset-chip"
              onClick={() => handleQuickFill('operator_bravo', 'Bravo@Aegis2026!')}
            >
              <div className="login-preset-chip__name">Unit Bravo</div>
              <div className="login-preset-chip__scope">Scope: Terisolasi (Hanya Server Unit Bravo)</div>
            </button>

            <button
              type="button"
              className="login-preset-chip login-preset-chip--admin"
              onClick={() => handleQuickFill('admin', 'Aegis@CommandHQ2026!')}
            >
              <div className="login-preset-chip__name">HQ Command</div>
              <div className="login-preset-chip__scope">Scope: Superadmin (Akses Seluruh Unit)</div>
            </button>
          </div>
        </div>

        {/* Security Footer Notice */}
        <div className="login-card__footer">
          <Shield size={14} className="login-card__footer-icon" />
          <span>Isolasi server-side aktif: Server Unit Alpha terisolasi penuh dari Unit Bravo.</span>
        </div>
      </div>
    </div>
  );
}
export default LoginScreen;
