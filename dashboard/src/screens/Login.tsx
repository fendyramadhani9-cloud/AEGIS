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
      setError('Please enter your username and password.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await loginUser(username.trim(), password);
      navigate(from, { replace: true });
    } catch (err: any) {
      const msg = err?.message || 'Authentication failed. Please verify your credentials.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        {/* Header */}
        <div className="login-card__header">
          <div className="login-card__logo-row">
            <LogoMark size={44} />
            <div className="login-card__title-box">
              <h1 className="login-card__title">AEGIS CLOUD DEFENSE</h1>
              <span className="login-card__badge">Enterprise Observability</span>
            </div>
          </div>
          <p className="login-card__subtitle">
            Next-generation Linux security observability, threat intelligence & autonomous incident investigation
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
              Username or ID
            </label>
            <div className="login-field__control">
              <User className="login-field__icon" aria-hidden />
              <input
                id="username"
                type="text"
                className="login-field__input"
                placeholder="Enter username or operator ID"
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
              Password
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
                title={showPassword ? 'Hide' : 'Show'}
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
              <span className="login-submit-btn__spinner">Authenticating...</span>
            ) : (
              <>
                <span>Sign In to Console</span>
                <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>

        {/* Security Footer Notice */}
        <div className="login-card__footer">
          <Shield size={14} className="login-card__footer-icon" />
          <span>256-BIT ENCRYPTION • ZERO-TRUST ARCHITECTURE • ALL SESSIONS AUDITED</span>
        </div>
      </div>
    </div>
  );
}
export default LoginScreen;
