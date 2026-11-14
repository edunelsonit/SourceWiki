import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { useAuth } from '../lib/auth-context';

export const AuthCallbackPage: React.FC = () => {
  const navigate = useNavigate();
  const { completeWikimediaLogin } = useAuth();

  useEffect(() => {
    completeWikimediaLogin().then((success) => {
      navigate(success ? '/' : '/auth?error=wikimedia_login_failed', { replace: true });
    });
  }, [completeWikimediaLogin, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="flex items-center gap-2 text-gray-600">
        <Loader2 className="h-5 w-5 animate-spin" />
        Completing Wikimedia login...
      </div>
    </div>
  );
};
