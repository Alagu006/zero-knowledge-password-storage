import { Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import { AutoLockProvider } from "./contexts/AutoLockContext";
import { VaultProvider } from "./contexts/VaultContext";
import { LoginPage } from "./components/LoginPage";
import { RegisterPage } from "./components/RegisterPage";
import { VaultPage } from "./components/VaultPage";
import { Layout } from "./components/Layout";
import { ChangePasswordPage } from "./components/ChangePasswordPage";
import { RecoverAccountPage } from "./components/RecoverAccountPage";
import { TwoFactorSetupPage } from "./components/TwoFactorSetupPage";
import { SessionsPage } from "./components/SessionsPage";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { token } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { token } = useAuth();
  if (token) return <Navigate to="/vault" replace />;
  return <>{children}</>;
}

export function App() {
  return (
    <AuthProvider>
      <AutoLockProvider>
        <Routes>
          <Route
            path="/login"
            element={
              <PublicRoute>
                <LoginPage />
              </PublicRoute>
            }
          />
          <Route
            path="/register"
            element={
              <PublicRoute>
                <RegisterPage />
              </PublicRoute>
            }
          />
          <Route
            path="/vault"
            element={
              <ProtectedRoute>
                <VaultProvider>
                  <VaultPage />
                </VaultProvider>
              </ProtectedRoute>
            }
          />
          <Route
            path="/change-password"
            element={
              <ProtectedRoute>
                <ChangePasswordPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/2fa-setup"
            element={
              <ProtectedRoute>
                <TwoFactorSetupPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/sessions"
            element={
              <ProtectedRoute>
                <SessionsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/recover"
            element={
              <PublicRoute>
                <RecoverAccountPage />
              </PublicRoute>
            }
          />
          <Route path="*" element={<Navigate to="/vault" replace />} />
        </Routes>
      </AutoLockProvider>
    </AuthProvider>
  );
}
