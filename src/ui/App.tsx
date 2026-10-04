import { Routes, Route, Navigate, useParams, useSearchParams } from "react-router-dom";
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
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Error4xxPage } from "./components/Error4xxPage";
import { Error5xxPage } from "./components/Error5xxPage";

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

function DynamicErrorDispatcher() {
  const { code: paramCode } = useParams<{ code?: string }>();
  const [searchParams] = useSearchParams();
  const code = parseInt(paramCode || searchParams.get("code") || "404", 10);
  if (code >= 500 && code < 600) {
    return <Error5xxPage code={code} />;
  }
  return <Error4xxPage code={code} />;
}

export function App() {
  return (
    <ErrorBoundary>
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
            {/* Dynamic Error Routes */}
            <Route path="/error/:code" element={<DynamicErrorDispatcher />} />
            <Route path="/error" element={<DynamicErrorDispatcher />} />
            <Route path="/4xx/:code" element={<Error4xxPage />} />
            <Route path="/5xx/:code" element={<Error5xxPage />} />

            {/* Direct 4xx Error Routes */}
            <Route path="/400" element={<Error4xxPage code={400} />} />
            <Route path="/401" element={<Error4xxPage code={401} />} />
            <Route path="/402" element={<Error4xxPage code={402} />} />
            <Route path="/403" element={<Error4xxPage code={403} />} />
            <Route path="/404" element={<Error4xxPage code={404} />} />
            <Route path="/405" element={<Error4xxPage code={405} />} />
            <Route path="/408" element={<Error4xxPage code={408} />} />
            <Route path="/409" element={<Error4xxPage code={409} />} />
            <Route path="/410" element={<Error4xxPage code={410} />} />
            <Route path="/413" element={<Error4xxPage code={413} />} />
            <Route path="/418" element={<Error4xxPage code={418} />} />
            <Route path="/422" element={<Error4xxPage code={422} />} />
            <Route path="/423" element={<Error4xxPage code={423} />} />
            <Route path="/429" element={<Error4xxPage code={429} />} />

            {/* Direct 5xx Error Routes */}
            <Route path="/500" element={<Error5xxPage code={500} />} />
            <Route path="/501" element={<Error5xxPage code={501} />} />
            <Route path="/502" element={<Error5xxPage code={502} />} />
            <Route path="/503" element={<Error5xxPage code={503} />} />
            <Route path="/504" element={<Error5xxPage code={504} />} />
            <Route path="/505" element={<Error5xxPage code={505} />} />
            <Route path="/507" element={<Error5xxPage code={507} />} />
            <Route path="/508" element={<Error5xxPage code={508} />} />

            {/* Catch-all unknown paths to custom animatic 404 */}
            <Route path="*" element={<Error4xxPage code={404} />} />
          </Routes>
        </AutoLockProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}


