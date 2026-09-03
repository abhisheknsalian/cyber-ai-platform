import { BrowserRouter, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/layout/AppShell";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { AboutPage } from "./pages/AboutPage";
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";
import { NetworkDetectionPage } from "./pages/NetworkDetectionPage";
import { RegisterPage } from "./pages/RegisterPage";
import { ThreatAnalysisPage } from "./pages/ThreatAnalysisPage";
import { ThreatIntelligencePage } from "./pages/ThreatIntelligencePage";

function AuthGate() {
  const { ready, authenticated } = useAuth();

  if (!ready) {
    // Avoids flashing the login page (or the app) before GET /auth/me resolves.
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-text-muted">Loading…</div>
    );
  }

  if (!authenticated) {
    return (
      <Routes>
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<LoginPage />} />
      </Routes>
    );
  }

  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/analyze" element={<ThreatAnalysisPage />} />
        <Route path="/detection" element={<NetworkDetectionPage />} />
        <Route path="/intelligence" element={<ThreatIntelligencePage />} />
        <Route path="/about" element={<AboutPage />} />
      </Routes>
    </AppShell>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AuthGate />
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
