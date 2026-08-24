import { BrowserRouter, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/layout/AppShell";
import { AboutPage } from "./pages/AboutPage";
import { DashboardPage } from "./pages/DashboardPage";
import { ThreatAnalysisPage } from "./pages/ThreatAnalysisPage";
import { ThreatIntelligencePage } from "./pages/ThreatIntelligencePage";

function App() {
  return (
    <BrowserRouter>
      <AppShell>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/analyze" element={<ThreatAnalysisPage />} />
          <Route path="/intelligence" element={<ThreatIntelligencePage />} />
          <Route path="/about" element={<AboutPage />} />
        </Routes>
      </AppShell>
    </BrowserRouter>
  );
}

export default App;
