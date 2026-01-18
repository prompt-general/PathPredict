// ui/src/App.tsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Dashboard from './pages/Dashboard';
import AttackPaths from './pages/AttackPaths';
import RealTimeEvents from './pages/RealTimeEvents';
import TerraformAnalyzer from './pages/TerraformAnalyzer';
import Navigation from './components/Navigation';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#90caf9',
    },
    secondary: {
      main: '#f48fb1',
    },
    background: {
      default: '#121212',
      paper: '#1d1d1d',
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Router>
        <Navigation />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/attack-paths" element={<AttackPaths />} />
          <Route path="/realtime-events" element={<RealTimeEvents />} />
          <Route path="/terraform-analyzer" element={<TerraformAnalyzer />} />
        </Routes>
      </Router>
    </ThemeProvider>
  );
}

export default App;
