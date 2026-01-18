// ui/src/components/Navigation.tsx
import React from 'react';
import { AppBar, Toolbar, Typography, Button, Box } from '@mui/material';
import { Link } from 'react-router-dom';
import SecurityIcon from '@mui/icons-material/Security';

const Navigation: React.FC = () => {
  return (
    <AppBar position="static">
      <Toolbar>
        <SecurityIcon sx={{ mr: 2 }} />
        <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
          Path Predict
        </Typography>
        <Box>
          <Button color="inherit" component={Link} to="/">
            Dashboard
          </Button>
          <Button color="inherit" component={Link} to="/attack-paths">
            Attack Paths
          </Button>
          <Button color="inherit" component={Link} to="/realtime-events">
            Real-Time Events
          </Button>
          <Button color="inherit" component={Link} to="/terraform-analyzer">
            Terraform Analyzer
          </Button>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navigation;
