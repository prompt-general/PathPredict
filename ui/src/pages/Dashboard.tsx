// ui/src/pages/Dashboard.tsx
import React, { useEffect, useState } from 'react';
import {
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  LinearProgress,
} from '@mui/material';
import { DataGrid, GridColDef } from '@mui/x-data-grid';
import { api } from '../services/api';

interface DashboardStats {
  total_nodes: number;
  providers: number;
  critical_resources: number;
  active_connections: number;
  current_attack_paths: number;
}

interface AttackPath {
  id: string;
  source: string;
  target: string;
  risk_score: number;
  risk_level: string;
  hop_count: number;
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentPaths, setRecentPaths] = useState<AttackPath[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const response = await api.get('/realtime/dashboard');
        const data = response.data.dashboard;
        setStats(data.stats);
        setRecentPaths(data.top_risks || []);
      } catch (error) {
        console.error('Failed to fetch dashboard:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboard();
    const interval = setInterval(fetchDashboard, 10000); // Update every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const columns: GridColDef[] = [
    { field: 'source', headerName: 'Source', width: 200 },
    { field: 'target', headerName: 'Target', width: 200 },
    { field: 'risk_score', headerName: 'Risk Score', width: 120 },
    { field: 'risk_level', headerName: 'Risk Level', width: 120 },
    { field: 'hop_count', headerName: 'Hops', width: 80 },
  ];

  if (loading) {
    return <LinearProgress />;
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>

      <Grid container spacing={3}>
        {/* Stats Cards */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Nodes
              </Typography>
              <Typography variant="h5">{stats?.total_nodes || 0}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Cloud Providers
              </Typography>
              <Typography variant="h5">{stats?.providers || 0}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Critical Resources
              </Typography>
              <Typography variant="h5">{stats?.critical_resources || 0}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Active Attack Paths
              </Typography>
              <Typography variant="h5">{stats?.current_attack_paths || 0}</Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Attack Paths */}
        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Recent Attack Paths
            </Typography>
            <div style={{ height: 400, width: '100%' }}>
              <DataGrid
                rows={recentPaths}
                columns={columns}
                pageSize={5}
                rowsPerPageOptions={[5]}
              />
            </div>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;
