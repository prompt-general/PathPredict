// ui/src/pages/AttackPaths.tsx
import React, { useEffect, useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  SelectChangeEvent,
  LinearProgress,
} from '@mui/material';
import CytoscapeComponent from 'react-cytoscapejs';
import { api } from '../services/api';

interface AttackPath {
  path_id: string;
  source: string;
  target: string;
  nodes: string[];
  relationships: string[];
  hop_count: number;
  risk_score: number;
  risk_level: string;
}

const AttackPaths: React.FC = () => {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [selectedPath, setSelectedPath] = useState<string>('');
  const [graphElements, setGraphElements] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchAttackPaths();
  }, []);

  const fetchAttackPaths = async () => {
    setLoading(true);
    try {
      const response = await api.get('/attack-paths/detect?limit=20');
      setPaths(response.data.paths);
    } catch (error) {
      console.error('Failed to fetch attack paths:', error);
    } finally {
      setLoading(false);
    }
  };

  const handlePathChange = (event: SelectChangeEvent) => {
    const pathId = event.target.value;
    setSelectedPath(pathId);

    const path = paths.find(p => p.path_id === pathId);
    if (path) {
      const elements: any[] = [];
      const nodeIds = new Set<string>();

      // Add nodes
      path.nodes.forEach((node, index) => {
        nodeIds.add(node);
        elements.push({
          data: { id: node, label: node.split('::').pop() },
        });
      });

      // Add edges
      for (let i = 0; i < path.nodes.length - 1; i++) {
        const source = path.nodes[i];
        const target = path.nodes[i + 1];
        const relationship = path.relationships[i] || 'connected';
        
        elements.push({
          data: {
            id: `${source}-${target}`,
            source,
            target,
            label: relationship,
          },
        });
      }

      setGraphElements(elements);
    }
  };

  const layout = {
    name: 'cose',
    directed: true,
    padding: 50,
  };

  const styleSheet = [
    {
      selector: 'node',
      style: {
        'background-color': '#90caf9',
        'label': 'data(label)',
        'text-valign': 'center',
        'text-halign': 'center',
        'color': '#fff',
        'font-size': '10px',
        'width': '60px',
        'height': '60px',
      },
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': '#f48fb1',
        'target-arrow-color': '#f48fb1',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '8px',
        'color': '#fff',
        'text-background-color': '#333',
        'text-background-opacity': 1,
      },
    },
  ];

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Attack Paths
      </Typography>

      {loading && <LinearProgress />}

      <Paper sx={{ p: 2, mb: 3 }}>
        <FormControl fullWidth>
          <InputLabel>Select Attack Path</InputLabel>
          <Select
            value={selectedPath}
            label="Select Attack Path"
            onChange={handlePathChange}
          >
            {paths.map(path => (
              <MenuItem key={path.path_id} value={path.path_id}>
                {path.source} → {path.target} (Risk: {path.risk_level}, Hops: {path.hop_count})
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Paper>

      {graphElements.length > 0 && (
        <Paper sx={{ p: 2, height: '600px' }}>
          <CytoscapeComponent
            elements={graphElements}
            style={{ width: '100%', height: '100%' }}
            layout={layout}
            stylesheet={styleSheet}
          />
        </Paper>
      )}
    </Box>
  );
};

export default AttackPaths;
