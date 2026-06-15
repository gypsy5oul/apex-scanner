import React from 'react';
import { Box, Card, CardContent, Grid, Skeleton, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';

// Reusable skeleton placeholders. Prefer these over a bare spinner for
// loads over ~300ms — they preserve layout (no CLS) and read as faster.

export function PageHeaderSkeleton() {
  return (
    <Box sx={{ mb: 4 }}>
      <Skeleton variant="text" width={280} height={40} />
      <Skeleton variant="text" width={420} height={24} />
    </Box>
  );
}

export function StatCardsSkeleton({ count = 4 }) {
  return (
    <Grid container spacing={3} sx={{ mb: 4 }}>
      {Array.from({ length: count }).map((_, i) => (
        <Grid item xs={12} sm={6} lg={3} key={i}>
          <Card>
            <CardContent sx={{ p: 2.5 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                <Skeleton variant="rounded" width={40} height={40} />
                <Skeleton variant="text" width={100} />
              </Box>
              <Skeleton variant="text" width={80} height={48} />
              <Skeleton variant="text" width={60} />
            </CardContent>
          </Card>
        </Grid>
      ))}
    </Grid>
  );
}

export function TableSkeleton({ rows = 6, cols = 5 }) {
  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            {Array.from({ length: cols }).map((_, i) => (
              <TableCell key={i}><Skeleton variant="text" /></TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {Array.from({ length: rows }).map((_, r) => (
            <TableRow key={r}>
              {Array.from({ length: cols }).map((_, c) => (
                <TableCell key={c}><Skeleton variant="text" /></TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

export function CardGridSkeleton({ count = 4, height = 160, cols = { xs: 12, md: 6 } }) {
  return (
    <Grid container spacing={3}>
      {Array.from({ length: count }).map((_, i) => (
        <Grid item {...cols} key={i}>
          <Skeleton variant="rounded" height={height} />
        </Grid>
      ))}
    </Grid>
  );
}
