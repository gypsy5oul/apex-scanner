import React, { useState, useMemo } from 'react';
import { TableCell, TableSortLabel } from '@mui/material';

// Lightweight client-side sorting for MUI <Table>.
//
// useTableSort(rows, accessors, initial) -> { sorted, orderBy, order, handleSort }
//   accessors: { columnKey: (row) => comparableValue }
//   initial:   { key, dir }  (dir = 'asc' | 'desc')
//
// Pair with <SortableHeadCell> which renders a TableSortLabel and sets the
// WCAG `aria-sort` attribute on the active column.

export function useTableSort(rows, accessors = {}, initial = {}) {
  const [orderBy, setOrderBy] = useState(initial.key || null);
  const [order, setOrder] = useState(initial.dir || 'asc');

  const sorted = useMemo(() => {
    if (!orderBy || !Array.isArray(rows)) return rows || [];
    const acc = accessors[orderBy] || ((r) => r?.[orderBy]);
    const dir = order === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const av = acc(a);
      const bv = acc(b);
      if (av == null && bv == null) return 0;
      if (av == null) return 1; // nulls always sink
      if (bv == null) return -1;
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
      return String(av).localeCompare(String(bv), undefined, { numeric: true }) * dir;
    });
  }, [rows, orderBy, order, accessors]);

  const handleSort = (key) => {
    if (orderBy === key) {
      setOrder((o) => (o === 'asc' ? 'desc' : 'asc'));
    } else {
      setOrderBy(key);
      setOrder('asc');
    }
  };

  return { sorted, orderBy, order, handleSort };
}

export function SortableHeadCell({ columnKey, orderBy, order, onSort, children, align }) {
  const active = orderBy === columnKey;
  return (
    <TableCell
      align={align}
      sortDirection={active ? order : false}
      aria-sort={active ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <TableSortLabel
        active={active}
        direction={active ? order : 'asc'}
        onClick={() => onSort(columnKey)}
      >
        {children}
      </TableSortLabel>
    </TableCell>
  );
}
