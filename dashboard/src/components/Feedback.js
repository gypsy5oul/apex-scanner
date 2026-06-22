import React, { createContext, useContext, useState, useCallback, useRef } from 'react';
import {
  Snackbar,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Button,
} from '@mui/material';

// App-wide feedback primitives that replace the browser's native alert() and
// window.confirm() (which are unstyled, blocking, and untestable).
//
//   const toast = useToast();
//   toast('Policy saved', 'success');
//
//   const confirm = useConfirm();
//   if (!(await confirm({ title: 'Delete policy?', message: '…', destructive: true }))) return;
//
// Both are theme-aware and accessible (Snackbar uses role="alert"/aria-live;
// the confirm dialog traps focus and is keyboard-operable).

const FeedbackContext = createContext(null);

export function FeedbackProvider({ children }) {
  // ---- Toast / snackbar ----
  const [toastState, setToastState] = useState({ open: false, message: '', severity: 'info' });
  const toast = useCallback((message, severity = 'info') => {
    setToastState({ open: true, message, severity });
  }, []);
  const closeToast = (_event, reason) => {
    if (reason === 'clickaway') return;
    setToastState((s) => ({ ...s, open: false }));
  };

  // ---- Confirm dialog (promise-based) ----
  const [confirmState, setConfirmState] = useState({
    open: false,
    title: '',
    message: '',
    confirmLabel: 'Confirm',
    cancelLabel: 'Cancel',
    destructive: false,
  });
  const resolverRef = useRef(null);
  const confirm = useCallback((opts) => {
    return new Promise((resolve) => {
      resolverRef.current = resolve;
      setConfirmState({
        open: true,
        title: 'Are you sure?',
        message: '',
        confirmLabel: 'Confirm',
        cancelLabel: 'Cancel',
        destructive: false,
        ...opts,
      });
    });
  }, []);
  const settle = (value) => {
    setConfirmState((s) => ({ ...s, open: false }));
    if (resolverRef.current) {
      resolverRef.current(value);
      resolverRef.current = null;
    }
  };

  return (
    <FeedbackContext.Provider value={{ toast, confirm }}>
      {children}

      <Snackbar
        open={toastState.open}
        autoHideDuration={4000}
        onClose={closeToast}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={closeToast}
          severity={toastState.severity}
          variant="filled"
          sx={{ width: '100%', alignItems: 'center' }}
        >
          {toastState.message}
        </Alert>
      </Snackbar>

      <Dialog
        open={confirmState.open}
        onClose={() => settle(false)}
        maxWidth="xs"
        fullWidth
        aria-labelledby="confirm-dialog-title"
      >
        <DialogTitle id="confirm-dialog-title" sx={{ fontWeight: 700 }}>
          {confirmState.title}
        </DialogTitle>
        {confirmState.message && (
          <DialogContent>
            <DialogContentText sx={{ color: 'text.secondary' }}>
              {confirmState.message}
            </DialogContentText>
          </DialogContent>
        )}
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => settle(false)} color="inherit">
            {confirmState.cancelLabel}
          </Button>
          <Button
            onClick={() => settle(true)}
            color={confirmState.destructive ? 'error' : 'primary'}
            variant="contained"
            autoFocus
          >
            {confirmState.confirmLabel}
          </Button>
        </DialogActions>
      </Dialog>
    </FeedbackContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(FeedbackContext);
  if (!ctx) throw new Error('useToast must be used within <FeedbackProvider>');
  return ctx.toast;
}

export function useConfirm() {
  const ctx = useContext(FeedbackContext);
  if (!ctx) throw new Error('useConfirm must be used within <FeedbackProvider>');
  return ctx.confirm;
}
