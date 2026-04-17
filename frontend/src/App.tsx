import type { ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Nav from './components/Nav';
import { useAuth } from './hooks/useAuth';
import Login from './pages/Login';
import Plan from './pages/Plan';
import Review from './pages/Review';
import Today from './pages/Today';

function Shell({ children }: { children: ReactNode }): JSX.Element {
  return (
    <>
      <Nav />
      {children}
    </>
  );
}

function RequireAuth({ children }: { children: ReactNode }): JSX.Element {
  const { authed } = useAuth();
  if (!authed) return <Navigate to="/login" replace />;
  return <Shell>{children}</Shell>;
}

export default function App(): JSX.Element {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/today"
        element={
          <RequireAuth>
            <Today />
          </RequireAuth>
        }
      />
      <Route
        path="/plan"
        element={
          <RequireAuth>
            <Plan />
          </RequireAuth>
        }
      />
      <Route
        path="/review"
        element={
          <RequireAuth>
            <Review />
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/today" replace />} />
    </Routes>
  );
}
