import { useCallback, useEffect, useState, useSyncExternalStore } from 'react';
import { actions, store } from '../data/api';

export type QueryState<T> =
  | { status: 'loading'; data?: undefined; error?: undefined }
  | { status: 'error'; data?: undefined; error: Error }
  | { status: 'success'; data: T; error?: undefined };

/**
 * Minimal data hook. Re-runs when `deps` change or when the store is
 * mutated.
 */
export function useQuery<T>(fetcher: () => Promise<T>, deps: unknown[] = []): QueryState<T> & { retry: () => void } {
  const version = useSyncExternalStore(store.subscribe, store.getVersion);
  const [nonce, setNonce] = useState(0);
  const [state, setState] = useState<QueryState<T>>({ status: 'loading' });

  useEffect(() => {
    let alive = true;
    setState({ status: 'loading' });
    fetcher().then(
      (data) => alive && setState({ status: 'success', data }),
      (error: Error) => alive && setState({ status: 'error', error }),
    );
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [version, nonce, ...deps]);

  const retry = useCallback(() => {
    setState({ status: 'loading' });
    setNonce((n) => n + 1);
  }, []);

  return { ...state, retry };
}

/** Re-render every `ms` so relative times and countdowns stay current. */
export function useNow(ms = 30_000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => {
      actions.expireSessions();
      setNow(Date.now());
    }, ms);
    return () => clearInterval(id);
  }, [ms]);
  return now;
}

