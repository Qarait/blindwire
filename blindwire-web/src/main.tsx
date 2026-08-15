import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App, createBrowserController } from './App';

const root = document.getElementById('root');
if (!root) {
  throw new Error('BlindWire root element is missing');
}
const controller = createBrowserController();

createRoot(root).render(
  <StrictMode>
    <App controller={controller} />
  </StrictMode>,
);
