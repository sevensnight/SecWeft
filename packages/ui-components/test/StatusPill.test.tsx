import '@testing-library/jest-dom/vitest';

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { StatusPill } from '../src/StatusPill';

describe('StatusPill', () => {
  it('renders a normalized status label', () => {
    render(<StatusPill status="pending_approval" />);
    expect(screen.getByText('pending approval')).toBeInTheDocument();
  });
});
