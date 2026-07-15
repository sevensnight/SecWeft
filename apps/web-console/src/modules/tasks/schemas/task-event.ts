import { z } from 'zod';

export const taskEventSchema = z.object({
  id: z.number().int().positive(),
  event_type: z.string().min(1),
  payload: z.record(z.string(), z.unknown()),
  created_at: z.string().min(1),
});
