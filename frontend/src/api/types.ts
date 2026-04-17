export type Source = 'phone' | 'checkin' | 'manual' | 'plan';

export interface Block {
  id?: number;
  client_id: string;
  start_ts: string;
  end_ts: string;
  source: Source;
  app?: string | null;
  activity?: string | null;
  category?: string | null;
}

export interface SummaryBucket {
  category: string;
  minutes: number;
}

export interface TodaySummary {
  date: string;
  total_minutes: number;
  accounted_minutes: number;
  unaccounted_minutes: number;
  buckets: SummaryBucket[];
}

export interface PlannedBlock {
  day: string;
  start_ts: string;
  end_ts: string;
  category?: string | null;
  note?: string | null;
}
