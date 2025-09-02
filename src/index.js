import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import mongoose from 'mongoose';

const app = express();

// Middlewares
app.use(helmet());
app.use(cors());
app.use(express.json());

// Health route
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'Bcomment', time: new Date().toISOString() });
});

// MongoDB
const { MONGO_URI = 'mongodb://localhost:27017/bcomment', PORT = 4000 } = process.env;

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log('[DB] connected');
    app.listen(PORT, () => console.log(`[API] http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('[DB] connection error:', err.message);
    process.exit(1);
  });
