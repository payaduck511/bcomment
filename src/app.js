const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const multer = require('multer');
const { exec } = require('child_process');
const cron = require('node-cron');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { createWorker } = require('tesseract.js');
const crypto = require('crypto');
const http = require('http');
const { Server } = require('socket.io');

const REPO_ROOT  = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(REPO_ROOT, 'public');
const PAGES_DIR  = path.join(PUBLIC_DIR, 'pages');
const UPLOADS_DIR = path.join(REPO_ROOT, 'uploads');

const Like              = require('./models/Like');
const Report            = require('./models/report');
const User              = require('./models/User');
const Comment           = require('./models/Comment');
const JobDescription    = require('./models/JobDescription');
const EmailVerification = require('./models/EmailVerification');
const CharacterName     = require('./models/CharacterName');
const { authenticateToken, isAdmin } =  require('./middleware/authMiddleware');
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', credentials: true }
});

const LiveChat = require('./models/LiveChat');

// ---- 기본 미들웨어 ----
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));

// ---- 정적 파일 ----
app.use(express.static(PUBLIC_DIR));
app.use('/assets', express.static(path.join(PUBLIC_DIR, 'assets')));
app.use('/pages', express.static(PAGES_DIR));

// ---- 유틸 ----
const delay = (ms) => new Promise(res => setTimeout(res, ms));

// ---- 메일러 ----
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// ====== 업로드/OCR ======
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
const upload = multer({ dest: UPLOADS_DIR });

app.post('/api/process-image', async (req, res) => {
  const { image } = req.body;
  if (!image) return res.status(400).json({ message: '이미지가 없습니다.' });

  const worker = createWorker();
  try {
    await worker.load();
    await worker.loadLanguage('eng');
    await worker.initialize('eng');

    const { data: { text } } = await worker.recognize(image);
    const cooldown = parseInt(text.trim(), 10);
    res.json({ cooldown: isNaN(cooldown) ? '인식 실패' : cooldown });
  } catch (error) {
    console.error('OCR 처리 중 오류:', error);
    res.status(500).json({ message: 'OCR 처리 실패' });
  } finally {
    try { await worker.terminate(); } catch (_) {}
  }
});

// ====== 넥슨 API 유틸 ======
async function getCharacterOcid(characterName) {
  try {
    const urlString = `https://open.api.nexon.com/maplestory/v1/id?character_name=${encodeURIComponent(characterName)}`;
    const response = await axios.get(urlString, {
      headers: { 'x-nxopen-api-key': process.env.NEXON_API_KEY },
    });
    if (response.data && response.data.ocid) return response.data.ocid;
    throw new Error(`Character not found for name: ${characterName}`);
  } catch (error) {
    console.error('Failed to fetch character ocid:', error.message);
    throw new Error('Failed to fetch character ocid');
  }
}
async function getCharacterBasicInfo(ocid) {
  try {
    const urlString = `https://open.api.nexon.com/maplestory/v1/character/basic?ocid=${ocid}`;
    const response = await axios.get(urlString, {
      headers: { 'x-nxopen-api-key': process.env.NEXON_API_KEY },
    });
    return response.data;
  } catch (error) {
    if (error.response) console.error('Failed to fetch basic info:', error.response.data);
    else console.error('Failed to fetch basic info:', error.message);
    throw new Error('Failed to fetch basic info');
  }
}

// ====== 인증 옵션 미들웨어 (있으면 토큰 검사) ======
function authenticateTokenOptional(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader) return authenticateToken(req, res, next);
  next();
}

// ====== 넥슨 관련 라우트 ======
app.get('/api/character/:characterName/equipment', async (req, res) => {
  try {
    const { characterName } = req.params;
    const ocid = await getCharacterOcid(characterName);
    const url = `https://open.api.nexon.com/maplestory/v1/character/item-equipment?ocid=${ocid}`;
    const response = await axios.get(url, { headers: { 'x-nxopen-api-key': process.env.NEXON_API_KEY } });
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching equipment data:', error.message);
    res.status(500).json({ error: 'Failed to fetch equipment data' });
  }
});
app.get('/api/character/:characterName/cash-equipment', async (req, res) => {
  try {
    const { characterName } = req.params;
    const ocid = await getCharacterOcid(characterName);
    const url = `https://open.api.nexon.com/maplestory/v1/character/cashitem-equipment?ocid=${ocid}`;
    const response = await axios.get(url, { headers: { 'x-nxopen-api-key': process.env.NEXON_API_KEY } });
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching cash equipment data:', error.message);
    res.status(500).json({ error: 'Failed to fetch cash equipment data' });
  }
});

// ====== 회원가입/로그인/계정 관련 ======
app.post('/api/register', async (req, res) => {
  const { username, password, nickname, email } = req.body;
  if (!username || !password || !nickname || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    const existingUser = await User.findOne({ username });
    const existingEmail = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Username already exists' });
    if (existingEmail) return res.status(400).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, nickname, email });
    await newUser.save();
    res.status(201).json({ message: 'Registration successful' });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// 이메일 인증/검증
app.post('/api/send-verification-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'Email Verification Code',
      text: `Your verification code is: ${verificationCode}`,
    };
    transporter.sendMail(mailOptions, async (error) => {
      if (error) {
        console.error('Error sending email:', error);
        return res.status(500).json({ error: 'Failed to send verification code' });
      }
      await EmailVerification.updateOne(
        { email },
        { $set: { verificationCode, verificationExpires: Date.now() + 600000 } },
        { upsert: true }
      );
      res.json({ message: 'Verification code sent successfully' });
    });
  } catch (error) {
    console.error('Error in sending verification code:', error);
    res.status(500).json({ error: 'Server error while sending verification code' });
  }
});

app.post('/api/verify-reset-code', async (req, res) => {
  const { email, resetCode } = req.body;
  if (!email || !resetCode) return res.status(400).json({ error: 'Email and verification code are required.' });
  try {
    const verificationRecord = await EmailVerification.findOne({ email });
    if (!verificationRecord) return res.status(404).json({ error: 'Verification record not found.' });
    if (verificationRecord.verificationCode !== resetCode) return res.status(400).json({ error: 'Invalid verification code.' });
    if (Date.now() > verificationRecord.verificationExpires) return res.status(400).json({ error: 'Verification code expired.' });
    await EmailVerification.deleteOne({ email });
    res.json({ message: 'Verification successful' });
  } catch (error) {
    console.error('Error verifying code:', error);
    res.status(500).json({ error: 'Server error while verifying code' });
  }
});

// 로그인
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
  try {
    const user = await User.findOne({ username }).catch(() => null);
    if (!user) return res.status(400).json({ error: 'Invalid username or password' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid username or password' });

    const token = jwt.sign(
      { id: user._id.toString(), username: user.username, nickname: user.nickname },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// 비밀번호 변경 (이메일 + 새 비번)
app.post('/api/update-password', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: '유효한 email과 6자 이상 password가 필요합니다.' });
    }

    const user = await User.findOne({ email }).exec();
    if (!user) return res.status(404).json({ error: '해당 이메일의 사용자 없음' });

    const hashed = await bcrypt.hash(password, 10);
    user.password = hashed;
    await user.save();

    return res.json({ message: '비밀번호가 재설정되었습니다.' });
  } catch (e) {
    console.error('Error updating password:', e);
    return res.status(500).json({ error: '비밀번호 재설정 중 서버 오류' });
  }
});

// 아이디 중복 체크
app.post('/api/check-username', async (req, res) => {
  try {
    const username = (req.body?.username || '').trim();
    if (!username || username.length < 4) {
      return res.status(400).json({ error: '아이디는 최소 4자 이상이어야 합니다.' });
    }

    const exists = await User.exists({ username });
    if (exists) {
      return res.status(409).json({ available: false, message: '이미 사용 중인 아이디입니다.' });
    }
    return res.status(200).json({ available: true, message: '사용 가능한 아이디입니다.' });
  } catch (e) {
    console.error('[check-username] error:', e);
    return res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 닉네임 중복 체크
app.post('/api/check-nickname', async (req, res) => {
  try {
    const nickname = (req.body?.nickname || '').trim();
    if (!nickname || nickname.length < 2) {
      return res.status(400).json({ error: '닉네임은 최소 2자 이상이어야 합니다.' });
    }

    const exists = await User.exists({ nickname });
    if (exists) {
      return res.status(409).json({ available: false, message: '이미 사용 중인 닉네임입니다.' });
    }
    return res.status(200).json({ available: true, message: '사용 가능한 닉네임입니다.' });
  } catch (e) {
    console.error('[check-nickname] error:', e);
    return res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ====== 댓글 관련 ======
app.post('/api/comments', authenticateToken, async (req, res) => {
  const { character_id, content } = req.body;
  const username = req.user.username;
  if (!character_id || !content) return res.status(400).json({ error: 'Character ID and content are required' });

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const cooldownTime = 60 * 1000;
    const now = Date.now();
    const last = user.lastCommentAt ? user.lastCommentAt.getTime() : 0;
    if (now - last < cooldownTime) {
      const timeLeft = Math.ceil((cooldownTime - (now - last)) / 1000);
      return res.status(429).json({ error: `댓글은 ${timeLeft}초 후에 다시 작성할 수 있습니다.`, timeLeft });
    }

    const newComment = new Comment({ character_id, username, content, createdAt: new Date() });
    await newComment.save();
    user.lastCommentAt = new Date();
    await user.save();
    res.status(201).json(newComment);
  } catch (error) {
    console.error('Error saving comment:', error);
    res.status(500).json({ error: 'Failed to post comment' });
  }
});

app.post('/api/comments/:commentId/like', authenticateToken, async (req, res) => {
  const commentId = req.params.commentId;
  const username = req.user.username;
  try {
    const existing = await Like.findOne({ commentId, username });
    if (existing) {
      await Like.deleteOne({ _id: existing._id });
      await Comment.findByIdAndUpdate(commentId, { $inc: { likes: -1 } });
      return res.json({ message: '추천이 취소되었습니다.', liked: false });
    } else {
      const newLike = new Like({ commentId, username });
      await newLike.save();
      await Comment.findByIdAndUpdate(commentId, { $inc: { likes: 1 } });
      return res.json({ message: '추천되었습니다.', liked: true });
    }
  } catch (error) {
    console.error('Error liking/unliking comment:', error);
    res.status(500).json({ error: '추천 처리 중 오류가 발생했습니다.' });
  }
});

app.get('/api/comments/:character_id', authenticateTokenOptional, async (req, res) => {
  const character_id = req.params.character_id;
  const username = req.user ? req.user.username : null;
  try {
    const comments = await Comment.find({ character_id }).sort({ createdAt: -1 });
    const ids = comments.map(c => c._id);
    let userLikes = [];
    if (username) userLikes = await Like.find({ commentId: { $in: ids }, username });
    const likedSet = new Set(userLikes.map(l => l.commentId.toString()));
    const data = comments.map(c => ({ ...c.toObject(), liked: likedSet.has(c._id.toString()) }));
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: '댓글을 불러오는 데 실패했습니다.' });
  }
});

app.get('/api/job-comments/:job', async (req, res) => {
  const job = req.params.job;
  try {
    const comments = await Comment.find({ job }).sort({ createdAt: -1 });
    if (!comments || comments.length === 0) return res.status(404).json({ message: '해당 직업에 대한 댓글이 없습니다.' });
    res.status(200).json(comments);
  } catch (error) {
    console.error('직업 댓글 불러오기 실패:', error);
    res.status(500).json({ error: '댓글을 불러오는 중 문제가 발생했습니다.' });
  }
});

app.post('/api/job-comments', authenticateToken, async (req, res) => {
  const { job, content } = req.body;
  const username = req.user.username;
  if (!job || !content) return res.status(400).json({ error: 'Job and content are required' });

  try {
    const newComment = new Comment({ sourceType: 'job', job, username, content, createdAt: new Date() });
    await newComment.save();
    res.status(201).json(newComment);
  } catch (error) {
    console.error('Error saving job comment:', error);
    res.status(500).json({ error: 'Failed to post job comment' });
  }
});

// 직업 설명
app.post('/api/job-description/:jobName', authenticateToken, async (req, res) => {
  const { jobName } = req.params;
  const { description } = req.body;
  try {
    let jd = await JobDescription.findOne({ jobName });
    if (jd) { jd.description = description; await jd.save(); }
    else { jd = new JobDescription({ jobName, description }); await jd.save(); }
    res.json({ message: '직업 설명이 성공적으로 저장되었습니다.', jobDesc: jd });
  } catch (error) {
    console.error('Error saving job description:', error);
    res.status(500).json({ error: '직업 설명을 저장하는 중 오류가 발생했습니다.' });
  }
});
app.get('/api/job-description/:jobName', async (req, res) => {
  const { jobName } = req.params;
  try {
    const jd = await JobDescription.findOne({ jobName });
    if (!jd) return res.status(404).json({ error: '설명 없음' });
    res.json({ description: jd.description });
  } catch (error) {
    console.error('Error fetching job description:', error);
    res.status(500).json({ error: '직업 설명을 불러오는 중 오류가 발생했습니다.' });
  }
});

// 인기/최신 댓글
app.get('/api/popular-comments', async (_req, res) => {
  try {
    const oneWeekAgo = new Date(); oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
    const popular = await Comment.aggregate([
      { $match: { createdAt: { $gte: oneWeekAgo } } },
      { $sort: { likes: -1 } }, { $limit: 10 },
      { $lookup: { from: 'users', localField: 'username', foreignField: 'username', as: 'user_info' } },
      { $lookup: { from: 'characternames', localField: 'character_id', foreignField: 'ocid', as: 'character_info' } },
      { $unwind: { path: '$user_info', preserveNullAndEmptyArrays: true } },
      { $unwind: { path: '$character_info', preserveNullAndEmptyArrays: true } },
      { $project: { job: 1, nickname: { $ifNull: ['$user_info.nickname', 'Unknown User'] },
        characterName: { $ifNull: ['$character_info.character_name', 'Unknown Character'] },
        content: 1, createdAt: 1, likes: 1 } },
    ]);
    const updated = popular.map(c => ({ ...c, displayName: c.job ? `직업: ${c.job}` :
      (c.characterName !== 'Unknown Character' ? c.characterName : 'Unknown Character') }));
    res.status(200).json(updated);
  } catch (e) { console.error('Error fetching popular comments:', e); res.status(500).json({ error: 'Failed to fetch popular comments' }); }
});

app.get('/api/recent-comments', async (_req, res) => {
  try {
    const recent = await Comment.aggregate([
      { $sort: { createdAt: -1 } }, { $limit: 10 },
      { $lookup: { from: 'users', localField: 'username', foreignField: 'username', as: 'user_info' } },
      { $lookup: { from: 'characternames', localField: 'character_id', foreignField: 'ocid', as: 'character_info' } },
      { $unwind: { path: '$user_info', preserveNullAndEmptyArrays: true } },
      { $unwind: { path: '$character_info', preserveNullAndEmptyArrays: true } },
      { $project: { job: 1, nickname: { $ifNull: ['$user_info.nickname', 'Unknown User'] },
        characterName: { $ifNull: ['$character_info.character_name', 'Unknown Character'] },
        content: 1, createdAt: 1 } },
    ]);
    const updated = recent.map(c => ({ ...c, displayName: c.job ? `직업: ${c.job}` :
      (c.characterName !== 'Unknown Character' ? c.characterName : 'Unknown Character') }));
    res.status(200).json(updated);
  } catch (e) { console.error('Error fetching recent comments:', e); res.status(500).json({ error: 'Failed to fetch recent comments' }); }
});

// 내 댓글/삭제
app.get('/api/my-comments', authenticateToken, async (req, res) => {
  try {
    const comments = await Comment.find({ username: req.user.username }).sort({ createdAt: -1 });
    res.status(200).json(comments);
  } catch (e) { console.error('Error fetching user comments:', e); res.status(500).json({ error: 'Failed to fetch user comments' }); }
});
app.delete('/api/comments/:commentId', authenticateToken, async (req, res) => {
  const commentId = req.params.commentId;
  const username = req.user.username;
  try {
    const comment = await Comment.findById(commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    if (comment.username !== username) return res.status(403).json({ error: 'You can only delete your own comments' });
    await Comment.findByIdAndDelete(commentId);
    res.status(200).json({ message: 'Comment deleted successfully' });
  } catch (e) { console.error('Error deleting comment:', e); res.status(500).json({ error: 'Failed to delete comment' }); }
});

// 신고 관련
app.post('/api/reports', authenticateToken, async (req, res) => {
  const { commentId, reason } = req.body;
  const username = req.user.username;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const userId = user._id;
    if (!mongoose.Types.ObjectId.isValid(commentId) || !mongoose.Types.ObjectId.isValid(userId))
      return res.status(400).json({ success: false, message: '유효하지 않은 ID입니다.' });

    const commentObjectId = new mongoose.Types.ObjectId(commentId);
    const userObjectId = new mongoose.Types.ObjectId(userId);
    const existing = await Report.findOne({ commentId: commentObjectId, reportedBy: userObjectId });
    if (existing) return res.status(400).json({ success: false, message: '이미 신고한 댓글입니다.' });

    const newReport = new Report({ commentId: commentObjectId, reportedBy: userObjectId, reason });
    await newReport.save();
    res.json({ success: true, message: '신고가 접수되었습니다.' });
  } catch (e) { console.error('신고 생성 중 오류:', e.message, e.stack); res.status(500).json({ success: false, message: '신고 처리 중 오류가 발생했습니다.' }); }
});

app.delete('/api/admin/reports/:reportId', authenticateToken, isAdmin, async (req, res) => {
  const { reportId } = req.params;
  try {
    const reportData = await Report.findById(reportId).populate('commentId');
    if (!reportData) return res.status(404).json({ success: false, message: '신고를 찾을 수 없습니다.' });
    if (reportData.commentId) await Comment.findByIdAndDelete(reportData.commentId._id);
    await Report.findByIdAndDelete(reportId);
    res.json({ success: true, message: '댓글과 신고가 삭제되었습니다.' });
  } catch (e) { console.error('신고 처리 중 오류:', e.message, e.stack); res.status(500).json({ success: false, message: '신고 처리 중 오류가 발생했습니다.' }); }
});

app.post('/api/admin/reports/:reportId/resolve', authenticateToken, isAdmin, async (req, res) => {
  const { reportId } = req.params;
  try {
    const reportData = await Report.findById(reportId);
    if (!reportData) return res.status(404).json({ success: false, message: '신고를 찾을 수 없습니다.' });
    await Report.findByIdAndDelete(reportId);
    res.json({ success: true, message: '신고가 처리되었습니다.' });
  } catch (e) { console.error('신고 처리 중 오류:', e.message, e.stack); res.status(500).json({ success: false, message: '신고 처리 중 오류가 발생했습니다.' }); }
});

// 캐릭터 기본 정보
app.get('/api/character/:name', async (req, res) => {
  const characterName = req.params.name;
  try {
    console.log(`Received request for character: ${characterName}`);
    await delay(1000);
    const ocid = await getCharacterOcid(characterName);
    console.log(`Fetched ocid: ${ocid}`);
    await delay(1000);
    const basicInfo = await getCharacterBasicInfo(ocid);
    if (!basicInfo) throw new Error('No basic info received');
    basicInfo.ocid = ocid;
    await CharacterName.findOneAndUpdate({ ocid }, { character_name: basicInfo.character_name }, { upsert: true, new: true });
    res.json(basicInfo);
  } catch (error) {
    console.error('Error fetching character info:', error);
    res.status(500).json({ error: 'Failed to fetch character data' });
  }
});

// 로그인된 유저 정보
app.get('/api/user-info', authenticateToken, (req, res) => {
  if (!req.user) return res.status(403).json({ message: 'User not authenticated' });
  res.json({ username: req.user.username, nickname: req.user.nickname });
});

// ====== 페이지 라우팅 (특정 파일) ======
app.get('/reset-password/:token', (req, res) => {
  res.sendFile(path.join(PAGES_DIR, 'reset-password.html'));
});
app.get('/job-chat.html', (_req, res) => {
  res.sendFile(path.join(PAGES_DIR, 'job-chat.html'));
});
app.get('/chat.html', (req, res) => {
  const characterName = req.query.characterName;
  if (!characterName) return res.redirect('/');
  res.sendFile(path.join(PAGES_DIR, 'chat.html'));
});
app.get('/', (_req, res) => {
  res.sendFile(path.join(PAGES_DIR, 'index.html'));
});

app.get(/^\/(?!api|assets|health|pages)(.*)$/, (req, res, next) => {
  let rel = req.path.replace(/^\//, '');
  if (!rel) rel = 'index.html';
  else if (!path.extname(rel)) rel += '.html';

  const full = path.join(PAGES_DIR, rel);

  // 디렉토리 탈출 방지
  if (!full.startsWith(PAGES_DIR)) return res.status(400).send('Bad Request');

  fs.access(full, fs.constants.F_OK, (err) => {
    if (err) return next();
    res.sendFile(full);
  });
});

// Health check
app.get('/health', (_req, res) => {
  res.json({
    mongo: mongoose.connection.readyState,
    uptime: process.uptime(),
  });
});

app.get('/.well-known/appspecific/com.chrome.devtools.json', (_req, res) => {
  res.type('application/json').send('{}');
});

// 404 (요청 로깅)
app.use((req, res) => {
  console.warn('404:', req.method, req.originalUrl);
  res.status(404).send('Not Found');
});

// ====== 부팅 시퀀스 (연결 후 서버 시작) ======
const PORT = process.env.PORT || 3000;

async function bootstrap() {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log('MongoDB connected');

    // SMTP 확인
    transporter.verify((error) => {
      if (error) console.log('SMTP connection error:', error);
      else console.log('SMTP server is ready to take messages');
    });

    // 주기 작업: 추천/댓글 정리 (연결 이후 등록)
    cron.schedule('0 0 * * 4', async () => {
      try {
        console.log('추천 수 초기화 및 추천 수 0인 댓글 삭제 작업 시작');
        await Comment.deleteMany({ likes: 0 });
        await Comment.updateMany({}, { likes: 0 });
        await Like.deleteMany({});
        console.log('추천 수 초기화 완료 및 추천 수 0인 댓글 삭제 완료');
      } catch (error) {
        console.error('추천 수 초기화 및 댓글 삭제 중 오류 발생:', error);
      }
    });
    server.listen(PORT, () => console.log(`✅ Server + Socket.IO running → http://localhost:${PORT}`));
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  }

  // 연결 이벤트 로깅(디버그용)
  mongoose.connection.on('error', (e) => console.error('Mongo connection error:', e));
  mongoose.connection.on('disconnected', () => console.warn('Mongo disconnected'));
}

bootstrap();

// ====== 종료 처리 ======
function gracefulShutdown() {
  console.log('Shutting down...');
  mongoose.connection.close(false, () => {
    console.log('Mongo connection closed.');
    process.exit(0);
  });
}
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

// JWT 인증
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('NO_TOKEN'));
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = { id: payload.id, nickname: payload.nickname };
    next();
  } catch {
    next(new Error('INVALID_TOKEN'));
  }
});

// 연결/메시지/종료
io.on('connection', (socket) => {
  console.log('✅ connected:', socket.user.nickname);

  socket.on('join', (room = 'lobby') => {
    socket.join(room);
    socket.emit('joined', { room, nickname: socket.user.nickname });
  });

  socket.on('chat:message', async ({ room = 'lobby', text }) => {
    const msg = {
      room,
      userId: socket.user.id,
      nickname: socket.user.nickname,
      text: (text || '').slice(0, 500),
      createdAt: new Date()
    };
    try {
      await LiveChat.create(msg);
    } catch (e) {
      console.error('LiveChat 저장 오류:', e?.message || e);
    }
    io.to(room).emit('chat:message', msg);
  });

  socket.on('disconnect', () => {
    console.log('❌ disconnected:', socket.user.nickname);
  });
});
