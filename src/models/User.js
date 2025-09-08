const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// 사용자 스키마 정의
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  password: { type: String, required: true },
  nickname: { type: String, required: true, trim: true },

  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },

  lastCommentAt: { type: Date, default: null },
  verificationCode: { type: String },
  verificationExpires: { type: Date },
  resetPasswordCode: { type: String },
  resetPasswordExpires: { type: Date },
  lastLogin: { type: Date, default: Date.now },
  isAdmin: { type: Boolean, default: false },
});

// 비밀번호 저장 전 암호화
userSchema.pre('save', async function (next) {
  const user = this;

  if (user.isModified('email') && typeof user.email === 'string') {
    user.email = user.email.trim().toLowerCase();
  }

  if (user.isModified('password')) {
    try {
      // 이미 해시된 문자열이 아니면 해시
      if (!user.password.startsWith('$2b$')) {
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(user.password, salt);
      }
      next();
    } catch (error) {
      next(error);
    }
  } else {
    next();
  }
});

// 비밀번호 비교 메서드
userSchema.methods.comparePassword = async function (inputPassword) {
  return bcrypt.compare(inputPassword, this.password);
};

// 마지막 로그인 시간 업데이트
userSchema.methods.updateLastLogin = function () {
  this.lastLogin = Date.now();
  return this.save();
};

userSchema.statics.findByIdentifier = function (identifier) {
  if (!identifier) return Promise.resolve(null);
  const email = String(identifier).trim().toLowerCase();
  return this.findOne({ $or: [{ email }, { username: identifier.trim() }] }).exec();
};

// 사용자 모델 생성
const User = mongoose.model('User', userSchema);

module.exports = User;
